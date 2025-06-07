package com.github.svaeu.infuser.client;

import com.github.svaeu.infuser.client.packet.PacketHandler;
import com.github.svaeu.infuser.client.packet.PacketListener;
import com.github.svaeu.infuser.client.usrinterface.cli.CLI;
import com.github.svaeu.infuser.client.usrinterface.ClientMode;
import com.github.svaeu.infuser.client.usrinterface.Interface;
import com.github.svaeu.infuser.client.usrinterface.cli.command.ChannelJoinCommand;
import com.github.svaeu.infuser.client.usrinterface.cli.command.ChannelListCommand;
import com.github.svaeu.infuser.client.util.ConsoleLogger;
import com.github.svaeu.infuser.client.channel.Channel;
import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.PacketProcessor;
import com.github.svaeu.infuser.packets.encryption.ECDHEUtil;
import com.github.svaeu.infuser.packets.encryption.RSAUtil;
import com.github.svaeu.infuser.packets.streamwrapper.PacketOutputStream;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TCPClient extends Thread {
    private final String hostAddress;
    private final int port;
    private ConnectionState connectionState;

    private final File sharedSecret = new File("server_fingerprint.key");
    private PrivateKey handshakeKey;
    private PublicKey serverFingerprint;
    private byte[] salt;

    private boolean isLoggedIn = false,
            isExpectingToken = false,
            isExpectingFingerprint = false,
            isExpectingSignedPubKey = false;

    private byte[] loginToken;
    private final File tokenFile = new File(".enc_auth_token");
    final String
            macUsername = System.getProperty("user.name"),
            osName = System.getProperty("os.name"),
            osArch = System.getProperty("os.arch");

    private String username;

    private final Interface anInterface;
    private Thread interThread;
    private ClientMode clientMode;

    private final ResourceBundle appMessages = ResourceBundle.getBundle("AppMessages", Locale.ENGLISH);

    private Socket clientSocket;

    private PacketListener packetListener;
    private PacketOutputStream packetStream;
    private boolean isStreamClosed = true;

    private SecretKey sessionKey;

    public final int KDF_ITERATIONS = 150000, AES_KEY_SIZE = 256;
    public final String CIPHER_ALGO = "AES", KDF_ALGO = "PBKDF2WithHmacSHA256";

    private Channel crtChannel;
    private final Set<Channel> channels = new HashSet<>();

    public enum ConnectionState {
        DISCONNECTED,
        CONNECTED,
        RECONNECTING
    }

    public TCPClient(String hostAddress, int port, Interface anInterface) {
        this.hostAddress = hostAddress;
        this.port = port;
        this.anInterface = anInterface;
        this.connectionState = ConnectionState.DISCONNECTED;
    }

    public TCPClient initialize() {
        clientMode = getInterface();
        interThread = new Thread(clientMode);
        return this;
    }

    @SuppressWarnings("BusyWait")
    @Override
    public void run() {
        for(;;) {
            if(connectionState == ConnectionState.CONNECTED) {
                try {
                    Thread.sleep(2000); //avoiding tight loop
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                continue;
            }
            terminate();
            crtChannel = null;
            channels.clear();

            try {
                clientSocket = new Socket(hostAddress, port);
                clientSocket.setTcpNoDelay(true);
                clientSocket.setKeepAlive(true);
                clientSocket.setSoTimeout(200000);

                clientMode.notifyToResume();

                packetStream = new PacketOutputStream(clientSocket.getOutputStream()) {
                    @Override
                    public void writePacket(Packet packet, byte[] data) throws IOException {
                        super.writePacket(packet, data);
                    }
                };
                packetListener = new PacketListener(clientSocket.getInputStream(), new PacketProcessor(
                        new PacketHandler(this)), this);
                packetListener.start();

                setConnectionState(ConnectionState.CONNECTED);
                isStreamClosed = false;
            } catch (IOException e) { continue; }

            try {
                performHandshake();
            } catch (IOException | InterruptedException | GeneralSecurityException e) {
                ConsoleLogger.error(null,
                        appMessages.getString("error.handshake") + ": " + e.getMessage());
                continue;
            }

            try {
                login();
            } catch (InterruptedException | ExecutionException | IOException | GeneralSecurityException |
                     TimeoutException e) {
                ConsoleLogger.error(null,
                        appMessages.getString("error.login") + ": " + e.getMessage());
                continue;
            }
            if(interThread != null) {
                if(interThread.isInterrupted())
                    interThread = new Thread(clientMode);

                interThread.start();
            }
        }
    }

    private ClientMode getInterface() {
        Logger.getLogger("").setLevel(Level.OFF);

        switch (anInterface) {
            case COMMAND_LINE -> {
                return new CLI(this, Set.of(
                        new ChannelJoinCommand(this),
                        new ChannelListCommand(this)
                ));
            }
            case GUI -> { }
            default -> {
                return null;
            }
        }
        return null;
    }

    private synchronized void performHandshake() throws IOException, InterruptedException,
            GeneralSecurityException {
        final KeyPair keyPair;
        if(!sharedSecret.exists() || Files.size(sharedSecret.toPath()) == 0) {
            ConsoleLogger.error(null, appMessages.getString("auth.tofu"));
            Thread.sleep(5000);

            clientMode.waitForIt(appMessages.getString("auth.fingerprint"));
            Thread.sleep(3000);

            packetStream.writePacket(Packet.SRV_FINGERPRINT, new byte[]{});
            isExpectingFingerprint = true;

            while(isExpectingFingerprint)
                this.wait();
        }
        try(FileInputStream fileInputStream = new FileInputStream(sharedSecret)) {
            serverFingerprint = RSAUtil.getPublicKeyFromBytes(fileInputStream.readAllBytes());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        keyPair = ECDHEUtil.generateECKeyPair();
        salt = ECDHEUtil.generateSalt();

        packetStream.writePacket(Packet.EC_SIGNATURE, ECDHEUtil.getSerializedSaltedKey(keyPair.getPublic(), salt));

        handshakeKey = keyPair.getPrivate();
        isExpectingSignedPubKey = true;

        while(isExpectingSignedPubKey)
            this.wait();
    }


    public synchronized void login() throws GeneralSecurityException, ExecutionException, InterruptedException, IOException, TimeoutException {
        final long startTime;
        final long timeout;
        long waitTime;

        if(isLoggedIn) return;

        if (!tokenFile.exists() && tokenFile.length() == 0) {
            packetStream.writeEncryptedPacket(Packet.REG_ACT, clientMode
                    .prompt(appMessages.getString("prompt.register.user"))
                    .getBytes(StandardCharsets.UTF_8), sessionKey);

            isExpectingToken = true;
            clientMode.waitForIt(appMessages.getString("auth.token"));

            while (isExpectingToken) {
                wait();
            }
            login(); return;
        }
        if (loginToken == null) {
            decryptAuthToken();
        }

        packetStream.writeEncryptedPacket(
                Packet.AUTH_LOGIN,
                loginToken,
                sessionKey
        );
        clientMode.waitForIt(appMessages.getString("auth.login"));

        startTime = System.currentTimeMillis();
        timeout = Duration.of(10, ChronoUnit.SECONDS).toMillis();

        while(!isLoggedIn) {
            waitTime = timeout - (System.currentTimeMillis() - startTime);

            if(waitTime <= 0) { login(); return; }
            this.wait(waitTime);

            if(connectionState == ConnectionState.DISCONNECTED)
                throw new IllegalStateException(connectionState.toString());
        }
    }

    private void decryptAuthToken() throws GeneralSecurityException, ExecutionException, InterruptedException {
        final String tokenPassword;
        final Cipher cipher;
        final PBEKeySpec spec;
        final SecretKeyFactory kf;
        final SecretKey aesKey;
        final byte[] keyBytes;

        tokenPassword = clientMode.prompt(appMessages.getString("prompt.token.pass"));
        if(tokenPassword.isEmpty()) {
            ConsoleLogger.error(null, appMessages.getString("error.token.empty"));
            return;
        }
        spec = new PBEKeySpec(
                (macUsername + "-" + osName + "-" + osArch).toCharArray(),
                tokenPassword.getBytes(StandardCharsets.UTF_8),
                KDF_ITERATIONS,
                AES_KEY_SIZE
        );
        kf = SecretKeyFactory.getInstance(KDF_ALGO);
        keyBytes = kf.generateSecret(spec).getEncoded();
        aesKey = new SecretKeySpec(keyBytes, CIPHER_ALGO);

        cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, aesKey);

        try {
            loginToken = cipher.doFinal(Files.readAllBytes(tokenFile.toPath()));
        } catch (BadPaddingException | IOException | IllegalBlockSizeException ex) {
            ConsoleLogger.error(null, appMessages.getString("error.token"));
            decryptAuthToken();
        }
    }

    public ClientMode getClientMode() {
        return clientMode;
    }

    public Channel getCrtChannel() {
        return crtChannel;
    }

    public void setCrtChannel(Channel crtChannel) {
        this.crtChannel = crtChannel;
    }

    public Set<Channel> getChannels() {
        return channels;
    }

    public void setConnectionState(ConnectionState connectionState) {
        this.connectionState = connectionState;
    }

    public boolean isLoggedIn() {
        return isLoggedIn;
    }

    public void setLoggedIn(boolean loggedIn) {
        isLoggedIn = loggedIn;
    }

    public String getMacUsername() {
        return macUsername;
    }

    public String getOsArch() {
        return osArch;
    }

    public String getOsName() {
        return osName;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public boolean isExpectingToken() {
        return isExpectingToken;
    }

    public boolean isExpectingFingerprint() {
        return isExpectingFingerprint;
    }

    public void setExpectingFingerprint(boolean expectingFingerprint) {
        isExpectingFingerprint = expectingFingerprint;
    }

    public boolean isExpectingSignedPubKey() {
        return isExpectingSignedPubKey;
    }

    public void setExpectingSignedPubKey(boolean expectingSignedPubKey) {
        isExpectingSignedPubKey = expectingSignedPubKey;
    }

    public void setExpectingToken(boolean expectingToken) {
        isExpectingToken = expectingToken;
    }


    public PacketOutputStream getPacketStream() {
        return packetStream;
    }

    public Socket getClientSocket() {
        return clientSocket;
    }

    public PacketListener getPacketListener() {
        return packetListener;
    }

    public SecretKey getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(SecretKey sessionKey) {
        this.sessionKey = sessionKey;
    }

    public Thread getInterThread() {
        return interThread;
    }

    public PublicKey getServerFingerprint() {
        return serverFingerprint;
    }

    public File getSharedSecret() {
        return sharedSecret;
    }

    public File getTokenFile() {
        return tokenFile;
    }

    public PrivateKey getHandshakeKey() {
        return handshakeKey;
    }

    public byte[] getSalt() {
        return salt;
    }

    public ResourceBundle getAppMessages() {
        return appMessages;
    }

    private void terminate() {
        setConnectionState(ConnectionState.RECONNECTING);
        setLoggedIn(false);
        clientMode.waitForIt(connectionState.toString());

        if(interThread != null && interThread.isAlive()) {
            interThread.interrupt();
            clientMode.shutdown();
        }
        try {
            if(clientSocket != null && !clientSocket.isClosed()) {
                clientSocket.close();
                clientSocket = null;
            }

            if(!isStreamClosed) {
                packetStream.close();
                packetListener.terminate();
                isStreamClosed = true;
            }
            Thread.sleep(5000);
        } catch (IOException | InterruptedException e) {
            ConsoleLogger.error(null,
                    appMessages.getString("error.cleanup") + ": " + e.getMessage());
            Thread.currentThread().interrupt();
        }
    }
}