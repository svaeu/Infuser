package com.github.svaeu.infuser.client.packet;

import com.github.svaeu.infuser.client.TCPClient;
import com.github.svaeu.infuser.client.channel.ActionHandler;
import com.github.svaeu.infuser.client.util.ConsoleLogger;
import com.github.svaeu.infuser.client.channel.Channel;
import com.github.svaeu.infuser.packets.channel.ActionType;
import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.PacketExecutor;
import com.github.svaeu.infuser.packets.encryption.ECDHEUtil;
import com.github.svaeu.infuser.packets.encryption.RSAUtil;
import com.github.svaeu.infuser.packets.exceptions.MalformedPacketException;
import com.github.svaeu.infuser.packets.exceptions.PacketParsingException;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

public final class PacketHandler extends PacketExecutor {

    private final TCPClient client;
    private final ActionHandler actionHandler;

    private final String AES_ALGO = "AES";

    public PacketHandler(TCPClient client) {
        this.client = client;
        this.actionHandler = new ActionHandler(client);
    }

    @Override
    protected void handleMessagePacket(Packet packet, Object... params) throws PacketParsingException, GeneralSecurityException, IOException, MalformedPacketException {
        final byte[] rawBytes;

        rawBytes = expectParam(params, 0, byte[].class);
        switch (packet) {
            case SRV_MESSAGE:
                final String message = new String(decryptBytes(rawBytes), StandardCharsets.UTF_8);
                if (message.isEmpty()) return;

                client.getClientMode().displayMessage(String.format("\u001B[0m[\u001B[34mSERVER\u001B[0m] -> %s", message));
                break;
            case CHAT_MESSAGE:
                final ByteBuffer messageBuffer;
                final byte[] username, broadMessage;

                messageBuffer = ByteBuffer.wrap(decryptBytes(rawBytes));

                username = new byte[messageBuffer.getInt()];
                messageBuffer.get(username);

                broadMessage = new byte[messageBuffer.getInt()];
                messageBuffer.get(broadMessage);

                client.getClientMode().displayMessage(String.format("~\033[1;37m%s\033[0m -> %s",
                        new String(username, StandardCharsets.UTF_8),
                        new String(client.getPacketListener().getDecryptedDataBytes(
                                broadMessage, client.getCrtChannel().getChannelKey()
                        ), StandardCharsets.UTF_8)));
                break;
            default:
                throw new MalformedPacketException("Unexpected packet: " + packet);
        }
    }

    @Override
    protected void handleCommandPacket(Object... params) {}

    @Override
    protected void handleKeyAction(Object... params) throws GeneralSecurityException, PacketParsingException, IOException {
        final byte[] decryptedSalt, encryptedRoomKey, serializedSalt;
        final Map.Entry<byte[], byte[]> peer;
        final KeyPair ephemeral;
        final ByteBuffer byteBuffer;
        SecretKey roomKey;

        decryptedSalt = client.getPacketListener().getDecryptedDataBytes(
                expectParam(params, 0, byte[].class), client.getSessionKey()
        );
        roomKey = Optional.ofNullable(client.getCrtChannel())
                .map(Channel::getChannelKey)
                .orElseGet(() -> {
                    final KeyGenerator keyGen;
                    try {
                        keyGen = KeyGenerator.getInstance(AES_ALGO);
                        keyGen.init(256);

                        return keyGen.generateKey();
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                    }
                });
        ephemeral = ECDHEUtil.generateECKeyPair();

        peer = ECDHEUtil.getDeserializedSaltedKey(decryptedSalt).entrySet().iterator().next();
        serializedSalt = ECDHEUtil.getSerializedSaltedKey(ephemeral.getPublic(), peer.getValue());

        encryptedRoomKey = client.getPacketStream()
                .getEncryptedBytes(roomKey.getEncoded(),
                        ECDHEUtil.deriveAES256Key(
                                ECDHEUtil.getPublicKeyFromBytes(peer.getKey()),
                                ephemeral.getPrivate(),
                                peer.getValue(),
                                "KeyTrxn"
                        ));
        byteBuffer = ByteBuffer.allocate(8 + serializedSalt.length + encryptedRoomKey.length)
                .putInt(serializedSalt.length)
                .put(serializedSalt)
                .putInt(encryptedRoomKey.length)
                .put(encryptedRoomKey);

        client.getPacketStream().writeEncryptedPacket(Packet.KEY_ACT, byteBuffer.array(), client.getSessionKey());
    }

    @Override
    protected void handleMediaPacket(Object... params) {

    }

    @Override
    protected void handleChannelUpdate(Object... params) throws PacketParsingException, GeneralSecurityException, MalformedPacketException, IOException {
        final byte[] channelMeta;
        final ByteBuffer channelMetaBuffer;
        final ActionType actionType;
        final byte[] channelID;
        final String channelTitle;

        channelMeta = expectParam(params, 0, byte[].class);
        if(channelMeta.length == 0) { resumeClient(); return; }

        channelMetaBuffer = ByteBuffer.wrap(decryptBytes(channelMeta));

        actionType = ActionType.getActionFromID(channelMetaBuffer.getInt());
        if(actionType == null) throw new MalformedPacketException("Unknown action type");

        channelID = new byte[channelMetaBuffer.getInt()];
        channelMetaBuffer.get(channelID);

        channelTitle = new String(channelID, StandardCharsets.UTF_8);

        switch (actionType) {
            case CREATE -> actionHandler.createChannel(channelTitle, channelMetaBuffer.getInt(), channelMetaBuffer.getInt());
            case META_UPDATE -> actionHandler.updateChannelMeta(channelTitle, channelMetaBuffer.getInt(), channelMetaBuffer.getInt());
            case REMOVE -> actionHandler.removeChannel(channelTitle);
            case KEY_UPDATE -> actionHandler.onKeyUpdate(channelTitle, channelMetaBuffer, channelID);
        }
        resumeClient();
    }

    @Override
    protected void handleAuthenticationAction(Object... params) throws PacketParsingException, GeneralSecurityException, InterruptedException, IOException, ExecutionException {
        final byte[] decUsername;

        if(client.isLoggedIn()) return;

        decUsername = client.getPacketListener().getDecryptedDataBytes
                (expectParam(params, 0, byte[].class), client.getSessionKey());

        if(decUsername.length == 0) { return; }

        Thread.sleep(2000);
        resumeClient();

        client.setLoggedIn(true);
        client.setUsername(new String(decUsername, StandardCharsets.UTF_8));
    }

    @Override
    protected void handleFingerprintVer(Object... params) throws PacketParsingException, IOException {
        if(!client.isExpectingFingerprint()) return;

        Files.write(client.getSharedSecret().toPath(), expectParam(params, 0, byte[].class),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        client.setExpectingFingerprint(false);

        resumeClient();
    }

    @Override
    protected void handleECSignature(Object... params) throws GeneralSecurityException, PacketParsingException {
        final Map.Entry<byte[], byte[]> signedKeyMap;

        if(!client.isExpectingSignedPubKey()) return;
        client.setExpectingSignedPubKey(false);

        signedKeyMap = RSAUtil.getDeserializedSignedKey(expectParam(params, 0, byte[].class)).entrySet().iterator().next();

        if(!RSAUtil.verifySignature(client.getServerFingerprint(), signedKeyMap.getKey(), signedKeyMap.getValue()))
            throw new SecurityException(client.getAppMessages().getString("error.signature"));

        client.setSessionKey(ECDHEUtil.deriveAES256Key(
                ECDHEUtil.getPublicKeyFromBytes(signedKeyMap.getKey()), client.getHandshakeKey(),
                client.getSalt(), "SessionKey"
        ));
        resumeClient();
    }

    @Override
    protected void handleRegistrationPacket(Object... params) throws PacketParsingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InterruptedException, ExecutionException, InvalidKeySpecException, IOException {
        final Cipher tokenCipher;
        final String tokenPassword;
        final byte[] decToken, encToken;
        final SecretKey keySpec;

        encToken = expectParam(params, 0, byte[].class);
        if(!client.isExpectingToken()) return;

        decToken = client.getPacketListener().getDecryptedDataBytes(encToken, client.getSessionKey());

        if(decToken.length != 0) Thread.sleep(2000);
        resumeClient();

        if (decToken.length == 0) {
            client.setExpectingToken(false);
            synchronized (client) { client.notify(); }
            return;
        }
        tokenPassword = client.getClientMode().prompt(
                client.getAppMessages().getString("prompt.token.pass.set")
        );
        if (tokenPassword.isEmpty()) {
            ConsoleLogger.error(null, client.getAppMessages().getString("error.token.empty"));
            handleRegistrationPacket((Object) encToken);
            return;
        }

        keySpec = new SecretKeySpec(
                SecretKeyFactory.getInstance(client.CIPHER_ALGO).generateSecret(
                        new PBEKeySpec(
                                (client.getMacUsername() + "-" + client.getOsName() + "-" + client.getOsArch()).toCharArray(),
                                tokenPassword.getBytes(StandardCharsets.UTF_8),
                                150000,
                                256)
                ).getEncoded(), AES_ALGO);

        tokenCipher = Cipher.getInstance(AES_ALGO);
        tokenCipher.init(Cipher.ENCRYPT_MODE, keySpec);
        Files.write(
                client.getTokenFile().toPath(),
                tokenCipher.doFinal(decToken),
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
        );
        ConsoleLogger.info(client.getAppMessages().getString("token.grant"));

        client.setExpectingToken(false);
        synchronized (client) { client.notify(); }
    }

    private byte[] decryptBytes(byte[] data) throws GeneralSecurityException {
        return client.getPacketListener().getDecryptedDataBytes(data, client.getSessionKey());
    }

    private void resumeClient() {
        client.getClientMode().notifyToResume();
        synchronized (client) { client.notify(); }
    }
}