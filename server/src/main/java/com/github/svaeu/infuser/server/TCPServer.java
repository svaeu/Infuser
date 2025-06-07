package com.github.svaeu.infuser.server;

import com.github.svaeu.infuser.packets.PacketProcessor;
import com.github.svaeu.infuser.packets.encryption.RSAUtil;
import com.github.svaeu.infuser.server.channel.VirtualRoom;
import com.github.svaeu.infuser.server.client.ClientEntity;
import com.github.svaeu.infuser.server.client.manager.PacketHandler;
import com.github.svaeu.infuser.server.database.DatabaseManager;
import com.github.svaeu.infuser.server.util.ConfigManager;
import com.github.svaeu.infuser.server.util.SessionLogger;
import com.github.svaeu.infuser.server.util.IPFilter;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TCPServer extends Thread {

    private int servicePort;
    private ServerSocket serverSocket;

    private byte[] serverFingerprint;
    private PrivateKey privateKey;

    private boolean isWhitelisted;

    private final Set<ClientEntity> clients = new HashSet<>();

    private List<VirtualRoom> virtualRooms;

    private DatabaseManager databaseManager;
    private ConfigManager configManager;

    private IPFilter IPFilter;

    private final PacketProcessor packetProcessor = new PacketProcessor(
            new PacketHandler(this)
    );

    public TCPServer() throws SQLException, IOException, GeneralSecurityException { initialize(); }

    private void initialize() throws IOException, GeneralSecurityException, SQLException {
        final KeyPair idKeys;

        this.configManager = new ConfigManager("config.yml");
        configManager.loadConfigurations();

        databaseManager = new DatabaseManager(configManager.getDBFilePath());

        this.servicePort = configManager.getServerPort();
        this.isWhitelisted = configManager.getIfWhitelisted();
        this.IPFilter = new IPFilter();

        this.virtualRooms = databaseManager.loadRooms();

        databaseManager.getAllIPs().forEach((ip, status) -> {
            IPFilter.ListType type;

            type = com.github.svaeu.infuser.server.util.IPFilter.ListType.valueOf(status.toUpperCase());
            switch (type) {
                case BLACKLISTED -> IPFilter.blacklist(ip);
                case WHITELISTED -> IPFilter.whitelist(ip);
            }
        });
        idKeys = loadIDKeys(
                Path.of("id_keys/server_fingerprint.key"),
                Path.of("id_keys/private_signing.key")
        );

        this.privateKey = idKeys.getPrivate();
        this.serverFingerprint = idKeys.getPublic().getEncoded();
    }

    private KeyPair loadIDKeys(Path fingerprintKey, Path signingKey) throws IOException, GeneralSecurityException {
        final KeyPair idPair;

        if(!(Files.exists(fingerprintKey) && Files.exists(signingKey))) {
            if(!signingKey.getParent().toFile().exists())
                Files.createDirectories(signingKey.getParent());

            idPair = RSAUtil.generateKeyPair(4096);

            Files.write(fingerprintKey, idPair.getPublic().getEncoded(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Files.write(signingKey, idPair.getPrivate().getEncoded(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            return idPair;
        }
        return new KeyPair(
                RSAUtil.getPublicKeyFromBytes(Files.readAllBytes(fingerprintKey)),
                RSAUtil.getPrivateKeyFromBytes(Files.readAllBytes(signingKey))
        );
    }

    @Override
    public void run() {
        Socket clientSocket;
        String clientIP;
        ClientEntity clientEntity;

        try {
            this.serverSocket = new ServerSocket(servicePort);
            serverSocket.setReuseAddress(true);

            while(!serverSocket.isClosed()) {
                clientSocket = serverSocket.accept();
                clientIP = clientSocket.getInetAddress().getHostAddress();

                if(IPFilter.isBlacklisted(clientIP) ||
                        (isWhitelisted && !IPFilter.isWhitelisted(clientIP))) {
                    clientSocket.close();
                    continue;
                }
                clientSocket.setTcpNoDelay(true);
                clientSocket.setKeepAlive(true);
                clientSocket.setSoTimeout(300000);

                clientEntity = new ClientEntity(clientSocket, this);
                clientEntity.getListener().initialize();
            }
        } catch (IOException e) {
            SessionLogger.log(e.getMessage(), SessionLogger.LogType.CRITICAL);
        }
    }

    public int getServicePort() {
        return servicePort;
    }

    public byte[] getServerFingerprint() {
        return serverFingerprint;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public List<VirtualRoom> getVirtualRooms() {
        return virtualRooms;
    }

    public VirtualRoom getVirtualRoomById(String id) {
        for(VirtualRoom vr : virtualRooms)
            if(vr.getTitle().equalsIgnoreCase(id))
                return vr;
        return null;
    }

    public PacketProcessor getPacketProcessor() {
        return packetProcessor;
    }

    public IPFilter getConnectionManager() {
        return IPFilter;
    }

    public DatabaseManager getDatabaseManager() {
        return databaseManager;
    }

    public void broadcastMessage(String message) {

        SessionLogger.log("[BROADCAST] -> "+message, SessionLogger.LogType.INFO);

        for(VirtualRoom vr : virtualRooms)
            vr.broadcastMessage(message);
    }

    public ConfigManager getConfigManager() {
        return configManager;
    }

    public Set<ClientEntity> getClients() {
        return clients;
    }

    public ServerSocket getServerSocket() {
        return serverSocket;
    }
}