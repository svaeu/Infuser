package com.github.svaeu.infuser.server.client.manager;

import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.PacketExecutor;
import com.github.svaeu.infuser.packets.channel.ActionType;
import com.github.svaeu.infuser.packets.encryption.ECDHEUtil;
import com.github.svaeu.infuser.packets.encryption.RSAUtil;
import com.github.svaeu.infuser.packets.exceptions.PacketParsingException;
import com.github.svaeu.infuser.server.TCPServer;
import com.github.svaeu.infuser.server.channel.ChannelRequest;
import com.github.svaeu.infuser.server.channel.RoomState;
import com.github.svaeu.infuser.server.channel.VirtualRoom;
import com.github.svaeu.infuser.server.client.ClientEntity;
import com.github.svaeu.infuser.server.util.SessionLogger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ThreadLocalRandom;

public final class PacketHandler extends PacketExecutor {
    private final TCPServer server;

    private final Map<ClientEntity, ChannelRequest> requestPool = new HashMap<>();

    public PacketHandler(TCPServer server) {
      this.server = server;
    }

    @Override
    protected void handleMessagePacket(Packet packet, Object... params) throws GeneralSecurityException, IOException, PacketParsingException {
        final ByteBuffer byteBuffer;
        final byte[] clientUsername;
        final ClientEntity client;
        final byte[] message;

        client = expectParam(params, 0, ClientEntity.class);
        message = expectParam(params, 1, byte[].class);

        if (!client.isLoggedIn() || client.getVirtualRoom() == null) return;

        clientUsername = client.getUsername().getBytes(StandardCharsets.UTF_8);

        byteBuffer = ByteBuffer.allocate(8 + clientUsername.length + message.length);
        byteBuffer.putInt(clientUsername.length)
                .put(clientUsername)
                .putInt(message.length)
                .put(message);

        client.getVirtualRoom().broadcastMessage(byteBuffer.array());
    }

    @Override
    protected void handleCommandPacket(Object... params) throws PacketParsingException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {

    }

    @Override
    protected void handleKeyAction(Object... params) throws PacketParsingException, GeneralSecurityException, IOException {
        final ChannelRequest req;
        final ClientEntity seekingClient, provider;
        final VirtualRoom reqRoom;
        final byte[] roomTitle, decryptedBundledKeys, bundledKeys;
        final ByteBuffer resBuffer;

        provider = expectParam(params, 0, ClientEntity.class);
        bundledKeys = expectParam(params, 1, byte[].class);

        req = requestPool.remove(provider);
        if(req == null) return;

        seekingClient = req.seekingClient();
        reqRoom = req.vr();

        roomTitle = reqRoom.getTitle().getBytes(StandardCharsets.UTF_8);

        decryptedBundledKeys = decryptBytes(provider, bundledKeys);

        resBuffer = ByteBuffer.allocate(12 + roomTitle.length + decryptedBundledKeys.length);
        resBuffer.putInt(ActionType.KEY_UPDATE.getActionID())
                .putInt(roomTitle.length).put(roomTitle)
                .putInt(decryptedBundledKeys.length)
                .put(decryptedBundledKeys);

        seekingClient.sendPacket(Packet.CHANNEL_UPDATE, resBuffer.array(), true);
    }

    @Override
    protected void handleMediaPacket(Object... params) {}


    @Override
    protected void handleChannelUpdate(Object... params) throws GeneralSecurityException, IOException, PacketParsingException {
        final ClientEntity client, provider;
        final ByteBuffer byteBuffer;
        final byte[] roomIDBytes;
        final String roomID;
        final byte[] saltedKey, payload;
        final VirtualRoom room;
        final List<String> errors;

        client = expectParam(params, 0, ClientEntity.class);
        payload = expectParam(params, 1, byte[].class);

        byteBuffer = ByteBuffer.wrap(decryptBytes(client, payload));

        roomIDBytes = new byte[byteBuffer.getInt()];
        byteBuffer.get(roomIDBytes);

        roomID = new String(roomIDBytes, StandardCharsets.UTF_8);
        room = server.getVirtualRoomById(roomID);

        errors = validateJoin(room, client);
        if (!errors.isEmpty()) {
            client.sendMessage(errors.getFirst());
            client.sendPacket(Packet.CHANNEL_UPDATE, new byte[0], false);
            return;
        }
        saltedKey = new byte[byteBuffer.getInt()];
        byteBuffer.get(saltedKey);

        if(saltedKey.length == 0) {
            Optional.ofNullable(client.getVirtualRoom())
                    .ifPresent(r -> {
                        try {
                            r.removeClient(client);
                            r.dispatchUpdate();
                        } catch (GeneralSecurityException | IOException e) {
                            SessionLogger.log("Channel update dispatch failure: " + e.getMessage(),
                                    SessionLogger.LogType.CRITICAL);
                        }
                    });
            room.addClient(client); room.dispatchUpdate();
            client.setVirtualRoom(room);
        } else {
            if(room.getClients().isEmpty()) {
                client.sendPacket(Packet.KEY_ACT, saltedKey, true);
                requestPool.put(client, new ChannelRequest(client, room));
            } else {
                provider = new ArrayList<>(room.getClients())
                        .get(ThreadLocalRandom.current()
                                .nextInt(room.getClients()
                                        .size())
                        );
                provider.sendPacket(Packet.KEY_ACT, saltedKey, true);
                requestPool.put(provider, new ChannelRequest(client, room));
            }
        }
    }

    private List<String> validateJoin(VirtualRoom room, ClientEntity client) {
        if (room == null) {
            return List.of("Channel does not exist.");
        }
        if (room.getRoomStates().contains(RoomState.PRIVATE)
                && client.hasPermission(room.getTitle() + ".access")) {
            return List.of("You're not permitted to join this private channel.");
        }
        if (room.getClients().size() >= room.getThreshold()) {
            return List.of("Channel is full.");
        }
        return Collections.emptyList();
    }


    @Override
    protected void handleAuthenticationAction(Object... params) throws PacketParsingException, GeneralSecurityException, IOException {
        final ClientEntity client;
        final byte[] token;

        client = expectParam(params, 0, ClientEntity.class);
        token = expectParam(params, 1, byte[].class);

        if (!server.getDatabaseManager().loadUser
                (new String(decryptBytes(client, token)), client)
        ) {
            client.sendPacket(Packet.AUTH_LOGIN, new byte[0], true);
            client.sendMessage("Login failed: invalid token.");
            return;
        }

        if(server.getClients().stream().anyMatch
                ((c -> c.getUsername().equalsIgnoreCase(client.getUsername())))
        ) {
            client.sendMessage("You're already logged in from another instance!");
            client.sendPacket(Packet.AUTH_LOGIN, new byte[0], true);
            return;
        }

        server.getClients().add(client);
        SessionLogger.log(
                "'"+client.getUsername()+ "' logged into the server with IP '"+ client.getIP()+"'.",
                SessionLogger.LogType.INFO);

        client.sendPacket(
                Packet.AUTH_LOGIN,
                client.getUsername().getBytes(StandardCharsets.UTF_8),
                true
        );
        client.setLoggedIn(true);

        server.getVirtualRooms().forEach(r ->
                {
                    try {
                        client.sendPacket(Packet.CHANNEL_UPDATE, r.serialize(ActionType.CREATE), true);
                    } catch (GeneralSecurityException | IOException e) {
                        SessionLogger.log(
                                "Channel update dispatch failure: " + e.getMessage(),
                                SessionLogger.LogType.CRITICAL);
                    }
                }
        );
    }

    @Override
    protected void handleFingerprintVer(Object... params) throws PacketParsingException, IOException, GeneralSecurityException {
        expectParam(params, 0, ClientEntity.class).sendPacket
                (Packet.SRV_FINGERPRINT, server.getServerFingerprint(), false);
    }

    @Override
    protected void handleECSignature(Object... params) throws GeneralSecurityException, PacketParsingException, IOException {
        final KeyPair keyPair;
        final byte[] pubKey, signature, saltedKey;
        final ClientEntity client;
        final Map.Entry<byte[], byte[]> peer;

        client = expectParam(params, 0, ClientEntity.class);
        saltedKey = expectParam(params, 1, byte[].class);

        if(client.isLoggedIn()) return;

        keyPair = ECDHEUtil.generateECKeyPair();
        pubKey = keyPair.getPublic().getEncoded();
        signature = RSAUtil.signPublicKey(server.getPrivateKey(), keyPair.getPublic());

        client.sendPacket(
                Packet.EC_SIGNATURE,
                RSAUtil.getSerialisedSignedKey(pubKey, signature),
                false
        );
        peer = ECDHEUtil.getDeserializedSaltedKey(saltedKey).entrySet().iterator().next();

        client.setSessionKey(
                ECDHEUtil.deriveAES256Key(
                        ECDHEUtil.getPublicKeyFromBytes(peer.getKey()),
                        keyPair.getPrivate(), peer.getValue(),
                        "SessionKey"
                )
        );
    }

    @Override
    protected void handleRegistrationPacket(Object... params) throws PacketParsingException, GeneralSecurityException, InterruptedException, ExecutionException, IOException {
        final String username;
        final ClientEntity client;
        final byte[] encUsername, token;

        client = expectParam(params, 0, ClientEntity.class);
        encUsername = expectParam(params, 1, byte[].class);

        username = new String(
                decryptBytes(client, encUsername),
                StandardCharsets.UTF_8
        ).trim().toLowerCase();

        if (!username.matches("^[a-z0-9_-]{3,32}$")) {
            client.sendMessage(
                    "Username must be 3-32 chars long and contain only letters, digits, '_' or '-'."
            );
            client.sendPacket(Packet.REG_ACT, new byte[0], true);
            return;
        }

        if(server.getDatabaseManager().isClientRegistered(username)) {
            client.sendMessage("This username is already taken.");
            client.sendPacket(Packet.REG_ACT, new byte[0], true);
            return;
        }

        token = server.getDatabaseManager().registerClient(username);
        client.sendPacket(Packet.REG_ACT, token, true);
    }

    private byte[] decryptBytes(ClientEntity client, byte[] encData) throws GeneralSecurityException {
        return client.getListener().getDecryptedDataBytes(encData, client.getSessionKey());
    }
}