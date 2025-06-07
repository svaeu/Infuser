package com.github.svaeu.infuser.server.channel;

import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.channel.ActionType;
import com.github.svaeu.infuser.server.client.ClientEntity;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.*;

public class VirtualRoom {

    private final String title;
    private final int threshold;

    private final Set<RoomState> roomStates = new HashSet<>();

    private final Set<ClientEntity> clients = new HashSet<>();

    public VirtualRoom(String title, int threshold) {
        this.title = title;
        this.threshold = threshold;
    }

    public void addClient(ClientEntity client) { clients.add(client); }

    public void removeClient(ClientEntity client) { clients.remove(client); }

    public void broadcastMessage(byte[] encryptedMessage) throws GeneralSecurityException, IOException {

        if(getRoomStates().contains(RoomState.LOCKED)) { return; }

        //message sent to every client inside this room
        for(ClientEntity client : clients) {
            client.sendPacket(Packet.CHAT_MESSAGE, encryptedMessage, true);
        }
    }

    public void broadcastMessage(String message) {
        for(ClientEntity client : clients)
            client.sendMessage(message);
    }

    public void dispatchUpdate() throws GeneralSecurityException, IOException {
        for(ClientEntity member : clients)
            member.sendPacket(Packet.CHANNEL_UPDATE, serialize(ActionType.META_UPDATE), true);
    }

    public int getThreshold() {
        return threshold;
    }

    public String getTitle() {
        return title;
    }

    public Set<RoomState> getRoomStates() {
        return roomStates;
    }

    public Set<ClientEntity> getClients() {
        return clients;
    }

    public byte[] serialize(ActionType actionType) {
        final byte[] roomTitle = title.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.allocate(16 + roomTitle.length)
                .putInt(actionType.getActionID())
                .putInt(roomTitle.length)
                .put(roomTitle)
                .putInt(clients.size())
                .putInt(threshold).array();
    }
}