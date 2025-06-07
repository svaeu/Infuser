package com.github.svaeu.infuser.server.client;

import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.streamwrapper.PacketOutputStream;
import com.github.svaeu.infuser.server.TCPServer;
import com.github.svaeu.infuser.server.channel.VirtualRoom;
import com.github.svaeu.infuser.server.client.manager.ClientListener;
import com.github.svaeu.infuser.server.util.SessionLogger;

import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class ClientEntity extends PacketOutputStream {
    private final Socket clientSocket;

    private final ClientListener listener;
    private String username;
    private SecretKey sessionKey;
    private boolean isLoggedIn;

    private long cooldown, timestamp;

    private final List<String> permissions = new ArrayList<>();
    private VirtualRoom virtualRoom;

    public ClientEntity(Socket clientSocket, TCPServer server) throws IOException {

        super(clientSocket.getOutputStream());

        this.clientSocket = clientSocket;
        this.listener = new ClientListener(this, server);
    }

    public void sendMessage(String message) {
        try {
            sendPacket(Packet.SRV_MESSAGE, message.getBytes(), true);
        }  catch (GeneralSecurityException | IOException e) {
            if(e instanceof GeneralSecurityException)
                SessionLogger.log(e.getMessage(), SessionLogger.LogType.CRITICAL);
        }
    }

    public void sendPacket(Packet packet, byte[] data, boolean encrypted) throws GeneralSecurityException, IOException {
        if(encrypted)
            writeEncryptedPacket(packet, data, sessionKey);
        else writePacket(packet, data);
    }

    public void kick(String reason) throws IOException, GeneralSecurityException {
        sendMessage(reason);
        terminate();
    }

    public VirtualRoom getVirtualRoom() {
        return virtualRoom;
    }

    public void setVirtualRoom(VirtualRoom virtualRoom) {
        this.virtualRoom = virtualRoom;
    }

    public String getIP() {
        return clientSocket.getInetAddress().getHostAddress();
    }

    public Socket getClientSocket() {
        return clientSocket;
    }

    public void addCooldown(long cooldown) {
        this.cooldown = cooldown;
        this.timestamp = TimeUnit
                .MILLISECONDS
                .toSeconds(System.currentTimeMillis());
    }

    public boolean hasActiveCooldown(String ip) {
        return (TimeUnit
                .MILLISECONDS
                .toSeconds(System.currentTimeMillis()) - timestamp)
                < cooldown;
    }

    public List<String> getPermissions() {
        return permissions;
    }

    public String getUsername() {
        return username;
    }

    public boolean isLoggedIn() {
        return isLoggedIn;
    }

    public void setLoggedIn(boolean loggedIn) {
        isLoggedIn = loggedIn;
    }

    public ClientListener getListener() {
        return listener;
    }

    public SecretKey getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(SecretKey sessionKey) {
        this.sessionKey = sessionKey;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public boolean hasPermission(String permission) {
        return !permissions.contains(permission);
    }

    public void terminate() throws IOException, GeneralSecurityException {
        listener.terminate();
        if(virtualRoom != null) {
            virtualRoom.removeClient(this);
            virtualRoom.dispatchUpdate();
        }
        clientSocket.close();
    }
}