package com.github.svaeu.infuser.server.client.manager;

import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.exceptions.MalformedPacketException;
import com.github.svaeu.infuser.packets.exceptions.PacketParsingException;
import com.github.svaeu.infuser.packets.streamwrapper.PacketInputStream;
import com.github.svaeu.infuser.server.util.SessionLogger;
import com.github.svaeu.infuser.server.TCPServer;
import com.github.svaeu.infuser.server.client.ClientEntity;

import java.io.IOException;
import java.security.*;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ClientListener extends PacketInputStream {
    private final ClientEntity client;

    private ExecutorService listenerExecutor;
    private Thread listenerThread;

    private final TCPServer tcpServer;

    public ClientListener(ClientEntity client, TCPServer tcpServer) throws IOException {
        super(client.getClientSocket().getInputStream(), tcpServer.getPacketProcessor());

        this.client = client;
        this.tcpServer = tcpServer;
    }

    public synchronized void initialize() throws IOException {
        if (listenerExecutor != null && !listenerExecutor.isShutdown()) {
            throw new IllegalStateException("Listener service '" + listenerThread.getName() + "' is already running.");
        }
        listenerExecutor = Executors.newSingleThreadExecutor(r -> {
            listenerThread = new Thread(r);
            listenerThread.setName("CL-" + client.getIP());
            listenerThread.setDaemon(true);

            return listenerThread;
        });
        listenerExecutor.submit(() -> {
            try {
                listen();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private void listen() throws IOException {
        try {
            Map.Entry<Packet, byte[]> entry;

            while (!client.getClientSocket().isClosed() && !Thread.currentThread().isInterrupted()) {

                entry = readPacket().entrySet().iterator().next();

                tcpServer.getPacketProcessor().getExecutor().exec(entry.getKey(), client, entry.getValue());
            }
        } catch (IOException e) {
            handleDisconnect(e);
        } catch (MalformedPacketException e) {
            SessionLogger.log("Received an unknown packet from " + clientIdentifier() +
                    " (possibly from a higher version client)", SessionLogger.LogType.IMPORTANT);
        } catch (PacketParsingException e) {
            SessionLogger.log("Packet parsing failed: " + e.getMessage(), SessionLogger.LogType.CRITICAL);
        } catch (GeneralSecurityException e) {
            SessionLogger.log("Failed to decrypt packet: " + e.getMessage(), SessionLogger.LogType.CRITICAL);
        } catch (ExecutionException | InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally { terminate(); }
    }

    private String clientIdentifier() {
        return client.getUsername() != null ? "'" + client.getUsername() + "'" : "Client " + client.getIP();
    }

    private void handleDisconnect(IOException e) {
        SessionLogger.log(clientIdentifier() + " disconnected from the server.",
                SessionLogger.LogType.INFO);

        tcpServer.getClients().remove(client);
        try {
            client.terminate();
        } catch (Exception ex) {
            SessionLogger.log("Error terminating client: " + ex.getMessage(), SessionLogger.LogType.CRITICAL);
        }
    }

    public void terminate() throws IOException {
        if (listenerExecutor != null && !listenerExecutor.isShutdown()) {
            listenerExecutor.shutdownNow();
        }
        this.close();
    }
}
