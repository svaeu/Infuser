package com.github.svaeu.infuser.client.packet;

import com.github.svaeu.infuser.client.TCPClient;
import com.github.svaeu.infuser.client.util.ConsoleLogger;
import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.PacketProcessor;
import com.github.svaeu.infuser.packets.exceptions.MalformedPacketException;
import com.github.svaeu.infuser.packets.exceptions.PacketParsingException;
import com.github.svaeu.infuser.packets.streamwrapper.PacketInputStream;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.util.Map;
import java.util.concurrent.ExecutionException;

public class PacketListener extends PacketInputStream {
    private final TCPClient client;
    private final Thread listenerThread;

    public PacketListener(InputStream in,
                          PacketProcessor packetProcessor,
                          TCPClient client) {
        super(in, packetProcessor);
        this.client = client;

        this.listenerThread = new Thread(() -> {
            try {
                listen();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }, "PL-MAIN-"+
                client.getClientSocket().getInetAddress().getHostAddress());
    }

    public synchronized void start() {
        if (listenerThread.isAlive()) {
            throw new IllegalStateException(
                    "Active listener on " + listenerThread.getName()
            );
        }
        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    private void listen() throws IOException {
        try {
            Map.Entry<Packet, byte[]> entry;
            while (!Thread.currentThread().isInterrupted()
                    && client.getClientSocket() != null
                    && !client.getClientSocket().isClosed()) {

                entry = readPacket()
                        .entrySet()
                        .iterator()
                        .next();

                getPacketProcessor()
                        .getExecutor()
                        .exec(entry.getKey(), (Object) entry.getValue());
            }
        } catch (IOException e) {
            client.setConnectionState(TCPClient.ConnectionState.DISCONNECTED);
            synchronized (client) { client.notifyAll(); }
        } catch (MalformedPacketException | PacketParsingException e) {
            ConsoleLogger.error(null, "Failed to process the packet: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            ConsoleLogger.error(null, "Decryption failure: " + e.getMessage());
        } catch (ExecutionException | InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            terminate();
        }
    }

    public void terminate() throws IOException {
        listenerThread.interrupt();
        this.close();
    }
}
