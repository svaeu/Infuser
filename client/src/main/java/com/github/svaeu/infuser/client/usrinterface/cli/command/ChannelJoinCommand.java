package com.github.svaeu.infuser.client.usrinterface.cli.command;

import com.github.svaeu.infuser.client.TCPClient;
import com.github.svaeu.infuser.client.util.ConsoleLogger;
import com.github.svaeu.infuser.client.channel.Channel;
import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.encryption.ECDHEUtil;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class ChannelJoinCommand implements CLICommand {

    private final TCPClient tcpClient;

    public ChannelJoinCommand(TCPClient tcpClient) {
        this.tcpClient = tcpClient;
    }

    @Override
    public String getDescription() {
        return "Join a channel with the given ID.";
    }

    @Override
    public String getUsage() {
        return "Usage: .join <roomID>";
    }

    @Override
    public String getName() {
        return "join";
    }

    @Override
    public void execute(String[] args) throws GeneralSecurityException, IOException, InterruptedException {
        final KeyPair keyPair;
        final byte[] roomID, saltedKey;
        ByteBuffer byteBuffer = null;

        if(args.length != 1) {
            ConsoleLogger.info("Correct "+getUsage());
            return;
        }
        keyPair = ECDHEUtil.generateECKeyPair();

        roomID = args[0].getBytes(StandardCharsets.UTF_8);
        saltedKey = ECDHEUtil.getSerializedSaltedKey(keyPair.getPublic(), ECDHEUtil.generateSalt());

        for(Channel channel : tcpClient.getChannels())
            if(channel.getTitle().equalsIgnoreCase(args[0])) {
                if(tcpClient.getCrtChannel() != null)
                    if(tcpClient.getCrtChannel().getTitle().equalsIgnoreCase(args[0])) {
                        ConsoleLogger.info("You are already in this channel.");
                        return;
                    }

                byteBuffer = ByteBuffer.allocate(8 + roomID.length + saltedKey.length);
                byteBuffer.putInt(roomID.length);
                byteBuffer.put(roomID);
                byteBuffer.putInt(saltedKey.length);
                byteBuffer.put(saltedKey);

                channel.setTrxnKey(keyPair.getPrivate());
            }
        if(byteBuffer == null) {
            ConsoleLogger.error(null, "No channel with ID: '"+new String(roomID, StandardCharsets.UTF_8)
                    +"' was found. Type .list to see available channels.");
            return;
        }
        tcpClient.getClientMode().waitForIt(tcpClient.getAppMessages().getString("auth.channel"));
        Thread.sleep(2000);

        tcpClient.getPacketStream().writeEncryptedPacket(Packet.CHANNEL_UPDATE, byteBuffer.array(), tcpClient.getSessionKey());
    }
}