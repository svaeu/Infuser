package com.github.svaeu.infuser.packets.streamwrapper;

import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.PacketProcessor;

import com.github.svaeu.infuser.packets.encryption.ECDHEUtil;
import com.github.svaeu.infuser.packets.exceptions.BlockedPacketException;
import com.github.svaeu.infuser.packets.exceptions.MalformedPacketException;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public abstract class PacketInputStream extends DataInputStream {

    private final PacketProcessor packetProcessor;

    private final Map<Packet, byte[]> packetMeta = new HashMap<>();

    public PacketInputStream(InputStream in, PacketProcessor packetProcessor) {
        super(new BufferedInputStream(in));
        this.packetProcessor = packetProcessor;
    }

    public Map<Packet, byte[]> readPacket() throws IOException, MalformedPacketException {
        final Packet packet;
        final int dataLength;
        final byte[] packetHeader;

        packetMeta.clear();

        packetHeader = readDataBytes(8);
        final ByteBuffer headerBuffer = ByteBuffer.wrap(packetHeader);

        packet = Packet.fromPacketID(headerBuffer.getInt());

        if(packet == null) throw new MalformedPacketException();

        else if (packetProcessor.getBlockedPackets().contains(packet))
            throw new BlockedPacketException(String.valueOf(packet.getPacketID()));

        dataLength = headerBuffer.getInt();

        packetMeta.put(packet, readDataBytes(dataLength));
        return packetMeta;
    }

    public byte[] getDecryptedDataBytes(byte[] encryptedDataWithIV, SecretKey secretKey) throws NoSuchPaddingException,
    NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        byte[] ivBytes = new byte[12];
        byte[] encryptedBytes = new byte[encryptedDataWithIV.length - 12];

        System.arraycopy(encryptedDataWithIV, 0, ivBytes, 0, 12);
        System.arraycopy(encryptedDataWithIV, 12, encryptedBytes, 0, encryptedBytes.length);

        Cipher cipher = Cipher.getInstance(ECDHEUtil.AES_TRANS);
        GCMParameterSpec spec = new GCMParameterSpec(128, ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        return cipher.doFinal(encryptedBytes);
    }

    private byte[] readDataBytes(int length) throws IOException {
        final byte[] dataBytes;

        dataBytes = new byte[length];
        readFully(dataBytes);

        return dataBytes;
    }

    public PacketProcessor getPacketProcessor() {
        return packetProcessor;
    }
}