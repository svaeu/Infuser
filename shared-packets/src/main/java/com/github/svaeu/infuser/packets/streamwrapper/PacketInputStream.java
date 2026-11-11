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

    /** Largest payload (in bytes) a single packet may carry. */
    public static final int MAX_PACKET_SIZE = 1024 * 1024;

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;

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

        // the length comes straight off the wire: reject it before allocating anything
        if (dataLength < 0 || dataLength > MAX_PACKET_SIZE)
            throw new MalformedPacketException("Invalid packet length: " + dataLength);

        packetMeta.put(packet, readDataBytes(dataLength));
        return packetMeta;
    }

    public byte[] getDecryptedDataBytes(byte[] encryptedDataWithIV, SecretKey secretKey) throws NoSuchPaddingException,
    NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {

        if (encryptedDataWithIV == null || encryptedDataWithIV.length < GCM_IV_LENGTH + GCM_TAG_LENGTH)
            throw new BadPaddingException("Encrypted payload is too short");

        byte[] ivBytes = new byte[GCM_IV_LENGTH];
        byte[] encryptedBytes = new byte[encryptedDataWithIV.length - GCM_IV_LENGTH];

        System.arraycopy(encryptedDataWithIV, 0, ivBytes, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedDataWithIV, GCM_IV_LENGTH, encryptedBytes, 0, encryptedBytes.length);

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