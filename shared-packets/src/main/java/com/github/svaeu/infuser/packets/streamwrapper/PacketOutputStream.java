package com.github.svaeu.infuser.packets.streamwrapper;

import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.encryption.ECDHEUtil;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public abstract class PacketOutputStream extends DataOutputStream {

    public PacketOutputStream(OutputStream out) { super(new BufferedOutputStream(out)); }

    public void writePacket(Packet packet, byte[] data) throws IOException {

        final ByteBuffer byteBuffer;

        byteBuffer = ByteBuffer.allocate(8);
        byteBuffer.putInt(packet.getPacketID());

        byteBuffer.putInt(data.length);

        writeNFlushBuffer(byteBuffer.array(), data);
    }

    public void writeEncryptedPacket(Packet packet, byte[] data, SecretKey secretKey) throws IOException, NoSuchPaddingException,
    NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        final ByteBuffer byteBuffer;
        final byte[] encryptedBytes;

        byteBuffer = ByteBuffer.allocate(8);
        byteBuffer.putInt(packet.getPacketID());

        encryptedBytes = getEncryptedBytes(data, secretKey);

        byteBuffer.putInt(encryptedBytes.length);

        writeNFlushBuffer(byteBuffer.array(), encryptedBytes);
    }

    private void writeNFlushBuffer(byte[] packetMeta, byte[] data) throws IOException {
        write(packetMeta);
        write(data);
        /*
        some data might still remain that is unable to fill the current
        buffer so it needs to be flushed out :)
         */
        flush();
    }

    public byte[] getEncryptedBytes(byte[] data, SecretKey secretKey) throws NoSuchPaddingException,
    NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

        final Cipher cipher;
        final GCMParameterSpec spec;
        final byte[] ivBytes, encryptedBytes;
        final ByteBuffer byteBuffer;

        ivBytes = new byte[12];
        new SecureRandom().nextBytes(ivBytes);

        cipher = Cipher.getInstance(ECDHEUtil.AES_TRANS);
        spec = new GCMParameterSpec(128, ivBytes);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        encryptedBytes = cipher.doFinal(data);

        byteBuffer = ByteBuffer.allocate(12 + encryptedBytes.length);
        byteBuffer.put(ivBytes);
        byteBuffer.put(encryptedBytes);

        return byteBuffer.array();
    }
}