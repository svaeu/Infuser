package com.github.svaeu.infuser.packets.streamwrapper;

import com.github.svaeu.infuser.packets.Packet;
import com.github.svaeu.infuser.packets.PacketProcessor;
import com.github.svaeu.infuser.packets.exceptions.BlockedPacketException;
import com.github.svaeu.infuser.packets.exceptions.MalformedPacketException;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

import static org.junit.Assert.*;

public class PacketStreamTest {

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 16;

    private SecretKey key;
    private PacketProcessor processor;

    @Before
    public void setUp() throws Exception {
        final KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);

        key = generator.generateKey();
        processor = new PacketProcessor(null); // the executor is never used by readPacket()
    }

    // ---- plain and encrypted round trips ----

    @Test
    public void plainPacketRoundTrips() throws Exception {
        final byte[] payload = "hello".getBytes(StandardCharsets.UTF_8);
        final ByteArrayOutputStream wire = new ByteArrayOutputStream();

        writer(wire).writePacket(Packet.CHAT_MESSAGE, payload);
        final Map.Entry<Packet, byte[]> read = reader(wire.toByteArray()).readPacket().entrySet().iterator().next();

        assertEquals(Packet.CHAT_MESSAGE, read.getKey());
        assertArrayEquals(payload, read.getValue());
    }

    @Test
    public void emptyPacketRoundTrips() throws Exception {
        final ByteArrayOutputStream wire = new ByteArrayOutputStream();

        writer(wire).writePacket(Packet.CHANNEL_UPDATE, new byte[0]);
        final Map.Entry<Packet, byte[]> read = reader(wire.toByteArray()).readPacket().entrySet().iterator().next();

        assertEquals(Packet.CHANNEL_UPDATE, read.getKey());
        assertEquals(0, read.getValue().length);
    }

    @Test
    public void encryptedPacketRoundTrips() throws Exception {
        final byte[] payload = "a secret message".getBytes(StandardCharsets.UTF_8);
        final ByteArrayOutputStream wire = new ByteArrayOutputStream();

        writer(wire).writeEncryptedPacket(Packet.CHAT_MESSAGE, payload, key);
        final PacketInputStream in = reader(wire.toByteArray());
        final Map.Entry<Packet, byte[]> read = in.readPacket().entrySet().iterator().next();

        assertEquals(Packet.CHAT_MESSAGE, read.getKey());
        assertFalse("ciphertext must not contain the plaintext",
                new String(read.getValue(), StandardCharsets.ISO_8859_1).contains("a secret message"));
        assertArrayEquals(payload, in.getDecryptedDataBytes(read.getValue(), key));
    }

    @Test
    public void encryptedPayloadHasIvAndTagOverhead() throws Exception {
        final byte[] encrypted = writer(new ByteArrayOutputStream()).getEncryptedBytes(new byte[100], key);

        assertEquals(IV_LENGTH + 100 + TAG_LENGTH, encrypted.length);
    }

    @Test
    public void everyMessageUsesAFreshIv() throws Exception {
        final PacketOutputStream out = writer(new ByteArrayOutputStream());
        final byte[] first = out.getEncryptedBytes("same".getBytes(StandardCharsets.UTF_8), key);
        final byte[] second = out.getEncryptedBytes("same".getBytes(StandardCharsets.UTF_8), key);

        assertFalse(Arrays.equals(Arrays.copyOf(first, IV_LENGTH), Arrays.copyOf(second, IV_LENGTH)));
        assertFalse(Arrays.equals(first, second));
    }

    // ---- tampering and wrong keys must fail authentication ----

    @Test
    public void tamperedCiphertextIsRejected() throws Exception {
        assertRejectedAfterFlip(IV_LENGTH + 2);
    }

    @Test
    public void tamperedIvIsRejected() throws Exception {
        assertRejectedAfterFlip(0);
    }

    @Test
    public void tamperedTagIsRejected() throws Exception {
        final byte[] encrypted = writer(new ByteArrayOutputStream()).getEncryptedBytes(new byte[40], key);

        assertRejectedAfterFlip(encrypted.length - 1);
    }

    @Test
    public void truncatedCiphertextIsRejected() throws Exception {
        final byte[] encrypted = writer(new ByteArrayOutputStream()).getEncryptedBytes(new byte[40], key);
        final byte[] truncated = Arrays.copyOf(encrypted, encrypted.length - 1);

        assertThrows(BadPaddingException.class, () -> reader(new byte[0]).getDecryptedDataBytes(truncated, key));
    }

    @Test
    public void wrongKeyIsRejected() throws Exception {
        final byte[] encrypted = writer(new ByteArrayOutputStream()).getEncryptedBytes("x".getBytes(), key);
        final KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        final SecretKey wrong = generator.generateKey();

        assertThrows(BadPaddingException.class, () -> reader(new byte[0]).getDecryptedDataBytes(encrypted, wrong));
    }

    @Test
    public void payloadsShorterThanIvPlusTagAreRejected() throws Exception {
        final PacketInputStream in = reader(new byte[0]);

        // used to throw NegativeArraySizeException (or an index error) instead of a clean failure
        for (int length : new int[]{0, 1, IV_LENGTH - 1, IV_LENGTH, IV_LENGTH + TAG_LENGTH - 1})
            assertThrows("length " + length, BadPaddingException.class,
                    () -> in.getDecryptedDataBytes(new byte[length], key));

        assertThrows(BadPaddingException.class, () -> in.getDecryptedDataBytes(null, key));
    }

    // ---- packet header validation ----

    @Test
    public void unknownPacketIdIsRejected() {
        assertThrows(MalformedPacketException.class, () -> reader(header(1, 0)).readPacket());
    }

    @Test(timeout = 5000)
    public void negativeLengthIsRejected() {
        assertThrows(MalformedPacketException.class,
                () -> reader(header(Packet.CHAT_MESSAGE.getPacketID(), -1)).readPacket());
    }

    @Test(timeout = 5000)
    public void hugeLengthIsRejectedWithoutAllocating() {
        // a 2 GiB allocation if it were trusted, and the stream holds no such data
        assertThrows(MalformedPacketException.class,
                () -> reader(header(Packet.CHAT_MESSAGE.getPacketID(), Integer.MAX_VALUE)).readPacket());
    }

    @Test(timeout = 5000)
    public void lengthJustOverTheLimitIsRejected() {
        assertThrows(MalformedPacketException.class,
                () -> reader(header(Packet.CHAT_MESSAGE.getPacketID(), PacketInputStream.MAX_PACKET_SIZE + 1)).readPacket());
    }

    @Test
    public void lengthAtTheLimitIsAccepted() throws Exception {
        final ByteArrayOutputStream wire = new ByteArrayOutputStream();
        wire.write(header(Packet.COMMAND_REQ.getPacketID(), PacketInputStream.MAX_PACKET_SIZE));
        wire.write(new byte[PacketInputStream.MAX_PACKET_SIZE]);

        final Map.Entry<Packet, byte[]> read = reader(wire.toByteArray()).readPacket().entrySet().iterator().next();

        assertEquals(PacketInputStream.MAX_PACKET_SIZE, read.getValue().length);
    }

    @Test
    public void truncatedBodyFailsWithEof() {
        final byte[] truncated = concat(header(Packet.CHAT_MESSAGE.getPacketID(), 100), new byte[10]);

        assertThrows(EOFException.class, () -> reader(truncated).readPacket());
    }

    @Test
    public void truncatedHeaderFailsWithEof() {
        assertThrows(EOFException.class, () -> reader(new byte[5]).readPacket());
    }

    @Test
    public void blockedPacketIsRejected() {
        processor.getBlockedPackets().add(Packet.COMMAND_REQ);

        assertThrows(BlockedPacketException.class,
                () -> reader(header(Packet.COMMAND_REQ.getPacketID(), 0)).readPacket());
    }

    @Test
    public void severalPacketsCanBeReadBackToBack() throws Exception {
        final ByteArrayOutputStream wire = new ByteArrayOutputStream();
        final PacketOutputStream out = writer(wire);
        out.writePacket(Packet.CHAT_MESSAGE, "one".getBytes());
        out.writePacket(Packet.SRV_MESSAGE, "two".getBytes());

        final PacketInputStream in = reader(wire.toByteArray());
        final Map.Entry<Packet, byte[]> first = in.readPacket().entrySet().iterator().next();
        final Map.Entry<Packet, byte[]> second = in.readPacket().entrySet().iterator().next();

        assertEquals(Packet.CHAT_MESSAGE, first.getKey());
        assertArrayEquals("one".getBytes(), first.getValue());
        assertEquals(Packet.SRV_MESSAGE, second.getKey());
        assertArrayEquals("two".getBytes(), second.getValue());
    }

    private void assertRejectedAfterFlip(int index) throws Exception {
        final byte[] encrypted = writer(new ByteArrayOutputStream()).getEncryptedBytes(new byte[40], key);
        encrypted[index] ^= 0x01;

        assertThrows(BadPaddingException.class, () -> reader(new byte[0]).getDecryptedDataBytes(encrypted, key));
    }

    private PacketInputStream reader(byte[] wire) {
        return new PacketInputStream(new ByteArrayInputStream(wire), processor) {};
    }

    private static PacketOutputStream writer(ByteArrayOutputStream wire) {
        return new PacketOutputStream(wire) {};
    }

    private static byte[] header(int packetId, int length) {
        return ByteBuffer.allocate(8).putInt(packetId).putInt(length).array();
    }

    private static byte[] concat(byte[] a, byte[] b) {
        final byte[] result = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
