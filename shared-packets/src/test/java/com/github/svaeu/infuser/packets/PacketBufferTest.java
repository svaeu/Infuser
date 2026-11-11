package com.github.svaeu.infuser.packets;

import com.github.svaeu.infuser.packets.exceptions.PacketParsingException;
import org.junit.Test;

import java.nio.ByteBuffer;

import static org.junit.Assert.*;

public class PacketBufferTest {

    @Test
    public void readsALengthPrefixedField() throws Exception {
        final ByteBuffer buffer = ByteBuffer.allocate(4 + 3).putInt(3).put(new byte[]{1, 2, 3});
        buffer.flip();

        assertArrayEquals(new byte[]{1, 2, 3}, PacketBuffers.readLengthPrefixed(buffer, "field"));
        assertEquals(0, buffer.remaining());
    }

    @Test
    public void zeroLengthYieldsAnEmptyArray() throws Exception {
        // an empty field is meaningful in the protocol (e.g. an empty key means "leave the channel")
        final ByteBuffer buffer = ByteBuffer.allocate(4).putInt(0);
        buffer.flip();

        assertEquals(0, PacketBuffers.readLengthPrefixed(buffer, "field").length);
    }

    @Test
    public void consecutiveFieldsAreReadInOrder() throws Exception {
        final ByteBuffer buffer = ByteBuffer.allocate(4 + 2 + 4 + 1)
                .putInt(2).put(new byte[]{7, 8})
                .putInt(1).put(new byte[]{9});
        buffer.flip();

        assertArrayEquals(new byte[]{7, 8}, PacketBuffers.readLengthPrefixed(buffer, "first"));
        assertArrayEquals(new byte[]{9}, PacketBuffers.readLengthPrefixed(buffer, "second"));
    }

    @Test(timeout = 5000)
    public void hugeLengthIsRejectedWithoutAllocating() {
        final ByteBuffer buffer = ByteBuffer.allocate(4).putInt(Integer.MAX_VALUE);
        buffer.flip();

        assertThrows(PacketParsingException.class, () -> PacketBuffers.readLengthPrefixed(buffer, "field"));
    }

    @Test(timeout = 5000)
    public void negativeLengthIsRejected() {
        final ByteBuffer buffer = ByteBuffer.allocate(4).putInt(-1);
        buffer.flip();

        assertThrows(PacketParsingException.class, () -> PacketBuffers.readLengthPrefixed(buffer, "field"));
    }

    @Test(timeout = 5000)
    public void lengthLargerThanTheRemainingDataIsRejected() {
        final ByteBuffer buffer = ByteBuffer.allocate(4 + 2).putInt(3).put(new byte[]{1, 2});
        buffer.flip();

        assertThrows(PacketParsingException.class, () -> PacketBuffers.readLengthPrefixed(buffer, "field"));
    }

    @Test
    public void truncatedPrefixIsRejected() {
        assertThrows(PacketParsingException.class,
                () -> PacketBuffers.readLengthPrefixed(ByteBuffer.wrap(new byte[]{0, 0, 1}), "field"));
        assertThrows(PacketParsingException.class,
                () -> PacketBuffers.readLengthPrefixed(ByteBuffer.wrap(new byte[0]), "field"));
    }

    @Test
    public void errorMessageNamesTheField() {
        final PacketParsingException e = assertThrows(PacketParsingException.class,
                () -> PacketBuffers.readLengthPrefixed(ByteBuffer.wrap(new byte[0]), "room id"));

        assertTrue(e.getMessage().contains("room id"));
    }
}
