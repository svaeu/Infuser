package com.github.svaeu.infuser.packets;

import com.github.svaeu.infuser.packets.exceptions.PacketParsingException;

import java.nio.ByteBuffer;

public final class PacketBuffers {

    private PacketBuffers() {}

    public static byte[] readLengthPrefixed(ByteBuffer buffer, String field) throws PacketParsingException {
        final int length;
        final byte[] bytes;

        if (buffer.remaining() < Integer.BYTES)
            throw new PacketParsingException("Truncated length prefix for " + field);

        length = buffer.getInt();

        if (length < 0 || length > buffer.remaining())
            throw new PacketParsingException("Invalid length " + length + " for " + field
                    + " (" + buffer.remaining() + " bytes available)");

        bytes = new byte[length];
        buffer.get(bytes);

        return bytes;
    }
}
