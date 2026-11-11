package com.github.svaeu.infuser.packets.encryption;

import com.github.svaeu.infuser.packets.exceptions.PacketParsingException;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.util.Map;

import static org.junit.Assert.*;

public class RSAUtilTest {

    // 2048 bits keeps the test fast; the server itself uses 4096
    private static KeyPair identity;
    private static KeyPair other;

    @BeforeClass
    public static void generateKeys() throws Exception {
        identity = RSAUtil.generateKeyPair(2048);
        other = RSAUtil.generateKeyPair(2048);
    }

    @Test
    public void validSignatureVerifies() throws Exception {
        final KeyPair ephemeral = ECDHEUtil.generateECKeyPair();
        final byte[] signature = RSAUtil.signPublicKey(identity.getPrivate(), ephemeral.getPublic());

        assertTrue(RSAUtil.verifySignature(identity.getPublic(), ephemeral.getPublic().getEncoded(), signature));
    }

    @Test
    public void signatureFromADifferentIdentityIsRejected() throws Exception {
        final KeyPair ephemeral = ECDHEUtil.generateECKeyPair();
        final byte[] signature = RSAUtil.signPublicKey(other.getPrivate(), ephemeral.getPublic());

        // the client has pinned `identity`; a signature by anyone else must not verify
        assertFalse(RSAUtil.verifySignature(identity.getPublic(), ephemeral.getPublic().getEncoded(), signature));
    }

    @Test
    public void swappedEphemeralKeyIsRejected() throws Exception {
        final KeyPair real = ECDHEUtil.generateECKeyPair();
        final KeyPair attacker = ECDHEUtil.generateECKeyPair();
        final byte[] signature = RSAUtil.signPublicKey(identity.getPrivate(), real.getPublic());

        // a man-in-the-middle substituting their own EC key under the real signature
        assertFalse(RSAUtil.verifySignature(identity.getPublic(), attacker.getPublic().getEncoded(), signature));
    }

    @Test
    public void tamperedSignatureIsRejected() throws Exception {
        final KeyPair ephemeral = ECDHEUtil.generateECKeyPair();
        final byte[] signature = RSAUtil.signPublicKey(identity.getPrivate(), ephemeral.getPublic());
        signature[signature.length / 2] ^= 0x01;

        assertFalse(RSAUtil.verifySignature(identity.getPublic(), ephemeral.getPublic().getEncoded(), signature));
    }

    @Test
    public void publicKeyRoundTripsThroughItsEncoding() throws Exception {
        assertEquals(identity.getPublic(), RSAUtil.getPublicKeyFromBytes(identity.getPublic().getEncoded()));
        assertEquals(identity.getPrivate(), RSAUtil.getPrivateKeyFromBytes(identity.getPrivate().getEncoded()));
    }

    @Test
    public void signedKeyRoundTrips() throws Exception {
        final byte[] key = {1, 2, 3, 4, 5};
        final byte[] signature = {9, 8, 7};

        final Map.Entry<byte[], byte[]> parsed = RSAUtil
                .getDeserializedSignedKey(RSAUtil.getSerialisedSignedKey(key, signature))
                .entrySet().iterator().next();

        assertArrayEquals(key, parsed.getKey());
        assertArrayEquals(signature, parsed.getValue());
    }

    // ---- hostile input ----

    @Test(timeout = 5000)
    public void hugeKeyLengthIsRejectedWithoutAllocating() {
        final byte[] frame = ByteBuffer.allocate(4).putInt(Integer.MAX_VALUE).array();

        assertThrows(PacketParsingException.class, () -> RSAUtil.getDeserializedSignedKey(frame));
    }

    @Test(timeout = 5000)
    public void negativeSignatureLengthIsRejected() {
        final byte[] frame = ByteBuffer.allocate(4 + 2 + 4)
                .putInt(2).put(new byte[2])
                .putInt(-5)
                .array();

        assertThrows(PacketParsingException.class, () -> RSAUtil.getDeserializedSignedKey(frame));
    }

    @Test(timeout = 5000)
    public void truncatedInputIsRejected() {
        assertThrows(PacketParsingException.class, () -> RSAUtil.getDeserializedSignedKey(new byte[0]));
        assertThrows(PacketParsingException.class, () -> RSAUtil.getDeserializedSignedKey(new byte[]{0, 0}));
    }
}
