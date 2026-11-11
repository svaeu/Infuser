package com.github.svaeu.infuser.packets.encryption;

import org.junit.Test;

import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.util.Map;

import static org.junit.Assert.*;

public class ECDHEUtilTest {

    private static final String SESSION = "SessionKey";

    @Test
    public void bothSidesDeriveTheSameKey() throws Exception {
        final KeyPair alice = ECDHEUtil.generateECKeyPair();
        final KeyPair bob = ECDHEUtil.generateECKeyPair();
        final byte[] salt = ECDHEUtil.generateSalt();

        final SecretKey aliceKey = ECDHEUtil.deriveAES256Key(bob.getPublic(), alice.getPrivate(), salt, SESSION);
        final SecretKey bobKey = ECDHEUtil.deriveAES256Key(alice.getPublic(), bob.getPrivate(), salt, SESSION);

        assertEquals(32, aliceKey.getEncoded().length);
        assertArrayEquals(aliceKey.getEncoded(), bobKey.getEncoded());
    }

    @Test
    public void differentSaltGivesDifferentKey() throws Exception {
        final KeyPair alice = ECDHEUtil.generateECKeyPair();
        final KeyPair bob = ECDHEUtil.generateECKeyPair();

        final SecretKey first = ECDHEUtil.deriveAES256Key(
                bob.getPublic(), alice.getPrivate(), ECDHEUtil.generateSalt(), SESSION);
        final SecretKey second = ECDHEUtil.deriveAES256Key(
                bob.getPublic(), alice.getPrivate(), ECDHEUtil.generateSalt(), SESSION);

        assertFalse(java.util.Arrays.equals(first.getEncoded(), second.getEncoded()));
    }

    @Test
    public void differentContextGivesDifferentKey() throws Exception {
        final KeyPair alice = ECDHEUtil.generateECKeyPair();
        final KeyPair bob = ECDHEUtil.generateECKeyPair();
        final byte[] salt = ECDHEUtil.generateSalt();

        final SecretKey session = ECDHEUtil.deriveAES256Key(bob.getPublic(), alice.getPrivate(), salt, SESSION);
        final SecretKey transfer = ECDHEUtil.deriveAES256Key(bob.getPublic(), alice.getPrivate(), salt, "KeyTrxn");

        assertFalse(java.util.Arrays.equals(session.getEncoded(), transfer.getEncoded()));
    }

    @Test
    public void unrelatedPeerCannotDeriveTheKey() throws Exception {
        final KeyPair alice = ECDHEUtil.generateECKeyPair();
        final KeyPair bob = ECDHEUtil.generateECKeyPair();
        final KeyPair mallory = ECDHEUtil.generateECKeyPair();
        final byte[] salt = ECDHEUtil.generateSalt();

        final SecretKey real = ECDHEUtil.deriveAES256Key(bob.getPublic(), alice.getPrivate(), salt, SESSION);
        final SecretKey attacker = ECDHEUtil.deriveAES256Key(alice.getPublic(), mallory.getPrivate(), salt, SESSION);

        assertFalse(java.util.Arrays.equals(real.getEncoded(), attacker.getEncoded()));
    }

    @Test
    public void generatedSaltsAre32BytesAndDiffer() {
        final byte[] a = ECDHEUtil.generateSalt();
        final byte[] b = ECDHEUtil.generateSalt();

        assertEquals(32, a.length);
        assertFalse(java.util.Arrays.equals(a, b));
    }

    @Test
    public void saltedKeyRoundTrips() throws Exception {
        final KeyPair pair = ECDHEUtil.generateECKeyPair();
        final byte[] salt = ECDHEUtil.generateSalt();

        final byte[] serialised = ECDHEUtil.getSerializedSaltedKey(pair.getPublic(), salt);
        final Map.Entry<byte[], byte[]> peer = ECDHEUtil.getDeserializedSaltedKey(serialised)
                .entrySet().iterator().next();

        assertArrayEquals(pair.getPublic().getEncoded(), peer.getKey());
        assertArrayEquals(salt, peer.getValue());
        assertEquals(pair.getPublic(), ECDHEUtil.getPublicKeyFromBytes(peer.getKey()));
    }

    // ---- hostile input: these lengths arrive from the network before authentication ----

    @Test(timeout = 5000)
    public void emptyInputIsRejected() {
        assertRejected(new byte[0]);
    }

    @Test(timeout = 5000)
    public void truncatedLengthPrefixIsRejected() {
        assertRejected(new byte[]{0, 0, 0});
    }

    @Test(timeout = 5000)
    public void negativeSaltLengthIsRejected() {
        assertRejected(frame(-1, new byte[0], 0, new byte[0]));
    }

    @Test(timeout = 5000)
    public void zeroSaltLengthIsRejected() {
        assertRejected(frame(0, new byte[0], 91, new byte[91]));
    }

    @Test(timeout = 5000)
    public void oversizedSaltLengthIsRejected() {
        assertRejected(frame(ECDHEUtil.MAX_SALT_LENGTH + 1, new byte[ECDHEUtil.MAX_SALT_LENGTH + 1], 91, new byte[91]));
    }

    @Test(timeout = 5000)
    public void hugeSaltLengthIsRejectedWithoutAllocating() {
        // would be a 2 GiB allocation if it were trusted
        assertRejected(frame(Integer.MAX_VALUE, new byte[0], 0, new byte[0]));
    }

    @Test(timeout = 5000)
    public void saltLongerThanTheDataIsRejected() {
        assertRejected(frame(32, new byte[5], 0, new byte[0]));
    }

    @Test(timeout = 5000)
    public void oversizedKeyLengthIsRejected() {
        assertRejected(frame(32, new byte[32], ECDHEUtil.MAX_PUBLIC_KEY_LENGTH + 1,
                new byte[ECDHEUtil.MAX_PUBLIC_KEY_LENGTH + 1]));
    }

    @Test(timeout = 5000)
    public void hugeKeyLengthIsRejectedWithoutAllocating() {
        assertRejected(frame(32, new byte[32], Integer.MAX_VALUE, new byte[0]));
    }

    @Test(timeout = 5000)
    public void missingKeyIsRejected() {
        // salt is fine, then the key length prefix is absent altogether
        assertRejected(frame(32, new byte[32]));
    }

    @Test
    public void maximumAllowedFieldSizesAreAccepted() throws Exception {
        final byte[] frame = frame(ECDHEUtil.MAX_SALT_LENGTH, new byte[ECDHEUtil.MAX_SALT_LENGTH],
                ECDHEUtil.MAX_PUBLIC_KEY_LENGTH, new byte[ECDHEUtil.MAX_PUBLIC_KEY_LENGTH]);

        final Map.Entry<byte[], byte[]> peer = ECDHEUtil.getDeserializedSaltedKey(frame).entrySet().iterator().next();

        assertEquals(ECDHEUtil.MAX_PUBLIC_KEY_LENGTH, peer.getKey().length);
        assertEquals(ECDHEUtil.MAX_SALT_LENGTH, peer.getValue().length);
    }

    private static void assertRejected(byte[] frame) {
        assertThrows(InvalidKeyException.class, () -> ECDHEUtil.getDeserializedSaltedKey(frame));
    }

    /** Builds a frame with the given claimed lengths, which need not match the data that follows. */
    private static byte[] frame(int saltLen, byte[] salt, int keyLen, byte[] key) {
        return ByteBuffer.allocate(8 + salt.length + key.length)
                .putInt(saltLen).put(salt)
                .putInt(keyLen).put(key)
                .array();
    }

    private static byte[] frame(int saltLen, byte[] salt) {
        return ByteBuffer.allocate(4 + salt.length).putInt(saltLen).put(salt).array();
    }
}
