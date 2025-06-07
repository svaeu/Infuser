package com.github.svaeu.infuser.packets.encryption;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

public class ECDHEUtil {

    private static final String EC_ALGO  = "EC";
    private static final String ECDH_ALGO = "ECDH";
    private static final String AES_ALGO = "AES";
    private static final String CURVE = "secp256r1";

    public static final String AES_TRANS = "AES/GCM/NoPadding";

    private static final SecureRandom RNG = new SecureRandom();

    public static KeyPair generateECKeyPair() throws GeneralSecurityException {
        final KeyPairGenerator keyPairGenerator;
        final ECGenParameterSpec ecGenParameterSpec;

        keyPairGenerator = KeyPairGenerator.getInstance(EC_ALGO);
        ecGenParameterSpec = new ECGenParameterSpec(CURVE);

        keyPairGenerator.initialize(ecGenParameterSpec);
        return keyPairGenerator.generateKeyPair();
    }

    public static SecretKey deriveAES256Key(
            PublicKey sharedPubKey,
            PrivateKey genPrvKey,
            byte[] exchangedSalt,
            String metaData) throws GeneralSecurityException {
        final Digest digest;
        final HKDFBytesGenerator hkdfBytesGenerator;
        final HKDFParameters hkdfParameters;

        final byte[] okm;

        digest = new SHA256Digest();
        hkdfBytesGenerator = new HKDFBytesGenerator(digest);

        hkdfParameters = new HKDFParameters(
                computeSharedSecret(genPrvKey, sharedPubKey),
                exchangedSalt,
                metaData.getBytes());
        hkdfBytesGenerator.init(hkdfParameters);

        okm = new byte[32];

        hkdfBytesGenerator.generateBytes(okm, 0, 32);

        return new SecretKeySpec(okm, AES_ALGO);
    }

    private static byte[] computeSharedSecret(
            PrivateKey genPrvKey,
            PublicKey sharedPubKey) throws GeneralSecurityException {
        final KeyAgreement keyAgreement;

        keyAgreement = KeyAgreement.getInstance(ECDH_ALGO);
        keyAgreement.init(genPrvKey);
        keyAgreement.doPhase(sharedPubKey, true);
        return keyAgreement.generateSecret();
    }

    public static byte[] getSerializedSaltedKey(PublicKey publicKey, byte[] salt) {
        final byte[] encodedPubKey;
        final ByteBuffer byteBuffer;

        encodedPubKey = publicKey.getEncoded();

        // 4 bytes for respective byte array lengths (salt and public key) included with
        // their actual sizes:
        byteBuffer = ByteBuffer.allocate(4 + salt.length + 4 + encodedPubKey.length)
                .putInt(salt.length)
                .put(salt)
                .putInt(encodedPubKey.length)
                .put(encodedPubKey);

        return byteBuffer.array();
    }

    public static Map<byte[], byte[]> getDeserializedSaltedKey(byte[] saltedKey) {
        final ByteBuffer byteBuffer;
        final byte[] ecPubKey, salt;

        byteBuffer = ByteBuffer.wrap(saltedKey);

        salt = new byte[byteBuffer.getInt()];
        byteBuffer.get(salt);

        ecPubKey = new byte[byteBuffer.getInt()];
        byteBuffer.get(ecPubKey);

        return Map.of(
                ecPubKey, salt
        );
    }

    public static byte[] generateSalt() {
        final byte[] salt;

        salt = new byte[32];
        RNG.nextBytes(salt);

        return salt;
    }

    public static PublicKey getPublicKeyFromBytes(byte[] keyBytes) throws GeneralSecurityException {
        final KeyFactory keyFactory;

        keyFactory = KeyFactory.getInstance(EC_ALGO);

        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }
}