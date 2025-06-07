package com.github.svaeu.infuser.packets.encryption;

import org.bouncycastle.jcajce.provider.asymmetric.RSA;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

public class RSAUtil {

    private static final String RSA_ALGO = "RSA";
    private static final String SIGNATURE_ALGO = "SHA256withRSA";

    public static byte[] signPublicKey(PrivateKey privateKey, PublicKey ecGenPubKey) throws GeneralSecurityException {
        final Signature ecSignature;

        ecSignature = Signature.getInstance(SIGNATURE_ALGO);
        ecSignature.initSign(privateKey);
        ecSignature.update(ecGenPubKey.getEncoded());

        return ecSignature.sign();
    }

    public static boolean verifySignature(
            PublicKey fingerprint,
            byte[] sharedECKey,
            byte[] signatureBytes) throws GeneralSecurityException {
        final Signature signature;

        signature = Signature.getInstance(SIGNATURE_ALGO);
        signature.initVerify(fingerprint);
        signature.update(sharedECKey);

        return signature.verify(signatureBytes);
    }

    public static byte[] getSerialisedSignedKey(byte[] ecPubKey, byte[] signature) {
        final ByteBuffer byteBuffer;

        byteBuffer = ByteBuffer.allocate(4 + ecPubKey.length + 4 + signature.length);
        byteBuffer.putInt(ecPubKey.length);
        byteBuffer.put(ecPubKey);
        byteBuffer.putInt(signature.length);
        byteBuffer.put(signature);

        return byteBuffer.array();
    }

    public static Map<byte[], byte[]> getDeserializedSignedKey(byte[] signedKeyBytes) {
        final ByteBuffer byteBuffer;
        final byte[] ecPublicKey, signatureBytes;

        byteBuffer = ByteBuffer.wrap(signedKeyBytes);

        ecPublicKey = new byte[byteBuffer.getInt()];
        byteBuffer.get(ecPublicKey);

        signatureBytes = new byte[byteBuffer.getInt()];
        byteBuffer.get(signatureBytes);

        return Map.of(
                ecPublicKey, signatureBytes
        );
    }

    public static KeyPair generateKeyPair(int keySize) throws GeneralSecurityException {
        final KeyPairGenerator keyPairGenerator;

        keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGO);
        keyPairGenerator.initialize(keySize);

        return keyPairGenerator.generateKeyPair();
    }

    public static PublicKey getPublicKeyFromBytes(byte[] keyBytes) throws GeneralSecurityException {
        final KeyFactory keyFactory;

        keyFactory = KeyFactory.getInstance(RSA_ALGO);

        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public static PrivateKey getPrivateKeyFromBytes(byte[] keyBytes) throws GeneralSecurityException {
        final KeyFactory keyFactory;

        keyFactory = KeyFactory.getInstance(RSA_ALGO);

        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }
}
