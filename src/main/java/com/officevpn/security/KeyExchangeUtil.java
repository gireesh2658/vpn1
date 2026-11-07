package com.officevpn.security;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Elliptic Curve Diffie-Hellman (ECDH) key exchange utility using curve secp256r1 (NIST P-256).
 * Enables Ephemeral Diffie-Hellman key agreement for Perfect Forward Secrecy (PFS).
 * Enforces rigorous EC point and curve validation to prevent invalid curve attacks.
 */
public final class KeyExchangeUtil {

    public static final String EC_CURVE = "secp256r1";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    // NIST P-256 / secp256r1 curve parameters
    private static final BigInteger SECP256R1_P = new BigInteger(
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    private static final BigInteger SECP256R1_A = new BigInteger(
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
    private static final BigInteger SECP256R1_B = new BigInteger(
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    private static final BigInteger SECP256R1_N = new BigInteger(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);

    private KeyExchangeUtil() {}

    /**
     * Generates an ephemeral EC key pair on NIST curve secp256r1.
     *
     * @return {@link KeyPair} containing EC private and public keys
     */
    public static KeyPair generateECDHKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(EC_CURVE);
            keyGen.initialize(ecSpec, SECURE_RANDOM);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("Failed to initialize ECDH key pair generator with " + EC_CURVE, e);
        }
    }

    /**
     * Validates that the provided public key is an authentic, valid EC point on curve secp256r1.
     * Prevents invalid-curve, small-subgroup, and point-at-infinity attacks.
     *
     * @param key Public key to validate
     * @return true if valid secp256r1 key, false otherwise
     */
    public static boolean isValidSecp256r1PublicKey(PublicKey key) {
        if (!(key instanceof ECPublicKey ecKey)) {
            return false;
        }
        ECParameterSpec spec = ecKey.getParams();
        if (spec == null) {
            return false;
        }
        // Verify curve field size is 256 bits
        if (spec.getCurve().getField().getFieldSize() != 256) {
            return false;
        }
        // Verify generator order matches secp256r1
        if (!SECP256R1_N.equals(spec.getOrder())) {
            return false;
        }
        // Reject point at infinity
        ECPoint point = ecKey.getW();
        if (point == null || point.equals(ECPoint.POINT_INFINITY)) {
            return false;
        }
        BigInteger x = point.getAffineX();
        BigInteger y = point.getAffineY();
        if (x == null || y == null) {
            return false;
        }
        // Coordinate bounds: 0 <= x, y < p
        if (x.signum() < 0 || y.signum() < 0 || x.compareTo(SECP256R1_P) >= 0 || y.compareTo(SECP256R1_P) >= 0) {
            return false;
        }
        // Verify curve equation: y^2 = x^3 + a*x + b (mod p)
        BigInteger lhs = y.modPow(BigInteger.valueOf(2), SECP256R1_P);
        BigInteger rhs = x.modPow(BigInteger.valueOf(3), SECP256R1_P)
                .add(SECP256R1_A.multiply(x))
                .add(SECP256R1_B)
                .mod(SECP256R1_P);
        return lhs.equals(rhs);
    }

    /**
     * Encodes an EC public key to standard Base64 X.509 format.
     */
    public static String ecPublicKeyToBase64(PublicKey key) {
        Objects.requireNonNull(key, "Public key cannot be null");
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Reconstructs and validates an EC public key from Base64 X.509 format.
     * Strictly verifies that the key lies on curve secp256r1.
     *
     * @param base64 Base64 X.509 string
     * @return Validated {@link PublicKey}
     * @throws SecurityException If key cannot be decoded or is not on curve secp256r1
     */
    public static PublicKey base64ToEcPublicKey(String base64) {
        Objects.requireNonNull(base64, "Base64 string cannot be null");
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey key = kf.generatePublic(spec);
            if (!isValidSecp256r1PublicKey(key)) {
                throw new SecurityException("Public key is not on curve secp256r1 or failed curve equation validation");
            }
            return key;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new SecurityException("Invalid or malformed EC public key: " + e.getMessage(), e);
        }
    }

    /**
     * Derives directional session keys (c2s and s2c) from the ECDH raw shared secret and transcript hash
     * using RFC 5869 HKDF-SHA256 Key Derivation.
     *
     * @param rawSharedSecret ECDH shared secret bytes
     * @param transcriptHash  SHA-256 hash of the complete handshake transcript (used as HKDF salt)
     * @return {@link CryptoUtils.DirectionalKeys} with isolated c2s and s2c AES-256 keys
     */
    public static CryptoUtils.DirectionalKeys deriveDirectionalKeys(byte[] rawSharedSecret, byte[] transcriptHash) {
        Objects.requireNonNull(rawSharedSecret, "Shared secret cannot be null");
        Objects.requireNonNull(transcriptHash, "Transcript hash cannot be null");

        byte[] prk = CryptoUtils.hkdfExtract(transcriptHash, rawSharedSecret);
        byte[] c2sBytes = null;
        byte[] s2cBytes = null;
        try {
            c2sBytes = CryptoUtils.hkdfExpand(prk, "OFFICE-VPN-2.0 c2s key".getBytes(StandardCharsets.UTF_8), 32);
            s2cBytes = CryptoUtils.hkdfExpand(prk, "OFFICE-VPN-2.0 s2c key".getBytes(StandardCharsets.UTF_8), 32);

            SecretKey c2sKey = new SecretKeySpec(c2sBytes, "AES");
            SecretKey s2cKey = new SecretKeySpec(s2cBytes, "AES");
            return new CryptoUtils.DirectionalKeys(c2sKey, s2cKey);
        } finally {
            Arrays.fill(prk, (byte) 0);
            if (c2sBytes != null) Arrays.fill(c2sBytes, (byte) 0);
            if (s2cBytes != null) Arrays.fill(s2cBytes, (byte) 0);
        }
    }



    /**
     * Derives the raw ECDH shared secret octets between the local private key and peer public key.
     *
     * @param localPrivateKey local party's private key
     * @param peerPublicKey   remote peer's public key
     * @return shared secret byte array
     */
    public static byte[] deriveRawSharedSecret(PrivateKey localPrivateKey, PublicKey peerPublicKey) {
        Objects.requireNonNull(localPrivateKey, "localPrivateKey cannot be null");
        Objects.requireNonNull(peerPublicKey, "peerPublicKey cannot be null");
        if (!isValidSecp256r1PublicKey(peerPublicKey)) {
            throw new SecurityException("Peer public key rejected: not on curve secp256r1");
        }
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(localPrivateKey);
            keyAgreement.doPhase(peerPublicKey, true);
            return keyAgreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new SecurityException("ECDH key agreement negotiation failed", e);
        }
    }
}
