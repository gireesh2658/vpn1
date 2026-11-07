package com.officevpn.security;

import com.officevpn.protocol.PacketType;
import com.officevpn.protocol.VpnPacket;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Hardened Hybrid Cryptography Engine for the Office VPN Wire Protocol.
 * <p>
 * Implements:
 * <ol>
 *   <li><b>RSA-2048 with Explicit SHA-256 OAEP &amp; MGF1-SHA256</b> for asymmetric key encapsulation during handshake.</li>
 *   <li><b>RSASSA-PSS with SHA-256 &amp; MGF1-SHA256</b> for cryptographically binding handshake transcripts and server identity.</li>
 *   <li><b>Public Key Pinning (SHA-256 Fingerprint)</b> ensuring only pre-authorized, out-of-band provisioned server keys are accepted.</li>
 *   <li><b>RFC 5869 HKDF-SHA256 Key Derivation &amp; Separation</b> for extracting PRK from Master Secret and expanding
 *       strictly independent 256-bit symmetric session keys (AES-256-GCM and HMAC-SHA256).</li>
 *   <li><b>AES-256-GCM with Canonical Length-Prefixed AAD + Separately Keyed HMAC-SHA256</b> for
 *       Encrypt-then-MAC defense-in-depth and live packet sniffer integrity verification.
 *       <p>
 *       <i>Architecture Note:</i> AES-256-GCM natively authenticates the ciphertext and AAD header/metadata fields via its 128-bit
 *       internal Galois/Counter mode authentication tag. The outer HMAC-SHA256 (computed with the cryptographically
 *       independent {@code hmacKey}) serves as an educational defense-in-depth pre-filter and packet-sniffer integrity tag.
 *       Key separation guarantees that compromised outer integrity state never leaks symmetric payload encryption keys.</li>
 *   <li><b>PBKDF2WithHmacSHA256</b> password hashing with constant-time verification
 *       and strict memory hygiene (password clearing &amp; zero-wiping).</li>
 * </ol>
 */
public final class CryptoUtils {

    /**
     * Explicit OAEP specification: SHA-256 message digest, MGF1 mask generation function with SHA-256,
     * and default empty PSpecified encoding. Prevents Bleichenbacher and padding-oracle attacks on RSA.
     */
    public static final OAEPParameterSpec OAEP_SHA256_SPEC = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
    );

    /**
     * Explicit RSASSA-PSS specification: SHA-256 hash, MGF1-SHA256 mask generation, 32-byte salt, trailer field 1.
     */
    public static final PSSParameterSpec PSS_SHA256_SPEC = new PSSParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            32,
            1
    );

    /** Standard AES-GCM recommended IV length: 96 bits (12 octets) per NIST SP 800-38D */
    public static final int GCM_IV_LENGTH_BYTES = 12;

    /** Standard AES-GCM authentication tag length: 128 bits */
    public static final int GCM_TAG_LENGTH_BITS = 128;

    /** Direction byte for Client-to-Server packets bound into AES-GCM AAD */
    public static final byte DIRECTION_C2S = 0x01;

    /** Direction byte for Server-to-Client packets bound into AES-GCM AAD */
    public static final byte DIRECTION_S2C = 0x02;

    /** Legacy PBKDF2 iteration count */
    public static final int LEGACY_PBKDF2_ITERATIONS = 65536;

    /** Default PBKDF2 iteration count for upgraded hashes */
    public static final int DEFAULT_PBKDF2_ITERATIONS = 600_000;

    /** PBKDF2 derived key length in bits */
    public static final int PBKDF2_KEY_LENGTH_BITS = 256;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CryptoUtils() {
        // Utility class
    }

    // =========================================================================
    // 1. RSA-2048 WITH EXPLICIT SHA-256 OAEP & RSASSA-PSS SIGNATURES
    // =========================================================================

    /**
     * Generates a fresh 2048-bit RSA key pair using {@link SecureRandom}.
     *
     * @return Generated RSA-2048 KeyPair
     */
    public static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048, SECURE_RANDOM);
            return keyGen.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to initialize RSA-2048 key pair generator", e);
        }
    }

    /**
     * Encrypts plaintext data using the recipient's RSA public key with explicit OAEP-SHA256 padding.
     *
     * @param data      Plaintext bytes to encrypt (e.g., 32-byte master secret)
     * @param publicKey Recipient's RSA public key
     * @return Encrypted ciphertext bytes
     */
    public static byte[] encryptWithRsaPublic(byte[] data, PublicKey publicKey) {
        Objects.requireNonNull(data, "Data cannot be null");
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, OAEP_SHA256_SPEC);
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("RSA-OAEP encryption failed", e);
        }
    }

    /**
     * Decrypts ciphertext data using the recipient's RSA private key with explicit OAEP-SHA256 padding.
     *
     * @param encryptedData Ciphertext bytes to decrypt
     * @param privateKey    Recipient's RSA private key
     * @return Decrypted plaintext bytes
     */
    public static byte[] decryptWithRsaPrivate(byte[] encryptedData, PrivateKey privateKey) {
        Objects.requireNonNull(encryptedData, "Encrypted data cannot be null");
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey, OAEP_SHA256_SPEC);
            return cipher.doFinal(encryptedData);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("RSA-OAEP decryption failed", e);
        }
    }

    /**
     * Signs data using RSASSA-PSS with SHA-256 and MGF1-SHA256.
     *
     * @param data       Data bytes to sign (e.g., canonical handshake transcript)
     * @param privateKey Signer's private key
     * @return Digital signature bytes
     */
    public static byte[] signWithRsaPss(byte[] data, PrivateKey privateKey) {
        Objects.requireNonNull(data, "Data to sign cannot be null");
        Objects.requireNonNull(privateKey, "Private key cannot be null");
        try {
            Signature signature = Signature.getInstance("RSASSA-PSS");
            signature.setParameter(PSS_SHA256_SPEC);
            signature.initSign(privateKey, SECURE_RANDOM);
            signature.update(data);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new SecurityException("RSASSA-PSS signing failed", e);
        }
    }

    /**
     * Verifies an RSASSA-PSS signature over data using the signer's public key.
     *
     * @param data           Original data bytes
     * @param signatureBytes Signature bytes to verify
     * @param publicKey      Signer's public key
     * @return True if signature is valid, false otherwise
     */
    public static boolean verifyWithRsaPss(byte[] data, byte[] signatureBytes, PublicKey publicKey) {
        if (data == null || signatureBytes == null || publicKey == null) {
            return false;
        }
        try {
            Signature signature = Signature.getInstance("RSASSA-PSS");
            signature.setParameter(PSS_SHA256_SPEC);
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /**
     * Encodes an RSA public key to an X.509 standard Base64 string for network transmission.
     *
     * @param key RSA public key
     * @return Base64 representation of X.509 encoded key
     */
    public static String publicKeyToBase64(PublicKey key) {
        Objects.requireNonNull(key, "Public key cannot be null");
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Reconstructs an RSA public key from an X.509 standard Base64 string.
     *
     * @param base64 Base64 string of X.509 encoded public key
     * @return Reconstituted PublicKey
     */
    public static PublicKey base64ToPublicKey(String base64) {
        Objects.requireNonNull(base64, "Base64 key cannot be null");
        try {
            byte[] keyBytes = Base64.getDecoder().decode(base64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey key = kf.generatePublic(spec);
            if (key instanceof java.security.interfaces.RSAKey rsaKey) {
                if (rsaKey.getModulus().bitLength() < 2048) {
                    throw new SecurityException("Insecure RSA public key: " + rsaKey.getModulus().bitLength() + " bits (minimum 2048 required)");
                }
            }
            return key;
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to decode RSA public key from Base64", e);
        }
    }

    // =========================================================================
    // PUBLIC KEY PINNING & TRANSCRIPT BINDING
    // =========================================================================

    /**
     * Computes the SHA-256 fingerprint hex string of an X.509 public key.
     *
     * @param publicKey Public key to fingerprint
     * @return 64-character lowercase hex SHA-256 digest of key's encoded bytes
     */
    public static String computeSha256FingerprintHex(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "Public key cannot be null");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(publicKey.getEncoded());
            return bytesToHex(hash);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 fingerprint computation failed", e);
        }
    }


    /**
     * Constructs a canonical binary handshake transcript to prevent man-in-the-middle, replay,
     * and transcript modification attacks during key exchange.
     *
     * @param protocolVersion Version string (e.g., "OFFICE-VPN-1.0")
     * @param clientRandom    Ephemeral client challenge/nonce (at least 16 bytes)
     * @param serverRandom    Ephemeral server challenge/nonce (at least 16 bytes)
     * @param encapsulatedKey RSA-OAEP encrypted master secret
     * @return Canonical deterministic length-prefixed transcript bytes
     */
    public static byte[] buildHandshakeTranscript(String protocolVersion,
                                                  byte[] clientRandom,
                                                  byte[] serverRandom,
                                                  byte[] encapsulatedKey) {
        Objects.requireNonNull(protocolVersion, "Protocol version cannot be null");
        Objects.requireNonNull(clientRandom, "Client random cannot be null");
        Objects.requireNonNull(serverRandom, "Server random cannot be null");
        Objects.requireNonNull(encapsulatedKey, "Encapsulated key cannot be null");

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            byte[] verBytes = protocolVersion.getBytes(StandardCharsets.UTF_8);
            dos.writeInt(verBytes.length);
            dos.write(verBytes);

            dos.writeInt(clientRandom.length);
            dos.write(clientRandom);

            dos.writeInt(serverRandom.length);
            dos.write(serverRandom);

            dos.writeInt(encapsulatedKey.length);
            dos.write(encapsulatedKey);

            dos.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Handshake transcript serialization failed", e);
        }
    }

    /**
     * Constructs a canonical binary handshake transcript for OFFICE-VPN-2.0 to prevent
     * man-in-the-middle, replay, and transcript modification attacks during ephemeral ECDH key exchange.
     *
     * @param protocolVersion Version string (e.g., "OFFICE-VPN-2.0")
     * @param clientNonce     Ephemeral client challenge/nonce (at least 16 bytes)
     * @param serverNonce     Ephemeral server challenge/nonce (at least 16 bytes)
     * @param clientEcPub     Client ephemeral EC public key X.509 encoded bytes
     * @param serverEcPub     Server ephemeral EC public key X.509 encoded bytes
     * @return Canonical deterministic length-prefixed transcript bytes
     */
    public static byte[] buildHandshakeTranscriptV2(String protocolVersion,
                                                    byte[] clientNonce,
                                                    byte[] serverNonce,
                                                    byte[] clientEcPub,
                                                    byte[] serverEcPub) {
        Objects.requireNonNull(protocolVersion, "Protocol version cannot be null");
        Objects.requireNonNull(clientNonce, "Client nonce cannot be null");
        Objects.requireNonNull(serverNonce, "Server nonce cannot be null");
        Objects.requireNonNull(clientEcPub, "Client EC public key cannot be null");
        Objects.requireNonNull(serverEcPub, "Server EC public key cannot be null");

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            byte[] verBytes = protocolVersion.getBytes(StandardCharsets.UTF_8);
            dos.writeInt(verBytes.length);
            dos.write(verBytes);

            dos.writeInt(clientNonce.length);
            dos.write(clientNonce);

            dos.writeInt(serverNonce.length);
            dos.write(serverNonce);

            dos.writeInt(clientEcPub.length);
            dos.write(clientEcPub);

            dos.writeInt(serverEcPub.length);
            dos.write(serverEcPub);

            dos.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Handshake transcript serialization failed", e);
        }
    }

    // =========================================================================
    // 2. RFC 5869 HKDF-SHA256 PRIMITIVES & DIRECTIONAL KEYS
    // =========================================================================

    public record DirectionalKeys(SecretKey c2sKey, SecretKey s2cKey) {
        public DirectionalKeys {
            Objects.requireNonNull(c2sKey, "c2sKey cannot be null");
            Objects.requireNonNull(s2cKey, "s2cKey cannot be null");
        }
    }

    /**
     * RFC 5869 HKDF-Extract stage: extracts a Pseudorandom Key (PRK) from Input Keying Material (IKM) and Salt.
     * <p>
     * {@code PRK = HMAC-Hash(salt, IKM)}
     *
     * @param salt Optional salt value (a non-secret random value); if null or empty, defaults to 32 zero octets
     * @param ikm  Input keying material (e.g., Master Secret)
     * @return 32-byte pseudorandom key (PRK)
     */
    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        Objects.requireNonNull(ikm, "IKM (Input Keying Material) cannot be null");
        try {
            byte[] actualSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(actualSalt, "HmacSHA256"));
            return mac.doFinal(ikm);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HKDF-Extract calculation failed", e);
        }
    }

    /**
     * RFC 5869 HKDF-Expand stage: expands a Pseudorandom Key (PRK) into Output Keying Material (OKM)
     * of length {@code outLen} octets using application-specific info context.
     * <p>
     * {@code OKM = first outLen octets of T(1) | T(2) | ... | T(N)}
     *
     * @param prk    Pseudorandom key of at least HashLen octets (from hkdfExtract)
     * @param info   Context and application specific information
     * @param outLen Length of output keying material in octets (L &le; 255 * HashLen)
     * @return Output Keying Material (OKM)
     */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int outLen) {
        Objects.requireNonNull(prk, "PRK cannot be null");
        final int hashLen = 32; // SHA-256 hash length in octets
        if (outLen < 0 || outLen > 255 * hashLen) {
            throw new IllegalArgumentException("Invalid outLen for HKDF-Expand: " + outLen + " (max: " + (255 * hashLen) + ")");
        }
        byte[] actualInfo = (info != null) ? info : new byte[0];
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(prk, "HmacSHA256"));

            int n = (int) Math.ceil((double) outLen / hashLen);
            byte[] okm = new byte[outLen];
            byte[] t = new byte[0];
            int bytesCopied = 0;

            for (int i = 1; i <= n; i++) {
                mac.reset();
                if (t.length > 0) {
                    mac.update(t);
                }
                if (actualInfo.length > 0) {
                    mac.update(actualInfo);
                }
                mac.update((byte) i);
                t = mac.doFinal();

                int toCopy = Math.min(hashLen, outLen - bytesCopied);
                System.arraycopy(t, 0, okm, bytesCopied, toCopy);
                bytesCopied += toCopy;
            }
            return okm;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HKDF-Expand calculation failed", e);
        }
    }

    // =========================================================================
    // 3. AES-256-GCM AEAD WITH DIRECTIONAL BINDING
    // =========================================================================

    /**
     * Generates a 12-byte (96-bit) cryptographically random Initialization Vector (IV) for AES-GCM.
     *
     * @return 12 random bytes
     */
    public static byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    /**
     * Computes a keyed HMAC-SHA256 hex string over Additional Authenticated Data (AAD), IV, and ciphertext.
     *
     * @param headerAad   Canonical packet header AAD bytes (type, IP, user, dept, timestamp, sorted metadata)
     * @param iv          Initialization vector bytes
     * @param cipherBytes AES-GCM encrypted payload bytes
     * @param hmacKey     Dedicated HMAC secret key derived from HKDF-SHA256
     * @return Hexadecimal representation of HMAC-SHA256 tag
     */
    public static String computeHmacSha256Hex(byte[] headerAad, byte[] iv, byte[] cipherBytes, SecretKey hmacKey) {
        Objects.requireNonNull(hmacKey, "HMAC key cannot be null");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(hmacKey);
            if (headerAad != null && headerAad.length > 0) {
                mac.update(headerAad);
            }
            if (iv != null && iv.length > 0) {
                mac.update(iv);
            }
            if (cipherBytes != null && cipherBytes.length > 0) {
                mac.update(cipherBytes);
            }
            byte[] hmacBytes = mac.doFinal();
            return bytesToHex(hmacBytes);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to compute HMAC-SHA256", e);
        }
    }

    /**
     * Creates an encrypted VpnPacket using AES-256-GCM with canonical AAD and a cryptographically bound direction byte.
     * Drops the outer HMAC in compliance with OFFICE-VPN-2.0 AEAD specifications.
     *
     * @param type         VPN packet type
     * @param virtualIp    Sender's virtual IP (e.g. 10.8.0.x)
     * @param username     Sender's username
     * @param dept         Sender's department
     * @param metadata     Metadata map (filenames, actions, etc.)
     * @param plainPayload Plaintext data payload to encrypt
     * @param aesKey       Directional AES-256 encryption key
     * @param direction    Direction byte (0x01 for C2S, 0x02 for S2C)
     * @return Encrypted and authenticated VpnPacket
     */


    public static VpnPacket createEncryptedPacket(PacketType type,
                                                  String virtualIp,
                                                  String username,
                                                  String dept,
                                                  Map<String, String> metadata,
                                                  byte[] plainPayload,
                                                  SecretKey aesKey,
                                                  byte direction) {
        Objects.requireNonNull(type, "PacketType cannot be null");
        Objects.requireNonNull(aesKey, "AES session key cannot be null");

        long timestamp = System.currentTimeMillis();
        byte[] iv = generateIv();
        Map<String, String> safeMeta = (metadata != null) ? new LinkedHashMap<>(metadata) : new LinkedHashMap<>();

        VpnPacket tempPacket = new VpnPacket(type, virtualIp, username, dept, timestamp, iv, null, null, safeMeta);
        byte[] headerAad = tempPacket.getHeaderAadBytes();

        byte[] encryptedPayload;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
            cipher.updateAAD(new byte[]{direction});
            cipher.updateAAD(headerAad);
            encryptedPayload = cipher.doFinal(plainPayload != null ? plainPayload : new byte[0]);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("AES-256-GCM encryption failed", e);
        }

        return new VpnPacket(
                type,
                virtualIp,
                username,
                dept,
                timestamp,
                iv,
                encryptedPayload,
                "", // Redundant outer HMAC dropped in OFFICE-VPN-2.0
                safeMeta
        );
    }

    /**
     * Decrypts an authenticated VpnPacket using AES-256-GCM and verifies canonical AAD and direction byte.
     *
     * @param packet            Target VpnPacket to decrypt
     * @param aesKey            Directional AES-256 decryption key
     * @param expectedDirection Expected direction byte (0x01 for C2S, 0x02 for S2C)
     * @return Decrypted plaintext bytes
     * @throws SecurityException If decryption fails, AAD is tampered with, or direction byte mismatches
     */
    public static byte[] decryptPacket(VpnPacket packet, SecretKey aesKey, byte expectedDirection) {
        Objects.requireNonNull(packet, "Packet cannot be null");
        Objects.requireNonNull(aesKey, "AES session key cannot be null");

        byte[] iv = packet.getIv();
        if (iv == null || iv.length != GCM_IV_LENGTH_BYTES) {
            throw new SecurityException("Malformed packet: IV must be exactly " + GCM_IV_LENGTH_BYTES
                    + " bytes, got: " + (iv != null ? iv.length : "null"));
        }

        byte[] headerAad = packet.getHeaderAadBytes();
        byte[] encryptedPayload = packet.getEncryptedPayload();

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
            cipher.updateAAD(new byte[]{expectedDirection});
            cipher.updateAAD(headerAad);
            return cipher.doFinal(encryptedPayload != null ? encryptedPayload : new byte[0]);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("AES-256-GCM decryption failed: authentication tag mismatch or directional tampering", e);
        }
    }



    // =========================================================================
    // 4. PASSWORD HASHING (PBKDF2WithHmacSHA256) WITH MEMORY HYGIENE
    // =========================================================================

    /**
     * Generates a 16-byte random salt for PBKDF2 password hashing.
     *
     * @return Base64 encoded 16-byte salt
     */
    public static String generateSalt() {
        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Hashes a password using PBKDF2WithHmacSHA256 and 256-bit key length.
     * Enforces best-effort memory hygiene by clearing PBEKeySpec and zero-wiping temporary buffers.
     *
     * @param password   Raw password characters
     * @param saltBase64 Base64 encoded salt
     * @return Base64 encoded hash
     */
    public static String hashPassword(char[] password, String saltBase64) {
        Objects.requireNonNull(password, "Password cannot be null");
        Objects.requireNonNull(saltBase64, "Salt cannot be null");

        byte[] salt = Base64.getDecoder().decode(saltBase64);
        try {
            return hashPasswordWithIterations(password, salt, LEGACY_PBKDF2_ITERATIONS);
        } finally {
            Arrays.fill(salt, (byte) 0);
        }
    }

    public static int getEffectiveDefaultIterations() {
        return DEFAULT_PBKDF2_ITERATIONS;
    }

    public static String hashPasswordWithIterations(char[] password, byte[] salt, int iterations) {
        Objects.requireNonNull(password, "Password cannot be null");
        Objects.requireNonNull(salt, "Salt cannot be null");

        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, PBKDF2_KEY_LENGTH_BITS);
        byte[] hash = null;
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            hash = skf.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 password hashing failed", e);
        } finally {
            spec.clearPassword();
            if (hash != null) {
                Arrays.fill(hash, (byte) 0);
            }
        }
    }

    public static String hashPasswordModular(char[] password) {
        return hashPasswordModular(password, getEffectiveDefaultIterations());
    }

    public static String hashPasswordModular(char[] password, int iterations) {
        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);
        try {
            String hashB64 = hashPasswordWithIterations(password, salt, iterations);
            return "pbkdf2-sha256$" + iterations + "$" + Base64.getEncoder().encodeToString(salt) + "$" + hashB64;
        } finally {
            Arrays.fill(salt, (byte) 0);
        }
    }

    public record ParsedPasswordHash(
            boolean isModular,
            int iterations,
            String saltB64,
            String hashB64,
            boolean malformed
    ) {}

    public static ParsedPasswordHash parseStoredHash(String storedHash) {
        if (storedHash == null || storedHash.isEmpty()) {
            return new ParsedPasswordHash(false, 0, null, null, true);
        }
        if (storedHash.startsWith("pbkdf2-sha256$")) {
            String[] parts = storedHash.split("\\$", -1);
            if (parts.length != 4 || !parts[0].equals("pbkdf2-sha256")) {
                return new ParsedPasswordHash(true, 0, null, null, true);
            }
            int iterations;
            try {
                iterations = Integer.parseInt(parts[1]);
            } catch (NumberFormatException e) {
                return new ParsedPasswordHash(true, 0, null, null, true);
            }
            int minFloor = 10_000;
            if (iterations < minFloor || iterations > 10_000_000) {
                return new ParsedPasswordHash(true, iterations, null, null, true);
            }
            String saltB64 = parts[2];
            String hashB64 = parts[3];
            if (saltB64.isEmpty() || hashB64.isEmpty()) {
                return new ParsedPasswordHash(true, iterations, null, null, true);
            }
            try {
                Base64.getDecoder().decode(saltB64);
                Base64.getDecoder().decode(hashB64);
            } catch (IllegalArgumentException e) {
                return new ParsedPasswordHash(true, iterations, null, null, true);
            }
            return new ParsedPasswordHash(true, iterations, saltB64, hashB64, false);
        } else {
            // Legacy hash
            try {
                Base64.getDecoder().decode(storedHash);
                return new ParsedPasswordHash(false, LEGACY_PBKDF2_ITERATIONS, null, storedHash, false);
            } catch (IllegalArgumentException e) {
                return new ParsedPasswordHash(false, 0, null, null, true);
            }
        }
    }

    public static boolean isMalformedHash(String storedHash) {
        return parseStoredHash(storedHash).malformed();
    }

    public static boolean verifyPasswordModular(char[] rawPassword, String storedHash, String legacySalt) {
        if (rawPassword == null || storedHash == null || storedHash.isEmpty()) {
            return false;
        }
        ParsedPasswordHash parsed = parseStoredHash(storedHash);
        if (parsed.malformed()) {
            return false;
        }

        if (parsed.isModular()) {
            byte[] salt = Base64.getDecoder().decode(parsed.saltB64());
            try {
                String computed = hashPasswordWithIterations(rawPassword, salt, parsed.iterations());
                return MessageDigest.isEqual(
                        computed.getBytes(StandardCharsets.UTF_8),
                        parsed.hashB64().getBytes(StandardCharsets.UTF_8)
                );
            } finally {
                Arrays.fill(salt, (byte) 0);
            }
        } else {
            if (legacySalt == null || legacySalt.isEmpty()) {
                return false;
            }
            return verifyPassword(rawPassword, legacySalt, storedHash);
        }
    }

    private static volatile String DUMMY_HASH = null;
    public static String getDummyHash() {
        if (DUMMY_HASH == null) {
            byte[] dummySalt = new byte[16];
            Arrays.fill(dummySalt, (byte) 0x5A);
            char[] dummyPass = "dummy_timing_salt_password_fixed_floor".toCharArray();
            int iters = getEffectiveDefaultIterations();
            String hash = hashPasswordWithIterations(dummyPass, dummySalt, iters);
            DUMMY_HASH = "pbkdf2-sha256$" + iters + "$" + Base64.getEncoder().encodeToString(dummySalt) + "$" + hash;
        }
        return DUMMY_HASH;
    }



    /**
     * Verifies a raw password against an expected PBKDF2 hash using constant-time comparison.
     *
     * @param rawPassword        Raw password attempt
     * @param saltBase64         Stored user salt
     * @param expectedHashBase64 Stored user password hash
     * @return True if matches, false otherwise
     */
    public static boolean verifyPassword(char[] rawPassword, String saltBase64, String expectedHashBase64) {
        if (rawPassword == null || saltBase64 == null || expectedHashBase64 == null) {
            return false;
        }
        String computedHash = hashPassword(rawPassword, saltBase64);
        return MessageDigest.isEqual(
                computedHash.getBytes(StandardCharsets.UTF_8),
                expectedHashBase64.getBytes(StandardCharsets.UTF_8)
        );
    }



    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute HMAC-SHA256", e);
        }
    }

    public static String hmacSha256Hex(byte[] key, byte[] data) {
        return bytesToHex(hmacSha256(key, data)).toLowerCase(Locale.ROOT);
    }

    public static byte[] computeRowHashData(
            String prevHash,
            long seq,
            String eventType,
            String username,
            String department,
            String details,
            String actor,
            String remoteIp,
            long tsMs
    ) {
        byte[] prevBytes = new byte[32];
        if (prevHash != null && !prevHash.isBlank() && !prevHash.equals("0000000000000000000000000000000000000000000000000000000000000000")) {
            byte[] parsed = hexToBytes(prevHash.trim());
            if (parsed.length != 32) {
                throw new IllegalArgumentException("Previous audit hash must be exactly 32 bytes (64 hex characters), got: " + parsed.length);
            }
            System.arraycopy(parsed, 0, prevBytes, 0, 32);
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        try {
            baos.write(prevBytes);
            baos.write(ByteBuffer.allocate(8).putLong(seq).array());
            writeLengthPrefixed(baos, eventType);
            writeLengthPrefixed(baos, username);
            writeLengthPrefixed(baos, department);
            writeLengthPrefixed(baos, details);
            writeLengthPrefixed(baos, actor);
            writeLengthPrefixed(baos, remoteIp);
            baos.write(ByteBuffer.allocate(8).putLong(tsMs).array());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return baos.toByteArray();
    }

    private static void writeLengthPrefixed(ByteArrayOutputStream baos, String str) throws IOException {
        byte[] bytes = (str != null) ? str.getBytes(StandardCharsets.UTF_8) : new byte[0];
        baos.write(ByteBuffer.allocate(4).putInt(bytes.length).array());
        baos.write(bytes);
    }

    public static String computeRowHash(
            byte[] auditKey,
            String prevHash,
            long seq,
            String eventType,
            String username,
            String department,
            String details,
            String actor,
            String remoteIp,
            long tsMs
    ) {
        byte[] data = computeRowHashData(prevHash, seq, eventType, username, department, details, actor, remoteIp, tsMs);
        return hmacSha256Hex(auditKey, data);
    }

    /**
     * Computes the SHA-256 hexadecimal hash of UTF-8 string text.
     *
     * @param text Input text
     * @return 64-character lowercase hex digest
     */
    public static String sha256Hex(String text) {
        if (text == null) {
            return "";
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(text.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    // =========================================================================
    // HELPER HEX UTILITIES
    // =========================================================================

    /**
     * Converts a byte array to a lowercase hexadecimal string.
     *
     * @param bytes Binary bytes
     * @return Hexadecimal representation
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0x0F, 16));
            sb.append(Character.forDigit(b & 0x0F, 16));
        }
        return sb.toString();
    }

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * @param hex Hex string
     * @return Parsed byte array
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }
        return java.util.HexFormat.of().parseHex(hex.trim());
    }
}
