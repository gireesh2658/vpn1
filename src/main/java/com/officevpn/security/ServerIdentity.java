package com.officevpn.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Manages persistent, encrypted RSA server identity and public key fingerprinting.
 * <p>
 * File layout: &lt;datadir&gt;/server_identity.key
 * Binary format:
 *   [0..7]   Magic: "OVPNID1\0" (8 bytes)
 *   [8..11]  Iterations: Big-Endian 32-bit int (4 bytes)
 *   [12..27] Salt: 16 bytes
 *   [28..39] IV: 12 bytes
 *   [40..N]  AES-256-GCM ciphertext + 16-byte tag (encrypts PKCS#8 DER private key)
 * AAD: magic (8) || iterations (4 BE) || salt (16) = 28 bytes.
 */
public record ServerIdentity(KeyPair keyPair, String fingerprintHex, Path path) {

    private static final Logger LOGGER = LoggerFactory.getLogger(ServerIdentity.class);

    public static final byte[] MAGIC = new byte[]{'O', 'V', 'P', 'N', 'I', 'D', '1', 0};
    public static final String IDENTITY_FILE_NAME = "server_identity.key";
    public static final int SALT_LENGTH = 16;
    public static final int IV_LENGTH = 12;
    public static final int TAG_LENGTH_BYTES = 16;
    public static final int HEADER_LENGTH = 8 + 4 + SALT_LENGTH + IV_LENGTH; // 40 bytes
    public static final int MIN_PASSPHRASE_LENGTH = 12;

    public boolean isEphemeral() {
        return path == null;
    }

    /**
     * Creates an in-memory ephemeral server identity (not persisted to disk).
     */
    public static ServerIdentity createEphemeral() {
        LOGGER.warn("EPHEMERAL IDENTITY - fingerprint changes on every start");
        KeyPair kp = CryptoUtils.generateRsaKeyPair();
        String fp = CryptoUtils.computeSha256FingerprintHex(kp.getPublic());
        return new ServerIdentity(kp, fp, null);
    }

    /**
     * Loads an existing server identity from disk or creates a new one atomically.
     * Always wipes the supplied passphrase character array upon completion.
     *
     * @param dir         Directory holding server_identity.key (null resolves default datadir)
     * @param passphrase  Passphrase for PBKDF2 key derivation (minimum 12 characters on creation)
     * @param allowCreate Whether to create a new identity file if one does not exist
     * @return Decrypted or newly created ServerIdentity record
     * @throws IdentityException If validation, decryption, or persistence fails
     */
    public static ServerIdentity loadOrCreate(Path dir, char[] passphrase, boolean allowCreate) throws IdentityException {
        try {
            Path targetDir = (dir != null) ? dir.toAbsolutePath() : AuditKeyStore.resolveDefaultDataDir();
            Path identityFile = targetDir.resolve(IDENTITY_FILE_NAME);

            if (Files.exists(identityFile)) {
                return loadExisting(identityFile, passphrase);
            }

            if (!allowCreate) {
                throw new IdentityException("Server identity file does not exist: " + identityFile);
            }

            if (passphrase == null || passphrase.length < MIN_PASSPHRASE_LENGTH) {
                throw new IdentityException("Passphrase must be at least " + MIN_PASSPHRASE_LENGTH + " characters for new identity creation");
            }

            return createNew(targetDir, identityFile, passphrase);
        } finally {
            if (passphrase != null) {
                Arrays.fill(passphrase, '\0');
            }
        }
    }

    private static ServerIdentity loadExisting(Path identityFile, char[] passphrase) throws IdentityException {
        if (passphrase == null) {
            throw new IdentityException("Passphrase required to decrypt server identity");
        }

        byte[] fileBytes;
        try {
            fileBytes = Files.readAllBytes(identityFile);
        } catch (IOException e) {
            throw new IdentityException("Failed to read server identity file: " + e.getMessage(), e);
        }

        if (fileBytes.length < HEADER_LENGTH + TAG_LENGTH_BYTES + 1) {
            throw new IdentityException("Server identity file is truncated or corrupted (length: " + fileBytes.length + ")");
        }

        ByteBuffer buffer = ByteBuffer.wrap(fileBytes);

        byte[] fileMagic = new byte[8];
        buffer.get(fileMagic);

        int iterations = buffer.getInt();
        if (iterations < 1000) {
            throw new IdentityException("Corrupted server identity header: iterations (" + iterations + ") below floor");
        }

        byte[] salt = new byte[SALT_LENGTH];
        buffer.get(salt);

        byte[] iv = new byte[IV_LENGTH];
        buffer.get(iv);

        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        byte[] aad = buildAad(fileMagic, iterations, salt);

        byte[] pkcs8Bytes;
        try {
            SecretKey aesKey = deriveAesKey(passphrase, salt, iterations);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
            cipher.updateAAD(aad);
            pkcs8Bytes = cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IdentityException("Failed to decrypt server identity: incorrect passphrase or corrupted file", e);
        }


        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
            if (!(privateKey instanceof RSAPrivateCrtKey crtKey)) {
                throw new IdentityException("Decrypted private key is not an RSAPrivateCrtKey");
            }
            RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent());
            PublicKey publicKey = kf.generatePublic(pubSpec);
            KeyPair kp = new KeyPair(publicKey, privateKey);
            String fp = CryptoUtils.computeSha256FingerprintHex(publicKey);
            return new ServerIdentity(kp, fp, identityFile);
        } catch (GeneralSecurityException e) {
            throw new IdentityException("Failed to parse decrypted private key: " + e.getMessage(), e);
        } finally {
            Arrays.fill(pkcs8Bytes, (byte) 0);
        }
    }

    private static ServerIdentity createNew(Path targetDir, Path identityFile, char[] passphrase) throws IdentityException {
        try {
            if (!Files.isDirectory(targetDir)) {
                Files.createDirectories(targetDir);
            }

            // Note on key size: RSA-2048 is retained because wire protocol v1 PRE_AUTH maxString is 512 bytes;
            // Base64 RSA-3072 is 564 characters which would violate framing limits.
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048, new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            byte[] pkcs8Bytes = kp.getPrivate().getEncoded();
            byte[] salt = new byte[SALT_LENGTH];
            new SecureRandom().nextBytes(salt);
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);

            int iterations = CryptoUtils.getEffectiveDefaultIterations();
            byte[] aad = buildAad(MAGIC, iterations, salt);

            SecretKey aesKey = deriveAesKey(passphrase, salt, iterations);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
            cipher.updateAAD(aad);
            byte[] ciphertext = cipher.doFinal(pkcs8Bytes);

            ByteBuffer out = ByteBuffer.allocate(HEADER_LENGTH + ciphertext.length);
            out.put(MAGIC);
            out.putInt(iterations);
            out.put(salt);
            out.put(iv);
            out.put(ciphertext);
            byte[] filePayload = out.array();

            Path tempFile = Files.createTempFile(targetDir, "srvid_", ".tmp");
            try {
                Files.write(tempFile, filePayload);
                applyOwnerOnlyPermissions(tempFile);
                try {
                    Files.move(tempFile, identityFile, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tempFile, identityFile);
                }
            } finally {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException cleanupEx) {
                    LOGGER.debug("Ignoring temp server identity file cleanup failure: {}", cleanupEx.getMessage());
                }
            }

            String fp = CryptoUtils.computeSha256FingerprintHex(kp.getPublic());
            return new ServerIdentity(kp, fp, identityFile);
        } catch (GeneralSecurityException | IOException e) {
            throw new IdentityException("Failed to create new server identity: " + e.getMessage(), e);
        }
    }

    private static byte[] buildAad(byte[] magic, int iterations, byte[] salt) {
        ByteBuffer aad = ByteBuffer.allocate(8 + 4 + salt.length);
        aad.put(magic);
        aad.putInt(iterations);
        aad.put(salt);
        return aad.array();
    }

    private static SecretKey deriveAesKey(char[] passphrase, byte[] salt, int iterations) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, iterations, 256);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = skf.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
        }
    }

    private static void applyOwnerOnlyPermissions(Path file) {
        Set<String> views = FileSystems.getDefault().supportedFileAttributeViews();
        if (views.contains("posix")) {
            try {
                Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                Files.setPosixFilePermissions(file, perms);
            } catch (Exception e) {
                LOGGER.warn("Failed to set POSIX permissions on {}: {}", file, e.getMessage());
            }
        }
        if (views.contains("acl")) {
            try {
                AclFileAttributeView view = Files.getFileAttributeView(file, AclFileAttributeView.class);
                if (view != null) {
                    UserPrincipal owner = Files.getOwner(file);
                    AclEntry entry = AclEntry.newBuilder()
                            .setType(AclEntryType.ALLOW)
                            .setPrincipal(owner)
                            .setPermissions(
                                    AclEntryPermission.READ_DATA,
                                    AclEntryPermission.WRITE_DATA,
                                    AclEntryPermission.APPEND_DATA,
                                    AclEntryPermission.READ_ATTRIBUTES,
                                    AclEntryPermission.WRITE_ATTRIBUTES,
                                    AclEntryPermission.READ_NAMED_ATTRS,
                                    AclEntryPermission.WRITE_NAMED_ATTRS,
                                    AclEntryPermission.READ_ACL,
                                    AclEntryPermission.SYNCHRONIZE
                            )
                            .build();
                    view.setAcl(Collections.singletonList(entry));
                }
            } catch (Exception e) {
                LOGGER.warn("Failed to set Windows owner-only ACL on {}: {}", file, e.getMessage());
            }
        }
    }
}
