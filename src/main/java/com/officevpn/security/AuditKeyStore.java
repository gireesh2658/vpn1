package com.officevpn.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Locale;
import java.util.Set;

/**
 * Manages the HMAC key and integrity head file for the audit hash chain.
 * <p>
 * Key storage: &lt;datadir&gt;/audit.key (32 bytes, permission 600 or Windows owner-only ACL).
 * Head storage: &lt;datadir&gt;/audit.head (seq|row_hash|hmac, written atomically).
 */
public final class AuditKeyStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuditKeyStore.class);

    public record AuditHead(long seq, String rowHash, String hmac, boolean validHmac) {}

    private final Path dataDir;
    private final Path keyFile;
    private final Path headFile;
    private byte[] inMemoryKey;

    public AuditKeyStore() {
        this(resolveDefaultDataDir());
    }

    public AuditKeyStore(Path path) {
        Path p = (path != null) ? path.toAbsolutePath() : resolveDefaultDataDir();
        if (p.getFileName() != null && p.getFileName().toString().endsWith(".key")) {
            this.dataDir = p.getParent();
            this.keyFile = p;
            String baseName = p.getFileName().toString().replaceFirst("\\.audit\\.key$|\\.key$", "");
            this.headFile = this.dataDir.resolve(baseName + ".audit.head");
        } else {
            this.dataDir = p;
            this.keyFile = this.dataDir.resolve("audit.key");
            this.headFile = this.dataDir.resolve("audit.head");
        }
    }

    public static Path resolveDefaultDataDir() {
        String prop = System.getProperty("officevpn.datadir");
        if (prop != null && !prop.isBlank()) {
            return Paths.get(prop.trim());
        }
        return Paths.get(System.getProperty("user.home"), ".officevpn");
    }

    // Test seam
    public Path getKeyFile() {
        return keyFile;
    }

    // Test seam
    public Path getHeadFile() {
        return headFile;
    }

    public synchronized boolean hasKey() {
        if (inMemoryKey != null) {
            return true;
        }
        try {
            return Files.isRegularFile(keyFile) && Files.size(keyFile) == 32;
        } catch (IOException e) {
            return false;
        }
    }

    public synchronized byte[] getKey() {
        if (inMemoryKey != null) {
            return inMemoryKey.clone();
        }
        if (Files.isRegularFile(keyFile)) {
            try {
                byte[] bytes = Files.readAllBytes(keyFile);
                if (bytes.length == 32) {
                    this.inMemoryKey = bytes.clone();
                    return bytes;
                }
            } catch (IOException ex) {
                LOGGER.warn("Failed to read audit key from {}: {}", keyFile, ex.getMessage());
            }
        }
        return null;
    }

    /**
     * Retrieves the existing 32-byte audit key, or generates a new one on first run.
     * <p>
     * If the database already holds chained rows but the key file is missing,
     * this method NEVER generates a new key to prevent chain forgery.
     *
     * @param dbHasChainedRows true if DB has existing chained audit rows
     * @return 32-byte key, or null if key is missing and cannot be generated
     */
    public synchronized byte[] getOrCreateKey(boolean dbHasChainedRows) {
        if (hasKey()) {
            return getKey();
        }
        if (dbHasChainedRows) {
            // Missing key for existing chain - DO NOT GENERATE!
            return null;
        }

        try {
            if (!Files.isDirectory(dataDir)) {
                Files.createDirectories(dataDir);
            }
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            Files.write(keyFile, key);
            applySecurePermissions(keyFile);
            this.inMemoryKey = key.clone();
            return key;
        } catch (IOException e) {
            LOGGER.error("Failed to create audit key file at {}: {}", keyFile, e.getMessage());
            return null;
        }
    }

    private void applySecurePermissions(Path file) {
        try {
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(file, perms);
        } catch (UnsupportedOperationException uoe) {
            applyWindowsOwnerOnlyAcl(file);
        } catch (Exception e) {
            LOGGER.warn("Failed to set POSIX permissions on {}: {}", file, e.getMessage());
        }
    }

    private void applyWindowsOwnerOnlyAcl(Path file) {
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

    public synchronized void writeHead(long seq, String rowHash) throws IOException {
        byte[] key = getKey();
        if (key == null) {
            throw new IllegalStateException("Cannot write audit head: key is missing");
        }
        if (!Files.isDirectory(dataDir)) {
            Files.createDirectories(dataDir);
        }
        String payload = seq + "|" + rowHash;
        String hmac = CryptoUtils.hmacSha256Hex(key, payload.getBytes(StandardCharsets.UTF_8));
        String content = payload + "|" + hmac + System.lineSeparator();

        Path tempFile = Files.createTempFile(dataDir, "audit_head_", ".tmp");
        try {
            Files.writeString(tempFile, content, StandardCharsets.UTF_8);
            try {
                Files.move(tempFile, headFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tempFile, headFile, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            try {
                Files.deleteIfExists(tempFile);
            } catch (IOException cleanupEx) {
                LOGGER.debug("Ignoring temp audit head file cleanup failure: {}", cleanupEx.getMessage());
            }
        }
    }

    public synchronized AuditHead readHead() {
        if (!Files.isRegularFile(headFile)) {
            return null;
        }
        try {
            String content = Files.readString(headFile, StandardCharsets.UTF_8).trim();
            String[] parts = content.split("\\|");
            if (parts.length != 3) {
                return new AuditHead(-1, "", "", false);
            }
            long seq = Long.parseLong(parts[0].trim());
            String rowHash = parts[1].trim();
            String hmac = parts[2].trim().toLowerCase(Locale.ROOT);

            byte[] key = getKey();
            boolean valid = false;
            if (key != null) {
                String expected = CryptoUtils.hmacSha256Hex(key, (parts[0].trim() + "|" + rowHash).getBytes(StandardCharsets.UTF_8));
                valid = MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), hmac.getBytes(StandardCharsets.UTF_8));
            }
            return new AuditHead(seq, rowHash, hmac, valid);
        } catch (Exception e) {
            return new AuditHead(-1, "", "", false);
        }
    }
}
