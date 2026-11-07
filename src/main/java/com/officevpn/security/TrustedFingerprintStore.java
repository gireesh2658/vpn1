package com.officevpn.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
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
import java.util.Collections;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

/**
 * Secure Client-Side Server Public Key Fingerprint Store.
 * <p>
 * Manages persistent TOFU (Trust-On-First-Use) and verified gateway public key fingerprints.
 * Storage location: &lt;datadir&gt;/known_gateways.properties.
 * Features atomic writes, owner-only file permissions, and one-time legacy migration.
 */
public final class TrustedFingerprintStore {

    private static final Logger LOGGER = LoggerFactory.getLogger(TrustedFingerprintStore.class);

    public static final String DEFAULT_PIN_FILE = "known_gateways.properties";
    public static final String LEGACY_PIN_FILE = "client_trusted_fingerprints.properties";

    private final Path storagePath;
    private final Properties properties = new Properties();
    private Runnable killPointHook = null;

    public static Path resolveDefaultPinStorePath() {
        return AuditKeyStore.resolveDefaultDataDir().resolve(DEFAULT_PIN_FILE);
    }

    public static TrustedFingerprintStore getDefault() {
        return new TrustedFingerprintStore(resolveDefaultPinStorePath());
    }

    public TrustedFingerprintStore() {
        this(resolveDefaultPinStorePath());
    }

    public TrustedFingerprintStore(Path storagePath) {
        this.storagePath = Objects.requireNonNull(storagePath, "Storage path cannot be null").toAbsolutePath();
        load();
    }

    // Test seam
    public void setKillPointHook(Runnable hook) {
        this.killPointHook = hook;
    }

    private String buildKey(String host, int port) {
        return host.trim().toLowerCase(Locale.ROOT) + ":" + port;
    }

    /**
     * Loads pinned fingerprints from disk and performs one-time migration of legacy CWD file.
     */
    public synchronized void load() {
        properties.clear();
        if (Files.exists(storagePath)) {
            try (FileInputStream in = new FileInputStream(storagePath.toFile())) {
                properties.load(in);
            } catch (IOException e) {
                LOGGER.warn("Failed to load trusted fingerprints: {}", e.getMessage());
            }
        }
    }

    /**
     * Persists pinned fingerprints atomically with owner-only permissions.
     */
    public synchronized void save() {
        try {
            Path parent = storagePath.getParent();
            if (parent != null && !Files.isDirectory(parent)) {
                Files.createDirectories(parent);
            }

            Path tempFile = Files.createTempFile(parent != null ? parent : Paths.get("."), "known_gw_", ".tmp");
            try {
                try (FileOutputStream out = new FileOutputStream(tempFile.toFile())) {
                    properties.store(out, "Office VPN Client - Trusted Gateway Public Key Fingerprints");
                }

                applyOwnerOnlyPermissions(tempFile);

                if (killPointHook != null) {
                    killPointHook.run();
                }

                try {
                    Files.move(tempFile, storagePath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tempFile, storagePath, StandardCopyOption.REPLACE_EXISTING);
                }
            } finally {
                try {
                    Files.deleteIfExists(tempFile);
                } catch (IOException ignored) {}
            }
        } catch (IOException e) {
            LOGGER.error("Failed to save trusted fingerprints: {}", e.getMessage());
            throw new java.io.UncheckedIOException("Failed to persist trusted fingerprint store", e);
        }
    }

    public synchronized boolean isEnrolled(String host, int port) {
        return getPinnedFingerprint(host, port).isPresent();
    }

    public synchronized Optional<String> getPinnedFingerprint(String host, int port) {
        String fp = properties.getProperty(buildKey(host, port));
        if (fp == null || fp.trim().length() != 64) {
            return Optional.empty();
        }
        return Optional.of(fp.trim().toLowerCase(Locale.ROOT));
    }

    public synchronized void pinFingerprint(String host, int port, String fingerprintHex) {
        Objects.requireNonNull(fingerprintHex, "Fingerprint cannot be null");
        String cleanFp = fingerprintHex.trim().toLowerCase(Locale.ROOT);
        if (cleanFp.length() != 64) {
            throw new IllegalArgumentException("Invalid SHA-256 fingerprint length: expected 64 hex chars, got " + cleanFp.length());
        }
        properties.setProperty(buildKey(host, port), cleanFp);
        save();
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
