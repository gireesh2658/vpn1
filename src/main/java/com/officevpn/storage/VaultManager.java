package com.officevpn.storage;

import com.officevpn.db.DatabaseManager;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Hardened Symlink-Resistant Departmental Vault Manager.
 * <p>
 * Implements strict departmental sandboxing with multiple layers of defense:
 * <ul>
 *   <li><b>Filename Allow-List & Sanitation:</b> Strict alphanumeric + safe character regex,
 *       rejection of Windows reserved device names, traversal sequences, and normalization checks.</li>
 *   <li><b>Safe I/O:</b> Canonical realPath confinement, NOFOLLOW_LINKS channel enforcement, symlink rejection.</li>
 *   <li><b>Atomic Overwrites &amp; Versioning:</b> Striped locks, temp file writes with fsync force, atomic rename,
 *       and automated pruning to 5 versions.</li>
 *   <li><b>Enforced Limits:</b> 8 MB max file size, 1000 files quota per vault.</li>
 *   <li><b>Tamper-Evident Audit:</b> Deterministic sha256 and size logging for all writes.</li>
 * </ul>
 */
public final class VaultManager {

    public static final String DEFAULT_VAULT_ROOT = "server_vaults";
    public static final int MAX_FILE_SIZE = 8 * 1024 * 1024; // 8 MB limit
    public static final int MAX_FILES_PER_VAULT = 1000;
    public static final int MAX_BACKUP_VERSIONS = 5;

    private static final Pattern FILENAME_PATTERN = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$");
    private static final Set<String> WINDOWS_RESERVED_NAMES = Set.of(
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    );

    private static final int LOCK_STRIPES = 64;
    private final ReentrantLock[] locks = new ReentrantLock[LOCK_STRIPES];
    private final SecureRandom secureRandom = new SecureRandom();

    private final Path rootDirectory;
    private VaultFileOps fileOps;

    private Runnable beforeFileOpenHook;
    private Runnable beforeFileWriteHook;
    private Runnable beforeDirectoryListHook;

    public VaultManager() {
        this(Path.of(DEFAULT_VAULT_ROOT), new DefaultVaultFileOps());
    }

    public VaultManager(Path rootDirectory) {
        this(rootDirectory, new DefaultVaultFileOps());
    }

    public VaultManager(VaultFileOps fileOps) {
        this(Path.of(DEFAULT_VAULT_ROOT), fileOps);
    }

    public VaultManager(Path rootDirectory, VaultFileOps fileOps) {
        Objects.requireNonNull(rootDirectory, "Root directory cannot be null");
        Objects.requireNonNull(fileOps, "VaultFileOps cannot be null");
        this.rootDirectory = rootDirectory.toAbsolutePath().normalize();
        this.fileOps = fileOps;
        for (int i = 0; i < LOCK_STRIPES; i++) {
            this.locks[i] = new ReentrantLock();
        }
        initializeVaultDirectories();
    }

    // Test seam
    public VaultFileOps getFileOps() {
        return fileOps;
    }

    // Test seam
    public void setBeforeFileOpenHook(Runnable hook) {
        this.beforeFileOpenHook = hook;
    }

    // Test seam
    public void setBeforeFileWriteHook(Runnable hook) {
        this.beforeFileWriteHook = hook;
    }

    // Test seam
    public void setBeforeDirectoryListHook(Runnable hook) {
        this.beforeDirectoryListHook = hook;
    }

    private void initializeVaultDirectories() {
        try {
            Files.createDirectories(rootDirectory);
            for (Department dept : Department.values()) {
                Path deptVault = rootDirectory.resolve(dept.name());
                Files.createDirectories(deptVault);
            }
            if (Boolean.getBoolean("officevpn.demo")) {
                seedDefaultDepartmentFiles();
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to initialize vault directory structure", e);
        }
    }

    /**
     * Validates a file name against allow-list rules, Windows reserved names, and NFC normalization.
     */
    public static void validateFileName(String fileName) {
        if (!isValidFileName(fileName)) {
            throw new VaultException("E_BAD_REQUEST", "Bad request: invalid file name or format");
        }
    }

    public static boolean isValidFileName(String fileName) {
        if (fileName == null || fileName.isBlank() || fileName.length() > 128) {
            return false;
        }
        if (fileName.endsWith(".") || fileName.endsWith(" ")) {
            return false;
        }
        if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\") || fileName.contains(":") || fileName.contains("\0")) {
            return false;
        }
        if (!FILENAME_PATTERN.matcher(fileName).matches()) {
            return false;
        }
        // Unicode NFC normalization check
        if (!Normalizer.normalize(fileName, Normalizer.Form.NFC).equals(fileName)) {
            return false;
        }
        // Windows reserved device names check (e.g. CON, con.txt, AUX, com1)
        int dotIndex = fileName.indexOf('.');
        String baseName = (dotIndex >= 0) ? fileName.substring(0, dotIndex) : fileName;
        if (WINDOWS_RESERVED_NAMES.contains(baseName.toUpperCase(Locale.ROOT))
                || WINDOWS_RESERVED_NAMES.contains(fileName.toUpperCase(Locale.ROOT))) {
            return false;
        }
        return true;
    }

    /**
     * Resolves and verifies that a requested filename stays strictly within the target department vault.
     */
    public Path resolveSafeFilePath(Department targetDept, String fileName, boolean forWrite) {
        Objects.requireNonNull(targetDept, "Target department cannot be null");
        validateFileName(fileName);

        Path deptRoot = rootDirectory.resolve(targetDept.name()).normalize();

        try {
            Path realDeptRoot = deptRoot.toRealPath();
            if (Files.isSymbolicLink(deptRoot)) {
                throw new VaultException("E_DENIED", "Access denied: departmental vault path security violation");
            }

            Path resolved = deptRoot.resolve(fileName).normalize();

            if (fileOps.exists(resolved, LinkOption.NOFOLLOW_LINKS)) {
                if (Files.isSymbolicLink(resolved)) {
                    throw new VaultException("E_DENIED", "Access denied: symbolic links not permitted in vault");
                }
                Path realResolved = resolved.toRealPath();
                if (!realResolved.startsWith(realDeptRoot)) {
                    throw new VaultException("E_DENIED", "Access denied: path traversal or symlink escape detected");
                }
                return realResolved;
            } else {
                Path parent = resolved.getParent();
                Path parentReal = (parent != null) ? parent.toRealPath() : realDeptRoot;
                if (!parentReal.startsWith(realDeptRoot)) {
                    throw new VaultException("E_DENIED", "Access denied: path traversal attempt on file creation");
                }
                return resolved;
            }
        } catch (IOException e) {
            throw new VaultException("E_DENIED", "Access denied: failed to safely resolve file path", e);
        }
    }

    public List<String> listFiles(UserAccount user, Department targetDept, DatabaseManager db) {
        return listFiles(user, targetDept, db, "local");
    }

    public List<String> listFiles(UserAccount user, Department targetDept, DatabaseManager db, String clientIp) {
        String safeIp = (clientIp != null && !clientIp.isBlank()) ? clientIp.trim() : "local";
        validateAccess(user, targetDept, db, "LIST_FILES", "ALL", safeIp);

        if (db != null) {
            db.logAuditEventOrThrow("VAULT_LIST", user.username(), targetDept.name(),
                    "List files in vault", user.username(), safeIp);
        }

        if (beforeDirectoryListHook != null) {
            beforeDirectoryListHook.run();
        }

        Path deptPath = rootDirectory.resolve(targetDept.name());
        List<String> fileNames = new ArrayList<>();

        try (Stream<Path> stream = Files.list(deptPath)) {
            stream.filter(p -> fileOps.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))
                    .filter(p -> !Files.isSymbolicLink(p))
                    .map(p -> p.getFileName().toString())
                    .filter(name -> !name.startsWith("."))
                    .filter(name -> !name.startsWith(".tmp-"))
                    .filter(VaultManager::isValidFileName)
                    .map(name -> name.replaceAll("[\\p{Cntrl}]", ""))
                    .sorted()
                    .forEach(fileNames::add);
            return Collections.unmodifiableList(fileNames);
        } catch (IOException e) {
            if (db != null) {
                db.logAuditEvent("VAULT_LIST_FAILED", user.username(), targetDept.name(),
                        "Failed to list vault files: " + e.getMessage(), user.username(), safeIp);
            }
            throw new VaultException("E_INTERNAL", "Failed to list vault files for " + targetDept, e);
        }
    }

    public byte[] readFile(UserAccount user, Department targetDept, String fileName, DatabaseManager db) {
        return readFile(user, targetDept, fileName, db, "local");
    }

    public byte[] readFile(UserAccount user, Department targetDept, String fileName, DatabaseManager db, String clientIp) {
        String safeIp = (clientIp != null && !clientIp.isBlank()) ? clientIp.trim() : "local";
        validateAccess(user, targetDept, db, "READ_FILE", fileName, safeIp);

        if (db != null) {
            db.logAuditEventOrThrow("VAULT_READ", user.username(), targetDept.name(),
                    "Read file " + fileName, user.username(), safeIp);
        }

        if (beforeFileOpenHook != null) {
            beforeFileOpenHook.run();
        }

        Path safePath = resolveSafeFilePath(targetDept, fileName, false);
        if (!fileOps.exists(safePath, LinkOption.NOFOLLOW_LINKS) || !fileOps.isRegularFile(safePath, LinkOption.NOFOLLOW_LINKS)) {
            if (db != null) {
                db.logAuditEvent("VAULT_READ_FAILED", user.username(), targetDept.name(),
                        "File not found: " + fileName, user.username(), safeIp);
            }
            throw new VaultException("E_NOT_FOUND", "The requested resource was not found");
        }

        try {
            long size = fileOps.size(safePath);
            if (size > MAX_FILE_SIZE) {
                throw new VaultException("E_TOO_LARGE", "File size exceeds maximum allowable limit");
            }
        } catch (VaultException ve) {
            throw ve;
        } catch (IOException e) {
            throw new VaultException("E_NOT_FOUND", "The requested resource was not found", e);
        }

        try (SeekableByteChannel ch = fileOps.newByteChannel(safePath, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            long sz = ch.size();
            if (sz > MAX_FILE_SIZE) {
                throw new VaultException("E_TOO_LARGE", "File size exceeds maximum allowable limit");
            }
            ByteBuffer buf = ByteBuffer.allocate((int) sz);
            while (buf.hasRemaining()) {
                if (ch.read(buf) < 0) break;
            }
            return buf.array();
        } catch (VaultException ve) {
            throw ve;
        } catch (IOException e) {
            if (db != null) {
                db.logAuditEvent("VAULT_READ_FAILED", user.username(), targetDept.name(),
                        "Failed to read file: " + e.getMessage(), user.username(), safeIp);
            }
            throw new VaultException("E_INTERNAL", "Failed to read vault file", e);
        }
    }

    public void writeFile(UserAccount user, Department targetDept, String fileName, byte[] data, DatabaseManager db) {
        writeFile(user, targetDept, fileName, data, db, "local");
    }

    public void writeFile(UserAccount user, Department targetDept, String fileName, byte[] data, DatabaseManager db, String clientIp) {
        String safeIp = (clientIp != null && !clientIp.isBlank()) ? clientIp.trim() : "local";
        validateAccess(user, targetDept, db, "WRITE_FILE", fileName, safeIp);

        if (user != null && user.role() == Role.AUDITOR) {
            if (db != null) {
                db.logAuditEvent("RBAC_VIOLATION", user.username(), user.department().name(),
                        "Auditor role is read-only and cannot upload/modify files in target vault: " + targetDept,
                        user.username(), safeIp);
            }
            throw new SecurityException("RBAC Access Denied: Auditor role is read-only and cannot upload/modify files");
        }

        if (data == null) {
            throw new VaultException("E_BAD_REQUEST", "File data cannot be null");
        }

        if (data.length > MAX_FILE_SIZE) {
            throw new VaultException("E_TOO_LARGE", "File size exceeds maximum allowable limit");
        }

        validateFileName(fileName);

        ReentrantLock lock = locks[Math.floorMod(fileName.toLowerCase(Locale.ROOT).hashCode(), LOCK_STRIPES)];
        lock.lock();
        try {
            Path deptRoot = rootDirectory.resolve(targetDept.name()).normalize();
            Path safePath = resolveSafeFilePath(targetDept, fileName, true);

            // Quota pre-check: 1000 files limit per department
            if (!fileOps.exists(safePath, LinkOption.NOFOLLOW_LINKS)) {
                long existingCount = countVaultFiles(deptRoot);
                if (existingCount >= MAX_FILES_PER_VAULT) {
                    throw new VaultException("E_QUOTA", "Quota exceeded: maximum 1000 files per vault");
                }
            }

            // Audit details: size=<n>; sha256=<hex>
            String sha256Hex = sha256Hex(data);
            if (db != null) {
                db.logAuditEventOrThrow("VAULT_WRITE", user.username(), targetDept.name(),
                        "size=" + data.length + "; sha256=" + sha256Hex, user.username(), safeIp);
            }

            if (beforeFileWriteHook != null) {
                beforeFileWriteHook.run();
            }

            // Temp file: .tmp-<16 hex random> in the same department directory
            byte[] randomBytes = new byte[8];
            secureRandom.nextBytes(randomBytes);
            String tempName = ".tmp-" + bytesToHex(randomBytes);
            Path tempPath = deptRoot.resolve(tempName);

            try {
                try (SeekableByteChannel ch = fileOps.newByteChannel(tempPath,
                        Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS))) {
                    ByteBuffer buf = ByteBuffer.wrap(data);
                    while (buf.hasRemaining()) {
                        ch.write(buf);
                    }
                    if (ch instanceof FileChannel fc) {
                        fc.force(true);
                    }
                }

                // If target exists, backup to .versions and keep newest 5
                if (fileOps.exists(safePath, LinkOption.NOFOLLOW_LINKS)) {
                    Path versionsDir = deptRoot.resolve(".versions");
                    if (!Files.exists(versionsDir)) {
                        Files.createDirectories(versionsDir);
                    }
                    Path backupPath = versionsDir.resolve(fileName + "." + System.currentTimeMillis());
                    fileOps.copy(safePath, backupPath, StandardCopyOption.REPLACE_EXISTING);

                    pruneVersions(versionsDir, fileName, MAX_BACKUP_VERSIONS);
                }

                // Move temp to target atomically, fallback to replace_existing with Windows retry
                boolean moved = false;
                for (int attempt = 0; attempt < 5 && !moved; attempt++) {
                    try {
                        try {
                            fileOps.move(tempPath, safePath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
                            fileOps.move(tempPath, safePath, StandardCopyOption.REPLACE_EXISTING);
                        }
                        moved = true;
                    } catch (java.nio.file.FileSystemException fse) {
                        if (attempt == 4) {
                            throw fse;
                        }
                        try {
                            Thread.sleep(15);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            throw fse;
                        }
                    }
                }
            } catch (Exception e) {
                try {
                    fileOps.deleteIfExists(tempPath);
                } catch (Exception ignored) {}
                if (e instanceof VaultException ve) {
                    throw ve;
                }
                if (db != null) {
                    db.logAuditEvent("VAULT_WRITE_FAILED", user.username(), targetDept.name(),
                            "Failed to write file: " + e.getMessage(), user.username(), safeIp);
                }
                throw new VaultException("E_INTERNAL", "Failed to write vault file", e);
            }
        } finally {
            lock.unlock();
        }
    }

    private void pruneVersions(Path versionsDir, String fileName, int keepCount) {
        try {
            if (!Files.exists(versionsDir)) return;
            java.util.regex.Pattern versionPattern = java.util.regex.Pattern.compile("^" + java.util.regex.Pattern.quote(fileName) + "\\.(\\d+)$");
            List<Path> versions = new ArrayList<>();
            try (Stream<Path> stream = Files.list(versionsDir)) {
                stream.filter(p -> versionPattern.matcher(p.getFileName().toString()).matches())
                        .forEach(versions::add);
            }
            if (versions.size() > keepCount) {
                versions.sort(Comparator.comparingLong(p -> {
                    java.util.regex.Matcher m = versionPattern.matcher(p.getFileName().toString());
                    if (m.matches()) {
                        try {
                            return Long.parseLong(m.group(1));
                        } catch (NumberFormatException ignored) {}
                    }
                    return 0L;
                }));
                int toDelete = versions.size() - keepCount;
                for (int i = 0; i < toDelete; i++) {
                    fileOps.deleteIfExists(versions.get(i));
                }
            }
        } catch (Exception ignored) {}
    }

    private long countVaultFiles(Path deptRoot) {
        try (Stream<Path> stream = Files.list(deptRoot)) {
            return stream.filter(p -> fileOps.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))
                    .filter(p -> !p.getFileName().toString().startsWith("."))
                    .count();
        } catch (IOException e) {
            return 0;
        }
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            return bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private void validateAccess(UserAccount user, Department targetDept, DatabaseManager db, String action, String targetFile, String clientIp) {
        String safeIp = (clientIp != null && !clientIp.isBlank()) ? clientIp.trim() : "local";
        if (user == null || !Department.canAccessVault(user.role(), user.department(), targetDept)) {
            String actingUser = (user != null) ? user.username() : "ANONYMOUS";
            String actingDept = (user != null) ? user.department().name() : "UNASSIGNED";
            String roleStr = (user != null) ? user.role().name() : "NONE";

            if (db != null) {
                db.logAuditEvent("RBAC_VIOLATION", actingUser, actingDept,
                        "Unauthorized attempt to " + action + " on target vault: " + targetDept + " (Target: " + targetFile + ")",
                        actingUser, safeIp);
            }

            throw new SecurityException(String.format(
                    "RBAC Access Denied: User '%s' with role %s in department %s cannot access %s vault",
                    actingUser, roleStr, actingDept, targetDept
            ));
        }
    }

    public void seedDefaultDepartmentFiles() {
        try {
            Path fin = rootDirectory.resolve(Department.FINANCE.name()).resolve("Q4_Payroll_2026.csv");
            if (!Files.exists(fin)) {
                String payrollContent = "EmployeeId,Name,Department,Salary_INR\nEMP101,Alice Smith,Finance,1450000\nEMP102,Bob Jones,Finance,1200000\n";
                Files.writeString(fin, payrollContent, StandardCharsets.UTF_8);
            }

            Path hr = rootDirectory.resolve(Department.HR.name()).resolve("Employee_Appraisals_2026.txt");
            if (!Files.exists(hr)) {
                String hrContent = "CONFIDENTIAL HR APPRAISAL RECORDS 2026\nRating: Alice (Exceeds), Bob (Meets)\n";
                Files.writeString(hr, hrContent, StandardCharsets.UTF_8);
            }

            Path it = rootDirectory.resolve(Department.IT.name()).resolve("Firewall_Config.conf");
            if (!Files.exists(it)) {
                String itContent = "# VPN GATEWAY FIREWALL RULES\nPORT 8443 ALLOW 10.8.0.0/24\nDEFAULT DENY ALL\n";
                Files.writeString(it, itContent, StandardCharsets.UTF_8);
            }

            Path hq = rootDirectory.resolve(Department.HEADQUARTERS.name()).resolve("Board_Strategy_2026.txt");
            if (!Files.exists(hq)) {
                String hqContent = "HEADQUARTERS EXECUTIVE STRATEGY 2026-2027\nRestricted to Corporate Officers Only.\n";
                Files.writeString(hq, hqContent, StandardCharsets.UTF_8);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to seed default department vault files", e);
        }
    }

    // Test seam
    public Path getRootDirectory() {
        return rootDirectory;
    }
}
