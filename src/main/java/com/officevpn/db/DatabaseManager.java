package com.officevpn.db;

import com.officevpn.admin.PasswordPolicy;
import com.officevpn.admin.UsernamePolicy;
import com.officevpn.config.ConfigUtil;
import com.officevpn.model.AuditVerifyResult;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;
import com.officevpn.security.AuditKeyStore;
import com.officevpn.security.AuditSanitizer;
import com.officevpn.security.AuditUnavailableException;
import com.officevpn.security.CryptoUtils;
import com.officevpn.security.PasswordHasher;
import com.officevpn.security.PasswordVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * SQLite Database and Security Audit Log Manager.
 * <p>
 * Manages user authentication identities, role/department assignments, and security audit trails.
 * Enforces parameter binding via {@link PreparedStatement} exclusively to prevent SQL injection.
 * <p>
 * <b>CREDENTIALS &amp; SECURITY POLICY:</b><br>
 * Raw passwords are never stored, logged, or serialized. Accounts are initialized through
 * {@link com.officevpn.admin.AdminBootstrap} on first run or seeded dynamically via
 * {@link com.officevpn.admin.DemoSeeder} when {@code -Dofficevpn.demo=true} is explicitly passed.
 * Any legacy prototype credentials are automatically neutralized on startup.
 */
public final class DatabaseManager implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseManager.class);
    public static final String DEFAULT_DB_URL = "jdbc:sqlite:office_vpn.db";

    private final String jdbcUrl;
    private final PasswordVerifier passwordVerifier;
    private final PasswordHasher passwordHasher;
    private final AuditKeyStore auditKeyStore;
    private final LongSupplier clockMillis;
    private final ScheduledExecutorService headFlushScheduler;
    private final boolean ownsScheduler;
    private final Map<String, Long> lastLockoutAuditTimes = new ConcurrentHashMap<>();
    private final Map<String, Long> lastAttackAuditTimes = new ConcurrentHashMap<>();
    private final AtomicLong bestEffortFailureCount = new AtomicLong(0);
    private long lastBestEffortErrorLogMs = 0L;
    private long auditCapacityThreshold = 1_000_000L;
    private long lastCapacityWarningMs = 0L;
    private boolean capacityWarningEmitted = false;
    private int rowsSinceLastHeadWrite = 0;
    private boolean dirtySinceLastHeadWrite = false;
    private long lastHeadWriteMs = 0L;
    private Connection connection;

    /**
     * Audit log record structure for security audits and verification.
     */
    public record AuditLogEntry(
            int id,
            long seq,
            String eventType,
            String username,
            String department,
            String details,
            String actor,
            String remoteIp,
            long timestamp
    ) {
        public String ipAddress() {
            return remoteIp != null ? remoteIp : "0.0.0.0";
        }
    }

    /**
     * Immutable snapshot of user row state read during authentication.
     */
    public record UserRowSnapshot(
            int id,
            String canonicalUsername,
            String salt,
            String hash,
            Department department,
            Role role,
            boolean isActive,
            long createdAt
    ) {}

    private record LegacyAuditRow(
            int id,
            String eventType,
            String username,
            String department,
            String details,
            String ipAddress,
            String timestampStr
    ) {}

    private record AuditRowVerifyDto(
            long seq,
            String eventType,
            String username,
            String department,
            String details,
            String actor,
            String remoteIp,
            long tsMs,
            String prevHash,
            String rowHash
    ) {}

    /**
     * Initializes DatabaseManager with default production SQLite database file (office_vpn.db).
     */
    public DatabaseManager() {
        this(DEFAULT_DB_URL, CryptoUtils::verifyPasswordModular, pw -> CryptoUtils.hashPasswordModular(pw), new AuditKeyStore(), System::currentTimeMillis);
    }

    /**
     * Initializes DatabaseManager with custom JDBC URL (e.g., in-memory or temp file for isolated testing).
     *
     * @param jdbcUrl SQLite JDBC URL
     */
    public DatabaseManager(String jdbcUrl) {
        this(jdbcUrl, CryptoUtils::verifyPasswordModular, pw -> CryptoUtils.hashPasswordModular(pw), new AuditKeyStore(), System::currentTimeMillis);
    }

    public DatabaseManager(String jdbcUrl, PasswordVerifier passwordVerifier) {
        this(jdbcUrl, passwordVerifier, pw -> CryptoUtils.hashPasswordModular(pw), new AuditKeyStore(), System::currentTimeMillis);
    }

    public DatabaseManager(String jdbcUrl, AuditKeyStore auditKeyStore) {
        this(jdbcUrl, CryptoUtils::verifyPasswordModular, pw -> CryptoUtils.hashPasswordModular(pw), auditKeyStore, System::currentTimeMillis);
    }

    public DatabaseManager(String jdbcUrl, AuditKeyStore auditKeyStore, LongSupplier clockMillis) {
        this(jdbcUrl, CryptoUtils::verifyPasswordModular, pw -> CryptoUtils.hashPasswordModular(pw), auditKeyStore, clockMillis);
    }

    public DatabaseManager(String jdbcUrl, PasswordVerifier passwordVerifier, LongSupplier clockMillis) {
        this(jdbcUrl, passwordVerifier, pw -> CryptoUtils.hashPasswordModular(pw), new AuditKeyStore(), clockMillis);
    }

    public DatabaseManager(String jdbcUrl, PasswordVerifier passwordVerifier, PasswordHasher passwordHasher, LongSupplier clockMillis) {
        this(jdbcUrl, passwordVerifier, passwordHasher, new AuditKeyStore(), clockMillis, null);
    }

    public DatabaseManager(String jdbcUrl, PasswordVerifier passwordVerifier, PasswordHasher passwordHasher, AuditKeyStore auditKeyStore, LongSupplier clockMillis) {
        this(jdbcUrl, passwordVerifier, passwordHasher, auditKeyStore, clockMillis, null);
    }

    public DatabaseManager(String jdbcUrl, PasswordVerifier passwordVerifier, PasswordHasher passwordHasher, AuditKeyStore auditKeyStore, LongSupplier clockMillis, ScheduledExecutorService headFlushScheduler) {
        if (jdbcUrl == null || jdbcUrl.trim().isEmpty()) {
            this.jdbcUrl = DEFAULT_DB_URL;
        } else if (jdbcUrl.startsWith("jdbc:sqlite:")) {
            this.jdbcUrl = jdbcUrl.trim();
        } else {
            this.jdbcUrl = "jdbc:sqlite:" + jdbcUrl.trim();
        }
        this.passwordVerifier = (passwordVerifier != null) ? passwordVerifier : CryptoUtils::verifyPasswordModular;
        this.passwordHasher = (passwordHasher != null) ? passwordHasher : (pw -> CryptoUtils.hashPasswordModular(pw));
        this.auditKeyStore = (auditKeyStore != null) ? auditKeyStore : new AuditKeyStore();
        this.clockMillis = (clockMillis != null) ? clockMillis : System::currentTimeMillis;
        this.lastHeadWriteMs = this.clockMillis.getAsLong();

        if (headFlushScheduler != null) {
            this.headFlushScheduler = headFlushScheduler;
            this.ownsScheduler = false;
        } else {
            this.headFlushScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "audit-head-flusher");
                t.setDaemon(true);
                return t;
            });
            this.ownsScheduler = true;
        }
        this.headFlushScheduler.scheduleWithFixedDelay(this::flushHeadIfDirty, 5, 5, TimeUnit.SECONDS);

        initConnection();
        initializeSchema();
        neutralizeLegacyDemoCredentials();
        purgeOldAuthFailures();
    }

    private synchronized void initConnection() {
        try {
            // Explicitly load SQLite JDBC driver
            Class.forName("org.sqlite.JDBC");
            this.connection = DriverManager.getConnection(this.jdbcUrl);
            try (Statement stmt = this.connection.createStatement()) {
                stmt.execute("PRAGMA foreign_keys = ON;");
                if (!jdbcUrl.contains(":memory:")) {
                    stmt.execute("PRAGMA journal_mode = WAL;");
                    stmt.execute("PRAGMA busy_timeout = 5000;");
                    stmt.execute("PRAGMA synchronous = NORMAL;");
                }
            }
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("SQLite JDBC driver not found on classpath", e);
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to connect to SQLite database at " + jdbcUrl, e);
        }
    }

    /**
     * Initializes database tables and indexes if they do not exist.
     * Uses PRAGMA user_version to manage idempotent migrations.
     */
    public synchronized void initializeSchema() {
        try (Statement stmt = connection.createStatement()) {
            int currentVersion = 0;
            try (ResultSet rs = stmt.executeQuery("PRAGMA user_version;")) {
                if (rs.next()) {
                    currentVersion = rs.getInt(1);
                }
            }

            if (currentVersion < 1) {
                stmt.execute("""
                        CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                            password_salt TEXT NOT NULL,
                            password_hash TEXT NOT NULL,
                            department TEXT NOT NULL,
                            role TEXT NOT NULL,
                            is_active INTEGER NOT NULL DEFAULT 1,
                            created_at INTEGER NOT NULL
                        );
                        """);

                stmt.execute("""
                        CREATE TABLE IF NOT EXISTS audit_logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            event_type TEXT NOT NULL,
                            username TEXT,
                            department TEXT,
                            details TEXT,
                            ip_address TEXT,
                            timestamp INTEGER NOT NULL
                        );
                        """);

                stmt.execute("CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs (timestamp);");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs (username);");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs (event_type);");
                stmt.execute("PRAGMA user_version = 1;");
                currentVersion = 1;
            }

            if (currentVersion < 2) {
                stmt.execute("""
                        CREATE TABLE IF NOT EXISTS auth_failures (
                            username_lc TEXT NOT NULL,
                            ip TEXT NOT NULL,
                            fail_count INTEGER NOT NULL,
                            window_start_ms INTEGER NOT NULL,
                            lock_until_ms INTEGER NOT NULL,
                            lock_level INTEGER NOT NULL,
                            PRIMARY KEY (username_lc, ip)
                        );
                        """);

                stmt.execute("CREATE INDEX IF NOT EXISTS idx_auth_failures_user ON auth_failures (username_lc);");
                stmt.execute("CREATE INDEX IF NOT EXISTS idx_auth_failures_lock ON auth_failures (lock_until_ms);");
                stmt.execute("PRAGMA user_version = 2;");
                currentVersion = 2;
            }

            if (currentVersion < 3) {
                migrateToVersion3(stmt);
            }

            // Schema v4: Production session tracking, connection logs, user device limits, TOTP
            stmt.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        username TEXT NOT NULL COLLATE NOCASE,
                        virtual_ip TEXT NOT NULL,
                        department TEXT NOT NULL,
                        role TEXT NOT NULL,
                        client_ip TEXT,
                        created_at INTEGER NOT NULL,
                        last_active_at INTEGER NOT NULL,
                        status TEXT NOT NULL DEFAULT 'ACTIVE'
                    );
                    """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (username);");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions (status);");

            stmt.execute("""
                    CREATE TABLE IF NOT EXISTS connection_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL COLLATE NOCASE,
                        virtual_ip TEXT,
                        client_ip TEXT,
                        event_type TEXT NOT NULL,
                        details TEXT,
                        timestamp INTEGER NOT NULL
                    );
                    """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_conn_logs_user ON connection_logs (username);");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_conn_logs_time ON connection_logs (timestamp);");

            stmt.execute("""
                    CREATE TABLE IF NOT EXISTS user_devices (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL COLLATE NOCASE,
                        device_fingerprint TEXT NOT NULL,
                        device_name TEXT,
                        first_seen_at INTEGER NOT NULL,
                        last_seen_at INTEGER NOT NULL,
                        is_trusted INTEGER NOT NULL DEFAULT 1,
                        UNIQUE (username, device_fingerprint)
                    );
                    """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_user_devices_user ON user_devices (username);");

            stmt.execute("""
                    CREATE TABLE IF NOT EXISTS totp_secrets (
                        username TEXT PRIMARY KEY COLLATE NOCASE,
                        base32_secret TEXT NOT NULL,
                        is_enabled INTEGER NOT NULL DEFAULT 1,
                        created_at INTEGER NOT NULL,
                        last_used_window INTEGER DEFAULT -1
                    );
                    """);
            try {
                stmt.execute("ALTER TABLE totp_secrets ADD COLUMN last_used_window INTEGER DEFAULT -1;");
            } catch (SQLException ignored) {
                // Column already exists in upgraded schemas
            }

            stmt.execute("""
                    CREATE TABLE IF NOT EXISTS site_to_site_peers (
                        peer_id TEXT PRIMARY KEY,
                        peer_gateway_ip TEXT NOT NULL,
                        local_subnet TEXT NOT NULL,
                        remote_subnet TEXT NOT NULL,
                        secret_hash TEXT NOT NULL,
                        status TEXT NOT NULL,
                        last_keepalive INTEGER NOT NULL
                    );
                    """);

            stmt.execute("""
                    CREATE TABLE IF NOT EXISTS bandwidth_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        bytes_allowed INTEGER NOT NULL,
                        bytes_throttled INTEGER NOT NULL,
                        timestamp INTEGER NOT NULL
                    );
                    """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_bandwidth_user ON bandwidth_logs (username);");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_bandwidth_time ON bandwidth_logs (timestamp);");

            stmt.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        username TEXT,
                        message TEXT NOT NULL,
                        is_read INTEGER DEFAULT 0,
                        timestamp INTEGER NOT NULL
                    );
                    """);
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_alerts_read ON alerts (is_read, severity);");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts (timestamp);");
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to initialize database schema", e);
        }
    }

    private void migrateToVersion3(Statement stmt) throws SQLException {
        boolean oldAutoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        try {
            Set<String> existingCols = new HashSet<>();
            try (ResultSet rs = stmt.executeQuery("PRAGMA table_info(audit_logs);")) {
                while (rs.next()) {
                    existingCols.add(rs.getString("name").toLowerCase(Locale.ROOT));
                }
            }

            if (!existingCols.contains("seq")) {
                stmt.execute("ALTER TABLE audit_logs ADD COLUMN seq INTEGER;");
            }
            if (!existingCols.contains("ts_ms")) {
                stmt.execute("ALTER TABLE audit_logs ADD COLUMN ts_ms INTEGER;");
            }
            if (!existingCols.contains("actor")) {
                stmt.execute("ALTER TABLE audit_logs ADD COLUMN actor TEXT;");
            }
            if (!existingCols.contains("remote_ip")) {
                stmt.execute("ALTER TABLE audit_logs ADD COLUMN remote_ip TEXT;");
            }
            if (!existingCols.contains("prev_hash")) {
                stmt.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT;");
            }
            if (!existingCols.contains("row_hash")) {
                stmt.execute("ALTER TABLE audit_logs ADD COLUMN row_hash TEXT;");
            }
            stmt.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_seq ON audit_logs (seq);");

            long currentSeq = 1;
            String prevHash = "0000000000000000000000000000000000000000000000000000000000000000";

            try (ResultSet rs = stmt.executeQuery("SELECT MAX(seq), row_hash FROM audit_logs WHERE seq IS NOT NULL;")) {
                if (rs.next() && rs.getObject(1) != null) {
                    currentSeq = rs.getLong(1) + 1;
                    prevHash = rs.getString(2);
                }
            }

            boolean hasChainedRows = currentSeq > 1;
            byte[] auditKey = auditKeyStore.getOrCreateKey(hasChainedRows);
            if (auditKey == null) {
                throw new IllegalStateException("Audit key unavailable for migration");
            }

            List<LegacyAuditRow> legacyRows = new ArrayList<>();
            try (ResultSet rs = stmt.executeQuery("SELECT id, event_type, username, department, details, ip_address, timestamp FROM audit_logs WHERE seq IS NULL ORDER BY id ASC;")) {
                while (rs.next()) {
                    legacyRows.add(new LegacyAuditRow(
                            rs.getInt("id"),
                            rs.getString("event_type"),
                            rs.getString("username"),
                            rs.getString("department"),
                            rs.getString("details"),
                            rs.getString("ip_address"),
                            rs.getString("timestamp")
                    ));
                }
            }

            String updateSql = "UPDATE audit_logs SET seq = ?, ts_ms = ?, actor = ?, remote_ip = ?, prev_hash = ?, row_hash = ? WHERE id = ?";
            try (PreparedStatement updatePstmt = connection.prepareStatement(updateSql)) {
                for (LegacyAuditRow row : legacyRows) {
                    long tsMs = parseTimestampToMs(row.timestampStr);
                    String actor = "LEGACY";
                    String remoteIp = AuditSanitizer.sanitizeRemoteIp(row.ipAddress);
                    String eventType = AuditSanitizer.sanitizeEventType(row.eventType);
                    String username = AuditSanitizer.sanitizeField(row.username, 64);
                    String department = AuditSanitizer.sanitizeField(row.department, 32);
                    String details = AuditSanitizer.sanitizeField(row.details, 512);
                    String cleanActor = AuditSanitizer.sanitizeField(actor, 64);

                    String rowHash = CryptoUtils.computeRowHash(auditKey, prevHash, currentSeq, eventType, username, department, details, cleanActor, remoteIp, tsMs);

                    updatePstmt.setLong(1, currentSeq);
                    updatePstmt.setLong(2, tsMs);
                    updatePstmt.setString(3, cleanActor);
                    updatePstmt.setString(4, remoteIp);
                    updatePstmt.setString(5, prevHash);
                    updatePstmt.setString(6, rowHash);
                    updatePstmt.setInt(7, row.id);
                    updatePstmt.executeUpdate();

                    prevHash = rowHash;
                    currentSeq++;
                }
            }

            String genesisEvent = "AUDIT_CHAIN_GENESIS";
            String genesisUser = "SYSTEM";
            String genesisDept = "SYSTEM";
            String genesisDetails = "Migrated from schema v2; legacy rows sealed at migration";
            String genesisActor = "SYSTEM";
            String genesisIp = "local";
            long genesisTs = clockMillis.getAsLong();
            String genesisHash = CryptoUtils.computeRowHash(auditKey, prevHash, currentSeq, genesisEvent, genesisUser, genesisDept, genesisDetails, genesisActor, genesisIp, genesisTs);

            String genesisSql = "INSERT INTO audit_logs (seq, event_type, username, department, details, actor, remote_ip, ts_ms, prev_hash, row_hash, ip_address, timestamp) " +
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            try (PreparedStatement insertPstmt = connection.prepareStatement(genesisSql)) {
                insertPstmt.setLong(1, currentSeq);
                insertPstmt.setString(2, genesisEvent);
                insertPstmt.setString(3, genesisUser);
                insertPstmt.setString(4, genesisDept);
                insertPstmt.setString(5, genesisDetails);
                insertPstmt.setString(6, genesisActor);
                insertPstmt.setString(7, genesisIp);
                insertPstmt.setLong(8, genesisTs);
                insertPstmt.setString(9, prevHash);
                insertPstmt.setString(10, genesisHash);
                insertPstmt.setString(11, genesisIp);
                insertPstmt.setLong(12, genesisTs);
                insertPstmt.executeUpdate();
            }

            try {
                auditKeyStore.writeHead(currentSeq, genesisHash);
            } catch (IOException e) {
                LOGGER.warn("Failed to write audit head during migration: {}", e.getMessage());
            }

            stmt.execute("""
                    CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
                    BEFORE UPDATE ON audit_logs
                    BEGIN
                        SELECT RAISE(ABORT, 'audit log is append-only');
                    END;
                    """);

            stmt.execute("""
                    CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
                    BEFORE DELETE ON audit_logs
                    BEGIN
                        SELECT RAISE(ABORT, 'audit log is append-only');
                    END;
                    """);

            stmt.execute("PRAGMA user_version = 3;");
            connection.commit();
        } catch (Exception e) {
            connection.rollback();
            throw (e instanceof SQLException sqle) ? sqle : new SQLException(e);
        } finally {
            connection.setAutoCommit(oldAutoCommit);
        }
    }

    private long parseTimestampToMs(String tsStr) {
        if (tsStr == null || tsStr.isBlank()) {
            return 0L;
        }
        try {
            return Long.parseLong(tsStr.trim());
        } catch (NumberFormatException ignored) {}

        try {
            return java.time.Instant.parse(tsStr.trim()).toEpochMilli();
        } catch (Exception ignored) {}

        try {
            return java.time.LocalDateTime.parse(tsStr.trim(), java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
                    .toInstant(java.time.ZoneOffset.UTC).toEpochMilli();
        } catch (Exception ignored) {}

        return 0L;
    }

    public CompletableFuture<AuditVerifyResult> startBackgroundVerify() {
        return CompletableFuture.supplyAsync(this::verifyAuditChain, r -> {
            Thread t = new Thread(r, "audit-verify-startup");
            t.setDaemon(true);
            t.start();
        });
    }

    public synchronized void flushHeadIfDirty() {
        if (!dirtySinceLastHeadWrite || connection == null) {
            return;
        }
        try {
            if (connection.isClosed()) {
                return;
            }
            String selectTail = "SELECT seq, row_hash FROM audit_logs WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1";
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(selectTail)) {
                if (rs.next()) {
                    long tailSeq = rs.getLong("seq");
                    String tailHash = rs.getString("row_hash");
                    auditKeyStore.writeHead(tailSeq, tailHash);
                    dirtySinceLastHeadWrite = false;
                    rowsSinceLastHeadWrite = 0;
                    lastHeadWriteMs = clockMillis.getAsLong();
                }
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to flush audit head: {}", e.getMessage());
        }
    }

    public synchronized String currentAnchor() {
        flushHeadIfDirty();
        java.nio.file.Path headPath = auditKeyStore.getHeadFile();
        if (java.nio.file.Files.isRegularFile(headPath)) {
            try {
                return java.nio.file.Files.readString(headPath, java.nio.charset.StandardCharsets.UTF_8).trim();
            } catch (IOException ignored) {}
        }
        return "";
    }

    private synchronized void purgeOldAuthFailures() {
        long now = clockMillis.getAsLong();
        long cutoff = now - (24 * 60 * 60 * 1000L);
        String purgeSql = "DELETE FROM auth_failures WHERE lock_until_ms < ? AND window_start_ms < ?";
        try (PreparedStatement pstmt = connection.prepareStatement(purgeSql)) {
            pstmt.setLong(1, cutoff);
            pstmt.setLong(2, cutoff);
            pstmt.executeUpdate();
        } catch (SQLException ignored) {}
    }

    private synchronized void maybePruneAuthFailuresTable() {
        String countSql = "SELECT COUNT(*) FROM auth_failures";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(countSql)) {
            if (rs.next() && rs.getInt(1) > 100_000) {
                long now = clockMillis.getAsLong();
                try (PreparedStatement del = connection.prepareStatement("DELETE FROM auth_failures WHERE lock_until_ms < ?")) {
                    del.setLong(1, now);
                    del.executeUpdate();
                }
            }
        } catch (SQLException ignored) {}
    }

    /**
     * Detects and neutralizes any legacy demonstration accounts in the database by setting
     * {@code is_active = 0} and appending a security audit trail entry.
     *
     * @return count of newly neutralized legacy accounts
     */
    public synchronized int neutralizeLegacyDemoCredentials() {
        int neutralized = 0;
        String sql = "SELECT id, username, password_salt, password_hash, department FROM users WHERE is_active = 1";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                int id = rs.getInt("id");
                String uname = rs.getString("username");
                String hash = rs.getString("password_hash");
                String dept = rs.getString("department");

                boolean isLegacy = false;
                if (CryptoUtils.isMalformedHash(hash) || (hash != null && hash.startsWith("pbkdf2:sha256:65536:"))) {
                    isLegacy = true;
                }

                if (isLegacy) {
                    String updateSql = "UPDATE users SET is_active = 0 WHERE id = ?";
                    try (PreparedStatement updateStmt = connection.prepareStatement(updateSql)) {
                        updateStmt.setInt(1, id);
                        updateStmt.executeUpdate();
                    }
                    logAuditEvent("LEGACY_DEMO_CREDENTIAL_DISABLED", uname, dept,
                            "Neutralized legacy demonstration account with outdated credentials", "local");
                    neutralized++;
                }
            }
        } catch (SQLException e) {
            LOGGER.warn("Failed checking legacy credentials: {}", e.getMessage());
        }
        // Purge synthetic demo devices from previous test runs so hardware trust reflects authentic devices only
        try (Statement purgeStmt = connection.createStatement()) {
            purgeStmt.executeUpdate("DELETE FROM user_devices WHERE device_fingerprint LIKE 'DEV-FP-%' OR device_name LIKE '%ThinkPad%' OR device_name LIKE '%MacBook%' OR device_name LIKE '%Latitude%' OR device_name LIKE '%ThinkCentre%'");
        } catch (SQLException ignored) {}
        return neutralized;
    }

    /**
     * Returns the count of active Headquarters administrators.
     */
    public synchronized int countActiveHqAdmins() {
        String sql = "SELECT COUNT(*) FROM users WHERE is_active = 1 AND role = 'ADMIN' AND department = 'HEADQUARTERS'";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Failed to query active HQ admins count", e);
        }
        return 0;
    }

    /**
     * Checks if the specified user is the sole active Headquarters administrator.
     */
    public synchronized boolean isSoleActiveHqAdmin(String username) {
        if (username == null) return false;
        UserAccount target = getUserByUsername(username.trim());
        if (target == null || !target.active()) {
            return false;
        }
        if (target.role() != Role.ADMIN || target.department() != Department.HEADQUARTERS) {
            return false;
        }
        return countActiveHqAdmins() <= 1;
    }

    /**
     * Creates a new user account as an administrative action with audit logging.
     *
     * @param username   Unique username
     * @param password   Raw plaintext password char array
     * @param department Assigned department
     * @param role       Assigned role
     * @param actor      Admin initiating the creation
     * @return Created UserAccount
     */
    public UserAccount createUser(String username, char[] password, Department department, Role role, String actor) {
        Objects.requireNonNull(username, "Username cannot be null");
        Objects.requireNonNull(password, "Password cannot be null");
        Objects.requireNonNull(department, "Department cannot be null");
        Objects.requireNonNull(role, "Role cannot be null");

        UsernamePolicy.validateUsername(username);
        PasswordPolicy.validatePassword(password, username);

        // PBKDF2 hashing performed outside monitor!
        String hash = passwordHasher.hash(password);
        String salt = CryptoUtils.parseStoredHash(hash).saltB64();
        if (salt == null || salt.isBlank()) {
            salt = CryptoUtils.generateSalt();
        }

        synchronized (this) {
            boolean oldAutoCommit;
            try {
                oldAutoCommit = connection.getAutoCommit();
                connection.setAutoCommit(false);
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
            try {
                if (getUserByUsername(username.trim()) != null) {
                    throw new IllegalArgumentException("Username already exists: " + username);
                }

                long now = clockMillis.getAsLong();
                String sql = "INSERT INTO users (username, password_salt, password_hash, department, role, is_active, created_at) " +
                        "VALUES (?, ?, ?, ?, ?, 1, ?)";

                try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
                    pstmt.setString(1, username.trim());
                    pstmt.setString(2, salt);
                    pstmt.setString(3, hash);
                    pstmt.setString(4, department.name());
                    pstmt.setString(5, role.name());
                    pstmt.setLong(6, now);
                    pstmt.executeUpdate();
                }

                String actorClean = (actor == null || actor.isBlank()) ? "SYSTEM" : actor.trim();
                logAuditEventOrThrow("ADMIN_USER_CREATED", username.trim(), department.name(),
                        "role=" + role + "; department=" + department.name(), actorClean, "local");

                connection.commit();
                return getUserByUsername(username.trim());
            } catch (Exception e) {
                try { connection.rollback(); } catch (SQLException ignored) {}
                if (e instanceof AuditUnavailableException aue) throw aue;
                if (e instanceof RuntimeException re) throw re;
                throw new IllegalStateException("Failed to create user: " + e.getMessage(), e);
            } finally {
                try { connection.setAutoCommit(oldAutoCommit); } catch (SQLException ignored) {}
            }
        }
    }

    /**
     * Resets a user's password as an administrative action.
     *
     * @param username    Target username
     * @param newPassword New password char array
     * @param actor       Admin performing the reset
     * @return True if reset successfully
     */
    public boolean resetPassword(String username, char[] newPassword, String actor) {
        Objects.requireNonNull(username, "Username cannot be null");
        Objects.requireNonNull(newPassword, "New password cannot be null");

        PasswordPolicy.validatePassword(newPassword, username);

        UserAccount existing = getUserByUsername(username.trim());
        if (existing == null) {
            throw new IllegalArgumentException("User not found: " + username);
        }

        // PBKDF2 hashing performed outside monitor!
        String hash = passwordHasher.hash(newPassword);
        String salt = CryptoUtils.parseStoredHash(hash).saltB64();
        if (salt == null || salt.isBlank()) {
            salt = CryptoUtils.generateSalt();
        }

        synchronized (this) {
            boolean oldAutoCommit;
            try {
                oldAutoCommit = connection.getAutoCommit();
                connection.setAutoCommit(false);
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
            try {
                UserAccount user = getUserByUsername(username.trim());
                if (user == null) {
                    throw new IllegalArgumentException("User not found: " + username);
                }

                String sql = "UPDATE users SET password_salt = ?, password_hash = ? WHERE username = ?";
                int updated;
                try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
                    pstmt.setString(1, salt);
                    pstmt.setString(2, hash);
                    pstmt.setString(3, username.trim());
                    updated = pstmt.executeUpdate();
                }

                if (updated > 0) {
                    String actorClean = (actor == null || actor.isBlank()) ? "SYSTEM" : actor.trim();
                    logAuditEventOrThrow("ADMIN_PASSWORD_RESET", username.trim(), user.department().name(),
                            "password reset", actorClean, "local");
                    connection.commit();
                    return true;
                }
                connection.rollback();
                return false;
            } catch (Exception e) {
                try { connection.rollback(); } catch (SQLException ignored) {}
                if (e instanceof AuditUnavailableException aue) throw aue;
                if (e instanceof RuntimeException re) throw re;
                throw new IllegalStateException("Failed to reset password: " + e.getMessage(), e);
            } finally {
                try { connection.setAutoCommit(oldAutoCommit); } catch (SQLException ignored) {}
            }
        }
    }

    /**
     * Changes a user's role with last-admin guard verification.
     *
     * @param username Target username
     * @param newRole  New role
     * @param actor    Admin performing the change
     * @return True if updated successfully
     */
    public synchronized boolean changeRole(String username, Role newRole, String actor) {
        Objects.requireNonNull(username, "Username cannot be null");
        Objects.requireNonNull(newRole, "New role cannot be null");

        UserAccount user = getUserByUsername(username.trim());
        if (user == null) {
            throw new IllegalArgumentException("User not found: " + username);
        }

        if (user.role() == newRole) {
            return true;
        }

        String actorClean = (actor == null || actor.isBlank()) ? "SYSTEM" : actor.trim();

        if (user.role() == Role.ADMIN && newRole != Role.ADMIN) {
            if (actorClean.equalsIgnoreCase(username.trim())) {
                throw new IllegalStateException("Administrator cannot self-demote role");
            }
            if (isSoleActiveHqAdmin(username)) {
                throw new IllegalStateException("Cannot demote the sole active Headquarters administrator");
            }
        }

        boolean oldAutoCommit;
        try {
            oldAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        try {
            String sql = "UPDATE users SET role = ? WHERE username = ?";
            int updated;
            try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
                pstmt.setString(1, newRole.name());
                pstmt.setString(2, username.trim());
                updated = pstmt.executeUpdate();
            }
            if (updated > 0) {
                logAuditEventOrThrow("ADMIN_ROLE_CHANGED", username.trim(), user.department().name(),
                        "oldRole=" + user.role() + "; newRole=" + newRole, actorClean, "local");
                connection.commit();
                return true;
            }
            connection.rollback();
            return false;
        } catch (Exception e) {
            try { connection.rollback(); } catch (SQLException ignored) {}
            if (e instanceof AuditUnavailableException aue) throw aue;
            if (e instanceof RuntimeException re) throw re;
            throw new IllegalStateException("Failed to change user role: " + e.getMessage(), e);
        } finally {
            try { connection.setAutoCommit(oldAutoCommit); } catch (SQLException ignored) {}
        }
    }

    /**
     * Changes a user's department with last-admin guard verification.
     *
     * @param username Target username
     * @param newDept  New department
     * @param actor    Admin performing the change
     * @return True if updated successfully
     */
    public synchronized boolean changeDepartment(String username, Department newDept, String actor) {
        Objects.requireNonNull(username, "Username cannot be null");
        Objects.requireNonNull(newDept, "New department cannot be null");

        UserAccount user = getUserByUsername(username.trim());
        if (user == null) {
            throw new IllegalArgumentException("User not found: " + username);
        }

        if (user.department() == newDept) {
            return true;
        }

        String actorClean = (actor == null || actor.isBlank()) ? "SYSTEM" : actor.trim();

        if (user.role() == Role.ADMIN && user.department() == Department.HEADQUARTERS && newDept != Department.HEADQUARTERS) {
            if (actorClean.equalsIgnoreCase(username.trim())) {
                throw new IllegalStateException("Administrator cannot change their own department away from Headquarters");
            }
            if (isSoleActiveHqAdmin(username)) {
                throw new IllegalStateException("Cannot change department of the sole active Headquarters administrator");
            }
        }

        boolean oldAutoCommit;
        try {
            oldAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        try {
            String sql = "UPDATE users SET department = ? WHERE username = ?";
            int updated;
            try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
                pstmt.setString(1, newDept.name());
                pstmt.setString(2, username.trim());
                updated = pstmt.executeUpdate();
            }
            if (updated > 0) {
                logAuditEventOrThrow("ADMIN_DEPARTMENT_CHANGED", username.trim(), newDept.name(),
                        "oldDept=" + user.department() + "; newDept=" + newDept, actorClean, "local");
                connection.commit();
                return true;
            }
            connection.rollback();
            return false;
        } catch (Exception e) {
            try { connection.rollback(); } catch (SQLException ignored) {}
            if (e instanceof AuditUnavailableException aue) throw aue;
            if (e instanceof RuntimeException re) throw re;
            throw new IllegalStateException("Failed to change user department: " + e.getMessage(), e);
        } finally {
            try { connection.setAutoCommit(oldAutoCommit); } catch (SQLException ignored) {}
        }
    }

    /**
     * Enables or disables a user account with last-admin and self-disable guard verification.
     *
     * @param username Target username
     * @param active   True for active, false for disabled
     * @param actor    Admin performing the status change
     * @return True if status updated successfully
     */
    public synchronized boolean setUserActiveStatus(String username, boolean active, String actor) {
        Objects.requireNonNull(username, "Username cannot be null");

        UserAccount user = getUserByUsername(username.trim());
        if (user == null) {
            throw new IllegalArgumentException("User not found: " + username);
        }

        if (user.active() == active) {
            return true;
        }

        String actorClean = (actor == null || actor.isBlank()) ? "SYSTEM" : actor.trim();

        if (!active) {
            if (actorClean.equalsIgnoreCase(username.trim())) {
                throw new IllegalStateException("Administrator cannot disable their own account");
            }
            if (isSoleActiveHqAdmin(username)) {
                throw new IllegalStateException("Cannot disable the sole active Headquarters administrator");
            }
        }

        boolean oldAutoCommit;
        try {
            oldAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        try {
            String sql = "UPDATE users SET is_active = ? WHERE username = ?";
            int updated;
            try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
                pstmt.setInt(1, active ? 1 : 0);
                pstmt.setString(2, username.trim());
                updated = pstmt.executeUpdate();
            }
            if (updated > 0) {
                logAuditEventOrThrow("ADMIN_USER_STATUS_CHANGED", username.trim(), user.department().name(),
                        "active=" + active, actorClean, "local");
                connection.commit();
                return true;
            }
            connection.rollback();
            return false;
        } catch (Exception e) {
            try { connection.rollback(); } catch (SQLException ignored) {}
            if (e instanceof AuditUnavailableException aue) throw aue;
            if (e instanceof RuntimeException re) throw re;
            throw new IllegalStateException("Failed to update user active status: " + e.getMessage(), e);
        } finally {
            try { connection.setAutoCommit(oldAutoCommit); } catch (SQLException ignored) {}
        }
    }

    /**
     * Soft-deletes a user account by deactivating it (is_active = 0) with last-admin guard verification.
     *
     * @param username Target username
     * @param actor    Admin performing the deletion
     * @return True if deleted/deactivated successfully
     */
    public synchronized boolean deleteUser(String username, String actor) {
        Objects.requireNonNull(username, "Username cannot be null");

        UserAccount user = getUserByUsername(username.trim());
        if (user == null) {
            throw new IllegalArgumentException("User not found: " + username);
        }

        String actorClean = (actor == null || actor.isBlank()) ? "SYSTEM" : actor.trim();

        if (actorClean.equalsIgnoreCase(username.trim())) {
            throw new IllegalStateException("Administrator cannot delete their own account");
        }
        if (isSoleActiveHqAdmin(username)) {
            throw new IllegalStateException("Cannot delete the sole active Headquarters administrator");
        }

        boolean oldAutoCommit;
        try {
            oldAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        try {
            String sql = "UPDATE users SET is_active = 0 WHERE username = ?";
            int updated;
            try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
                pstmt.setString(1, username.trim());
                updated = pstmt.executeUpdate();
            }
            if (updated > 0) {
                logAuditEventOrThrow("USER_DELETED", username.trim(), user.department().name(),
                        "soft deleted", actorClean, "local");
                connection.commit();
                return true;
            }
            connection.rollback();
            return false;
        } catch (Exception e) {
            try { connection.rollback(); } catch (SQLException ignored) {}
            if (e instanceof AuditUnavailableException aue) throw aue;
            if (e instanceof RuntimeException re) throw re;
            throw new IllegalStateException("Failed to delete user: " + e.getMessage(), e);
        } finally {
            try { connection.setAutoCommit(oldAutoCommit); } catch (SQLException ignored) {}
        }
    }

    private synchronized UserRowSnapshot fetchUserSnapshot(String username) {
        String sql = "SELECT id, username, password_salt, password_hash, department, role, is_active, created_at " +
                "FROM users WHERE username = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new UserRowSnapshot(
                            rs.getInt("id"),
                            rs.getString("username"),
                            rs.getString("password_salt"),
                            rs.getString("password_hash"),
                            Department.valueOf(rs.getString("department")),
                            Role.valueOf(rs.getString("role")),
                            rs.getInt("is_active") == 1,
                            rs.getLong("created_at")
                    );
                }
            }
        } catch (SQLException ignored) {}
        return null;
    }

    /**
     * Authenticates a user candidate.
     * <p>
     * <b>Non-Blocking Architecture:</b> This method does NOT hold the database monitor during
     * PBKDF2 hash computation. A short synchronized section fetches an immutable snapshot of user state,
     * verification executes outside any lock, and a final short synchronized section performs
     * lockout bookkeeping, audit logging, and opportunistic hash upgrades.
     *
     * @param username    Username
     * @param rawPassword Plaintext password candidate char array
     * @param ipAddress   Client host IP address
     * @return Authenticated {@link UserAccount} if successful; {@code null} on bad credentials, inactive, or locked account
     */
    public UserAccount authenticateUser(String username, char[] rawPassword, String ipAddress) {
        return authenticateUser(username, rawPassword, null, ipAddress);
    }

    public UserAccount authenticateUser(String username, char[] rawPassword, String totpCode, String ipAddress) {
        String cleanIp = (ipAddress != null && !ipAddress.isBlank()) ? ipAddress.trim() : "UNKNOWN";

        // Pre-validation: Input format rejected BEFORE any database access
        if (username == null || !UsernamePolicy.isValid(username)
                || rawPassword == null || rawPassword.length == 0 || rawPassword.length > 1024) {
            String sanitizedUser = AuditSanitizer.sanitize(username, 64);
            logAuditEvent("AUTH_INVALID_INPUT", sanitizedUser, "UNKNOWN", "Invalid username or password format", cleanIp);
            return null;
        }

        String usernameClean = username.trim();
        String usernameLc = usernameClean.toLowerCase(Locale.ROOT);
        long now = clockMillis.getAsLong();

        UserRowSnapshot snapshot;
        boolean isLocked = false;
        boolean shouldAuditLockout = false;

        // Step 1: Read row snapshot inside synchronized section
        synchronized (this) {
            String lockSql = "SELECT fail_count, window_start_ms, lock_until_ms, lock_level FROM auth_failures WHERE username_lc = ? AND ip = ?";
            try (PreparedStatement pstmt = connection.prepareStatement(lockSql)) {
                pstmt.setString(1, usernameLc);
                pstmt.setString(2, cleanIp);
                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        long lockUntil = rs.getLong("lock_until_ms");
                        if (now < lockUntil) {
                            isLocked = true;
                            String auditKey = usernameLc + "@" + cleanIp;
                            Long lastAudit = lastLockoutAuditTimes.get(auditKey);
                            if (lastAudit == null || now - lastAudit >= 60_000L) {
                                shouldAuditLockout = true;
                                lastLockoutAuditTimes.put(auditKey, now);
                            }
                        }
                    }
                }
            } catch (SQLException e) {
                LOGGER.error("Database failure reading lockout status for user {}: {}", usernameLc, e.getMessage());
                isLocked = true; // Fail-closed on database error
            }

            snapshot = fetchUserSnapshot(usernameClean);
        }

        // Step 2: Verification OUTSIDE any lock!
        boolean verified = false;
        boolean hashCorrupt = false;

        if (snapshot == null || !snapshot.isActive() || isLocked) {
            // Uniform timing: burn one dummy verification call
            passwordVerifier.verify(rawPassword, CryptoUtils.getDummyHash(), null);
            verified = false;
        } else {
            if (CryptoUtils.isMalformedHash(snapshot.hash())) {
                passwordVerifier.verify(rawPassword, CryptoUtils.getDummyHash(), null);
                hashCorrupt = true;
                verified = false;
            } else {
                verified = passwordVerifier.verify(rawPassword, snapshot.hash(), snapshot.salt());
            }
        }

        // Opportunistic hash upgrade computation OUTSIDE monitor!
        String upgradedHash = null;
        if (verified && snapshot != null) {
            boolean needsUpgrade = false;
            String oldHash = snapshot.hash();
            if (!oldHash.startsWith("pbkdf2-sha256$")) {
                needsUpgrade = true;
            } else {
                CryptoUtils.ParsedPasswordHash parsed = CryptoUtils.parseStoredHash(oldHash);
                if (!parsed.malformed() && parsed.iterations() < CryptoUtils.getEffectiveDefaultIterations()) {
                    needsUpgrade = true;
                }
            }
            if (needsUpgrade) {
                try {
                    upgradedHash = passwordHasher.hash(rawPassword);
                } catch (Exception ignored) {}
            }
        }

        // Step 3: Bookkeeping & audit inside synchronized section
        synchronized (this) {
            if (isLocked) {
                if (shouldAuditLockout) {
                    logAuditEvent("AUTH_LOCKOUT_BLOCKED",
                            (snapshot != null) ? snapshot.canonicalUsername() : AuditSanitizer.sanitize(usernameClean, 64),
                            (snapshot != null) ? snapshot.department().name() : "UNKNOWN",
                            "Authentication attempt blocked due to active IP lockout",
                            cleanIp);
                }
                return null;
            }

            if (hashCorrupt) {
                logAuditEvent("AUTH_HASH_CORRUPT", snapshot.canonicalUsername(), snapshot.department().name(),
                        "Corrupted or malformed password hash detected in storage", cleanIp);
                recordAuthFailure(usernameLc, cleanIp, now);
                return null;
            }

            if (snapshot == null) {
                recordAuthFailure(usernameLc, cleanIp, now);
                logAuditEvent("AUTH_FAILURE", AuditSanitizer.sanitize(usernameClean, 64), "UNKNOWN",
                        "Authentication failed: invalid credentials or account disabled", cleanIp);
                return null;
            }

            if (!snapshot.isActive()) {
                recordAuthFailure(usernameLc, cleanIp, now);
                logAuditEvent("AUTH_FAILURE", snapshot.canonicalUsername(), snapshot.department().name(),
                        "Authentication failed: invalid credentials or account disabled", cleanIp);
                return null;
            }

            if (!verified) {
                recordAuthFailure(usernameLc, cleanIp, now);
                logAuditEvent("AUTH_FAILURE", snapshot.canonicalUsername(), snapshot.department().name(),
                        "Invalid password attempt", cleanIp);
                return null;
            }

            // Enforce Multi-Factor Authentication (TOTP) atomically if enabled
            if (isTotpEnabled(snapshot.canonicalUsername())) {
                if (totpCode == null || !verifyAndConsumeTotpCode(snapshot.canonicalUsername(), totpCode)) {
                    recordAuthFailure(usernameLc, cleanIp, now);
                    logAuditEvent("AUTH_TOTP_FAILED", snapshot.canonicalUsername(), snapshot.department().name(),
                            "Two-factor authentication failed or time step replayed", cleanIp);
                    return null;
                }
            }

            // Success! Only reset failures when BOTH password and TOTP succeed
            resetAuthFailures(usernameLc, cleanIp);
            logAuditEventOrThrow("AUTH_SUCCESS", snapshot.canonicalUsername(), snapshot.department().name(),
                    "Successful authentication as " + snapshot.role(), snapshot.canonicalUsername(), cleanIp);

            // Upgrade-on-login CAS (fast DB update only, hashing computed in Step 2)
            if (upgradedHash != null) {
                applyUpgradedHash(snapshot.canonicalUsername(), snapshot.hash(), upgradedHash);
            }

            return new UserAccount(
                    snapshot.id(),
                    snapshot.canonicalUsername(),
                    snapshot.salt(),
                    snapshot.hash(),
                    snapshot.department(),
                    snapshot.role(),
                    snapshot.isActive(),
                    snapshot.createdAt()
            );
        }
    }

    public synchronized void recordAuthFailure(String username, String ip) {
        if (username == null) return;
        String cleanIp = (ip != null && !ip.isBlank()) ? ip.trim() : "UNKNOWN";
        recordAuthFailure(username.trim().toLowerCase(Locale.ROOT), cleanIp, clockMillis.getAsLong());
    }

    private synchronized void recordAuthFailure(String usernameLc, String ip, long now) {
        long fifteenMinutes = 15 * 60 * 1000L;
        String selectSql = "SELECT fail_count, window_start_ms, lock_until_ms, lock_level FROM auth_failures WHERE username_lc = ? AND ip = ?";
        int failCount = 0;
        long windowStart = now;
        int lockLevel = 0;
        long lockUntil = 0;
        boolean rowExists = false;

        try (PreparedStatement pstmt = connection.prepareStatement(selectSql)) {
            pstmt.setString(1, usernameLc);
            pstmt.setString(2, ip);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    rowExists = true;
                    failCount = rs.getInt("fail_count");
                    windowStart = rs.getLong("window_start_ms");
                    lockLevel = rs.getInt("lock_level");
                    lockUntil = rs.getLong("lock_until_ms");
                }
            }
        } catch (SQLException ignored) {}

        if (!rowExists || (now - windowStart > fifteenMinutes && now >= lockUntil)) {
            failCount = 1;
            windowStart = now;
            lockUntil = 0;
        } else {
            failCount++;
        }

        // Lock trigger: 5 failures within 15 min
        if (failCount >= 5 && now >= lockUntil) {
            lockLevel = Math.min(lockLevel + 1, 3);
            long lockDuration;
            if (lockLevel == 1) {
                lockDuration = 15 * 60 * 1000L;
            } else if (lockLevel == 2) {
                lockDuration = 30 * 60 * 1000L;
            } else {
                lockDuration = 60 * 60 * 1000L;
            }
            lockUntil = now + lockDuration;
        }

        String upsertSql = """
                INSERT INTO auth_failures (username_lc, ip, fail_count, window_start_ms, lock_until_ms, lock_level)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(username_lc, ip) DO UPDATE SET
                    fail_count = excluded.fail_count,
                    window_start_ms = excluded.window_start_ms,
                    lock_until_ms = excluded.lock_until_ms,
                    lock_level = excluded.lock_level;
                """;
        try (PreparedStatement upsert = connection.prepareStatement(upsertSql)) {
            upsert.setString(1, usernameLc);
            upsert.setString(2, ip);
            upsert.setInt(3, failCount);
            upsert.setLong(4, windowStart);
            upsert.setLong(5, lockUntil);
            upsert.setInt(6, lockLevel);
            upsert.executeUpdate();
        } catch (SQLException ignored) {}

        // Check cross-IP distributed attack detection
        String sumSql = "SELECT SUM(fail_count) FROM auth_failures WHERE username_lc = ? AND window_start_ms >= ?";
        try (PreparedStatement sumStmt = connection.prepareStatement(sumSql)) {
            sumStmt.setString(1, usernameLc);
            sumStmt.setLong(2, now - fifteenMinutes);
            try (ResultSet rs = sumStmt.executeQuery()) {
                if (rs.next()) {
                    int totalFailures = rs.getInt(1);
                    if (totalFailures > 20) {
                        Long lastAttackLog = lastAttackAuditTimes.get(usernameLc);
                        if (lastAttackLog == null || now - lastAttackLog >= 60_000L) {
                            lastAttackAuditTimes.put(usernameLc, now);
                            logAuditEvent("AUTH_USERNAME_UNDER_ATTACK", usernameLc, "UNKNOWN",
                                    "Distributed brute force detected across multiple IPs (" + totalFailures + " failures in 15m)", ip);
                        }
                    }
                }
            }
        } catch (SQLException ignored) {}

        maybePruneAuthFailuresTable();
    }

    private synchronized void resetAuthFailures(String usernameLc, String ip) {
        String delSql = "DELETE FROM auth_failures WHERE username_lc = ? AND ip = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(delSql)) {
            pstmt.setString(1, usernameLc);
            pstmt.setString(2, ip);
            pstmt.executeUpdate();
        } catch (SQLException ignored) {}
    }



    private synchronized void applyUpgradedHash(String username, String oldHash, String newHash) {
        String updateSql = "UPDATE users SET password_hash = ? WHERE username = ? AND password_hash = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(updateSql)) {
            pstmt.setString(1, newHash);
            pstmt.setString(2, username);
            pstmt.setString(3, oldHash);
            int updated = pstmt.executeUpdate();
            if (updated > 0) {
                logAuditEvent("PASSWORD_HASH_UPGRADED", username, "UNKNOWN",
                        "Password hash upgraded to latest security parameters", "local");
            }
        } catch (SQLException ignored) {}
    }

    public synchronized boolean unlockAccount(String username, String actor) {
        if (username == null || username.isBlank()) {
            return false;
        }
        String usernameClean = username.trim();
        String usernameLc = usernameClean.toLowerCase(Locale.ROOT);

        boolean oldAutoCommit;
        try {
            oldAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
        try {
            lastLockoutAuditTimes.keySet().removeIf(k -> k.startsWith(usernameLc + "@"));
            String sql = "DELETE FROM auth_failures WHERE username_lc = ?";
            int rows;
            try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
                pstmt.setString(1, usernameLc);
                rows = pstmt.executeUpdate();
            }

            String actorClean = (actor != null && !actor.isBlank()) ? actor.trim() : "ADMIN";
            logAuditEventOrThrow("ADMIN_UNLOCK_ACCOUNT", usernameClean, "NONE",
                    "cleared account lockouts (" + rows + " entries removed)", actorClean, "local");
            connection.commit();
            return true;
        } catch (Exception e) {
            try { connection.rollback(); } catch (SQLException ignored) {}
            if (e instanceof AuditUnavailableException aue) throw aue;
            if (e instanceof RuntimeException re) throw re;
            throw new IllegalStateException("Failed to unlock account: " + e.getMessage(), e);
        } finally {
            try { connection.setAutoCommit(oldAutoCommit); } catch (SQLException ignored) {}
        }
    }



    /**
     * Retrieves user record by username.
     *
     * @param username Username to query
     * @return UserAccount or null if not found
     */
    public synchronized UserAccount getUserByUsername(String username) {
        if (username == null) return null;
        String sql = "SELECT id, username, password_salt, password_hash, department, role, is_active, created_at " +
                "FROM users WHERE username = ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, username.trim());
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new UserAccount(
                            rs.getInt("id"),
                            rs.getString("username"),
                            rs.getString("password_salt"),
                            rs.getString("password_hash"),
                            Department.valueOf(rs.getString("department")),
                            Role.valueOf(rs.getString("role")),
                            rs.getInt("is_active") == 1,
                            rs.getLong("created_at")
                    );
                }
            }
        } catch (SQLException e) {
            // Return null on lookup failure
        }
        return null;
    }

    /**
     * Retrieves all registered user accounts ordered by database ID ascending.
     * Used by the Headquarters Server Admin controller for user management.
     *
     * @return List of all UserAccount records
     */
    public synchronized List<UserAccount> listAllUsers() {
        List<UserAccount> users = new ArrayList<>();
        String sql = "SELECT id, username, password_salt, password_hash, department, role, is_active, created_at " +
                "FROM users ORDER BY id ASC";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                users.add(new UserAccount(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("password_salt"),
                        rs.getString("password_hash"),
                        Department.valueOf(rs.getString("department")),
                        Role.valueOf(rs.getString("role")),
                        rs.getInt("is_active") == 1,
                        rs.getLong("created_at")
                ));
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to list all users: {}", e.getMessage());
        }
        return users;
    }

    private volatile boolean forceAuditFailure = false;

    // Test seam
    public void setForceAuditFailure(boolean forceAuditFailure) {
        this.forceAuditFailure = forceAuditFailure;
    }

    /**
     * Appends an audit event to the hash chain and database, throwing AuditUnavailableException if unavailable.
     */
    public synchronized void logAuditEventOrThrow(
            String eventType,
            String username,
            String department,
            String details,
            String actor,
            String remoteIp
    ) throws AuditUnavailableException {
        if (forceAuditFailure) {
            throw new AuditUnavailableException("Forced audit failure for testing");
        }
        try {
            if (connection == null || connection.isClosed()) {
                throw new AuditUnavailableException("Database connection is closed");
            }
        } catch (SQLException e) {
            throw new AuditUnavailableException("Database connection error", e);
        }

        byte[] auditKey = auditKeyStore.getKey();
        if (auditKey == null) {
            long chainedCount = 0;
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM audit_logs WHERE seq IS NOT NULL;")) {
                if (rs.next()) {
                    chainedCount = rs.getLong(1);
                }
            } catch (SQLException ignored) {
                // Table might be freshly created
            }

            auditKey = auditKeyStore.getOrCreateKey(chainedCount > 0);
            if (auditKey == null) {
                throw new AuditUnavailableException("Audit logging unavailable: audit.key is missing for existing chain");
            }
        }

        long now = clockMillis.getAsLong();
        String cleanEventType = AuditSanitizer.sanitizeEventType(eventType);
        String cleanUsername = AuditSanitizer.sanitizeField(username, 64);
        String cleanDept = AuditSanitizer.sanitizeField(department, 32);
        String cleanDetails = AuditSanitizer.sanitizeField(details, 512);
        String cleanActor = AuditSanitizer.sanitizeField(actor, 64);
        String cleanRemoteIp = AuditSanitizer.sanitizeRemoteIp(remoteIp);

        // Capacity check
        checkAuditCapacity(now);

        long nextSeq = 1;
        String prevHash = "0000000000000000000000000000000000000000000000000000000000000000";

        String selectTail = "SELECT seq, row_hash FROM audit_logs WHERE seq IS NOT NULL ORDER BY seq DESC LIMIT 1";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(selectTail)) {
            if (rs.next()) {
                nextSeq = rs.getLong("seq") + 1;
                prevHash = rs.getString("row_hash");
            }
        } catch (SQLException e) {
            throw new AuditUnavailableException("Failed to query audit chain tail", e);
        }

        String rowHash = CryptoUtils.computeRowHash(auditKey, prevHash, nextSeq, cleanEventType, cleanUsername, cleanDept, cleanDetails, cleanActor, cleanRemoteIp, now);

        String insertSql = "INSERT INTO audit_logs (seq, event_type, username, department, details, actor, remote_ip, ts_ms, prev_hash, row_hash, ip_address, timestamp) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = connection.prepareStatement(insertSql)) {
            pstmt.setLong(1, nextSeq);
            pstmt.setString(2, cleanEventType);
            pstmt.setString(3, cleanUsername);
            pstmt.setString(4, cleanDept);
            pstmt.setString(5, cleanDetails);
            pstmt.setString(6, cleanActor);
            pstmt.setString(7, cleanRemoteIp);
            pstmt.setLong(8, now);
            pstmt.setString(9, prevHash);
            pstmt.setString(10, rowHash);
            pstmt.setString(11, cleanRemoteIp);
            pstmt.setLong(12, now);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            throw new AuditUnavailableException("Failed to insert audit log row: " + e.getMessage(), e);
        }

        rowsSinceLastHeadWrite++;
        dirtySinceLastHeadWrite = true;
        if (rowsSinceLastHeadWrite >= 20 || (now - lastHeadWriteMs >= 5000L && dirtySinceLastHeadWrite)) {
            try {
                auditKeyStore.writeHead(nextSeq, rowHash);
                rowsSinceLastHeadWrite = 0;
                dirtySinceLastHeadWrite = false;
                lastHeadWriteMs = now;
            } catch (IOException e) {
                LOGGER.warn("Failed to write audit head: {}", e.getMessage());
            }
        }
    }

    private void checkAuditCapacity(long now) {
        if (capacityWarningEmitted) return;
        try {
            long count = 0;
            try (Statement st = connection.createStatement();
                 ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM audit_logs;")) {
                if (rs.next()) {
                    count = rs.getLong(1);
                }
            }
            if (count >= auditCapacityThreshold) {
                if (now - lastCapacityWarningMs >= 24 * 60 * 60 * 1000L) {
                    lastCapacityWarningMs = now;
                    capacityWarningEmitted = true;
                    try {
                        logAuditEventOrThrow("AUDIT_CAPACITY", "SYSTEM", "SYSTEM",
                                "Audit log row count " + count + " exceeds capacity threshold " + auditCapacityThreshold,
                                "SYSTEM", "local");
                    } finally {
                        capacityWarningEmitted = false;
                    }
                }
            }
        } catch (Exception ignored) {}
    }

    /**
     * Best-effort security audit event logger. Never throws.
     * Failed logs are counted and reported to System.err at most once per 60 seconds.
     */
    public void logAuditEvent(String eventType, String username, String department, String details, String ipAddress) {
        logAuditEvent(eventType, username, department, details, (username != null ? username : "SYSTEM"), ipAddress);
    }

    public void logAuditEvent(String eventType, String username, String department, String details, String actor, String ipAddress) {
        try {
            logAuditEventOrThrow(eventType, username, department, details, (actor != null ? actor : (username != null ? username : "SYSTEM")), ipAddress);
        } catch (Exception e) {
            bestEffortFailureCount.incrementAndGet();
            long now = clockMillis.getAsLong();
            synchronized (this) {
                if (now - lastBestEffortErrorLogMs >= 60_000L) {
                    lastBestEffortErrorLogMs = now;
                    LOGGER.error("Audit logging failed: {} (total failures: {})", e.getMessage(), bestEffortFailureCount.get());
                }
            }
        }
    }

    /**
     * Retrieves recent audit log entries in reverse chronological order.
     *
     * @param limit Maximum number of records to return
     * @return List of AuditLogEntry records
     */
    public synchronized List<AuditLogEntry> getRecentAuditLogs(int limit) {
        List<AuditLogEntry> list = new ArrayList<>();
        String sql = "SELECT id, seq, event_type, username, department, details, actor, remote_ip, timestamp " +
                "FROM audit_logs ORDER BY id DESC LIMIT ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setInt(1, Math.max(1, limit));
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    list.add(new AuditLogEntry(
                            rs.getInt("id"),
                            rs.getLong("seq"),
                            rs.getString("event_type"),
                            rs.getString("username"),
                            rs.getString("department"),
                            rs.getString("details"),
                            rs.getString("actor"),
                            rs.getString("remote_ip"),
                            rs.getLong("timestamp")
                    ));
                }
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to read audit logs: {}", e.getMessage());
        }
        return list;
    }

    private volatile Runnable verifyBatchProcessedHook = null;

    // Test seam
    public void setVerifyBatchProcessedHook(Runnable hook) {
        this.verifyBatchProcessedHook = hook;
    }

    /**
     * Verifies cryptographic integrity of the audit hash chain from genesis to tail.
     *
     * @return AuditVerifyResult indicating chain status, checked rows, and any broken sequence
     */
    public AuditVerifyResult verifyAuditChain() {
        byte[] auditKey = auditKeyStore.getKey();
        long chainedCount = 0;
        long maxSeq = 0;

        synchronized (this) {
            try {
                if (connection == null || connection.isClosed()) {
                    return new AuditVerifyResult(AuditVerifyResult.AuditStatus.SCHEMA_ERROR, 0, -1, "Database connection closed");
                }
                try (Statement stmt = connection.createStatement();
                     ResultSet rs = stmt.executeQuery("SELECT COUNT(*), MAX(seq) FROM audit_logs WHERE seq IS NOT NULL;")) {
                    if (rs.next()) {
                        chainedCount = rs.getLong(1);
                        maxSeq = rs.getLong(2);
                    }
                }
            } catch (SQLException e) {
                return new AuditVerifyResult(AuditVerifyResult.AuditStatus.SCHEMA_ERROR, 0, -1, "Failed to query audit schema: " + e.getMessage());
            }
        }

        if (chainedCount > 0 && auditKey == null) {
            return new AuditVerifyResult(AuditVerifyResult.AuditStatus.KEY_MISSING, 0, -1, "Audit key file is missing");
        }

        if (chainedCount == 0) {
            return new AuditVerifyResult(AuditVerifyResult.AuditStatus.OK, 0, -1, "Audit log is empty");
        }

        // Validate head file
        AuditKeyStore.AuditHead head = auditKeyStore.readHead();
        if (head != null) {
            if (!head.validHmac()) {
                return new AuditVerifyResult(AuditVerifyResult.AuditStatus.HASH_MISMATCH, 0, head.seq(), "Audit head file HMAC is invalid or tampered");
            }
            if (maxSeq < head.seq()) {
                return new AuditVerifyResult(AuditVerifyResult.AuditStatus.TRUNCATED, maxSeq, head.seq(),
                        "Audit log truncated: DB tail seq " + maxSeq + " < head file seq " + head.seq());
            }
        }

        long expectedSeq = 1;
        String expectedPrev = "0000000000000000000000000000000000000000000000000000000000000000";
        long rowsChecked = 0;
        long batchStartSeq = 1;

        while (batchStartSeq <= maxSeq) {
            List<AuditRowVerifyDto> batch = fetchVerifyBatch(batchStartSeq, 1000);
            if (batch.isEmpty()) {
                break;
            }

            Runnable hook = verifyBatchProcessedHook;
            if (hook != null) {
                hook.run();
            }

            for (AuditRowVerifyDto row : batch) {
                if (row.seq != expectedSeq) {
                    return new AuditVerifyResult(AuditVerifyResult.AuditStatus.SEQ_GAP, rowsChecked, expectedSeq,
                            "Sequence gap at seq " + row.seq + " (expected " + expectedSeq + ")");
                }
                if (!row.prevHash.equalsIgnoreCase(expectedPrev)) {
                    return new AuditVerifyResult(AuditVerifyResult.AuditStatus.PREV_MISMATCH, rowsChecked, row.seq,
                            "Previous hash mismatch at seq " + row.seq);
                }
                String computedHash = CryptoUtils.computeRowHash(auditKey, expectedPrev, row.seq,
                        row.eventType, row.username, row.department, row.details, row.actor, row.remoteIp, row.tsMs);
                if (!computedHash.equalsIgnoreCase(row.rowHash)) {
                    return new AuditVerifyResult(AuditVerifyResult.AuditStatus.HASH_MISMATCH, rowsChecked, row.seq,
                            "Row hash mismatch at seq " + row.seq);
                }
                expectedPrev = row.rowHash;
                expectedSeq++;
                rowsChecked++;
            }
            batchStartSeq += 1000;
        }

        return new AuditVerifyResult(AuditVerifyResult.AuditStatus.OK, rowsChecked, -1,
                "Audit hash chain verified successfully (" + rowsChecked + " rows)");
    }

    private synchronized List<AuditRowVerifyDto> fetchVerifyBatch(long startSeq, int limit) {
        List<AuditRowVerifyDto> batch = new ArrayList<>(limit);
        String sql = "SELECT seq, event_type, username, department, details, actor, remote_ip, ts_ms, prev_hash, row_hash " +
                "FROM audit_logs WHERE seq >= ? ORDER BY seq ASC LIMIT ?";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setLong(1, startSeq);
            pstmt.setInt(2, limit);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    batch.add(new AuditRowVerifyDto(
                            rs.getLong("seq"),
                            rs.getString("event_type"),
                            rs.getString("username"),
                            rs.getString("department"),
                            rs.getString("details"),
                            rs.getString("actor"),
                            rs.getString("remote_ip"),
                            rs.getLong("ts_ms"),
                            rs.getString("prev_hash"),
                            rs.getString("row_hash")
                    ));
                }
            }
        } catch (SQLException ignored) {}
        return batch;
    }

    // Test seam
    public void setAuditCapacityThreshold(long threshold) {
        this.auditCapacityThreshold = threshold;
    }

    // Test seam
    synchronized int getBusyTimeout() {
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA busy_timeout;")) {
            if (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            LOGGER.debug("Failed to read sequence value: {}", e.getMessage());
        }

        return -1;
    }

    // =========================================================================
    // PRODUCTION SESSION MANAGEMENT, CONNECTION LOGS & DEVICE TRACKING
    // =========================================================================

    public record SessionRecord(
            String sessionId,
            String username,
            String virtualIp,
            String department,
            String role,
            String clientIp,
            long createdAt,
            long lastActiveAt,
            String status
    ) {}

    /**
     * Records an active authenticated VPN session.
     */
    public synchronized void insertSession(String sessionId, String username, String virtualIp,
                                          String department, String role, String clientIp) {
        Objects.requireNonNull(sessionId, "sessionId cannot be null");
        Objects.requireNonNull(username, "username cannot be null");
        long now = clockMillis.getAsLong();
        String sql = "INSERT OR REPLACE INTO sessions (session_id, username, virtual_ip, department, role, client_ip, created_at, last_active_at, status) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, sessionId);
            ps.setString(2, username);
            ps.setString(3, virtualIp != null ? virtualIp : "");
            ps.setString(4, department != null ? department : "");
            ps.setString(5, role != null ? role : "");
            ps.setString(6, clientIp != null ? clientIp : "");
            ps.setLong(7, now);
            ps.setLong(8, now);
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to insert session {}: {}", sessionId, e.getMessage());
        }
    }

    /**
     * Updates the last active timestamp of an active session.
     */
    public synchronized void updateSessionActivity(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return;
        }
        long now = clockMillis.getAsLong();
        String sql = "UPDATE sessions SET last_active_at = ? WHERE session_id = ? AND status = 'ACTIVE'";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, now);
            ps.setString(2, sessionId);
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to update session activity for {}: {}", sessionId, e.getMessage());
        }
    }

    /**
     * Marks an active session as closed.
     */
    public synchronized void closeSession(String sessionId, String reason) {
        if (sessionId == null || sessionId.isBlank()) {
            return;
        }
        long now = clockMillis.getAsLong();
        String sql = "UPDATE sessions SET status = 'CLOSED', last_active_at = ? WHERE session_id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, now);
            ps.setString(2, sessionId);
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to close session {}: {}", sessionId, e.getMessage());
        }
    }

    /**
     * Retrieves an existing session record by its identifier.
     */
    public synchronized SessionRecord getSession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return null;
        }
        String sql = "SELECT session_id, username, virtual_ip, department, role, client_ip, created_at, last_active_at, status FROM sessions WHERE session_id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, sessionId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new SessionRecord(
                            rs.getString(1),
                            rs.getString(2),
                            rs.getString(3),
                            rs.getString(4),
                            rs.getString(5),
                            rs.getString(6),
                            rs.getLong(7),
                            rs.getLong(8),
                            rs.getString(9)
                    );
                }
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to retrieve session {}: {}", sessionId, e.getMessage());
        }
        return null;
    }

    /**
     * Returns a list of currently active sessions.
     */
    public synchronized List<SessionRecord> listActiveSessions() {
        List<SessionRecord> list = new ArrayList<>();
        String sql = "SELECT session_id, username, virtual_ip, department, role, client_ip, created_at, last_active_at, status FROM sessions WHERE status = 'ACTIVE'";
        try (PreparedStatement ps = connection.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                list.add(new SessionRecord(
                        rs.getString(1),
                        rs.getString(2),
                        rs.getString(3),
                        rs.getString(4),
                        rs.getString(5),
                        rs.getString(6),
                        rs.getLong(7),
                        rs.getLong(8),
                        rs.getString(9)
                ));
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to list active sessions: {}", e.getMessage());
        }
        return list;
    }

    /**
     * Appends an event to the connection_logs audit table.
     */
    public synchronized void logConnectionEvent(String username, String virtualIp, String clientIp, String eventType, String details) {
        Objects.requireNonNull(username, "username cannot be null");
        Objects.requireNonNull(eventType, "eventType cannot be null");
        long now = clockMillis.getAsLong();
        String sql = "INSERT INTO connection_logs (username, virtual_ip, client_ip, event_type, details, timestamp) "
                + "VALUES (?, ?, ?, ?, ?, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, virtualIp != null ? virtualIp : "");
            ps.setString(3, clientIp != null ? clientIp : "");
            ps.setString(4, eventType);
            ps.setString(5, details != null ? details : "");
            ps.setLong(6, now);
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to log connection event for {}: {}", username, e.getMessage());
        }
    }

    /**
     * Registers a device fingerprint for a user.
     *
     * @return true if device was registered or updated, false otherwise
     */
    public synchronized boolean registerDevice(String username, String deviceFingerprint, String deviceName) {
        Objects.requireNonNull(username, "username cannot be null");
        Objects.requireNonNull(deviceFingerprint, "deviceFingerprint cannot be null");
        long now = clockMillis.getAsLong();
        String sql = "INSERT INTO user_devices (username, device_fingerprint, device_name, first_seen_at, last_seen_at, is_trusted) "
                + "VALUES (?, ?, ?, ?, ?, 1) "
                + "ON CONFLICT(username, device_fingerprint) DO UPDATE SET last_seen_at = excluded.last_seen_at";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, deviceFingerprint);
            ps.setString(3, deviceName != null ? deviceName : "Default-Device");
            ps.setLong(4, now);
            ps.setLong(5, now);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            LOGGER.error("Failed to register device for {}: {}", username, e.getMessage());
            return false;
        }
    }

    /**
     * Counts the number of trusted devices registered to a specific user.
     */
    public synchronized int countDevicesForUser(String username) {
        if (username == null || username.isBlank()) {
            return 0;
        }
        String sql = "SELECT COUNT(*) FROM user_devices WHERE username = ? COLLATE NOCASE AND is_trusted = 1";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username.trim());
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to count devices for {}: {}", username, e.getMessage());
        }
        return 0;
    }

    /**
     * Stores or updates a user's Base32 TOTP secret.
     */
    public synchronized void saveTotpSecret(String username, String base32Secret) {
        Objects.requireNonNull(username, "username cannot be null");
        Objects.requireNonNull(base32Secret, "base32Secret cannot be null");
        long now = clockMillis.getAsLong();
        String sql = "INSERT OR REPLACE INTO totp_secrets (username, base32_secret, is_enabled, created_at) "
                + "VALUES (?, ?, 1, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username.trim());
            ps.setString(2, base32Secret.trim());
            ps.setLong(3, now);
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to save TOTP secret for {}: {}", username, e.getMessage());
        }
    }

    /**
     * Retrieves the Base32 TOTP secret for a user if enabled.
     */
    public synchronized String getTotpSecret(String username) {
        if (username == null || username.isBlank()) {
            return null;
        }
        String sql = "SELECT base32_secret FROM totp_secrets WHERE username = ? COLLATE NOCASE AND is_enabled = 1";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username.trim());
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getString(1);
                }
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to get TOTP secret for {}: {}", username, e.getMessage());
        }
        return null;
    }

    /**
     * Checks if TOTP two-factor authentication is active for the user.
     */
    public synchronized boolean isTotpEnabled(String username) {
        return getTotpSecret(username) != null;
    }

    /**
     * Verifies a 6-digit TOTP code and prevents replay attacks by ensuring each time step window is consumed only once.
     *
     * @param username User claiming the code
     * @param code     6-digit OTP string
     * @return true if valid and consumed; false if invalid, replayed, or disabled
     */
    public synchronized boolean verifyAndConsumeTotpCode(String username, String code) {
        if (username == null || code == null || username.isBlank() || code.isBlank()) {
            return false;
        }
        String sql = "SELECT base32_secret, last_used_window FROM totp_secrets WHERE username = ? COLLATE NOCASE AND is_enabled = 1";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username.trim());
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String base32Secret = rs.getString("base32_secret");
                    long lastUsedWindow = rs.getLong("last_used_window");
                    long verifiedWindow = com.officevpn.security.TotpUtil.verifyCodeWithReplayCheck(base32Secret, code, lastUsedWindow);
                    if (verifiedWindow > lastUsedWindow) {
                        String updateSql = "UPDATE totp_secrets SET last_used_window = ? WHERE username = ? COLLATE NOCASE";
                        try (PreparedStatement psUp = connection.prepareStatement(updateSql)) {
                            psUp.setLong(1, verifiedWindow);
                            psUp.setString(2, username.trim());
                            psUp.executeUpdate();
                        }
                        return true;
                    }
                    return false; // Code incorrect or replayed
                }
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to verify TOTP code for {}: {}", username, e.getMessage());
        }
        return false;
    }



    // =========================================================================
    // SITE-TO-SITE PEERING & BANDWIDTH LOGGING
    // =========================================================================

    public record SiteToSitePeerRecord(
            String peerId,
            String peerGatewayIp,
            String localSubnet,
            String remoteSubnet,
            String secretHash,
            String status,
            long lastKeepalive
    ) {}

    public synchronized void saveSiteToSitePeer(String peerId, String peerGatewayIp, String localSubnet,
                                               String remoteSubnet, String secretHash, String status, long lastKeepalive) {
        Objects.requireNonNull(peerId, "peerId cannot be null");
        String sql = "INSERT INTO site_to_site_peers (peer_id, peer_gateway_ip, local_subnet, remote_subnet, secret_hash, status, last_keepalive) "
                + "VALUES (?, ?, ?, ?, ?, ?, ?) "
                + "ON CONFLICT(peer_id) DO UPDATE SET peer_gateway_ip = excluded.peer_gateway_ip, "
                + "local_subnet = excluded.local_subnet, remote_subnet = excluded.remote_subnet, "
                + "secret_hash = excluded.secret_hash, status = excluded.status, last_keepalive = excluded.last_keepalive";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, peerId);
            ps.setString(2, peerGatewayIp != null ? peerGatewayIp : "");
            ps.setString(3, localSubnet != null ? localSubnet : "");
            ps.setString(4, remoteSubnet != null ? remoteSubnet : "");
            ps.setString(5, secretHash != null ? secretHash : "");
            ps.setString(6, status != null ? status : "ONLINE");
            ps.setLong(7, lastKeepalive);
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to save site-to-site peer {}: {}", peerId, e.getMessage());
        }
    }

    public synchronized void deleteSiteToSitePeer(String peerId) {
        if (peerId == null || peerId.isBlank()) return;
        String sql = "DELETE FROM site_to_site_peers WHERE peer_id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, peerId.trim());
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to delete site-to-site peer {}: {}", peerId, e.getMessage());
        }
    }

    public synchronized void updateSiteToSiteKeepalive(String peerId, String status, long lastKeepalive) {
        if (peerId == null || peerId.isBlank()) return;
        String sql = "UPDATE site_to_site_peers SET status = ?, last_keepalive = ? WHERE peer_id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, status != null ? status : "ONLINE");
            ps.setLong(2, lastKeepalive);
            ps.setString(3, peerId.trim());
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to update site-to-site keepalive for {}: {}", peerId, e.getMessage());
        }
    }

    public synchronized SiteToSitePeerRecord getSiteToSitePeer(String peerId) {
        if (peerId == null || peerId.isBlank()) return null;
        String sql = "SELECT peer_id, peer_gateway_ip, local_subnet, remote_subnet, secret_hash, status, last_keepalive FROM site_to_site_peers WHERE peer_id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, peerId.trim());
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return new SiteToSitePeerRecord(
                            rs.getString(1),
                            rs.getString(2),
                            rs.getString(3),
                            rs.getString(4),
                            rs.getString(5),
                            rs.getString(6),
                            rs.getLong(7)
                    );
                }
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to retrieve site-to-site peer {}: {}", peerId, e.getMessage());
        }
        return null;
    }

    public synchronized List<SiteToSitePeerRecord> listSiteToSitePeers() {
        List<SiteToSitePeerRecord> list = new ArrayList<>();
        String sql = "SELECT peer_id, peer_gateway_ip, local_subnet, remote_subnet, secret_hash, status, last_keepalive FROM site_to_site_peers";
        try (PreparedStatement ps = connection.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                list.add(new SiteToSitePeerRecord(
                        rs.getString(1),
                        rs.getString(2),
                        rs.getString(3),
                        rs.getString(4),
                        rs.getString(5),
                        rs.getString(6),
                        rs.getLong(7)
                ));
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to list site-to-site peers: {}", e.getMessage());
        }
        return list;
    }

    public String getJdbcUrl() {
        return jdbcUrl;
    }

    public synchronized boolean updatePasswordDirect(String username, String salt, String hash, String actor) {
        if (username == null || hash == null) return false;
        String s = (salt != null && !salt.isBlank()) ? salt : CryptoUtils.generateSalt();
        String sql = "UPDATE users SET password_salt = ?, password_hash = ? WHERE username = ? COLLATE NOCASE";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, s);
            pstmt.setString(2, hash);
            pstmt.setString(3, username.trim());
            int updated = pstmt.executeUpdate();
            if (updated > 0) {
                UserAccount u = getUserByUsername(username.trim());
                String dept = u != null ? u.department().name() : "UNKNOWN";
                logAuditEvent("PASSWORD_RESET", username.trim(), dept, "Password updated by " + actor, actor, "local");
                return true;
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to update password directly for {}: {}", username, e.getMessage());
        }
        return false;
    }

    public synchronized void logBandwidthConsumption(String username, long bytesAllowed, long bytesThrottled) {
        Objects.requireNonNull(username, "username cannot be null");
        long now = clockMillis.getAsLong();
        String sql = "INSERT INTO bandwidth_logs (username, bytes_allowed, bytes_throttled, timestamp) VALUES (?, ?, ?, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setLong(2, bytesAllowed);
            ps.setLong(3, bytesThrottled);
            ps.setLong(4, now);
            ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to log bandwidth consumption for {}: {}", username, e.getMessage());
        }
    }

    // --- ALERTS SYSTEM SUPPORT ---
    public record AlertRecord(long id, String alertType, String severity, String username, String message, boolean isRead, long timestamp) {}

    public synchronized long saveAlert(String alertType, String severity, String username, String message) {
        Objects.requireNonNull(alertType, "alertType cannot be null");
        Objects.requireNonNull(severity, "severity cannot be null");
        Objects.requireNonNull(message, "message cannot be null");
        long now = clockMillis.getAsLong();
        String sql = "INSERT INTO alerts (alert_type, severity, username, message, is_read, timestamp) VALUES (?, ?, ?, ?, 0, ?)";
        try (PreparedStatement ps = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, alertType.trim());
            ps.setString(2, severity.trim());
            ps.setString(3, username != null ? username.trim() : "SYSTEM");
            ps.setString(4, message.trim());
            ps.setLong(5, now);
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                if (rs.next()) {
                    return rs.getLong(1);
                }
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to save alert {}: {}", alertType, e.getMessage());
        }
        return -1L;
    }

    public synchronized List<AlertRecord> listAlerts(boolean unreadOnly, String severityFilter) {
        List<AlertRecord> list = new ArrayList<>();
        StringBuilder sql = new StringBuilder("SELECT id, alert_type, severity, username, message, is_read, timestamp FROM alerts WHERE 1=1 ");
        if (unreadOnly) {
            sql.append("AND is_read = 0 ");
        }
        if (severityFilter != null && !severityFilter.isBlank()) {
            sql.append("AND severity = ? ");
        }
        sql.append("ORDER BY id DESC");

        try (PreparedStatement ps = connection.prepareStatement(sql.toString())) {
            if (severityFilter != null && !severityFilter.isBlank()) {
                ps.setString(1, severityFilter.trim().toUpperCase(Locale.ROOT));
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(new AlertRecord(
                            rs.getLong(1),
                            rs.getString(2),
                            rs.getString(3),
                            rs.getString(4),
                            rs.getString(5),
                            rs.getInt(6) == 1,
                            rs.getLong(7)
                    ));
                }
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to list alerts: {}", e.getMessage());
        }
        return Collections.unmodifiableList(list);
    }

    public synchronized boolean markAlertRead(long alertId) {
        String sql = "UPDATE alerts SET is_read = 1 WHERE id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, alertId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            LOGGER.error("Failed to mark alert {} as read: {}", alertId, e.getMessage());
            return false;
        }
    }

    public synchronized int countUnreadAlerts() {
        String sql = "SELECT COUNT(*) FROM alerts WHERE is_read = 0";
        try (Statement s = connection.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : 0;
        } catch (SQLException e) {
            LOGGER.error("Failed to count unread alerts: {}", e.getMessage());
            return 0;
        }
    }

    public synchronized int countUnreadCriticalAlerts() {
        String sql = "SELECT COUNT(*) FROM alerts WHERE is_read = 0 AND severity = 'CRITICAL'";
        try (Statement s = connection.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : 0;
        } catch (SQLException e) {
            LOGGER.error("Failed to count critical alerts: {}", e.getMessage());
            return 0;
        }
    }

    public synchronized int deleteOldAlerts(long beforeTimestamp) {
        String sql = "DELETE FROM alerts WHERE timestamp < ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, beforeTimestamp);
            return ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to delete old alerts: {}", e.getMessage());
            return 0;
        }
    }

    // --- DEVICE MANAGEMENT SUPPORT ---
    public record UserDeviceRecord(long id, String username, String deviceFingerprint, String deviceName, long firstSeenAt, long lastSeenAt, boolean isTrusted) {}

    public synchronized List<UserDeviceRecord> listDevicesForUser(String username) {
        List<UserDeviceRecord> list = new ArrayList<>();
        if (username == null || username.isBlank()) {
            return list;
        }
        String sql = "SELECT id, username, device_fingerprint, device_name, first_seen_at, last_seen_at, is_trusted FROM user_devices WHERE username = ? COLLATE NOCASE ORDER BY last_seen_at DESC";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username.trim());
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(new UserDeviceRecord(
                            rs.getLong(1),
                            rs.getString(2),
                            rs.getString(3),
                            rs.getString(4),
                            rs.getLong(5),
                            rs.getLong(6),
                            rs.getInt(7) == 1
                    ));
                }
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to list devices for user {}: {}", username, e.getMessage());
        }
        return Collections.unmodifiableList(list);
    }

    public synchronized List<UserDeviceRecord> listAllDevices() {
        List<UserDeviceRecord> list = new ArrayList<>();
        String sql = "SELECT id, username, device_fingerprint, device_name, first_seen_at, last_seen_at, is_trusted FROM user_devices ORDER BY last_seen_at DESC";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                list.add(new UserDeviceRecord(
                        rs.getLong(1),
                        rs.getString(2),
                        rs.getString(3),
                        rs.getString(4),
                        rs.getLong(5),
                        rs.getLong(6),
                        rs.getInt(7) == 1
                ));
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to list all devices: {}", e.getMessage());
        }
        return Collections.unmodifiableList(list);
    }

    public synchronized boolean setDeviceTrust(String username, String deviceFingerprint, boolean trusted) {
        if (username == null || deviceFingerprint == null) return false;
        String sql = "UPDATE user_devices SET is_trusted = ? WHERE username = ? COLLATE NOCASE AND device_fingerprint = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, trusted ? 1 : 0);
            ps.setString(2, username.trim());
            ps.setString(3, deviceFingerprint.trim());
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            LOGGER.error("Failed to update device trust: {}", e.getMessage());
            return false;
        }
    }

    public static final int MAX_DEVICES_PER_USER = 3;

    public synchronized boolean isDeviceTrusted(String username, String deviceFingerprint) {
        if (username == null || deviceFingerprint == null || username.isBlank() || deviceFingerprint.isBlank()) {
            return false; // Fail-closed on missing parameters
        }
        String sql = "SELECT is_trusted FROM user_devices WHERE username = ? COLLATE NOCASE AND device_fingerprint = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username.trim());
            ps.setString(2, deviceFingerprint.trim());
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    int trusted = rs.getInt(1);
                    if (trusted == 1) {
                        updateDeviceLastSeen(username.trim(), deviceFingerprint.trim());
                        return true;
                    }
                    return false; // Revoked by administrator
                }
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to query device trust for {}: {}", username, e.getMessage());
            return false; // Fail-closed on database error
        }

        // Device not yet enrolled: auto-enroll within one atomic transaction up to device cap
        try {
            boolean originalAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                int count = 0;
                String countSql = "SELECT COUNT(*) FROM user_devices WHERE username = ? COLLATE NOCASE";
                try (PreparedStatement psCount = connection.prepareStatement(countSql)) {
                    psCount.setString(1, username.trim());
                    try (ResultSet rs = psCount.executeQuery()) {
                        if (rs.next()) {
                            count = rs.getInt(1);
                        }
                    }
                }

                int maxDevices = ConfigUtil.getInt("device.maxPerUser", MAX_DEVICES_PER_USER);
                if (count >= maxDevices) {
                    connection.rollback();
                    connection.setAutoCommit(originalAutoCommit);
                    logAuditEvent("DEVICE_CAP_EXCEEDED", username.trim(), "UNKNOWN",
                            "Device enrollment rejected: user device cap reached (" + count + "/" + maxDevices + ") for " + deviceFingerprint.trim(),
                            "GATEWAY");
                    return false; // Fail-closed when cap reached
                }

                long now = clockMillis.getAsLong();
                String insertSql = "INSERT INTO user_devices (username, device_fingerprint, device_name, first_seen_at, last_seen_at, is_trusted) "
                        + "VALUES (?, ?, ?, ?, ?, 1)";
                try (PreparedStatement psInsert = connection.prepareStatement(insertSql)) {
                    psInsert.setString(1, username.trim());
                    psInsert.setString(2, deviceFingerprint.trim());
                    psInsert.setString(3, "Authorized-Device-" + deviceFingerprint.trim());
                    psInsert.setLong(4, now);
                    psInsert.setLong(5, now);
                    psInsert.executeUpdate();
                }

                connection.commit();
                connection.setAutoCommit(originalAutoCommit);
                logAuditEvent("DEVICE_ENROLLED", username.trim(), "UNKNOWN",
                        "New hardware device auto-enrolled (" + (count + 1) + "/" + maxDevices + "): " + deviceFingerprint.trim(),
                        "GATEWAY");
                return true;
            } catch (SQLException ex) {
                connection.rollback();
                throw ex;
            } finally {
                connection.setAutoCommit(originalAutoCommit);
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to auto-enroll device for {}: {}", username, e.getMessage());
            return false; // Fail-closed on error
        }
    }

    private void updateDeviceLastSeen(String username, String deviceFingerprint) {
        String updateSql = "UPDATE user_devices SET last_seen_at = ? WHERE username = ? COLLATE NOCASE AND device_fingerprint = ?";
        try (PreparedStatement ps = connection.prepareStatement(updateSql)) {
            ps.setLong(1, clockMillis.getAsLong());
            ps.setString(2, username);
            ps.setString(3, deviceFingerprint);
            ps.executeUpdate();
        } catch (SQLException ignored) {}
    }

    public synchronized int trustAllDevicesForUser(String username) {
        if (username == null) return 0;
        String sql = "UPDATE user_devices SET is_trusted = 1 WHERE username = ? COLLATE NOCASE";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username.trim());
            return ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to trust all devices for {}: {}", username, e.getMessage());
            return 0;
        }
    }

    public synchronized int revokeAllDevicesForUser(String username) {
        if (username == null) return 0;
        String sql = "UPDATE user_devices SET is_trusted = 0 WHERE username = ? COLLATE NOCASE";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username.trim());
            return ps.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("Failed to revoke all devices for {}: {}", username, e.getMessage());
            return 0;
        }
    }

    public synchronized boolean deleteDevice(String username, String deviceFingerprint) {
        if (username == null || deviceFingerprint == null) return false;
        String sql = "DELETE FROM user_devices WHERE username = ? COLLATE NOCASE AND device_fingerprint = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, username.trim());
            ps.setString(2, deviceFingerprint.trim());
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            LOGGER.error("Failed to delete device: {}", e.getMessage());
            return false;
        }
    }

    // --- METRICS SUPPORT ---
    public synchronized int countTotalUsers() {
        String sql = "SELECT COUNT(*) FROM users";
        try (Statement s = connection.createStatement(); ResultSet rs = s.executeQuery(sql)) {
            return rs.next() ? rs.getInt(1) : 0;
        } catch (SQLException e) {
            LOGGER.error("Failed to count total users: {}", e.getMessage());
            return 0;
        }
    }

    public synchronized int countConnectionsToday(long startOfDayMillis) {
        String sql = "SELECT COUNT(*) FROM connection_logs WHERE timestamp >= ? AND (event_type = 'CONNECT' OR event_type IS NULL OR event_type = '')";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, startOfDayMillis);
            try (ResultSet rs = ps.executeQuery()) {
                int count = rs.next() ? rs.getInt(1) : 0;
                if (count > 0) {
                    return count;
                }
            }
        } catch (SQLException ignored) {}

        String auditSql = "SELECT COUNT(*) FROM audit_logs WHERE ts_ms >= ? AND event_type = 'TUNNEL_ESTABLISHED'";
        try (PreparedStatement ps = connection.prepareStatement(auditSql)) {
            ps.setLong(1, startOfDayMillis);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to count connections today: {}", e.getMessage());
            return 0;
        }
    }

    public synchronized long sumBandwidthToday(long startOfDayMillis) {
        String sql = "SELECT SUM(bytes_allowed) FROM bandwidth_logs WHERE timestamp >= ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setLong(1, startOfDayMillis);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getLong(1) : 0L;
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to sum bandwidth: {}", e.getMessage());
            return 0L;
        }
    }

    public record UserBandwidthStat(String username, long totalBytes) {}

    public synchronized List<UserBandwidthStat> getTopUsersByBandwidth(int limit) {
        List<UserBandwidthStat> list = new ArrayList<>();
        String sql = "SELECT username, SUM(bytes_allowed) as total FROM bandwidth_logs GROUP BY username ORDER BY total DESC LIMIT ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, Math.max(1, limit));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(new UserBandwidthStat(rs.getString(1), rs.getLong(2)));
                }
            }
        } catch (SQLException e) {
            LOGGER.error("Failed to query top users by bandwidth: {}", e.getMessage());
        }
        return Collections.unmodifiableList(list);
    }

    public synchronized void close() {
        if (headFlushScheduler != null && ownsScheduler) {
            headFlushScheduler.shutdown();
            try {
                if (!headFlushScheduler.awaitTermination(2, TimeUnit.SECONDS)) {
                    headFlushScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                headFlushScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        flushHeadIfDirty();
        if (connection != null) {
            try {
                if (!connection.isClosed()) {
                    connection.close();
                }
            } catch (SQLException e) {
                LOGGER.debug("Error while closing database connection: {}", e.getMessage());
            }
        }
    }
}
