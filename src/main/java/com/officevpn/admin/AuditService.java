package com.officevpn.admin;

import com.officevpn.db.DatabaseManager;
import com.officevpn.model.AuditVerifyResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Enterprise Audit Trail Viewer &amp; Verification Service.
 * Provides query filtering, CSV export, and cryptographic hash chain verification.
 */
public final class AuditService {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuditService.class);

    private final DatabaseManager databaseManager;
    private final AlertManager alertManager;

    public AuditService(DatabaseManager databaseManager) {
        this(databaseManager, new AlertManager(databaseManager));
    }

    public AuditService(DatabaseManager databaseManager, AlertManager alertManager) {
        this.databaseManager = Objects.requireNonNull(databaseManager, "DatabaseManager cannot be null");
        this.alertManager = alertManager;
    }

    /**
     * Retrieves the most recent audit log entries up to the specified limit.
     */
    public List<DatabaseManager.AuditLogEntry> getRecentAudit(int limit) {
        return databaseManager.getRecentAuditLogs(limit);
    }

    /**
     * Searches the audit trail filtered by username, event type, and timestamp range.
     */
    public List<DatabaseManager.AuditLogEntry> searchAudit(String username, String eventType, Long fromTimestamp, Long toTimestamp) {
        List<DatabaseManager.AuditLogEntry> results = new ArrayList<>();
        StringBuilder sql = new StringBuilder("SELECT id, seq, event_type, username, department, details, actor, remote_ip, timestamp FROM audit_logs WHERE 1=1 ");

        List<Object> params = new ArrayList<>();
        if (username != null && !username.isBlank()) {
            sql.append("AND LOWER(username) = LOWER(?) ");
            params.add(username.trim());
        }
        if (eventType != null && !eventType.isBlank()) {
            sql.append("AND event_type = ? ");
            params.add(eventType.trim());
        }
        if (fromTimestamp != null && fromTimestamp > 0) {
            sql.append("AND timestamp >= ? ");
            params.add(fromTimestamp);
        }
        if (toTimestamp != null && toTimestamp > 0) {
            sql.append("AND timestamp <= ? ");
            params.add(toTimestamp);
        }
        sql.append("ORDER BY id DESC");

        try (Connection conn = databaseManager.openConnection();
             PreparedStatement ps = conn.prepareStatement(sql.toString())) {
            for (int i = 0; i < params.size(); i++) {
                ps.setObject(i + 1, params.get(i));
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    results.add(new DatabaseManager.AuditLogEntry(
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
            LOGGER.error("Failed to execute audit search query: {}", e.getMessage());
        }

        return Collections.unmodifiableList(results);
    }

    /**
     * Exports the entire audit log trail to a CSV file.
     *
     * @param outputPath destination CSV file path
     * @return count of exported rows
     */
    public int exportAuditToCsv(Path outputPath) throws IOException {
        Objects.requireNonNull(outputPath, "outputPath cannot be null");
        if (outputPath.getParent() != null && !Files.exists(outputPath.getParent())) {
            Files.createDirectories(outputPath.getParent());
        }

        List<DatabaseManager.AuditLogEntry> logs = databaseManager.getRecentAuditLogs(10_000);
        try (BufferedWriter writer = Files.newBufferedWriter(outputPath)) {
            writer.write("ID,Seq,Timestamp,ISO8601,Event,Username,Department,Details,Actor,IP");
            writer.newLine();

            for (DatabaseManager.AuditLogEntry e : logs) {
                String safeDetails = e.details() != null ? e.details().replace("\"", "\"\"") : "";
                writer.write(String.format("%d,%d,%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"",
                        e.id(),
                        e.seq(),
                        e.timestamp(),
                        Instant.ofEpochMilli(e.timestamp()).toString(),
                        e.eventType(),
                        e.username(),
                        e.department(),
                        safeDetails,
                        e.actor(),
                        e.remoteIp()));
                writer.newLine();
            }
        }

        LOGGER.info("Exported {} audit entries to CSV at {}", logs.size(), outputPath);
        return logs.size();
    }

    /**
     * Verifies the cryptographic HMAC hash chain integrity across all stored audit entries.
     * If tampering or broken sequence is detected, generates a CRITICAL security alert.
     *
     * @return true if the hash chain is fully intact; false if broken or tampered
     */
    public boolean verifyAuditChain() {
        AuditVerifyResult result = databaseManager.verifyAuditChain();
        boolean intact = (result.status() == AuditVerifyResult.AuditStatus.OK);

        if (!intact) {
            String warningMsg = String.format("Audit chain integrity verification FAILED (%s): checked %d rows, broken at seq %d. Details: %s",
                    result.status(), result.rowsChecked(), result.firstBadSeq(), result.details());
            LOGGER.error("AUDIT INTEGRITY ALERT: {}", warningMsg);
            if (alertManager != null) {
                alertManager.createAlert(AlertManager.AlertType.BRUTE_FORCE, AlertManager.AlertSeverity.CRITICAL, "SYSTEM", warningMsg);
            }
        } else {
            LOGGER.info("Audit hash chain integrity verified successfully: {} rows verified intact.", result.rowsChecked());
        }

        return intact;
    }

    public DatabaseManager getDatabaseManager() {
        return databaseManager;
    }
}

