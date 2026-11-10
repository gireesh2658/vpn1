package com.officevpn.admin;

import com.officevpn.db.DatabaseManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * Enterprise Alerting &amp; Real-Time Security Incident Monitoring Service.
 * Centralizes alert dispatch, severity classification, and persistence to MySQL.
 */
public final class AlertManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(AlertManager.class);

    public enum AlertSeverity {
        INFO,
        WARNING,
        CRITICAL
    }

    public enum AlertType {
        BRUTE_FORCE,
        KILL_SWITCH,
        DNS_LEAK,
        BANDWIDTH_THROTTLE,
        PEER_OFFLINE,
        SESSION_TIMEOUT,
        CONFIG_CHANGED,
        USER_OFFBOARDED,
        LOGIN_FAILED
    }

    public record SystemAlert(
            long id,
            AlertType type,
            AlertSeverity severity,
            String username,
            String message,
            boolean isRead,
            long timestamp
    ) {}

    private final DatabaseManager databaseManager;

    public AlertManager(DatabaseManager databaseManager) {
        this.databaseManager = Objects.requireNonNull(databaseManager, "DatabaseManager cannot be null");
    }

    /**
     * Creates and records a system alert.
     */
    public long createAlert(AlertType type, AlertSeverity severity, String username, String message) {
        Objects.requireNonNull(type, "AlertType cannot be null");
        Objects.requireNonNull(severity, "AlertSeverity cannot be null");
        Objects.requireNonNull(message, "Message cannot be null");

        String targetUser = (username != null && !username.isBlank()) ? username.trim() : "SYSTEM";
        long id = databaseManager.saveAlert(type.name(), severity.name(), targetUser, message.trim());

        if (severity == AlertSeverity.CRITICAL) {
            LOGGER.error("CRITICAL SECURITY ALERT [{}]: User '{}' - {}", type, targetUser, message);
        } else if (severity == AlertSeverity.WARNING) {
            LOGGER.warn("WARNING ALERT [{}]: User '{}' - {}", type, targetUser, message);
        } else {
            LOGGER.info("INFO ALERT [{}]: User '{}' - {}", type, targetUser, message);
        }

        return id;
    }

    /**
     * Returns all unread system alerts.
     */
    public List<SystemAlert> getUnreadAlerts() {
        return mapRecords(databaseManager.listAlerts(true, null));
    }

    /**
     * Returns alerts matching the specified severity filter.
     */
    public List<SystemAlert> getAlertsBySeverity(AlertSeverity severity) {
        if (severity == null) {
            return mapRecords(databaseManager.listAlerts(false, null));
        }
        return mapRecords(databaseManager.listAlerts(false, severity.name()));
    }

    /**
     * Returns all recorded alerts.
     */
    public List<SystemAlert> getAllAlerts() {
        return mapRecords(databaseManager.listAlerts(false, null));
    }

    /**
     * Marks an alert as acknowledged / read.
     */
    public boolean markAlertRead(long alertId) {
        return databaseManager.markAlertRead(alertId);
    }

    /**
     * Returns count of unread CRITICAL severity alerts for GUI badge display.
     */
    public int getUnreadCriticalCount() {
        return databaseManager.countUnreadCriticalAlerts();
    }

    /**
     * Returns total unread alert count.
     */
    public int getUnreadCount() {
        return databaseManager.countUnreadAlerts();
    }

    /**
     * Summarizes alert counts partitioned by AlertType.
     */
    public Map<AlertType, Integer> getAlertCountByType() {
        Map<AlertType, Integer> map = new EnumMap<>(AlertType.class);
        for (AlertType t : AlertType.values()) {
            map.put(t, 0);
        }
        for (DatabaseManager.AlertRecord r : databaseManager.listAlerts(false, null)) {
            try {
                AlertType t = AlertType.valueOf(r.alertType().toUpperCase(Locale.ROOT));
                map.put(t, map.getOrDefault(t, 0) + 1);
            } catch (Exception ignored) {}
        }
        return map;
    }

    /**
     * Deletes alerts older than the specified retention window in days.
     */
    public int clearOldAlerts(int days) {
        long cutoff = System.currentTimeMillis() - (days * 86_400_000L);
        return databaseManager.deleteOldAlerts(cutoff);
    }

    // --- Automated Security Alert Dispatchers ---

    public void notifyFailedLogin(String username, int consecutiveFailures) {
        if (consecutiveFailures >= 5) {
            createAlert(AlertType.BRUTE_FORCE, AlertSeverity.CRITICAL, username,
                    "Brute-force password attack suspected: " + consecutiveFailures + " consecutive failed attempts");
        } else {
            createAlert(AlertType.LOGIN_FAILED, AlertSeverity.WARNING, username,
                    "Failed authentication attempt (attempt " + consecutiveFailures + ")");
        }
    }

    public void notifyKillSwitchActivated() {
        createAlert(AlertType.KILL_SWITCH, AlertSeverity.WARNING, "SYSTEM",
                "Tunnel dropped unexpectedly; Kill Switch activated in BLOCKING mode");
    }

    public void notifyDnsLeakBlocked(String resolverIp) {
        createAlert(AlertType.DNS_LEAK, AlertSeverity.WARNING, "SYSTEM",
                "DNS query to public resolver blocked: " + resolverIp);
    }

    public void notifyBandwidthThrottled(String username, long bytesThrottled) {
        createAlert(AlertType.BANDWIDTH_THROTTLE, AlertSeverity.INFO, username,
                "Traffic packet delayed by token bucket rate limit (" + bytesThrottled + " bytes)");
    }

    public void notifyPeerOffline(String peerId) {
        createAlert(AlertType.PEER_OFFLINE, AlertSeverity.WARNING, peerId,
                "Site-to-site branch peer timed out (> 45s keepalive) and marked OFFLINE: " + peerId);
    }

    private List<SystemAlert> mapRecords(List<DatabaseManager.AlertRecord> records) {
        List<SystemAlert> list = new ArrayList<>();
        for (DatabaseManager.AlertRecord r : records) {
            AlertType t;
            try {
                t = AlertType.valueOf(r.alertType().toUpperCase(Locale.ROOT));
            } catch (Exception e) {
                t = AlertType.LOGIN_FAILED;
            }

            AlertSeverity s;
            try {
                s = AlertSeverity.valueOf(r.severity().toUpperCase(Locale.ROOT));
            } catch (Exception e) {
                s = AlertSeverity.INFO;
            }

            list.add(new SystemAlert(r.id(), t, s, r.username(), r.message(), r.isRead(), r.timestamp()));
        }
        return list;
    }
}

