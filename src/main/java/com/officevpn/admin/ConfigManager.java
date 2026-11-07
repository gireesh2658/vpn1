package com.officevpn.admin;

import com.officevpn.config.ConfigUtil;
import com.officevpn.db.DatabaseManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Enterprise Configuration Manager allowing administrators to inspect and dynamically
 * adjust runtime properties with strict key allowlisting, input validation, and audit trail logging.
 */
public final class ConfigManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigManager.class);

    public static final Set<String> ALLOWED_KEYS = Set.of(
            "server.port",
            "session.timeoutMinutes",
            "tunnel.mode",
            "bandwidth.defaultKbpsPerUser",
            "dns.leakProtection",
            "compression.enabled",
            "siteToSite.enabled"
    );

    private final DatabaseManager databaseManager;
    private final AlertManager alertManager;

    public ConfigManager(DatabaseManager databaseManager) {
        this(databaseManager, new AlertManager(databaseManager));
    }

    public ConfigManager(DatabaseManager databaseManager, AlertManager alertManager) {
        this.databaseManager = Objects.requireNonNull(databaseManager, "DatabaseManager cannot be null");
        this.alertManager = alertManager;
    }

    /**
     * Reads current value of a configuration parameter.
     */
    public String getConfig(String key) {
        if (key == null) return "";
        return ConfigUtil.getString(key, "");
    }

    /**
     * Updates an allowed configuration parameter with validation, audit logging, and alert creation.
     *
     * @param adminUsername initiating administrator identity
     * @param key           configuration parameter key
     * @param value         new configuration value
     */
    public void setConfig(String adminUsername, String key, String value) {
        String actor = (adminUsername != null && !adminUsername.isBlank()) ? adminUsername.trim() : "ADMIN";
        if (key == null || !ALLOWED_KEYS.contains(key.trim())) {
            throw new IllegalArgumentException("Configuration key not in administrative allowlist: " + key);
        }
        Objects.requireNonNull(value, "Value cannot be null");
        String cleanKey = key.trim();
        String cleanVal = value.trim();

        // Validate values
        validateConfigValue(cleanKey, cleanVal);

        String previousVal = ConfigUtil.getString(cleanKey, "");
        ConfigUtil.setPropertyForTest(cleanKey, cleanVal);

        // Audit Trail Logging
        databaseManager.logAuditEvent("CONFIG_CHANGED", actor, "HEADQUARTERS",
                String.format("Config '%s' changed from '%s' to '%s'", cleanKey, previousVal, cleanVal),
                actor, "local");

        // Alert Creation
        if (alertManager != null) {
            alertManager.createAlert(AlertManager.AlertType.CONFIG_CHANGED, AlertManager.AlertSeverity.INFO, actor,
                    String.format("Configuration parameter '%s' updated to '%s'", cleanKey, cleanVal));
        }

        LOGGER.info("Config key '{}' updated to '{}' by '{}'", cleanKey, cleanVal, actor);
    }

    /**
     * Returns a snapshot map of all currently allowed configurable properties.
     */
    public Map<String, String> getAllConfigs() {
        Map<String, String> map = new LinkedHashMap<>();
        for (String k : ALLOWED_KEYS) {
            map.put(k, ConfigUtil.getString(k, ""));
        }
        return Collections.unmodifiableMap(map);
    }

    /**
     * Resets runtime configurations to standard production defaults.
     */
    public void resetToDefaults(String adminUsername) {
        String actor = (adminUsername != null && !adminUsername.isBlank()) ? adminUsername.trim() : "ADMIN";
        setConfig(actor, "server.port", "8443");
        setConfig(actor, "session.timeoutMinutes", "30");
        setConfig(actor, "tunnel.mode", "SPLIT");
        setConfig(actor, "bandwidth.defaultKbpsPerUser", "10240");
        setConfig(actor, "dns.leakProtection", "true");
        setConfig(actor, "compression.enabled", "true");
        setConfig(actor, "siteToSite.enabled", "true");
        LOGGER.info("Configuration reset to production defaults by '{}'", actor);
    }

    private void validateConfigValue(String key, String value) {
        switch (key) {
            case "server.port" -> {
                int port = parsePositiveInt(value, "server.port");
                if (port < 1 || port > 65535) {
                    throw new IllegalArgumentException("Port must be between 1 and 65535, got: " + port);
                }
            }
            case "session.timeoutMinutes" -> {
                int timeout = parsePositiveInt(value, "session.timeoutMinutes");
                if (timeout < 1) {
                    throw new IllegalArgumentException("Session timeout must be at least 1 minute, got: " + timeout);
                }
            }
            case "tunnel.mode" -> {
                String mode = value.toUpperCase(Locale.ROOT);
                if (!mode.equals("SPLIT") && !mode.equals("FULL")) {
                    throw new IllegalArgumentException("Tunnel mode must be either SPLIT or FULL, got: " + value);
                }
            }
            case "bandwidth.defaultKbpsPerUser" -> {
                int kbps = parsePositiveInt(value, "bandwidth.defaultKbpsPerUser");
                if (kbps < 64) {
                    throw new IllegalArgumentException("Bandwidth limit must be at least 64 Kbps, got: " + kbps);
                }
            }
            case "dns.leakProtection", "compression.enabled", "siteToSite.enabled" -> {
                if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
                    throw new IllegalArgumentException("Boolean parameter must be 'true' or 'false', got: " + value);
                }
            }
        }
    }

    private int parsePositiveInt(String val, String paramName) {
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid numeric integer format for " + paramName + ": " + val);
        }
    }
}

