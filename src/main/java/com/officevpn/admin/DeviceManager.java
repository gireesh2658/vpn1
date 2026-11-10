package com.officevpn.admin;

import com.officevpn.db.DatabaseManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Objects;

/**
 * Enterprise Device Management service enforcing hardware fingerprint authorization,
 * device limits, and trust revocation.
 */
public final class DeviceManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(DeviceManager.class);

    private final DatabaseManager databaseManager;

    public record DeviceInfo(
            long id,
            String username,
            String fingerprint,
            String deviceName,
            long firstSeenAt,
            long lastSeenAt,
            boolean isTrusted
    ) {}

    public DeviceManager(DatabaseManager databaseManager) {
        this.databaseManager = Objects.requireNonNull(databaseManager, "DatabaseManager cannot be null");
    }

    /**
     * Lists all hardware devices registered to a specific user.
     *
     * @param username target employee username
     * @return list of {@link DeviceInfo}
     */
    public List<DeviceInfo> listDevicesForUser(String username) {
        if (username == null || username.isBlank()) {
            return List.of();
        }
        List<DatabaseManager.UserDeviceRecord> records = databaseManager.listDevicesForUser(username.trim());
        return records.stream()
                .map(r -> new DeviceInfo(r.id(), r.username(), r.deviceFingerprint(), r.deviceName(), r.firstSeenAt(), r.lastSeenAt(), r.isTrusted()))
                .toList();
    }

    /**
     * Revokes trust for a specific device fingerprint belonging to a user.
     *
     * @param username    target user
     * @param fingerprint hardware public key / SHA-256 fingerprint
     * @return true if updated successfully
     */
    public boolean revokeDevice(String username, String fingerprint) {
        return revokeDevice(username, fingerprint, "ADMIN");
    }

    public boolean revokeDevice(String username, String fingerprint, String actor) {
        if (username == null || fingerprint == null) {
            return false;
        }
        String cleanActor = (actor != null && !actor.isBlank()) ? actor.trim() : "ADMIN";
        boolean ok = databaseManager.setDeviceTrust(username, fingerprint, false);
        if (ok) {
            databaseManager.logAuditEvent("DEVICE_REVOKED", username, "UNKNOWN",
                    "Device fingerprint revoked: " + fingerprint, cleanActor, "local");
            LOGGER.info("Revoked device trust for user '{}' by '{}' (fingerprint: {})", username, cleanActor, fingerprint);
        }
        return ok;
    }

    public int revokeAllDevices(String username) {
        return revokeAllDevices(username, "ADMIN");
    }

    public int revokeAllDevices(String username, String actor) {
        if (username == null) {
            return 0;
        }
        String cleanActor = (actor != null && !actor.isBlank()) ? actor.trim() : "ADMIN";
        int count = databaseManager.revokeAllDevicesForUser(username);
        if (count > 0) {
            databaseManager.logAuditEvent("ALL_DEVICES_REVOKED", username, "UNKNOWN",
                    "All registered devices revoked (count=" + count + ")", cleanActor, "local");
            LOGGER.info("Revoked all {} devices for user '{}' by '{}'", count, username, cleanActor);
        }
        return count;
    }

    public boolean trustDevice(String username, String fingerprint) {
        return trustDevice(username, fingerprint, "ADMIN");
    }

    public boolean trustDevice(String username, String fingerprint, String actor) {
        if (username == null || fingerprint == null) {
            return false;
        }
        String cleanActor = (actor != null && !actor.isBlank()) ? actor.trim() : "ADMIN";
        boolean ok = databaseManager.setDeviceTrust(username, fingerprint, true);
        if (ok) {
            databaseManager.logAuditEvent("DEVICE_TRUSTED", username, "UNKNOWN",
                    "Device fingerprint trusted: " + fingerprint, cleanActor, "local");
        }
        return ok;
    }

    public boolean registerAndTrustDevice(String username, String fingerprint, String deviceName) {
        return registerAndTrustDevice(username, fingerprint, deviceName, "ADMIN");
    }

    public boolean registerAndTrustDevice(String username, String fingerprint, String deviceName, String actor) {
        if (username == null || username.isBlank() || fingerprint == null || fingerprint.isBlank()) {
            return false;
        }
        String cleanActor = (actor != null && !actor.isBlank()) ? actor.trim() : "ADMIN";
        boolean ok = databaseManager.registerDevice(username.trim(), fingerprint.trim(),
                (deviceName != null && !deviceName.isBlank()) ? deviceName.trim() : "Authorized-Hardware");
        if (ok) {
            databaseManager.setDeviceTrust(username.trim(), fingerprint.trim(), true);
            databaseManager.logAuditEvent("DEVICE_PREAUTHORIZED", username.trim(), "UNKNOWN",
                    "Hardware device pre-authorized: " + fingerprint.trim() + " (" + deviceName + ")", cleanActor, "local");
            LOGGER.info("Pre-authorized device '{}' ({}) for user '{}' by '{}'", fingerprint, deviceName, username, cleanActor);
        }
        return ok;
    }

    public int trustAllDevices(String username) {
        return trustAllDevices(username, "ADMIN");
    }

    public int trustAllDevices(String username, String actor) {
        if (username == null) {
            return 0;
        }
        String cleanActor = (actor != null && !actor.isBlank()) ? actor.trim() : "ADMIN";
        int count = databaseManager.trustAllDevicesForUser(username);
        if (count > 0) {
            databaseManager.logAuditEvent("ALL_DEVICES_TRUSTED", username, "UNKNOWN",
                    "All registered devices approved/trusted (count=" + count + ")", cleanActor, "local");
            LOGGER.info("Approved all {} devices for user '{}' by '{}'", count, username, cleanActor);
        }
        return count;
    }

    /**
     * Returns count of active/trusted devices for a user.
     *
     * @param username user
     * @return trusted device count
     */
    public int getDeviceCount(String username) {
        return databaseManager.countDevicesForUser(username);
    }

    public boolean deleteDevice(String username, String fingerprint) {
        return databaseManager.deleteDevice(username, fingerprint);
    }
}
