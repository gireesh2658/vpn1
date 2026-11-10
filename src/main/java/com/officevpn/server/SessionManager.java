package com.officevpn.server;

import com.officevpn.config.ConfigUtil;
import com.officevpn.db.DatabaseManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enterprise Session Manager managing concurrent VPN sessions, virtual IP leases,
 * device limits, idle/absolute timeout eviction, and MySQL database synchronization.
 */
public final class SessionManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(SessionManager.class);

    public record VpnSession(
            String sessionId,
            String username,
            String virtualIp,
            String department,
            String role,
            String clientIp,
            String deviceFingerprint,
            long createdAt,
            long lastActiveAt
    ) {
        public VpnSession withLastActiveAt(long now) {
            return new VpnSession(sessionId, username, virtualIp, department, role, clientIp, deviceFingerprint, createdAt, now);
        }
    }

    private final DatabaseManager databaseManager;
    private final VirtualIpPool virtualIpPool;
    private final Map<String, VpnSession> sessionsById = new ConcurrentHashMap<>();
    private final Map<String, String> userToSessionMap = new ConcurrentHashMap<>();

    public SessionManager(DatabaseManager databaseManager) {
        this(databaseManager, new VirtualIpPool());
    }

    public SessionManager(DatabaseManager databaseManager, VirtualIpPool virtualIpPool) {
        this.databaseManager = Objects.requireNonNull(databaseManager, "DatabaseManager cannot be null");
        this.virtualIpPool = Objects.requireNonNull(virtualIpPool, "VirtualIpPool cannot be null");
    }

    /**
     * Creates and registers a new active VPN session.
     * Enforces device limits and synchronizes session state to the MySQL database.
     *
     * @param username          user identity
     * @param department        department name
     * @param role              role name
     * @param clientIp          remote client IP
     * @param deviceFingerprint optional client hardware/device fingerprint
     * @return newly created {@link VpnSession}
     */
    public synchronized VpnSession createSession(String username, String department, String role,
                                                 String clientIp, String deviceFingerprint) {
        Objects.requireNonNull(username, "Username cannot be null");

        // Enforce maximum devices per user policy
        int maxDevices = ConfigUtil.getMaxDevicesPerUser();
        if (deviceFingerprint != null && !deviceFingerprint.isBlank()) {
            int currentDevices = databaseManager.countDevicesForUser(username);
            if (currentDevices >= maxDevices) {
                // If it's a completely new device exceeding threshold, reject
                LOGGER.warn("User {} reached maximum device limit ({} devices registered)", username, maxDevices);
                throw new IllegalStateException("Maximum device limit reached (" + maxDevices + " devices registered)");
            }
            databaseManager.registerDevice(username, deviceFingerprint, "Client-Device-" + username);
        }

        // Close any pre-existing session for this user (single-active-session policy per employee)
        String oldSessionId = userToSessionMap.get(username);
        if (oldSessionId != null) {
            terminateSession(oldSessionId, "SUPERSEDED_BY_NEW_LOGIN");
        }

        String sessionId = UUID.randomUUID().toString();
        String virtualIp = virtualIpPool.acquireIp(username, sessionId);
        long now = System.currentTimeMillis();

        VpnSession session = new VpnSession(
                sessionId,
                username,
                virtualIp,
                department != null ? department : "UNKNOWN",
                role != null ? role : "EMPLOYEE",
                clientIp != null ? clientIp : "127.0.0.1",
                deviceFingerprint != null ? deviceFingerprint : "UNKNOWN",
                now,
                now
        );

        sessionsById.put(sessionId, session);
        userToSessionMap.put(username, sessionId);

        // Sync to DB
        databaseManager.insertSession(sessionId, username, virtualIp, department, role, clientIp);
        databaseManager.logConnectionEvent(username, virtualIp, clientIp, "CONNECT", "Tunnel session established");
        LOGGER.info("Created VPN session {} for user {} with VIP {}", sessionId, username, virtualIp);

        return session;
    }

    /**
     * Updates activity timestamp for the given session.
     */
    public void touchSession(String sessionId) {
        if (sessionId == null) {
            return;
        }
        sessionsById.computeIfPresent(sessionId, (k, s) -> {
            long now = System.currentTimeMillis();
            databaseManager.updateSessionActivity(sessionId);
            return s.withLastActiveAt(now);
        });
    }

    /**
     * Terminates an active session, frees leased virtual IP, and records closing in DB.
     */
    public synchronized void terminateSession(String sessionId, String reason) {
        if (sessionId == null) {
            return;
        }
        VpnSession removed = sessionsById.remove(sessionId);
        if (removed != null) {
            userToSessionMap.remove(removed.username());
            virtualIpPool.releaseIp(removed.username(), sessionId);
            databaseManager.closeSession(sessionId, reason);
            databaseManager.logConnectionEvent(removed.username(), removed.virtualIp(),
                    removed.clientIp(), "DISCONNECT", reason);
            LOGGER.info("Terminated VPN session {} for user {}: {}", sessionId, removed.username(), reason);
        }
    }

    /**
     * Inspects all active sessions and terminates those exceeding idle or absolute timeout limits.
     *
     * @param idleTimeoutMinutes     idle inactivity threshold in minutes
     * @param absoluteTimeoutMinutes absolute max connection duration in minutes
     * @return count of terminated timed-out sessions
     */
    public synchronized int checkTimeouts(int idleTimeoutMinutes, int absoluteTimeoutMinutes) {
        long now = System.currentTimeMillis();
        long idleLimitMs = idleTimeoutMinutes * 60L * 1000L;
        long absoluteLimitMs = absoluteTimeoutMinutes * 60L * 1000L;
        List<String> toEvict = new ArrayList<>();

        for (VpnSession s : sessionsById.values()) {
            if (idleLimitMs > 0 && (now - s.lastActiveAt() > idleLimitMs)) {
                toEvict.add(s.sessionId());
            } else if (absoluteLimitMs > 0 && (now - s.createdAt() > absoluteLimitMs)) {
                toEvict.add(s.sessionId());
            }
        }

        for (String id : toEvict) {
            terminateSession(id, "SESSION_TIMEOUT");
        }
        return toEvict.size();
    }

    public synchronized void revokeSession(String sessionId) {
        terminateSession(sessionId, "REVOKED_BY_ADMIN");
    }

    public synchronized int revokeAllSessions(String username) {
        if (username == null) {
            return 0;
        }
        int count = 0;
        String activeSessionId = userToSessionMap.get(username);
        if (activeSessionId != null) {
            terminateSession(activeSessionId, "ALL_SESSIONS_REVOKED");
            count++;
        }
        // Also ensure any lingering sessions in sessionsById are terminated
        for (VpnSession s : new ArrayList<>(sessionsById.values())) {
            if (s.username().equalsIgnoreCase(username)) {
                terminateSession(s.sessionId(), "ALL_SESSIONS_REVOKED");
                count++;
            }
        }
        return count;
    }

    public List<VpnSession> listSessionsForUser(String username) {
        if (username == null) {
            return Collections.emptyList();
        }
        List<VpnSession> list = new ArrayList<>();
        for (VpnSession s : sessionsById.values()) {
            if (s.username().equalsIgnoreCase(username)) {
                list.add(s);
            }
        }
        return Collections.unmodifiableList(list);
    }

    public VpnSession getSession(String sessionId) {
        return sessionId != null ? sessionsById.get(sessionId) : null;
    }

    public VpnSession getSessionByUsername(String username) {
        if (username == null) {
            return null;
        }
        String id = userToSessionMap.get(username);
        return id != null ? sessionsById.get(id) : null;
    }

    public List<VpnSession> getActiveSessions() {
        return Collections.unmodifiableList(new ArrayList<>(sessionsById.values()));
    }

    public int getActiveSessionCount() {
        return sessionsById.size();
    }

    public VirtualIpPool getVirtualIpPool() {
        return virtualIpPool;
    }

    public DatabaseManager getDatabaseManager() {
        return databaseManager;
    }
}
