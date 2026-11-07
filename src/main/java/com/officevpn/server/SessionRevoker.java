package com.officevpn.server;

/**
 * Functional callback interface for revoking active employee VPN sessions.
 */
@FunctionalInterface
public interface SessionRevoker {

    /**
     * Revokes an active user session immediately.
     *
     * @param username Target username to disconnect
     * @param reason   Human-readable reason for disconnection
     * @param actor    Administrator or system actor initiating the revocation
     */
    void revoke(String username, String reason, String actor);

    /**
     * Revokes a session by session ID.
     *
     * @param sessionId Target session ID
     */
    default void revokeSession(String sessionId) {
        revoke(sessionId, "Administrative session revocation", "SYSTEM");
    }

    /**
     * Revokes all active sessions for the specified user.
     *
     * @param username Target username
     */
    default void revokeAllSessionsForUser(String username) {
        revoke(username, "Administrative bulk revocation", "SYSTEM");
    }
}


