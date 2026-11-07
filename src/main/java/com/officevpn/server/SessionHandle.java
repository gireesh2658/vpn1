package com.officevpn.server;

/**
 * Handle representing an active authenticated client session.
 */
public interface SessionHandle {

    /**
     * Unique identifier for this session handle (used as the lease owner token).
     */
    String id();

    /**
     * Terminate the session with a human-readable reason.
     *
     * @param reason Reason for termination
     */
    void terminate(String reason);
}

