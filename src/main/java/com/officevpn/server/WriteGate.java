package com.officevpn.server;

/**
 * Deterministic test hook for gating or stalling outbound socket writes.
 */
@FunctionalInterface
public interface WriteGate {

    /**
     * Called immediately before an outbound packet write begins.
     *
     * @throws InterruptedException if interrupted while waiting
     */
    void beforeWrite() throws InterruptedException;
}

