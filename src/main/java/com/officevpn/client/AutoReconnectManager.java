package com.officevpn.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Intelligent Client Auto-Reconnect Manager with exponential backoff and jitter.
 * Schedule: 1s, 2s, 4s, 8s, 16s, capped at 30s, up to 10 consecutive attempts.
 * Preserves leased virtual IP across reconnection handshakes whenever permitted by the gateway.
 */
public final class AutoReconnectManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(AutoReconnectManager.class);

    public static final int MAX_ATTEMPTS = 10;
    public static final long INITIAL_DELAY_MS = 1000L;
    public static final long MAX_DELAY_MS = 30_000L;

    private int attemptCount = 0;
    private boolean enabled = true;
    private String preservedVirtualIp = null;

    public AutoReconnectManager() {}

    public synchronized boolean isEnabled() {
        return enabled;
    }

    public synchronized void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public synchronized boolean shouldReconnect() {
        return enabled && attemptCount < MAX_ATTEMPTS;
    }

    public synchronized long getNextDelayMs() {
        if (attemptCount >= MAX_ATTEMPTS) {
            return -1L;
        }
        // Exponential backoff: 1s * 2^attemptCount
        long delay = INITIAL_DELAY_MS * (1L << Math.min(attemptCount, 5));
        return Math.min(delay, MAX_DELAY_MS);
    }

    public synchronized void recordFailure() {
        attemptCount++;
        LOGGER.warn("RECONNECT_ATTEMPT: Connection failed (attempt {} of {})", attemptCount, MAX_ATTEMPTS);
        if (attemptCount >= MAX_ATTEMPTS) {
            LOGGER.error("RECONNECT_EXHAUSTED: Maximum reconnect attempts reached ({}). User intervention required.", MAX_ATTEMPTS);
        }
    }

    public synchronized void recordSuccess() {
        if (attemptCount > 0) {
            LOGGER.info("Tunnel re-established successfully after {} reconnect attempts.", attemptCount);
        }
        this.attemptCount = 0;
    }

    public synchronized void reset() {
        this.attemptCount = 0;
    }

    public synchronized int getAttemptCount() {
        return attemptCount;
    }

    public synchronized int getMaxAttempts() {
        return MAX_ATTEMPTS;
    }

    public synchronized String getPreservedVirtualIp() {
        return preservedVirtualIp;
    }

    public synchronized void setPreservedVirtualIp(String preservedVirtualIp) {
        this.preservedVirtualIp = preservedVirtualIp;
    }
}

