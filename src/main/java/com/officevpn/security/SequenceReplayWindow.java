package com.officevpn.security;

import java.util.BitSet;

/**
 * Thread-safe sliding replay protection window for the Office VPN Wire Protocol.
 * <p>
 * Implements an RFC 6479 / RFC 4303 style sliding bitmap window to eliminate replay attacks
 * without unbounded memory consumption or cache-eviction vulnerabilities.
 * <p>
 * <b>Security Guarantees:</b>
 * <ul>
 *   <li>Rejects duplicate sequence numbers.</li>
 *   <li>Rejects stale/out-of-window sequence numbers.</li>
 *   <li>Rejects non-positive sequence numbers (&le; 0).</li>
 *   <li>Supports out-of-order packet delivery within the configured window span.</li>
 * </ul>
 */
public final class SequenceReplayWindow {

    public static final int DEFAULT_WINDOW_SIZE = 128;

    private final int windowSize;
    private long maxSeqSeen = 0;
    private final BitSet receivedBitmap;

    /**
     * Constructs a replay window with the default window size (128 packets).
     */
    public SequenceReplayWindow() {
        this(DEFAULT_WINDOW_SIZE);
    }

    /**
     * Constructs a replay window with a custom window size.
     *
     * @param windowSize Window capacity in packets (must be &ge; 32)
     */
    public SequenceReplayWindow(int windowSize) {
        if (windowSize < 32) {
            throw new IllegalArgumentException("Window size must be at least 32, got: " + windowSize);
        }
        this.windowSize = windowSize;
        this.receivedBitmap = new BitSet(windowSize);
    }

    /**
     * Validates an incoming sequence number and records it if valid.
     *
     * @param seqNum Incoming packet sequence number
     * @return True if valid and newly recorded
     * @throws SecurityException If duplicate, non-positive, or stale/out-of-window sequence number is detected
     */
    public synchronized boolean checkAndRecord(long seqNum) {
        // 1. Non-positive sequence number check
        if (seqNum <= 0) {
            throw new SecurityException("Replay Defense Violation: Invalid non-positive sequence number: " + seqNum);
        }

        // 2. Initial packet in session
        if (maxSeqSeen == 0) {
            maxSeqSeen = seqNum;
            receivedBitmap.set(0);
            return true;
        }

        // 3. Packet is newer than the highest sequence number seen so far
        if (seqNum > maxSeqSeen) {
            long diff = seqNum - maxSeqSeen;
            if (diff < windowSize) {
                // Shift bitmap left by diff positions
                for (int i = windowSize - 1; i >= diff; i--) {
                    receivedBitmap.set(i, receivedBitmap.get((int) (i - diff)));
                }
                for (int i = 0; i < diff && i < windowSize; i++) {
                    receivedBitmap.clear(i);
                }
            } else {
                // Window completely passed; clear all previous history
                receivedBitmap.clear();
            }
            maxSeqSeen = seqNum;
            receivedBitmap.set(0);
            return true;
        }

        // 4. Packet is older than or equal to maxSeqSeen
        long diff = maxSeqSeen - seqNum;

        // 4a. Packet is too old (outside sliding window)
        if (diff >= windowSize) {
            throw new SecurityException(String.format(
                    "Replay Defense Violation: Stale sequence number %d is outside replay window (Window Size: %d, Max Seen: %d, Diff: %d)",
                    seqNum, windowSize, maxSeqSeen, diff
            ));
        }

        int bitIndex = (int) diff;

        // 4b. Duplicate packet check
        if (receivedBitmap.get(bitIndex)) {
            throw new SecurityException(String.format(
                    "Replay Defense Violation: Duplicate sequence number detected: %d (already processed)",
                    seqNum
            ));
        }

        // 4c. Valid out-of-order packet within sliding window
        receivedBitmap.set(bitIndex);
        return true;
    }

    // Test seam
    public synchronized long getMaxSeqSeen() {
        return maxSeqSeen;
    }

    public synchronized void reset() {
        this.maxSeqSeen = 0;
        this.receivedBitmap.clear();
    }
}

