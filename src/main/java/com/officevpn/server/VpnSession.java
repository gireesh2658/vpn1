package com.officevpn.server;

import com.officevpn.model.UserAccount;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.security.CryptoUtils;
import com.officevpn.security.SequenceReplayWindow;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Encapsulates the active cryptographic and network state for a connected VPN client tunnel.
 * <p>
 * Implements strict per-session replay attack protection:
 * <ul>
 *   <li><b>Clock-Skew Window:</b> Rejects any packet whose timestamp deviates by more than &plusmn;5 minutes.</li>
 *   <li><b>IV Uniqueness Cache:</b> Tracks all 12-byte AES-GCM IVs received during this session and rejects duplicates.</li>
 * </ul>
 */
public final class VpnSession {

    public static final long MAX_CLOCK_SKEW_MS = 5 * 60 * 1000L; // 5 minutes
    public static final int MAX_TRACKED_IVS = 10_000;

    private final String sessionId;
    private final String clientSocketAddress;
    private final long connectedAt;
    private volatile long lastActivityAt;

    private volatile String assignedVirtualIp;
    private volatile UserAccount authenticatedUser;
    private volatile CryptoUtils.DirectionalKeys directionalKeys;

    // Thread-safe sliding sequence replay window for client-to-server traffic
    private final SequenceReplayWindow inboundSeqWindow = new SequenceReplayWindow(128);

    // Monotonically increasing sequence generator for server-to-client traffic
    private final AtomicLong serverSendSeq = new AtomicLong(1);

    // Thread-safe bounded cache of seen initialization vectors (Hex strings)
    private final Map<String, Boolean> seenIvHexMap = Collections.synchronizedMap(new LinkedHashMap<>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Boolean> eldest) {
            return size() > MAX_TRACKED_IVS;
        }
    });

    public VpnSession(String sessionId, String clientSocketAddress) {
        this.sessionId = Objects.requireNonNull(sessionId, "Session ID cannot be null");
        this.clientSocketAddress = Objects.requireNonNull(clientSocketAddress, "Socket address cannot be null");
        this.connectedAt = System.currentTimeMillis();
        this.lastActivityAt = this.connectedAt;
    }

    /**
     * Validates packet timestamp freshness and enforces IV uniqueness to prevent replay attacks.
     *
     * @param packet Incoming encrypted VpnPacket
     * @throws SecurityException If replay attack or excessive clock skew is detected
     */
    public synchronized void validateAndRecordPacket(VpnPacket packet) {
        Objects.requireNonNull(packet, "Packet cannot be null");

        long now = System.currentTimeMillis();
        long packetTime = packet.getTimestamp();

        // 1. Clock-skew freshness verification
        if (Math.abs(now - packetTime) > MAX_CLOCK_SKEW_MS) {
            throw new SecurityException(String.format(
                    "Replay Defense Violation: Packet timestamp (%d) exceeds allowable ±5min clock skew (Server: %d)",
                    packetTime, now
            ));
        }

        // 2. IV uniqueness check
        byte[] iv = packet.getIv();
        if (iv != null && iv.length > 0) {
            String ivHex = CryptoUtils.bytesToHex(iv);
            if (seenIvHexMap.put(ivHex, Boolean.TRUE) != null) {
                throw new SecurityException("Replay Attack Detected: AES-GCM IV reused within session: " + ivHex);
            }
        }

        // 3. Sliding sequence-number replay window check (mandatory for authenticated tunnel packets)
        if (packet.hasSequenceNumber()) {
            inboundSeqWindow.checkAndRecord(packet.getSequenceNumber());
        } else if (authenticatedUser != null) {
            throw new SecurityException("Sequence Replay Violation: Authenticated tunnel packet missing required sequence number");
        }

        this.lastActivityAt = now;
    }

    public long getNextServerSendSeq() {
        return serverSendSeq.getAndIncrement();
    }

    public SequenceReplayWindow getInboundSeqWindow() {
        return inboundSeqWindow;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getClientSocketAddress() {
        return clientSocketAddress;
    }

    public long getConnectedAt() {
        return connectedAt;
    }

    public long getLastActivityAt() {
        return lastActivityAt;
    }


    public String getAssignedVirtualIp() {
        return assignedVirtualIp;
    }

    public void setAssignedVirtualIp(String assignedVirtualIp) {
        this.assignedVirtualIp = assignedVirtualIp;
    }

    public UserAccount getAuthenticatedUser() {
        return authenticatedUser;
    }

    public void setAuthenticatedUser(UserAccount authenticatedUser) {
        this.authenticatedUser = authenticatedUser;
    }

    public CryptoUtils.DirectionalKeys getDirectionalKeys() {
        return directionalKeys;
    }

    public void setDirectionalKeys(CryptoUtils.DirectionalKeys directionalKeys) {
        this.directionalKeys = directionalKeys;
    }

    public boolean isAuthenticated() {
        return authenticatedUser != null && assignedVirtualIp != null && directionalKeys != null;
    }

    public long getEstablishedTime() {
        return connectedAt;
    }

    public long getLastActivityTime() {
        return lastActivityAt;
    }

    public void recordActivity() {
        this.lastActivityAt = System.currentTimeMillis();
    }
}
