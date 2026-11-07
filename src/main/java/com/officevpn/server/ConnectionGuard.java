package com.officevpn.server;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Pre-authentication Connection &amp; Rate-Limiting Guard.
 * <p>
 * Enforces global concurrent connection caps, per-IP unauthenticated quotas, and per-IP
 * token-bucket handshake rate limits without blocking threads or creating audit-flood vectors.
 */
public final class ConnectionGuard {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionGuard.class);

    public enum RejectionReason {
        GLOBAL_CAP,
        IP_UNAUTH_CAP,
        RATE_LIMIT,
        POOL_FULL,
        DEADLINE
    }

    private static final long IDLE_ENTRY_TTL_MILLIS = 10 * 60 * 1000L; // 10 minutes
    private static final long LOG_RATE_LIMIT_MILLIS = 5000L;            // 5 seconds

    private final ServerLimits limits;
    private final LongSupplier clockMillis;

    private final AtomicInteger currentGlobalConnections = new AtomicInteger(0);
    private final Map<RejectionReason, AtomicLong> rejectionCounters = new java.util.EnumMap<>(RejectionReason.class);
    private final Map<RejectionReason, Long> lastLogTimes = new java.util.EnumMap<>(RejectionReason.class);

    static final class IpState {
        double tokens;
        long lastRefillMillis;
        int unauthConnections;
        int totalConnections;
        long lastActiveMillis;

        IpState(double initialTokens, long now) {
            this.tokens = initialTokens;
            this.lastRefillMillis = now;
            this.unauthConnections = 0;
            this.totalConnections = 0;
            this.lastActiveMillis = now;
        }

        void refill(int capacity, long now) {
            if (now > lastRefillMillis) {
                double elapsedSeconds = (now - lastRefillMillis) / 1000.0;
                double refillRatePerSecond = capacity / 60.0;
                this.tokens = Math.min(capacity, this.tokens + (elapsedSeconds * refillRatePerSecond));
                this.lastRefillMillis = now;
            }
        }
    }

    private final Map<String, IpState> ipStateMap;

    public ConnectionGuard(ServerLimits limits) {
        this(limits, System::currentTimeMillis);
    }

    public ConnectionGuard(ServerLimits limits, LongSupplier clockMillis) {
        this.limits = Objects.requireNonNull(limits, "ServerLimits cannot be null");
        this.clockMillis = Objects.requireNonNull(clockMillis, "Clock supplier cannot be null");

        for (RejectionReason r : RejectionReason.values()) {
            rejectionCounters.put(r, new AtomicLong(0));
            lastLogTimes.put(r, 0L);
        }

        this.ipStateMap = new LinkedHashMap<String, IpState>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, IpState> eldest) {
                return size() > limits.getTrackedIpCap();
            }
        };
    }

    /**
     * Opaque connection permit holding tracking counters for a live connection.
     */
    public final class Permit {
        private final String ip;
        private final AtomicBoolean unauthHeld = new AtomicBoolean(true);
        private final AtomicBoolean released = new AtomicBoolean(false);

        Permit(String ip) {
            this.ip = ip;
        }

        public void markAuthenticated() {
            if (unauthHeld.compareAndSet(true, false)) {
                decrementUnauth(ip);
            }
        }

        public void release() {
            if (released.compareAndSet(false, true)) {
                if (unauthHeld.compareAndSet(true, false)) {
                    decrementUnauth(ip);
                }
                decrementGlobal(ip);
            }
        }
    }

    public Permit tryAccept(InetAddress inetAddress) {
        if (inetAddress == null) {
            return tryAccept("UNKNOWN");
        }
        return tryAccept(inetAddress.getHostAddress());
    }

    public synchronized Permit tryAccept(String rawIp) {
        String ip = normalizeIp(rawIp);
        long now = clockMillis.getAsLong();

        // 0. Periodic LRU cleanup of idle entries
        cleanupIdleEntries(now);

        // 1. Global Connection Cap
        if (currentGlobalConnections.get() >= limits.getMaxConnections()) {
            recordRejection(RejectionReason.GLOBAL_CAP);
            return null;
        }

        // 2. Fetch or create Per-IP state
        IpState state = ipStateMap.get(ip);
        if (state == null) {
            state = new IpState(limits.getPerIpHandshakesPerMinute(), now);
            ipStateMap.put(ip, state);
        }

        // 3. Per-IP Unauthenticated Connection Cap
        if (state.unauthConnections >= limits.getPerIpUnauthMax()) {
            recordRejection(RejectionReason.IP_UNAUTH_CAP);
            return null;
        }

        // 4. Per-IP Token Bucket Rate Limiting
        state.refill(limits.getPerIpHandshakesPerMinute(), now);
        if (state.tokens < 1.0) {
            recordRejection(RejectionReason.RATE_LIMIT);
            return null;
        }

        // Grant permit: consume 1 token and increment connection counts
        state.tokens -= 1.0;
        state.unauthConnections++;
        state.totalConnections++;
        state.lastActiveMillis = now;
        currentGlobalConnections.incrementAndGet();

        return new Permit(ip);
    }

    private synchronized void decrementUnauth(String ip) {
        IpState state = ipStateMap.get(ip);
        if (state != null) {
            if (state.unauthConnections > 0) {
                state.unauthConnections--;
            }
            state.lastActiveMillis = clockMillis.getAsLong();
        }
    }

    private synchronized void decrementGlobal(String ip) {
        currentGlobalConnections.decrementAndGet();
        IpState state = ipStateMap.get(ip);
        if (state != null) {
            if (state.totalConnections > 0) {
                state.totalConnections--;
            }
            state.lastActiveMillis = clockMillis.getAsLong();
        }
    }

    private void cleanupIdleEntries(long now) {
        Iterator<Map.Entry<String, IpState>> it = ipStateMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, IpState> entry = it.next();
            IpState state = entry.getValue();
            if (state.totalConnections <= 0 && (now - state.lastActiveMillis > IDLE_ENTRY_TTL_MILLIS)) {
                it.remove();
            }
        }
    }

    public synchronized void recordRejection(RejectionReason reason) {
        AtomicLong counter = rejectionCounters.get(reason);
        if (counter != null) {
            counter.incrementAndGet();
        }
        long now = clockMillis.getAsLong();
        Long lastLog = lastLogTimes.get(reason);
        if (lastLog == null || (now - lastLog >= LOG_RATE_LIMIT_MILLIS)) {
            lastLogTimes.put(reason, now);
            LOGGER.warn("Connection rejected: {} (total count: {})", reason, (counter != null ? counter.get() : 1));
        }
    }

    // Test seam
    long getRejectionCount(RejectionReason reason) {
        AtomicLong counter = rejectionCounters.get(reason);
        return counter != null ? counter.get() : 0L;
    }

    // Test seam
    int getCurrentGlobalConnections() {
        return currentGlobalConnections.get();
    }

    // Test seam
    synchronized int getTrackedIpCount() {
        return ipStateMap.size();
    }

    // Test seam
    synchronized int getUnauthCountForIp(String rawIp) {
        IpState state = ipStateMap.get(normalizeIp(rawIp));
        return state != null ? state.unauthConnections : 0;
    }

    public static String normalizeIp(String rawIp) {
        if (rawIp == null || rawIp.trim().isEmpty()) {
            return "UNKNOWN";
        }
        String clean = rawIp.trim();
        if (clean.startsWith("/")) {
            clean = clean.substring(1);
        }
        // If string contains port e.g. 127.0.0.1:54321 or [::1]:54321
        if (clean.startsWith("[") && clean.contains("]")) {
            clean = clean.substring(1, clean.indexOf(']'));
        } else if (clean.indexOf(':') != -1 && clean.indexOf(':') == clean.lastIndexOf(':')) {
            // IPv4 with port e.g. "127.0.0.1:8080"
            clean = clean.substring(0, clean.indexOf(':'));
        }

        try {
            return InetAddress.getByName(clean).getHostAddress();
        } catch (UnknownHostException e) {
            return clean;
        }
    }
}

