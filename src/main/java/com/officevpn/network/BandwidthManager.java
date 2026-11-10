package com.officevpn.network;

import com.officevpn.config.ConfigUtil;
import com.officevpn.db.DatabaseManager;
import com.officevpn.model.Department;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Enterprise Token-Bucket Bandwidth Rate Limiter.
 * Enforces per-user and per-department egress/ingress throughput limits:
 * - Rate: configured in Kbps (kilobits per second)
 * - Bucket Capacity (Burst): 2x configured sustained rate
 * - Departamental default allocations:
 *     - HEADQUARTERS: 51.2 Mbps (51,200 Kbps)
 *     - IT: 51.2 Mbps (51,200 Kbps)
 *     - FINANCE: 20.48 Mbps (20,480 Kbps)
 *     - HR: 10.24 Mbps (10,240 Kbps)
 */
public final class BandwidthManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(BandwidthManager.class);

    private static class TokenBucket {
        final long capacityBytes;
        final long refillRateBytesPerSec;
        double currentTokens;
        long lastRefillTime;

        TokenBucket(int kbps) {
            long bytesPerSec = (kbps * 1000L) / 8L;
            this.refillRateBytesPerSec = bytesPerSec;
            this.capacityBytes = bytesPerSec * 2L; // 2x burst
            this.currentTokens = capacityBytes;
            this.lastRefillTime = System.currentTimeMillis();
        }

        synchronized boolean tryConsume(int bytes) {
            refill();
            if (currentTokens >= bytes) {
                currentTokens -= bytes;
                return true;
            }
            return false;
        }

        synchronized long getRemainingBytes() {
            refill();
            return (long) currentTokens;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            long elapsed = now - lastRefillTime;
            if (elapsed > 0) {
                double added = (elapsed / 1000.0) * refillRateBytesPerSec;
                currentTokens = Math.min(capacityBytes, currentTokens + added);
                lastRefillTime = now;
            }
        }
    }

    private final DatabaseManager databaseManager;
    private final boolean enabled;
    private final Map<String, TokenBucket> userBuckets = new ConcurrentHashMap<>();
    private final Map<String, AtomicLong> pendingAllowedBytes = new ConcurrentHashMap<>();
    private final Map<String, Integer> userCustomLimits = new ConcurrentHashMap<>();
    private final Map<Department, Integer> departmentLimits = new ConcurrentHashMap<>();

    public BandwidthManager(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
        this.enabled = ConfigUtil.isBandwidthEnabled();
        initDepartmentLimits();
    }

    private void initDepartmentLimits() {
        departmentLimits.put(Department.HEADQUARTERS, 51_200); // 51.2 Mbps
        departmentLimits.put(Department.IT, 51_200);           // 51.2 Mbps
        departmentLimits.put(Department.FINANCE, 20_480);      // 20.48 Mbps
        departmentLimits.put(Department.HR, 10_240);           // 10.24 Mbps
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setLimitForUser(String username, int kbps) {
        Objects.requireNonNull(username, "Username cannot be null");
        userCustomLimits.put(username, kbps);
        userBuckets.put(username, new TokenBucket(kbps));
        LOGGER.info("Set custom bandwidth limit for user {}: {} Kbps", username, kbps);
    }

    public void setLimitForDepartment(Department dept, int kbps) {
        Objects.requireNonNull(dept, "Department cannot be null");
        departmentLimits.put(dept, kbps);
        LOGGER.info("Set bandwidth limit for department {}: {} Kbps", dept, kbps);
    }

    public int getLimitForDepartment(Department dept) {
        return departmentLimits.getOrDefault(dept, ConfigUtil.getDefaultKbpsPerUser());
    }

    public int getLimitForUser(String username, Department dept) {
        if (username != null && userCustomLimits.containsKey(username)) {
            return userCustomLimits.get(username);
        }
        if (dept != null && departmentLimits.containsKey(dept)) {
            return departmentLimits.get(dept);
        }
        return ConfigUtil.getDefaultKbpsPerUser();
    }

    /**
     * Attempts to consume token budget for outbound/inbound transmission.
     *
     * @param username user transmitting payload
     * @param bytes    size in bytes
     * @return true if permitted within bandwidth allocation; false if throttled
     */
    public boolean tryConsume(String username, int bytes) {
        return tryConsume(username, Department.HR, bytes);
    }

    public boolean tryConsume(String username, Department dept, int bytes) {
        if (!enabled || username == null) {
            return true;
        }

        TokenBucket bucket = userBuckets.computeIfAbsent(username, u -> {
            int kbps = getLimitForUser(u, dept);
            return new TokenBucket(kbps);
        });

        boolean allowed = bucket.tryConsume(bytes);
        if (!allowed) {
            LOGGER.warn("BANDWIDTH_THROTTLED: User '{}' exceeded throughput quota (requested {} bytes)", username, bytes);
            if (databaseManager != null && !databaseManager.isClosed()) {
                databaseManager.logBandwidthConsumption(username, 0, bytes);
            }
        } else if (databaseManager != null && !databaseManager.isClosed() && bytes > 0) {
            AtomicLong acc = pendingAllowedBytes.computeIfAbsent(username, k -> new AtomicLong(0L));
            long current = acc.addAndGet(bytes);
            if (current >= 1024L) {
                long toFlush = acc.getAndSet(0L);
                if (toFlush > 0) {
                    databaseManager.logBandwidthConsumption(username, toFlush, 0);
                }
            }
        }
        return allowed;
    }

    public long getRemainingTokens(String username) {
        if (username == null) return 0L;
        TokenBucket b = userBuckets.get(username);
        return b != null ? b.getRemainingBytes() : 0L;
    }
}

