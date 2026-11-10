package com.officevpn.server;

import com.officevpn.config.ConfigUtil;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Thread-safe Virtual IP Lease Pool Manager for the private VPN subnet (10.8.0.0/24).
 * <p>
 * Subnet Topology:
 * <ul>
 *   <li>{@code 10.8.0.1}: Reserved statically for the Headquarters VPN Gateway Server.</li>
 *   <li>{@code 10.8.0.2} to {@code 10.8.0.254}: Dynamically leased to authenticated employee tunnels.</li>
 *   <li>{@code 10.8.0.255}: Reserved for subnet broadcast.</li>
 * </ul>
 */
public final class VirtualIpPool {

    public static final String GATEWAY_SERVER_IP = ConfigUtil.getGatewayVirtualIp();
    public static final int SUBNET_MIN_HOST = 2;
    public static final int SUBNET_MAX_HOST = 254;
    private static final String SUBNET_PREFIX = ConfigUtil.getSubnetPrefix();

    public record Lease(String virtualIp, String username, String ownerToken) {}

    private final Map<String, Lease> ipToLeaseMap = new TreeMap<>();
    private final Map<String, Lease> userToLeaseMap = new LinkedHashMap<>();

    public VirtualIpPool() {
    }

    /**
     * Leases the lowest available virtual IP in the range 10.8.0.2 to 10.8.0.254 to the given user.
     *
     * @param username Authenticated employee username
     * @return Leased virtual IP string (e.g. "10.8.0.2")
     * @throws IllegalStateException If the IP pool is exhausted
     */
    public synchronized String acquireIp(String username) {
        return acquireIp(username, "default");
    }

    /**
     * Leases a virtual IP for the given user recording the specified owner token.
     * If the user already holds a lease, updates the owner token and returns the existing VIP.
     *
     * @param username   Authenticated employee username
     * @param ownerToken Token identifying the session owning this lease
     * @return Leased virtual IP string
     */
    public synchronized String acquireIp(String username, String ownerToken) {
        Objects.requireNonNull(username, "Username cannot be null");
        String token = (ownerToken != null) ? ownerToken : "";

        // If user already has an active lease, re-use existing assigned IP and update token
        if (userToLeaseMap.containsKey(username)) {
            Lease existing = userToLeaseMap.get(username);
            Lease updated = new Lease(existing.virtualIp(), username, token);
            userToLeaseMap.put(username, updated);
            ipToLeaseMap.put(existing.virtualIp(), updated);
            return existing.virtualIp();
        }

        for (int host = SUBNET_MIN_HOST; host <= SUBNET_MAX_HOST; host++) {
            String candidateIp = SUBNET_PREFIX + host;
            if (!ipToLeaseMap.containsKey(candidateIp)) {
                Lease lease = new Lease(candidateIp, username, token);
                ipToLeaseMap.put(candidateIp, lease);
                userToLeaseMap.put(username, lease);
                return candidateIp;
            }
        }

        throw new IllegalStateException("VPN Subnet IP Pool Exhausted (all leases 10.8.0.2 to 10.8.0.254 occupied)");
    }

    /**
     * Releases a leased virtual IP only if the owner token matches the active lease.
     *
     * @param username   Username whose lease is being released
     * @param ownerToken Owner token of the session performing release
     * @return true if the lease was released; false if token did not match or no lease existed
     */
    public synchronized boolean releaseIp(String username, String ownerToken) {
        if (username == null) {
            return false;
        }
        Lease lease = userToLeaseMap.get(username);
        if (lease != null) {
            if (ownerToken == null || Objects.equals(lease.ownerToken(), ownerToken)) {
                userToLeaseMap.remove(username);
                ipToLeaseMap.remove(lease.virtualIp());
                return true;
            }
        }
        return false;
    }

    /**
     * Releases a leased virtual IP back into the available pool.
     *
     * @param virtualIp Virtual IP to release
     */
    public synchronized void releaseIp(String virtualIp) {
        if (virtualIp == null || virtualIp.trim().isEmpty()) {
            return;
        }
        Lease lease = ipToLeaseMap.remove(virtualIp);
        if (lease != null) {
            userToLeaseMap.remove(lease.username());
        }
    }

    // Test seam
    synchronized String getUsernameForIp(String virtualIp) {
        Lease l = ipToLeaseMap.get(virtualIp);
        return l != null ? l.username() : null;
    }

    // Test seam
    synchronized String getIpForUser(String username) {
        Lease l = userToLeaseMap.get(username);
        return l != null ? l.virtualIp() : null;
    }

    // Test seam
    synchronized String getOwnerToken(String username) {
        Lease l = userToLeaseMap.get(username);
        return l != null ? l.ownerToken() : null;
    }

    // Test seam
    synchronized Map<String, String> getActiveLeases() {
        Map<String, String> map = new TreeMap<>();
        for (Map.Entry<String, Lease> e : ipToLeaseMap.entrySet()) {
            map.put(e.getKey(), e.getValue().username());
        }
        return Collections.unmodifiableMap(map);
    }
}

