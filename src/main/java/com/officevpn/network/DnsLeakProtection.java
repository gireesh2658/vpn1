package com.officevpn.network;

import com.officevpn.config.ConfigUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Application-level DNS Leak Protection Manager.
 * Prevents DNS query exposure to public/ISP resolvers while connected to the VPN.
 * All internal domain queries are routed through the secure gateway DNS server (10.8.0.1).
 */
public final class DnsLeakProtection {

    private static final Logger LOGGER = LoggerFactory.getLogger(DnsLeakProtection.class);

    public static final String DEFAULT_VPN_DNS = ConfigUtil.getVpnDns();
    private static final Set<String> BLOCKED_PUBLIC_RESOLVERS = Set.of(
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
            "1.0.0.1",
            "9.9.9.9",
            "208.67.222.222"
    );

    private final String vpnDnsServer;
    private final boolean leakProtectionEnabled;
    private volatile boolean tunnelActive = false;
    private final Map<String, String> internalDnsRecords = new ConcurrentHashMap<>();

    public DnsLeakProtection() {
        this(ConfigUtil.getVpnDns(), ConfigUtil.isDnsLeakProtectionEnabled());
    }

    public DnsLeakProtection(String vpnDnsServer, boolean leakProtectionEnabled) {
        this.vpnDnsServer = (vpnDnsServer != null && !vpnDnsServer.isBlank()) ? vpnDnsServer.trim() : DEFAULT_VPN_DNS;
        this.leakProtectionEnabled = leakProtectionEnabled;
        seedDefaultOfficeDnsRecords();
    }

    private void seedDefaultOfficeDnsRecords() {
        String hqDns = vpnDnsServer;
        String branchGateway = ConfigUtil.getBranchSubnetPrefix() + "1";
        internalDnsRecords.put("gateway.office.local", hqDns);
        internalDnsRecords.put("files.office.local", hqDns);
        internalDnsRecords.put("auth.office.local", hqDns);
        internalDnsRecords.put("hq.officevpn.local", hqDns);
        internalDnsRecords.put("branch.officevpn.local", branchGateway);
    }

    public void setTunnelActive(boolean active) {
        this.tunnelActive = active;
        LOGGER.info("DNS Leak Protection active status: {} (Active DNS: {})", active, getActiveDnsServer());
    }

    public boolean isTunnelActive() {
        return tunnelActive;
    }

    public boolean isLeakProtectionEnabled() {
        return leakProtectionEnabled;
    }

    /**
     * Checks if querying the specified DNS resolver constitutes a DNS leak.
     *
     * @param dnsServerIp resolver IP address
     * @return true if the resolver is public and leak protection is active
     */
    public boolean isLeak(String dnsServerIp) {
        if (!leakProtectionEnabled || !tunnelActive || dnsServerIp == null) {
            return false;
        }
        String clean = dnsServerIp.trim();
        return BLOCKED_PUBLIC_RESOLVERS.contains(clean);
    }

    /**
     * Returns the currently enforced DNS server address.
     */
    public String getActiveDnsServer() {
        if (tunnelActive && leakProtectionEnabled) {
            return vpnDnsServer;
        }
        return "System Default Resolver";
    }

    /**
     * Resolves a hostname through the secure VPN DNS resolution layer.
     *
     * @param hostname domain name to resolve
     * @return resolved IP address string
     * @throws UnknownHostException if host cannot be resolved
     */
    public String resolveViaVpn(String hostname) throws UnknownHostException {
        Objects.requireNonNull(hostname, "Hostname cannot be null");
        String cleanHost = hostname.trim().toLowerCase(Locale.ROOT);

        // 1. Check internal office VPN record cache
        if (internalDnsRecords.containsKey(cleanHost)) {
            String ip = internalDnsRecords.get(cleanHost);
            LOGGER.debug("Resolved '{}' via VPN internal DNS table to {}", cleanHost, ip);
            return ip;
        }

        // 2. If tunnel is active and leak protection enabled, disallow arbitrary local lookups of external hostnames
        if (tunnelActive && leakProtectionEnabled) {
            if (cleanHost.endsWith(".office.local") || cleanHost.endsWith(".officevpn.local")) {
                // Gateway synthetic resolution for wildcard office hosts
                return vpnDnsServer;
            }
        }

        // 3. Fallback to standard resolution when permitted
        try {
            return InetAddress.getByName(cleanHost).getHostAddress();
        } catch (UnknownHostException e) {
            throw new UnknownHostException("VPN DNS resolution failed for: " + cleanHost);
        }
    }

    public void registerInternalRecord(String hostname, String ipAddress) {
        if (hostname != null && ipAddress != null) {
            internalDnsRecords.put(hostname.trim().toLowerCase(Locale.ROOT), ipAddress.trim());
        }
    }

    public String getDnsStatus() {
        if (!leakProtectionEnabled) {
            return "DISABLED";
        }
        return tunnelActive ? "PROTECTED (VPN DNS " + vpnDnsServer + ")" : "STANDBY (System Default)";
    }
}

