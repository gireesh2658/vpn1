package com.officevpn.tunnel;

import com.officevpn.config.ConfigUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Application-level Tunnel Manager controlling Split Tunneling and Full Tunneling routing decisions.
 * Evaluates whether outbound application traffic must be tunneled through the encrypted VPN session
 * or bypassed directly to the local network/internet.
 */
public final class TunnelManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(TunnelManager.class);

    public enum TunnelMode {
        SPLIT,
        FULL
    }

    private volatile TunnelMode mode;
    private final Set<String> officeDomains = new CopyOnWriteArraySet<>();
    private final List<String> officeSubnets = new ArrayList<>(ConfigUtil.getOfficeSubnets());
    private final List<String> bypassRoutes = new ArrayList<>(ConfigUtil.getTunnelBypassRoutes());
    private final String subnetPrefix = ConfigUtil.getSubnetPrefix();
    private final String branchSubnetPrefix = ConfigUtil.getBranchSubnetPrefix();

    public TunnelManager() {
        this(resolveInitialMode());
    }

    public TunnelManager(TunnelMode mode) {
        this.mode = Objects.requireNonNull(mode, "TunnelMode cannot be null");
        this.officeDomains.addAll(ConfigUtil.getOfficeDomains());
        // Default fallbacks
        this.officeDomains.add("office.local");
        this.officeDomains.add("officevpn.local");
    }

    private static TunnelMode resolveInitialMode() {
        String configured = ConfigUtil.getTunnelMode();
        try {
            return TunnelMode.valueOf(configured.trim().toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            return TunnelMode.SPLIT;
        }
    }

    public TunnelMode getMode() {
        return mode;
    }

    public void setMode(TunnelMode mode) {
        this.mode = Objects.requireNonNull(mode, "TunnelMode cannot be null");
        LOGGER.info("Tunnel mode updated to: {}", mode);
    }

    /**
     * Determines whether outbound traffic to a specific destination host/IP should route through the VPN tunnel.
     *
     * @param destinationHost target hostname (e.g. "files.office.local", "google.com")
     * @param destinationIp   target IP address (e.g. "10.8.0.1", "142.250.190.46")
     * @return true if traffic must route through the encrypted tunnel; false if direct bypass is allowed
     */
    public boolean shouldRouteThroughVpn(String destinationHost, String destinationIp) {
        String host = destinationHost != null ? destinationHost.trim().toLowerCase(Locale.ROOT) : "";
        String ip = destinationIp != null ? destinationIp.trim() : "";

        // Localhost bypass is never routed through VPN
        if (isLocalhost(host) || isLocalhost(ip)) {
            return false;
        }

        // FULL Tunneling: Route everything through VPN except localhost
        if (mode == TunnelMode.FULL) {
            return true;
        }

        // SPLIT Tunneling: Route only office subnet, office domains, and marked office private IPs
        // 1. Check office IP subnets (10.8.0.x, 10.9.0.x)
        if (isOfficeIp(ip)) {
            return true;
        }

        // 2. Check office domain suffixes
        if (!host.isEmpty()) {
            for (String domain : officeDomains) {
                if (host.equals(domain) || host.endsWith("." + domain)) {
                    return true;
                }
            }
        }

        // All other public internet destinations (e.g. google.com, 8.8.8.8) bypass the VPN in SPLIT mode
        return false;
    }

    private boolean isLocalhost(String target) {
        return target.equals("127.0.0.1") || target.equals("localhost") || target.equals("::1");
    }

    public boolean isOfficeIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return false;
        }
        return ip.startsWith(subnetPrefix) || ip.startsWith(branchSubnetPrefix);
    }

    public List<String> getOfficeRoutes() {
        List<String> routes = new ArrayList<>(officeSubnets);
        routes.addAll(officeDomains);
        return Collections.unmodifiableList(routes);
    }

    public List<String> getBypassRoutes() {
        return Collections.unmodifiableList(bypassRoutes);
    }

    public void addOfficeDomain(String domain) {
        if (domain != null && !domain.isBlank()) {
            officeDomains.add(domain.trim().toLowerCase(Locale.ROOT));
        }
    }
}

