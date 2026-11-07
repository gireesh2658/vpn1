package com.officevpn.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Application-level Kill Switch Manager.
 * Prevents unencrypted data leakage when the VPN tunnel terminates unexpectedly.
 * When activated (BLOCKING), all outbound traffic is dropped except for localhost loopback
 * and direct reconnection to the VPN gateway.
 */
public final class KillSwitchManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(KillSwitchManager.class);

    public enum State {
        ENABLED,
        DISABLED,
        BLOCKING
    }

    public interface KillSwitchListener {
        void onKillSwitchStateChanged(State newState, String reason);
    }

    private volatile State state = State.ENABLED;
    private volatile boolean tunnelConnected = false;
    private final List<KillSwitchListener> listeners = new CopyOnWriteArrayList<>();

    public KillSwitchManager() {}

    public State getState() {
        return state;
    }

    public boolean isTunnelConnected() {
        return tunnelConnected;
    }

    /**
     * Re-arms the kill switch into standard protection mode.
     */
    public synchronized void enable() {
        this.state = State.ENABLED;
        LOGGER.info("Kill switch has been ENABLED.");
        notifyListeners("Kill switch enabled");
    }

    /**
     * Manually disables the kill switch. Requires user/operator identification.
     *
     * @param user   admin or employee username performing override
     * @param reason administrative justification
     */
    public synchronized void disable(String user, String reason) {
        String actor = user != null ? user : "UNKNOWN";
        this.state = State.DISABLED;
        LOGGER.warn("KILL SWITCH MANUALLY DISABLED by user '{}'. Justification: {}", actor, reason);
        notifyListeners("Manually disabled by " + actor);
    }

    /**
     * Invoked when the VPN client successfully establishes an encrypted tunnel.
     */
    public synchronized void onTunnelConnected() {
        this.tunnelConnected = true;
        if (state == State.BLOCKING) {
            this.state = State.ENABLED;
            LOGGER.info("Tunnel re-established; kill switch cleared from BLOCKING to ENABLED.");
            notifyListeners("Tunnel re-connected; traffic unblocked");
        }
    }

    /**
     * Invoked when the VPN tunnel drops unexpectedly (network partition, timeout, server reset).
     */
    public synchronized void onTunnelDisconnectedUnexpectedly() {
        this.tunnelConnected = false;
        if (state == State.ENABLED) {
            this.state = State.BLOCKING;
            LOGGER.error("KILL SWITCH ACTIVATED: Tunnel unexpectedly disconnected. All non-VPN network egress BLOCKED.");
            notifyListeners("KILL SWITCH ACTIVE - Traffic Blocked");
        }
    }

    /**
     * Invoked on voluntary, clean user logout.
     */
    public synchronized void onCleanDisconnect() {
        this.tunnelConnected = false;
        if (state == State.BLOCKING) {
            this.state = State.ENABLED;
        }
        notifyListeners("Clean disconnect");
    }

    /**
     * Evaluates whether outbound traffic to a destination is permitted.
     *
     * @param destination destination hostname or IP address
     * @return true if permitted; false if blocked by kill switch
     */
    public boolean isTrafficAllowed(String destination) {
        if (state == State.DISABLED) {
            LOGGER.warn("Traffic egress permitted to '{}' under DISABLED kill switch protection", destination);
            return true;
        }

        if (state == State.BLOCKING) {
            // Under BLOCKING state, permit only localhost and VPN gateway
            if (isLocalhostOrGateway(destination)) {
                return true;
            }
            LOGGER.warn("Outbound traffic to '{}' BLOCKED by active Kill Switch", destination);
            return false;
        }

        // State is ENABLED
        if (tunnelConnected) {
            return true;
        }

        // Tunnel not connected yet; permit gateway and localhost setup
        return isLocalhostOrGateway(destination);
    }

    private boolean isLocalhostOrGateway(String destination) {
        if (destination == null || destination.isBlank()) {
            return true;
        }
        String clean = destination.trim();
        return clean.equals("127.0.0.1")
                || clean.equalsIgnoreCase("localhost")
                || clean.equals("::1")
                || clean.equals("10.8.0.1");
    }

    public void addListener(KillSwitchListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeListener(KillSwitchListener listener) {
        listeners.remove(listener);
    }

    private void notifyListeners(String reason) {
        for (KillSwitchListener l : listeners) {
            try {
                l.onKillSwitchStateChanged(state, reason);
            } catch (Exception e) {
                LOGGER.debug("Error delivering kill switch event: {}", e.getMessage());
            }
        }
    }
}

