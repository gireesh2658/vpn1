package com.officevpn.admin;

import com.officevpn.server.VpnGatewayServer;
import com.officevpn.server.VirtualIpPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Objects;

/**
 * Enterprise Server Lifecycle Manager controlling start, stop, restart,
 * and port monitoring. Delegates all underlying networking to {@link VpnGatewayServer}.
 */
public final class ServerManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(ServerManager.class);

    private final VpnGatewayServer gatewayServer;
    private long startedAtMs = 0L;

    public ServerManager(VpnGatewayServer gatewayServer) {
        this.gatewayServer = Objects.requireNonNull(gatewayServer, "VpnGatewayServer cannot be null");
        if (gatewayServer.isRunning()) {
            this.startedAtMs = System.currentTimeMillis();
        }
    }

    /**
     * Starts listening on the specified port.
     */
    public synchronized void startServer(int port) throws IOException {
        if (gatewayServer.isRunning()) {
            LOGGER.info("Server is already running on port {}", gatewayServer.getBoundPort());
            return;
        }
        gatewayServer.start(port);
        this.startedAtMs = System.currentTimeMillis();
        LOGGER.info("Server started successfully on port {}", gatewayServer.getBoundPort());
    }

    /**
     * Stops the gateway server and terminates active client sessions.
     */
    public synchronized void stopServer() {
        if (!gatewayServer.isRunning()) {
            return;
        }
        gatewayServer.stop();
        this.startedAtMs = 0L;
        LOGGER.info("Server stopped successfully.");
    }

    /**
     * Restarts the gateway server on the specified port.
     */
    public synchronized void restartServer(int port) throws IOException {
        LOGGER.info("Restarting VPN Gateway Server...");
        stopServer();
        try {
            Thread.sleep(150);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        startServer(port);
    }

    /**
     * Returns server operational status: "RUNNING" or "STOPPED".
     */
    public String getServerStatus() {
        return gatewayServer.isRunning() ? "RUNNING" : "STOPPED";
    }

    /**
     * Returns the bound TCP listening port, or -1 if stopped.
     */
    public int getBoundPort() {
        return gatewayServer.getBoundPort();
    }

    /**
     * Returns the central VPN Gateway Intranet IP (10.8.0.1).
     */
    public String getGatewayIp() {
        return VirtualIpPool.GATEWAY_SERVER_IP;
    }

    /**
     * Returns server uptime in seconds.
     */
    public long getUptimeSeconds() {
        if (!gatewayServer.isRunning() || startedAtMs == 0L) {
            return 0L;
        }
        return (System.currentTimeMillis() - startedAtMs) / 1000L;
    }

    public VpnGatewayServer getGatewayServer() {
        return gatewayServer;
    }
}

