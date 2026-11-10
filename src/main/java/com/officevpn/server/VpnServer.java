package com.officevpn.server;

import com.officevpn.config.ConfigUtil;
import com.officevpn.db.DatabaseManager;
import com.officevpn.security.IdentityException;
import com.officevpn.security.ServerIdentity;
import com.officevpn.storage.VaultManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

/**
 * Enterprise VPN Server entry point and facade delegating to {@link VpnGatewayServer}.
 * Handles configuration discovery, server identity management, graceful shutdown hooks,
 * and startup diagnostics banner.
 */
public final class VpnServer implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(VpnServer.class);

    private final DatabaseManager databaseManager;
    private final VaultManager vaultManager;
    private final ServerIdentity serverIdentity;
    private final VpnGatewayServer gatewayServer;
    private final int port;

    public VpnServer() {
        this(ConfigUtil.getPort());
    }

    public VpnServer(int port) {
        this(port, new DatabaseManager(), new VaultManager(Path.of("server_vaults")), resolveServerIdentity());
    }

    public VpnServer(int port, DatabaseManager db, VaultManager vaultManager, ServerIdentity identity) {
        this.port = port;
        this.databaseManager = Objects.requireNonNull(db, "DatabaseManager cannot be null");
        this.vaultManager = Objects.requireNonNull(vaultManager, "VaultManager cannot be null");
        this.serverIdentity = Objects.requireNonNull(identity, "ServerIdentity cannot be null");
        this.gatewayServer = new VpnGatewayServer(this.databaseManager, this.vaultManager, this.serverIdentity);
    }

    public static ServerIdentity resolveServerIdentity() {
        if (Boolean.getBoolean("officevpn.demo")) {
            LOGGER.info("Starting with in-memory ephemeral server identity (-Dofficevpn.demo=true)");
            return ServerIdentity.createEphemeral();
        }

        char[] passphrase = null;
        String envPass = System.getenv("OFFICEVPN_KEYSTORE_PASS");
        if (envPass != null && !envPass.isBlank()) {
            passphrase = envPass.toCharArray();
        } else if (System.getProperty("officevpn.keystore.pass") != null) {
            passphrase = System.getProperty("officevpn.keystore.pass").toCharArray();
        } else if (System.console() != null) {
            passphrase = System.console().readPassword("Enter server identity keystore passphrase (min 12 characters): ");
        }

        if (passphrase == null || passphrase.length == 0) {
            throw new IllegalStateException(
                    "Server identity keystore passphrase required. Provide via OFFICEVPN_KEYSTORE_PASS environment variable, " +
                    "-Dofficevpn.keystore.pass system property, interactive console, or run with -Dofficevpn.demo=true for ephemeral testing."
            );
        }

        if (passphrase.length < 12) {
            Arrays.fill(passphrase, '\0');
            throw new IllegalArgumentException("Keystore passphrase must be at least 12 characters.");
        }

        try {
            return ServerIdentity.loadOrCreate(null, passphrase, true);
        } catch (IdentityException e) {
            LOGGER.error("CRITICAL: Failed to decrypt server identity keystore: {}", e.getMessage());
            LOGGER.error("If server_identity.key was encrypted with a different passphrase, delete server_identity.key to regenerate, and have clients re-pin the new fingerprint.");
            throw new IllegalStateException("Server identity initialization failed: " + e.getMessage(), e);
        } finally {
            if (passphrase != null) {
                Arrays.fill(passphrase, '\0');
            }
        }
    }

    /**
     * Starts the VPN Gateway Server on the configured port.
     */
    public synchronized void start() throws IOException {
        gatewayServer.start(port);
        LOGGER.info("Office VPN Server started on port {} with SHA-256 fingerprint: {}",
                gatewayServer.getBoundPort(), serverIdentity.fingerprintHex());
    }

    /**
     * Gracefully stops the VPN Gateway Server and closes associated resources.
     */
    public synchronized void stop() {
        gatewayServer.stop();
        LOGGER.info("Office VPN Server stopped.");
    }

    @Override
    public void close() {
        stop();
        databaseManager.close();
    }

    public int getPort() {
        return gatewayServer.getBoundPort() > 0 ? gatewayServer.getBoundPort() : port;
    }

    public boolean isRunning() {
        return gatewayServer.isRunning();
    }

    public VpnGatewayServer getGatewayServer() {
        return gatewayServer;
    }

    public DatabaseManager getDatabaseManager() {
        return databaseManager;
    }

    public VaultManager getVaultManager() {
        return vaultManager;
    }

    public ServerIdentity getServerIdentity() {
        return serverIdentity;
    }

    public static void printBanner(int port, String fingerprint) {
        LOGGER.info("========================================================================");
        LOGGER.info("       OFFICE VPN GATEWAY SERVER - ENTERPRISE ZERO TRUST");
        LOGGER.info("       Runtime: Java {} | Port: {} | Gateway Virtual IP: {}",
                System.getProperty("java.version"), port, VirtualIpPool.GATEWAY_SERVER_IP);
        LOGGER.info("       Protocol: OFFICE-VPN-2.0 (AES-256-GCM + Ephemeral ECDH + RSASSA-PSS)");
        LOGGER.info("       Server Key Fingerprint: {}", fingerprint);
        LOGGER.info("========================================================================");
    }

    public static void main(String[] args) {
        int targetPort = args.length > 0 ? Integer.parseInt(args[0]) : ConfigUtil.getPort();
        VpnServer server = new VpnServer(targetPort);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOGGER.info("JVM shutdown initiated; stopping Office VPN Server...");
            server.close();
        }, "vpn-shutdown-hook"));

        try {
            server.start();
            printBanner(server.getPort(), server.getServerIdentity().fingerprintHex());
            LOGGER.info("Office VPN Gateway is active. Press Ctrl+C to terminate.");

            // Keep main thread alive
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.info("VPN Server thread interrupted; exiting.");
        } catch (Exception e) {
            LOGGER.error("Fatal error starting Office VPN Server: {}", e.getMessage(), e);
        } finally {
            server.close();
        }
    }
}
