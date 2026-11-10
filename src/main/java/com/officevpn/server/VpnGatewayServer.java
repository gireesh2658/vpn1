package com.officevpn.server;

import com.officevpn.db.DatabaseManager;
import com.officevpn.network.BandwidthManager;
import com.officevpn.network.SiteToSiteManager;
import com.officevpn.model.UserAccount;
import com.officevpn.protocol.PacketType;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.security.AuditSanitizer;
import com.officevpn.security.CryptoUtils;
import com.officevpn.security.ServerIdentity;
import com.officevpn.storage.VaultManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Headquarters Multithreaded VPN Gateway Server Engine.
 * <p>
 * Coordinates:
 * <ul>
 *   <li>Asymmetric RSA-2048 key encapsulation &amp; RSASSA-PSS handshake transcript authentication.</li>
 *   <li>Dynamic Virtual IP lease management in the {@code 10.8.0.0/24} private intranet subnet.</li>
 *   <li>Database RBAC authentication, user credential verification, and immutable security audit logs.</li>
 *   <li>Hardened symlink-resistant departmental file vaults.</li>
 *   <li>Real-time event and packet sniffer broadcasting to GUI and test harnesses.</li>
 * </ul>
 */
public final class VpnGatewayServer implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(VpnGatewayServer.class);

    private final ServerIdentity serverIdentity;
    private final KeyPair serverKeyPair;
    public record BindResult(String virtualIp, SessionHandle supersededHandle) {}

    private final java.util.concurrent.atomic.AtomicInteger postHandshakeInitPacketCount = new java.util.concurrent.atomic.AtomicInteger(0);

    private final DatabaseManager databaseManager;
    private final VaultManager vaultManager;
    private final VirtualIpPool virtualIpPool;
    private final BandwidthManager bandwidthManager;
    private final SiteToSiteManager siteToSiteManager;

    private final Map<String, ClientHandler> activeClients = new ConcurrentHashMap<>();
    private final Map<String, SessionHandle> activeClientHandles = new ConcurrentHashMap<>();
    private final java.util.Set<ClientHandler> allHandlers = ConcurrentHashMap.newKeySet();
    private final List<ServerEventListener> listeners = new CopyOnWriteArrayList<>();

    private final ServerLimits serverLimits;
    private final ConnectionGuard connectionGuard;
    private java.util.concurrent.ScheduledExecutorService deadlineScheduler;
    private java.util.concurrent.ScheduledExecutorService stallWatchdogScheduler;
    private final java.util.concurrent.atomic.AtomicInteger handlerThreadId = new java.util.concurrent.atomic.AtomicInteger(1);

    private ServerSocket serverSocket;
    private ExecutorService threadPool;
    private Thread acceptThread;
    private volatile boolean running = false;
    private int boundPort = -1;

    /**
     * Initializes the VPN Gateway Server with default ServerLimits and an ephemeral test identity.
     */
    public VpnGatewayServer(DatabaseManager databaseManager, VaultManager vaultManager) {
        this(databaseManager, vaultManager, ServerIdentity.createEphemeral(), ServerLimits.DEFAULT);
    }

    /**
     * Initializes the VPN Gateway Server with database, vault managers, and explicit limits.
     */
    public VpnGatewayServer(DatabaseManager databaseManager, VaultManager vaultManager, ServerLimits serverLimits) {
        this(databaseManager, vaultManager, ServerIdentity.createEphemeral(), serverLimits);
    }

    /**
     * Initializes the VPN Gateway Server with a persistent or ephemeral ServerIdentity.
     */
    public VpnGatewayServer(DatabaseManager databaseManager, VaultManager vaultManager, ServerIdentity serverIdentity) {
        this(databaseManager, vaultManager, serverIdentity, ServerLimits.DEFAULT);
    }

    /**
     * Initializes the VPN Gateway Server with database, vault managers, explicit identity, and limits.
     */
    public VpnGatewayServer(DatabaseManager databaseManager, VaultManager vaultManager, ServerIdentity serverIdentity, ServerLimits serverLimits) {
        this.databaseManager = Objects.requireNonNull(databaseManager, "DatabaseManager cannot be null");
        this.vaultManager = Objects.requireNonNull(vaultManager, "VaultManager cannot be null");
        this.serverIdentity = Objects.requireNonNull(serverIdentity, "ServerIdentity cannot be null");
        this.serverLimits = Objects.requireNonNull(serverLimits, "ServerLimits cannot be null");
        this.connectionGuard = new ConnectionGuard(this.serverLimits);
        this.virtualIpPool = new VirtualIpPool();
        this.serverKeyPair = this.serverIdentity.keyPair();
        this.bandwidthManager = new BandwidthManager(this.databaseManager);
        this.siteToSiteManager = new SiteToSiteManager(this.databaseManager);
    }

    public ServerIdentity getServerIdentity() {
        return serverIdentity;
    }

    // Test seam
    int getPostHandshakeInitPacketCount() {
        return postHandshakeInitPacketCount.get();
    }

    // Test seam
    void resetPostHandshakeInitPacketCount() {
        postHandshakeInitPacketCount.set(0);
    }

    public void recordPostHandshakeInitPacket() {
        postHandshakeInitPacketCount.incrementAndGet();
    }

    public ServerLimits getServerLimits() {
        return serverLimits;
    }

    // Test seam
    ConnectionGuard getConnectionGuard() {
        return connectionGuard;
    }

    /**
     * Starts listening for incoming VPN client tunnels on the specified TCP port.
     *
     * @param port Target port (pass 0 for ephemeral OS-allocated port in tests)
     * @throws IOException If server socket fails to bind
     */
    public synchronized void start(int port) throws IOException {
        if (running) {
            return;
        }

        String bindAddrStr = serverLimits.getBindAddress();
        InetAddress bindAddr;
        try {
            bindAddr = InetAddress.getByName(bindAddrStr);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid server bind address configured: " + bindAddrStr, e);
        }

        this.serverSocket = new ServerSocket();
        try {
            this.serverSocket.bind(new InetSocketAddress(bindAddr, port));
        } catch (Exception e) {
            try {
                this.serverSocket.close();
            } catch (IOException closeEx) {
                LOGGER.debug("Ignoring serverSocket close failure after bind failure: {}", closeEx.getMessage());
            }
            throw new IllegalArgumentException("Failed to bind server to address: " + bindAddrStr + " (" + e.getMessage() + ")", e);
        }
        this.boundPort = serverSocket.getLocalPort();
        this.running = true;

        this.threadPool = new java.util.concurrent.ThreadPoolExecutor(
                serverLimits.getCoreThreads(),
                serverLimits.getMaxThreads(),
                60L, java.util.concurrent.TimeUnit.SECONDS,
                new java.util.concurrent.SynchronousQueue<>(),
                r -> {
                    Thread t = new Thread(r, "vpn-client-handler-" + handlerThreadId.getAndIncrement());
                    t.setDaemon(true);
                    return t;
                },
                new java.util.concurrent.ThreadPoolExecutor.AbortPolicy()
        );

        this.deadlineScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "vpn-deadline-timer");
            t.setDaemon(true);
            return t;
        });

        this.stallWatchdogScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "vpn-stall-watchdog");
            t.setDaemon(true);
            return t;
        });
        long watchdogIntervalMs = Math.max(100L, serverLimits.getWriteStallMillis() / 2);
        this.stallWatchdogScheduler.scheduleWithFixedDelay(this::checkStalledWrites, watchdogIntervalMs, watchdogIntervalMs, java.util.concurrent.TimeUnit.MILLISECONDS);
        this.stallWatchdogScheduler.scheduleWithFixedDelay(this::checkSessionTimeouts, 15_000L, 15_000L, java.util.concurrent.TimeUnit.MILLISECONDS);

        log(String.format("Headquarters VPN Gateway Server started on port %d (Gateway IP: %s)",
                boundPort, VirtualIpPool.GATEWAY_SERVER_IP));
        log("Server RSA-2048 Public Key SHA-256 Fingerprint: " + getServerPublicKeyFingerprintHex());

        this.acceptThread = new Thread(this::acceptLoop, "vpn-gateway-acceptor");
        this.acceptThread.setDaemon(true);
        this.acceptThread.start();
    }

    private void acceptLoop() {
        while (running && serverSocket != null && !serverSocket.isClosed()) {
            Socket clientSocket = null;
            ConnectionGuard.Permit permit = null;
            try {
                clientSocket = serverSocket.accept();
                clientSocket.setTcpNoDelay(true);

                permit = connectionGuard.tryAccept(clientSocket.getInetAddress());
                if (permit == null) {
                    try {
                        clientSocket.close();
                    } catch (IOException closeEx) {
                        LOGGER.debug("Ignoring rejected client socket close error: {}", closeEx.getMessage());
                    }
                    continue;
                }

                ClientHandler handler = new ClientHandler(clientSocket, this, permit);
                final Socket targetSocket = clientSocket;
                java.util.concurrent.ScheduledFuture<?> deadlineTask = deadlineScheduler.schedule(() -> {
                    if (handler.getHandshakeState().compareAndSet(ClientHandler.HANDSHAKE_PENDING, ClientHandler.HANDSHAKE_TIMED_OUT)) {
                        connectionGuard.recordRejection(ConnectionGuard.RejectionReason.DEADLINE);
                        try {
                            targetSocket.close();
                        } catch (IOException closeEx) {
                            LOGGER.debug("Ignoring handshake-deadline socket close error: {}", closeEx.getMessage());
                        }
                    }
                }, serverLimits.getHandshakeDeadlineMillis(), java.util.concurrent.TimeUnit.MILLISECONDS);
                handler.setDeadlineTask(deadlineTask);

                try {
                    threadPool.submit(handler);
                } catch (java.util.concurrent.RejectedExecutionException rex) {
                    connectionGuard.recordRejection(ConnectionGuard.RejectionReason.POOL_FULL);
                    deadlineTask.cancel(false);
                    try {
                        clientSocket.close();
                    } catch (IOException closeEx) {
                        LOGGER.debug("Ignoring pool-full socket close error: {}", closeEx.getMessage());
                    }
                    permit.release();
                }
            } catch (java.net.SocketException e) {
                if (!running) {
                    break;
                }
                log("Acceptor socket error: " + e.getMessage());
            } catch (IOException e) {
                if (!running) {
                    break;
                }
                log("Accept error on gateway port: " + e.getMessage());
            } catch (Exception e) {
                if (!running) {
                    break;
                }
                log("Unexpected error accepting connection: " + e.getMessage());
                if (clientSocket != null && !clientSocket.isClosed()) {
                    try {
                        clientSocket.close();
                    } catch (IOException closeEx) {
                        LOGGER.debug("Ignoring client socket close failure on accept error: {}", closeEx.getMessage());
                    }
                }
                if (permit != null) {
                    permit.release();
                }
            }
        }
    }

    /**
     * Broadcasts an intranet chat message to all currently authenticated employee tunnel sessions.
     *
     * @param senderUser Acting sender username
     * @param senderDept Sender's department
     * @param senderVip  Sender's assigned virtual IP
     * @param message    Intranet chat message text
     */
    public void broadcastChatMessage(String senderUser, String senderDept, String senderVip, String message) {
        byte[] payload = message.getBytes(StandardCharsets.UTF_8);

        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("senderUser", senderUser);
        meta.put("senderDept", senderDept);
        meta.put("senderVip", senderVip);

        for (ClientHandler client : activeClients.values()) {
            VpnSession s = client.getSession();
            if (s.isAuthenticated() && s.getDirectionalKeys() != null) {
                // Enforce departmental isolation (M5): Only deliver to same department or Headquarters broadcast
                if (!"HEADQUARTERS".equalsIgnoreCase(senderDept)
                        && (s.getAuthenticatedUser() == null || !s.getAuthenticatedUser().department().name().equalsIgnoreCase(senderDept))) {
                    continue;
                }
                try {
                    Map<String, String> clientMeta = new LinkedHashMap<>(meta);
                    clientMeta.put("seqNum", String.valueOf(s.getNextServerSendSeq()));
                    VpnPacket chatPacket = CryptoUtils.createEncryptedPacket(
                            PacketType.CHAT_MESSAGE,
                            senderVip,
                            senderUser,
                            senderDept,
                            clientMeta,
                            payload,
                            s.getDirectionalKeys().s2cKey(),
                            CryptoUtils.DIRECTION_S2C
                    );
                    client.enqueueBroadcast(chatPacket);
                } catch (Exception e) {
                    log("Failed to deliver chat broadcast to " + s.getClientSocketAddress());
                }
            }
        }

        for (ServerEventListener l : listeners) {
            l.onChatBroadcast(senderUser, senderDept, senderVip, message);
        }
    }

    private void checkStalledWrites() {
        long now = System.currentTimeMillis();
        long limit = serverLimits.getWriteStallMillis();
        for (ClientHandler handler : activeClients.values()) {
            long start = handler.getWriteStartTime();
            if (start > 0 && (now - start) > limit) {
                log("Client " + handler.getRemoteHost() + " write stalled > " + limit + "ms - terminating");
                if (databaseManager != null) {
                    UserAccount u = handler.getSession().getAuthenticatedUser();
                    databaseManager.logAuditEvent(
                            "WRITE_STALL",
                            u != null ? u.username() : "UNKNOWN",
                            u != null ? u.department().name() : "UNKNOWN",
                            "Outbound write stalled > " + limit + "ms (watchdog terminated)",
                            "SYSTEM",
                            handler.getRemoteHost()
                    );
                }
                handler.terminateSession("Socket write stall watchdog timeout");
            }
        }
    }

    private void checkSessionTimeouts() {
        long now = System.currentTimeMillis();
        long idleLimitMs = com.officevpn.config.ConfigUtil.getInt("session.timeoutMinutes", 30) * 60L * 1000L;
        long absLimitMs = com.officevpn.config.ConfigUtil.getInt("session.absoluteTimeoutMinutes", 480) * 60L * 1000L;

        for (ClientHandler client : new ArrayList<>(activeClients.values())) {
            VpnSession s = client.getSession();
            if (s != null && s.isAuthenticated()) {
                long lastActivity = s.getLastActivityTime();
                long established = s.getEstablishedTime();
                String uname = s.getAuthenticatedUser() != null ? s.getAuthenticatedUser().username() : "UNKNOWN";
                if (idleLimitMs > 0 && lastActivity > 0 && (now - lastActivity) > idleLimitMs) {
                    log("Session idle timeout exceeded for user '" + uname + "' from " + s.getClientSocketAddress());
                    client.terminateSession("Session idle timeout exceeded (" + (idleLimitMs / 60000) + "m)");
                } else if (absLimitMs > 0 && established > 0 && (now - established) > absLimitMs) {
                    log("Session absolute lifetime exceeded for user '" + uname + "' from " + s.getClientSocketAddress());
                    client.terminateSession("Session absolute maximum lifetime exceeded (" + (absLimitMs / 60000) + "m)");
                }
            }
        }
    }

    /**
     * Dispatches an administrative system broadcast across all active tunnels.
     *
     * @param text System notification text
     */
    public void broadcastSystemMessage(String text) {
        broadcastChatMessage("SYSTEM_ADMIN", "HEADQUARTERS", VirtualIpPool.GATEWAY_SERVER_IP, text);
    }

    public void broadcastSystemMessage(String text, String actor) {
        broadcastSystemMessage(text);
        if (databaseManager != null) {
            String act = (actor != null && !actor.isBlank()) ? actor.trim() : "ADMIN";
            databaseManager.logAuditEvent("ADMIN_BROADCAST", "SYSTEM", "HEADQUARTERS",
                    "System broadcast message: " + text, act, "local");
        }
    }

    /**
     * Forcefully terminates an active user session by username (Admin control).
     *
     * @param username Target username to disconnect
     * @return True if user was found and terminated, false otherwise
     */
    public boolean disconnectUser(String username) {
        return disconnectUser(username, "Administrative session revocation", "ADMIN");
    }

    public boolean disconnectUser(String username, String actor) {
        return disconnectUser(username, "Administrative session revocation", actor);
    }

    public boolean disconnectUser(String username, String reason, String actor) {
        if (username == null) {
            return false;
        }
        ClientHandler handler = activeClients.get(username);
        if (handler != null) {
            String r = (reason != null && !reason.isBlank()) ? reason : "Administrative session revocation";
            log("Administrative revocation invoked for user: " + username + " (" + r + ")");
            handler.terminateSession(r);
            activeClients.remove(username, handler);
            notifySessionUpdated();
            if (databaseManager != null) {
                String act = (actor != null && !actor.isBlank()) ? actor.trim() : "ADMIN";
                databaseManager.logAuditEvent("ADMIN_DISCONNECT_USER", username, "UNKNOWN",
                        r, act, "local");
            }
            return true;
        }
        return false;
    }

    public BindResult bindSession(UserAccount user, SessionHandle handle) {
        BindResult result;
        synchronized (this) {
            Objects.requireNonNull(user, "User cannot be null");
            Objects.requireNonNull(handle, "SessionHandle cannot be null");
            String ownerToken = handle.id();
            String virtualIp = virtualIpPool.acquireIp(user.username(), ownerToken);
            SessionHandle superseded = activeClientHandles.put(user.username(), handle);
            if (handle instanceof ClientHandler ch) {
                activeClients.put(user.username(), ch);
            }
            result = new BindResult(virtualIp, superseded);
        }
        notifySessionUpdated();
        return result;
    }

    public void unregisterAuthenticatedClient(String username, ClientHandler handler) {
        if (activeClients.remove(username, handler)) {
            activeClientHandles.remove(username, handler);
            notifySessionUpdated();
        }
    }

    public ClientHandler getActiveClient(String username) {
        return activeClients.get(username);
    }

    public void addServerEventListener(ServerEventListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeServerEventListener(ServerEventListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    public void log(String message) {
        String sanitized = AuditSanitizer.sanitizeLog(message, 1024);
        for (ServerEventListener l : listeners) {
            l.onServerLog(sanitized);
        }
    }

    public static final int MAX_PREAUTH_SNIFF_PER_SECOND = 50;
    private final AtomicInteger preAuthSniffCount = new AtomicInteger(0);
    private final AtomicLong preAuthSniffWindowStart = new AtomicLong(System.currentTimeMillis());

    public void notifyPacketSniffed(VpnPacket packet, String direction) {
        if (packet != null && isPreAuthPacket(packet.getType())) {
            long now = System.currentTimeMillis();
            long windowStart = preAuthSniffWindowStart.get();
            if (now - windowStart >= 1000) {
                if (preAuthSniffWindowStart.compareAndSet(windowStart, now)) {
                    preAuthSniffCount.set(0);
                }
            }
            if (preAuthSniffCount.incrementAndGet() > MAX_PREAUTH_SNIFF_PER_SECOND) {
                return;
            }
        }
        for (ServerEventListener l : listeners) {
            l.onPacketSniffed(packet, direction);
        }
    }

    private static boolean isPreAuthPacket(PacketType type) {
        return type == PacketType.HANDSHAKE_INIT
                || type == PacketType.HANDSHAKE_CHALLENGE
                || type == PacketType.HANDSHAKE_SESSION_KEY
                || type == PacketType.AUTH_REQUEST
                || type == PacketType.AUTH_RESPONSE;
    }

    public void notifySessionUpdated() {
        for (ServerEventListener l : listeners) {
            l.onSessionUpdated();
        }
    }

    public String getServerPublicKeyFingerprintHex() {
        return serverIdentity.fingerprintHex();
    }

    public KeyPair getServerKeyPair() {
        return serverKeyPair;
    }

    public DatabaseManager getDatabaseManager() {
        return databaseManager;
    }

    public VaultManager getVaultManager() {
        return vaultManager;
    }

    public VirtualIpPool getVirtualIpPool() {
        return virtualIpPool;
    }

    public BandwidthManager getBandwidthManager() {
        return bandwidthManager;
    }

    public SiteToSiteManager getSiteToSiteManager() {
        return siteToSiteManager;
    }

    public int getBoundPort() {
        return boundPort;
    }

    public boolean isRunning() {
        return running;
    }

    public Map<String, VpnSession> getActiveSessions() {
        Map<String, VpnSession> map = new LinkedHashMap<>();
        for (Map.Entry<String, ClientHandler> e : activeClients.entrySet()) {
            map.put(e.getKey(), e.getValue().getSession());
        }
        return Collections.unmodifiableMap(map);
    }

    public void registerHandler(ClientHandler handler) {
        if (handler != null) {
            allHandlers.add(handler);
        }
    }

    public void unregisterHandler(ClientHandler handler) {
        if (handler != null) {
            allHandlers.remove(handler);
        }
    }

    public synchronized void stop() {
        this.running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException closeEx) {
            LOGGER.debug("Ignoring server socket close error during stop(): {}", closeEx.getMessage());
        }

        // Terminate all connected and connecting client handlers
        for (ClientHandler handler : new ArrayList<>(allHandlers)) {
            handler.terminateSession("Gateway server shutdown");
        }
        allHandlers.clear();
        activeClients.clear();
        activeClientHandles.clear();

        if (stallWatchdogScheduler != null) {
            stallWatchdogScheduler.shutdownNow();
        }
        if (deadlineScheduler != null) {
            deadlineScheduler.shutdownNow();
        }
        if (threadPool != null) {
            threadPool.shutdownNow();
            try {
                if (!threadPool.awaitTermination(1500, TimeUnit.MILLISECONDS)) {
                    LOGGER.debug("Timed out waiting for client handler threads to drain on stop()");
                }
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }
        }
        log("Headquarters VPN Gateway Server stopped.");
    }

    @Override
    public void close() {
        stop();
    }
}

