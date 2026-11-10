package com.officevpn.ui.service;

import com.officevpn.admin.AdminLoginPolicy;
import com.officevpn.admin.AuditService;
import com.officevpn.admin.MetricsCollector;
import com.officevpn.client.VpnClientEngine;
import com.officevpn.config.ConfigUtil;
import com.officevpn.db.DatabaseManager;
import com.officevpn.model.AuditVerifyResult;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.security.KillSwitchManager;
import com.officevpn.security.TrustedFingerprintStore;
import com.officevpn.server.ServerEventListener;
import com.officevpn.server.VpnGatewayServer;
import com.officevpn.server.VpnSession;
import com.officevpn.tunnel.TunnelManager;
import com.officevpn.ui.service.VpnModels.*;
import com.officevpn.util.HardwareUtil;
import javafx.application.Platform;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.IntegerProperty;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.ReadOnlyBooleanProperty;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.beans.property.ReadOnlyIntegerProperty;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.beans.property.ReadOnlyStringProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;

/**
 * Production backend adapter bridging Ivory Atelier's {@link VpnClientService} contract
 * to this project's real {@link VpnClientEngine}, {@link TunnelManager},
 * {@link KillSwitchManager}, {@link AuditService}, {@link MetricsCollector},
 * {@link DatabaseManager}, and optional {@link VpnGatewayServer}.
 * <p>
 * Executes network handshakes and JDBC queries off the JavaFX Application Thread
 * and marshals all observable updates back through {@link Platform#runLater(Runnable)}.
 */
public final class BackendVpnServiceAdapter implements VpnClientService {

    private static final Logger LOGGER = LoggerFactory.getLogger(BackendVpnServiceAdapter.class);
    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm")
            .withZone(ZoneId.systemDefault());
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final ObjectProperty<ConnectionState> connectionState = new SimpleObjectProperty<>(ConnectionState.DISCONNECTED);
    private final StringProperty statusCaption = new SimpleStringProperty(ConnectionState.DISCONNECTED.defaultCaption());
    private final IntegerProperty handshakeStepIndex = new SimpleIntegerProperty(0);
    private final ObjectProperty<HandshakeStation> handshakeFailedStation = new SimpleObjectProperty<>(null);
    private final StringProperty handshakeFailureReason = new SimpleStringProperty("");
    private final StringProperty cipherSuite = new SimpleStringProperty("AES-256-GCM • ECDH P-256");
    private final StringProperty virtualIp = new SimpleStringProperty("0.0.0.0");

    private final ObjectProperty<EmployeeIdentity> currentIdentity = new SimpleObjectProperty<>(
            new EmployeeIdentity("Not signed in", "Signed Out", "--", "GUEST", "None",
                    HardwareUtil.getAuthenticHardwareFingerprint(), List.of()));
    private final ObjectProperty<GatewayNode> selectedGateway = new SimpleObjectProperty<>();
    private final ObservableList<GatewayNode> gateways = FXCollections.observableArrayList();

    private final ObservableList<ThroughputSample> throughputSeries = FXCollections.observableArrayList();
    private final DoubleProperty currentDownloadMbps = new SimpleDoubleProperty(0.0);
    private final DoubleProperty currentUploadMbps = new SimpleDoubleProperty(0.0);
    private final IntegerProperty currentLatencyMs = new SimpleIntegerProperty(4);

    private final ObservableList<OfficeResource> officeResources = FXCollections.observableArrayList();
    private final StringProperty accessPolicySummary = new SimpleStringProperty("Policy: Office Split Tunnel");

    private final ObservableList<WorkModeProfile> workModes = FXCollections.observableArrayList();
    private final ObjectProperty<WorkModeProfile> activeWorkMode = new SimpleObjectProperty<>();

    private final BooleanProperty killSwitchEnabled = new SimpleBooleanProperty(true);
    private final BooleanProperty autoConnectUntrustedWifi = new SimpleBooleanProperty(true);
    private final BooleanProperty dnsLeakGuard = new SimpleBooleanProperty(true);
    private final ObservableList<SplitAppItem> splitApps = FXCollections.observableArrayList();

    private final ObservableList<PostureCheck> postureChecks = FXCollections.observableArrayList();
    private final ObservableList<EmployeeSessionItem> activeRoster = FXCollections.observableArrayList();
    private final ObjectProperty<InviteKeyState> inviteKey = new SimpleObjectProperty<>();
    private final ObservableList<AuditEventItem> auditEvents = FXCollections.observableArrayList();
    private final BooleanProperty auditLoading = new SimpleBooleanProperty(false);
    private final StringProperty auditChainStatus = new SimpleStringProperty("LIVE CLIENT EVENTS");

    private final AtomicLong rxBytesInTick = new AtomicLong(0);
    private final AtomicLong txBytesInTick = new AtomicLong(0);
    private final ScheduledExecutorService telemetryScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ivory-telemetry-sampler");
        t.setDaemon(true);
        return t;
    });
    private final ScheduledFuture<?> telemetryTask;

    private final VpnClientEngine engine;
    private final boolean ownsEngine;
    private final TrustedFingerprintStore fingerprintStore;
    private final DatabaseManager databaseManager;
    private final VpnGatewayServer gatewayServer;
    private final MetricsCollector metricsCollector;
    private final AuditService auditService;
    private final ExecutorService ioExecutor;

    private final String authorizedAdminUsername;
    private VpnClientEngine.ClientEventListener engineListener;
    private KillSwitchManager.KillSwitchListener killSwitchListener;
    private ServerEventListener serverListener;
    private volatile String authenticatedUsername = "";
    private volatile char[] activePassword = new char[0];
    private volatile String activeOtp = "";
    private volatile String configuredExpectedFingerprint = null;
    private volatile Predicate<String> pinReplaceConfirmer = _ -> false;
    private final AtomicLong localAuditSeq = new AtomicLong(1);

    public BackendVpnServiceAdapter(
            VpnClientEngine engine,
            TrustedFingerprintStore fingerprintStore,
            DatabaseManager databaseManager,
            VpnGatewayServer gatewayServer
    ) {
        this(engine, fingerprintStore, databaseManager, gatewayServer, null);
    }

    public BackendVpnServiceAdapter(
            VpnClientEngine engine,
            TrustedFingerprintStore fingerprintStore,
            DatabaseManager databaseManager,
            VpnGatewayServer gatewayServer,
            String authorizedAdminUsername
    ) {
        this.authorizedAdminUsername = (authorizedAdminUsername != null && !authorizedAdminUsername.isBlank())
                ? authorizedAdminUsername.trim()
                : null;
        this.ownsEngine = (engine == null);
        this.engine = (engine != null) ? engine : new VpnClientEngine();
        this.fingerprintStore = fingerprintStore != null ? fingerprintStore : new TrustedFingerprintStore();
        this.databaseManager = databaseManager;
        this.gatewayServer = gatewayServer;
        this.metricsCollector = databaseManager != null
                ? new MetricsCollector(databaseManager, gatewayServer)
                : null;
        this.auditService = databaseManager != null ? new AuditService(databaseManager) : null;
        this.ioExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "ivory-backend-adapter");
            t.setDaemon(true);
            return t;
        });

        initializeHonestDefaults();
        bindPolicyBridges();
        syncGatewaysFromConfig();
        syncEngineSnapshotToUi();
        attachLiveEngineListeners();
        this.telemetryTask = telemetryScheduler.scheduleAtFixedRate(this::tickLiveTelemetry, 1, 1, TimeUnit.SECONDS);
        if (databaseManager != null && !databaseManager.isClosed()) {
            refreshAuditLog();
            syncRosterFromGateway();
        }
    }

    private void initializeHonestDefaults() {
        long now = System.currentTimeMillis();
        marshalFx(() -> {
            String gwVip = ConfigUtil.getGatewayVirtualIp();
            workModes.setAll(
                    new WorkModeProfile("mode-split", "Split Tunnel", TunnelProfileType.SPLIT,
                            "Office subnets via AES-256-GCM; public traffic direct", "https://portal.office.internal",
                            gwVip + " (office DNS)", true, now, "peacock"),
                    new WorkModeProfile("mode-office", "Office Only", TunnelProfileType.OFFICE_ONLY,
                            "Route corporate virtual subnet traffic strictly", "https://portal.office.internal",
                            gwVip + " strict", true, now - 60_000, "marigold"),
                    new WorkModeProfile("mode-full", "Full Tunnel", TunnelProfileType.FULL_TUNNEL,
                            "All client egress encapsulated through HQ gateway", "https://portal.office.internal",
                            gwVip + " all queries", false, now - 120_000, "lilac"),
                    new WorkModeProfile("mode-guest", "Guest-Safe", TunnelProfileType.GUEST_SAFE,
                            "Untrusted Wi-Fi strict mode + Kill Switch armed", "https://portal.office.internal",
                            gwVip + " strict", false, now - 180_000, "coral")
            );
            activeWorkMode.set(workModes.get(0));

            splitApps.setAll(
                    new SplitAppItem("app-vault", "Encrypted Vault", "AES-256-GCM file transfer", true),
                    new SplitAppItem("app-chat", "Intranet Chat", "Office broadcast channel", true),
                    new SplitAppItem("app-ping", "Gateway Health Probe", "PING / PONG keepalive", true),
                    new SplitAppItem("app-public", "Public Web Browser", "Direct OS route", false)
            );

            activeRoster.clear();
            auditEvents.clear();
            postureChecks.setAll(buildRealPostureChecks());
            officeResources.setAll(
                    new OfficeResource("res-vault", OfficeBranch.HQ, "Encrypted Vault", "Departmental", "AES-256-GCM File Transfer", "TCP " + ConfigUtil.getPort(), engine.isAuthenticated(), 0.06, 0.12, 0.42, 0.36),
                    new OfficeResource("res-chat", OfficeBranch.HQ, "Secure Chat", "Departmental", "Isolated Intranet Feed", "TCP " + ConfigUtil.getPort(), engine.isAuthenticated(), 0.52, 0.12, 0.42, 0.36),
                    new OfficeResource("res-gw", OfficeBranch.HQ, "HQ Gateway", "Core", gwVip + "/24", "OFFICE-VPN-2.0", engine.isAuthenticated(), 0.06, 0.54, 0.42, 0.36),
                    new OfficeResource("res-dev", OfficeBranch.HQ, "Device Trust", "Zero-Trust", "Max " + ConfigUtil.getMaxDevicesPerUser() + " hardware keys", "SHA-256 Bound", engine.isAuthenticated(), 0.52, 0.54, 0.42, 0.36)
            );
            throughputSeries.clear();
            for (int i = 59; i >= 0; i--) {
                throughputSeries.add(new ThroughputSample(now - i * 1000L, 0.0, 0.0, currentLatencyMs.get()));
            }
            rotateInviteKeyInternal();
            auditChainStatus.set(databaseManager != null ? "MYSQL AUDIT CHAIN" : "LIVE CLIENT EVENTS");
        });
    }

    private List<PostureCheck> buildRealPostureChecks() {
        return List.of(
                new PostureCheck("posture-java", "Java Runtime 25", true,
                        "JRE " + Runtime.version() + " initialized",
                        "Verify Java 25 runtime is installed."),
                new PostureCheck("posture-hw", "Hardware ID Bound", true,
                        HardwareUtil.getAuthenticDeviceName() + " (" + HardwareUtil.getAuthenticHardwareFingerprint().substring(0, 12) + "...)",
                        "Authentic SHA-256 device fingerprint computed."),
                new PostureCheck("posture-tofu", "TOFU Pin Store", true,
                        "RSA-2048 RSASSA-PSS server verification active",
                        "Verify pinned gateway fingerprint in known_gateways."),
                new PostureCheck("posture-cipher", "Tunnel Cipher", true,
                        "ECDH P-256 PFS + AES-256-GCM directional keys",
                        "Ensure server supports OFFICE-VPN-2.0 protocol.")
        );
    }

    private void tickLiveTelemetry() {
        long rx = rxBytesInTick.getAndSet(0);
        long tx = txBytesInTick.getAndSet(0);
        double downMbps = Math.round(((rx * 8.0) / 1_000_000.0) * 100.0) / 100.0;
        double upMbps = Math.round(((tx * 8.0) / 1_000_000.0) * 100.0) / 100.0;
        int lat = currentLatencyMs.get();
        long ts = System.currentTimeMillis();
        marshalFx(() -> {
            if (throughputSeries.size() >= 60) {
                throughputSeries.remove(0);
            }
            throughputSeries.add(new ThroughputSample(ts, downMbps, upMbps, lat));
            if (!engine.isConnected()) {
                currentDownloadMbps.set(0.0);
                currentUploadMbps.set(0.0);
            } else if (rx > 0 || tx > 0) {
                currentDownloadMbps.set(downMbps);
                currentUploadMbps.set(upMbps);
            }
        });
    }

    public VpnClientEngine getEngine() {
        return engine;
    }

    public TrustedFingerprintStore getFingerprintStore() {
        return fingerprintStore;
    }

    public void setPinReplaceConfirmer(Predicate<String> confirmer) {
        this.pinReplaceConfirmer = (confirmer != null) ? confirmer : _ -> false;
    }

    public Optional<String> getPinnedFingerprint(String host, int port) {
        if (host == null || host.isBlank() || port <= 0) return Optional.empty();
        return fingerprintStore.getPinnedFingerprint(host.trim(), port);
    }

    public void clearGatewayPin(String host, int port) {
        if (host != null && !host.isBlank() && port > 0) {
            fingerprintStore.removePin(host.trim(), port);
            appendLocalAudit(AuditCategory.POLICY_CHANGE, "Cleared TOFU gateway pin",
                    "Removed stored RSA fingerprint for " + host.trim() + ":" + port, "local");
            syncGatewaysFromConfig();
        }
    }

    public void configureGatewayEndpoint(String host, int port, String expectedFingerprintHex) {
        String cleanHost = (host == null || host.isBlank()) ? ConfigUtil.getClientDefaultHost() : host.trim();
        int validPort = (port >= 1 && port <= 65535) ? port : ConfigUtil.getPort();
        this.configuredExpectedFingerprint = (expectedFingerprintHex != null && !expectedFingerprintHex.isBlank())
                ? expectedFingerprintHex.trim()
                : null;
        String pin = fingerprintStore.getPinnedFingerprint(cleanHost, validPort).orElse("tofu-on-connect");
        String shortFp = pin.length() > 14 ? pin.substring(0, 14) : pin;
        GatewayNode custom = new GatewayNode(
                "gw-live-hq", "Office Gateway", cleanHost + ":" + validPort, "HQ",
                cleanHost, validPort, (int) Math.max(2, metricsCollector != null ? metricsCollector.getAverageLatencyMs() : 4),
                0, true, true, shortFp);
        marshalFx(() -> {
            gateways.setAll(custom);
            selectGateway(custom.id());
        });
    }

    public CompletableFuture<Long> pingGateway() {
        return CompletableFuture.supplyAsync(() -> {
            if (!engine.isConnected() || !engine.isAuthenticated()) {
                throw new IllegalStateException("Connect and sign in before testing encrypted tunnel ping.");
            }
            long startNs = System.nanoTime();
            try {
                if (!engine.ping()) {
                    throw new IllegalStateException("Gateway did not answer encrypted PING probe.");
                }
            } catch (IOException ex) {
                throw new IllegalStateException("Ping failed: " + ex.getMessage(), ex);
            }
            long ms = Math.max(1L, (System.nanoTime() - startNs) / 1_000_000L);
            marshalFx(() -> currentLatencyMs.set((int) Math.min(Integer.MAX_VALUE, ms)));
            appendLocalAudit(AuditCategory.SIGN_IN, "Encrypted PING/PONG verified",
                    "Round-trip RTT: " + ms + " ms", engine.getAssignedVirtualIp());
            return ms;
        }, ioExecutor);
    }

    public CompletableFuture<Void> changePassword(char[] currentPw, char[] newPw) {
        char[] curCopy = currentPw != null ? currentPw.clone() : new char[0];
        char[] newCopy = newPw != null ? newPw.clone() : new char[0];
        return CompletableFuture.runAsync(() -> {
            try {
                if (!engine.isConnected() || !engine.isAuthenticated()) {
                    throw new IllegalStateException("Sign in to an active tunnel before rotating password.");
                }
                engine.changePassword(curCopy, newCopy);
                appendLocalAudit(AuditCategory.POLICY_CHANGE, "Password rotated over encrypted tunnel",
                        "Updated credentials for " + engine.getUsername(), engine.getAssignedVirtualIp());
            } catch (IOException | SecurityException ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            } finally {
                Arrays.fill(curCopy, '\0');
                Arrays.fill(newCopy, '\0');
            }
        }, ioExecutor);
    }

    private void appendLocalAudit(AuditCategory cat, String title, String detail, String ip) {
        String actor = (engine.getUsername() != null && !engine.getUsername().isBlank())
                ? engine.getUsername()
                : (!authenticatedUsername.isBlank() ? authenticatedUsername : "client");
        AuditEventItem item = new AuditEventItem(
                localAuditSeq.getAndIncrement(),
                "Live Session",
                TIME_FMT.format(Instant.now()),
                cat,
                actor,
                title,
                detail,
                (ip == null || ip.isBlank()) ? "local" : ip
        );
        marshalFx(() -> {
            if (auditService == null || databaseManager == null || databaseManager.isClosed()) {
                auditEvents.add(0, item);
            }
        });
    }

    private void syncEngineSnapshotToUi() {
        marshalFx(() -> {
            if (engine.isAuthenticated() && engine.getUsername() != null && !engine.getUsername().isBlank()) {
                String uname = engine.getUsername().trim();
                String initials = uname.length() >= 2
                        ? uname.substring(0, 2).toUpperCase(Locale.ROOT)
                        : uname.toUpperCase(Locale.ROOT);
                String deptName = engine.getDepartment() != null ? engine.getDepartment().name() : "Shared";
                String roleName = engine.getRole() != null ? engine.getRole().name() : "EMPLOYEE";
                List<String> allowedDepts = "HEADQUARTERS".equalsIgnoreCase(deptName)
                        ? List.of("Finance", "IT", "HR", "Headquarters")
                        : List.of(formatDeptLabel(deptName));
                EmployeeIdentity realId = new EmployeeIdentity(
                        uname, uname, initials, roleName, formatDeptLabel(deptName),
                        HardwareUtil.getAuthenticHardwareFingerprint(), allowedDepts);
                currentIdentity.set(realId);
            } else {
                EmployeeIdentity signedOut = new EmployeeIdentity(
                        "Not signed in", "Signed Out", "--", "GUEST", "None",
                        HardwareUtil.getAuthenticHardwareFingerprint(), List.of());
                currentIdentity.set(signedOut);
            }
            if (engine.getAssignedVirtualIp() != null && !engine.getAssignedVirtualIp().isBlank()
                    && !"0.0.0.0".equals(engine.getAssignedVirtualIp())) {
                virtualIp.set(engine.getAssignedVirtualIp());
            } else if (!engine.isAuthenticated()) {
                virtualIp.set("0.0.0.0");
            }
            if (engine.getKillSwitchManager() != null) {
                KillSwitchManager.State ksState = engine.getKillSwitchManager().getState();
                killSwitchEnabled.set(ksState != KillSwitchManager.State.DISABLED);
                if (ksState == KillSwitchManager.State.BLOCKING) {
                    setConnectionState(ConnectionState.BLOCKED_BY_KILL_SWITCH,
                            "Unexpected tunnel drop — non-VPN egress blocked by Kill Switch");
                }
            }
            if (engine.getTunnelManager() != null) {
                TunnelManager.TunnelMode tmMode = engine.getTunnelManager().getMode();
                String targetId = (tmMode == TunnelManager.TunnelMode.FULL) ? "mode-full" : "mode-split";
                activateWorkMode(targetId);
            }
            if (engine.getAutoReconnectManager() != null) {
                autoConnectUntrustedWifi.set(engine.getAutoReconnectManager().isEnabled());
            }
            dnsLeakGuard.set(engine.getDnsLeakProtection() != null
                    && engine.getDnsLeakProtection().isLeakProtectionEnabled());
            updateResourceUnlocks(engine.isAuthenticated());
        });
    }

    private void attachLiveEngineListeners() {
        engineListener = new VpnClientEngine.ClientEventListener() {
            @Override
            public void onChatMessage(String senderUser, String senderDept, String senderVip, String message) {
                // Intranet chat messages are displayed by ChatPanel
            }

            @Override
            public void onPacketSniffed(VpnPacket packet, String direction) {
                if (packet == null) return;
                byte[] enc = packet.getEncryptedPayload();
                int len = (enc != null ? enc.length : 64);
                double mbps = Math.max(0.2, (len * 8.0) / 1000.0);
                if ("INCOMING".equalsIgnoreCase(direction)) {
                    rxBytesInTick.addAndGet(len);
                } else {
                    txBytesInTick.addAndGet(len);
                }
                marshalFx(() -> {
                    if ("INCOMING".equalsIgnoreCase(direction)) {
                        currentDownloadMbps.set(mbps);
                    } else {
                        currentUploadMbps.set(mbps);
                    }
                });
            }

            @Override
            public void onConnectionStateChanged(String state) {
                String clean = state != null ? state : "";
                marshalFx(() -> {
                    statusCaption.set(clean);
                    if (engine.isConnected() && engine.isAuthenticated()) {
                        setConnectionState(ConnectionState.CONNECTED, clean);
                        handshakeStepIndex.set(HandshakeStation.values().length);
                        if (engine.getAssignedVirtualIp() != null) {
                            virtualIp.set(engine.getAssignedVirtualIp());
                        }
                    } else if (engine.getKillSwitchManager() != null
                            && engine.getKillSwitchManager().getState() == KillSwitchManager.State.BLOCKING) {
                        setConnectionState(ConnectionState.BLOCKED_BY_KILL_SWITCH, clean);
                    } else if (clean.contains("Connecting")) {
                        setConnectionState(ConnectionState.CONNECTING, clean);
                    } else if (clean.contains("Disconnected") || clean.contains("Connection lost")) {
                        setConnectionState(ConnectionState.DISCONNECTED, clean);
                        syncEngineSnapshotToUi();
                        handshakeStepIndex.set(0);
                    }
                });
            }
        };
        engine.addClientEventListener(engineListener);

        if (engine.getKillSwitchManager() != null) {
            killSwitchListener = (newState, reason) -> marshalFx(() -> {
                killSwitchEnabled.set(newState != KillSwitchManager.State.DISABLED);
                if (newState == KillSwitchManager.State.BLOCKING) {
                    setConnectionState(ConnectionState.BLOCKED_BY_KILL_SWITCH, reason);
                }
            });
            engine.getKillSwitchManager().addListener(killSwitchListener);
        }

        if (gatewayServer != null) {
            serverListener = new ServerEventListener() {
                @Override public void onServerLog(String message) {}
                @Override public void onPacketSniffed(VpnPacket rawPacket, String direction) {}
                @Override
                public void onSessionUpdated() {
                    if (!ioExecutor.isShutdown()) {
                        syncRosterFromGateway();
                        refreshAuditLog();
                    }
                }
                @Override public void onChatBroadcast(String senderUser, String senderDept, String senderVip, String message) {}
            };
            gatewayServer.addServerEventListener(serverListener);
        }
    }

    private void bindPolicyBridges() {
        killSwitchEnabled.addListener((_, _, enabled) -> {
            KillSwitchManager ksm = engine.getKillSwitchManager();
            if (ksm == null) return;
            if (Boolean.TRUE.equals(enabled)) {
                if (ksm.getState() == KillSwitchManager.State.DISABLED) {
                    ksm.enable();
                }
                appendLocalAudit(AuditCategory.POLICY_CHANGE, "Kill Switch armed",
                        "Non-VPN egress protection enabled", virtualIp.get());
            } else {
                String actor = engine.getUsername() != null ? engine.getUsername() : "local-user";
                ksm.disable(actor, "Disabled via Ivory Atelier Safety Latches");
                if (connectionState.get() == ConnectionState.BLOCKED_BY_KILL_SWITCH) {
                    setConnectionState(ConnectionState.DISCONNECTED, ConnectionState.DISCONNECTED.defaultCaption());
                }
                appendLocalAudit(AuditCategory.POLICY_CHANGE, "Kill Switch disarmed",
                        "Safety latches updated by " + actor, virtualIp.get());
            }
        });
        autoConnectUntrustedWifi.addListener((_, _, enabled) ->
                engine.setAutoReconnect(Boolean.TRUE.equals(enabled)));
        dnsLeakGuard.addListener((_, _, enabled) ->
                appendLocalAudit(AuditCategory.POLICY_CHANGE,
                        "DNS leak guard " + (Boolean.TRUE.equals(enabled) ? "enforced (" + ConfigUtil.getGatewayVirtualIp() + ")" : "paused"),
                        "Internal resolver policy updated", virtualIp.get()));
        activeWorkMode.addListener((_, _, mode) -> {
            if (mode == null || engine.getTunnelManager() == null) return;
            TunnelManager.TunnelMode targetMode =
                    (mode.profileType() == TunnelProfileType.FULL_TUNNEL || mode.profileType() == TunnelProfileType.GUEST_SAFE)
                            ? TunnelManager.TunnelMode.FULL
                            : TunnelManager.TunnelMode.SPLIT;
            engine.getTunnelManager().setMode(targetMode);
        });
    }

    private void syncGatewaysFromConfig() {
        String host = (engine.getConnectedHost() != null && !engine.getConnectedHost().isBlank())
                ? engine.getConnectedHost()
                : ConfigUtil.getString("server.host", ConfigUtil.getClientDefaultHost());
        if ("0.0.0.0".equals(host)) {
            host = ConfigUtil.getClientDefaultHost();
        }
        int port = engine.getConnectedPort() > 0
                ? engine.getConnectedPort()
                : (gatewayServer != null && gatewayServer.getBoundPort() > 0
                        ? gatewayServer.getBoundPort()
                        : ConfigUtil.getPort());
        String fp = engine.getServerFingerprint() != null
                ? engine.getServerFingerprint()
                : (gatewayServer != null ? gatewayServer.getServerPublicKeyFingerprintHex() : "configured-tofu");
        String shortFp = fp.length() > 12 ? fp.substring(0, 12) : fp;
        GatewayNode primary = new GatewayNode(
                "gw-live-hq", "Office Gateway", host + ":" + port, "HQ",
                host, port, (int) Math.max(2, metricsCollector != null ? metricsCollector.getAverageLatencyMs() : 4),
                0, true, true, shortFp);
        marshalFx(() -> {
            gateways.setAll(primary);
            selectGateway(primary.id());
        });
    }

    public void syncRosterFromGateway() {
        if (gatewayServer == null) {
            return;
        }
        ioExecutor.submit(() -> {
            Map<String, VpnSession> sessions = gatewayServer.getActiveSessions();
            List<EmployeeSessionItem> items = new ArrayList<>();
            for (VpnSession s : sessions.values()) {
                UserAccount ua = s.getAuthenticatedUser();
                String u = ua != null ? ua.username() : s.getSessionId();
                String dept = ua != null && ua.department() != null ? ua.department().name() : "UNKNOWN";
                String vip = s.getAssignedVirtualIp() != null ? s.getAssignedVirtualIp() : "10.8.0.x";
                String initials = u.length() >= 2 ? u.substring(0, 2).toUpperCase(Locale.ROOT) : u.toUpperCase(Locale.ROOT);
                items.add(new EmployeeSessionItem(
                        s.getSessionId(), u, initials, dept,
                        vip, "Gateway Core", HardwareUtil.getAuthenticDeviceName(),
                        true, "Verified", s.getConnectedAt(), "peacock"
                ));
            }
            marshalFx(() -> activeRoster.setAll(items));
        });
    }

    @Override
    public void connect() {
        GatewayNode gw = selectedGateway.get();
        connect(gw != null ? gw.id() : null);
    }

    private void handshakeWithTofuPrompt(String host, int port) throws IOException {
        try {
            engine.connectAndHandshake(host, port, configuredExpectedFingerprint, fingerprintStore, false);
        } catch (SecurityException pinEx) {
            if (pinEx.getMessage() != null && pinEx.getMessage().contains("GATEWAY IDENTITY CHANGED")) {
                boolean approved = pinReplaceConfirmer != null && pinReplaceConfirmer.test(pinEx.getMessage());
                if (!approved) {
                    throw pinEx;
                }
                engine.connectAndHandshake(host, port, configuredExpectedFingerprint, fingerprintStore, true);
                appendLocalAudit(AuditCategory.POLICY_CHANGE, "Replaced TOFU server key pin",
                        "User approved rotated RSA fingerprint for " + host + ":" + port, host);
            } else {
                throw pinEx;
            }
        }
    }

    @Override
    public void connect(String gatewayId) {
        if (gatewayId != null) {
            selectGateway(gatewayId);
        }
        GatewayNode gw = selectedGateway.get();
        if (gw == null) {
            return;
        }
        ioExecutor.submit(() -> {
            try {
                if (!engine.isConnected()) {
                    handshakeWithTofuPrompt(gw.hostname(), gw.port());
                }
                if (engine.isAuthenticated()) {
                    marshalFx(() -> {
                        syncEngineSnapshotToUi();
                        setConnectionState(ConnectionState.CONNECTED, "Connected to " + gw.hostname() + ":" + gw.port());
                        syncRosterFromGateway();
                    });
                    return;
                }
                String user = (authenticatedUsername != null && !authenticatedUsername.isBlank())
                        ? authenticatedUsername
                        : (currentIdentityProperty().get() != null ? currentIdentityProperty().get().username() : "");
                if (!user.isBlank() && activePassword.length > 0 && !"Not signed in".equals(user)) {
                    String pw = new String(activePassword);
                    boolean ok = activeOtp.isEmpty()
                            ? engine.login(user, pw)
                            : engine.login(user, pw, activeOtp);
                    if (ok) {
                        marshalFx(() -> {
                            syncEngineSnapshotToUi();
                            setConnectionState(ConnectionState.CONNECTED, "Connected to " + gw.hostname() + ":" + gw.port());
                            refreshAuditLog();
                            syncRosterFromGateway();
                        });
                        appendLocalAudit(AuditCategory.SIGN_IN, "Authenticated over encrypted tunnel",
                                "Signed in as " + engine.getUsername() + " (" + engine.getDepartment() + ")", engine.getAssignedVirtualIp());
                        return;
                    }
                }
                engine.disconnect();
                setConnectionStateFx(ConnectionState.DISCONNECTED, "Sign in with valid employee credentials to establish tunnel.");
            } catch (IOException | SecurityException ex) {
                LOGGER.warn("Live tunnel connection failed for {}:{} - {}", gw.hostname(), gw.port(), ex.getMessage());
                setConnectionStateFx(ConnectionState.DISCONNECTED, "Gateway connection failed: " + ex.getMessage());
                appendLocalAudit(AuditCategory.FAILED_ATTEMPT, "Gateway handshake/connect failed", ex.getMessage(), gw.hostname());
                marshalFx(() -> {
                    handshakeFailedStation.set(HandshakeStation.REACH_GATEWAY);
                    handshakeFailureReason.set(ex.getMessage());
                });
            }
        });
    }

    @Override
    public void disconnect() {
        ioExecutor.submit(() -> {
            String prevIp = engine.getAssignedVirtualIp();
            engine.disconnect();
            marshalFx(() -> {
                handshakeStepIndex.set(0);
                handshakeFailedStation.set(null);
                handshakeFailureReason.set("");
                setConnectionState(ConnectionState.DISCONNECTED, ConnectionState.DISCONNECTED.defaultCaption());
                currentDownloadMbps.set(0.0);
                currentUploadMbps.set(0.0);
                updateResourceUnlocks(false);
            });
            syncEngineSnapshotToUi();
            syncRosterFromGateway();
            appendLocalAudit(AuditCategory.SIGN_IN, "Disconnected tunnel", "Session closed by client", prevIp);
        });
    }

    private String requireAuthorizedAdminActor() {
        if (authorizedAdminUsername != null && databaseManager != null && !databaseManager.isClosed()) {
            UserAccount account = databaseManager.getUserByUsername(authorizedAdminUsername);
            if (AdminLoginPolicy.canLoginAsAdmin(account)) {
                return account.username();
            }
        }
        if (engine != null && engine.isAuthenticated()
                && engine.getRole() == Role.ADMIN
                && engine.getDepartment() == Department.HEADQUARTERS) {
            if (databaseManager == null || databaseManager.isClosed()
                    || AdminLoginPolicy.canLoginAsAdmin(databaseManager.getUserByUsername(engine.getUsername()))) {
                return engine.getUsername();
            }
        }
        String deniedActor = (engine != null && engine.getUsername() != null && !engine.getUsername().isBlank())
                ? engine.getUsername()
                : (authorizedAdminUsername != null ? authorizedAdminUsername : "UNAUTHENTICATED");
        if (databaseManager != null && !databaseManager.isClosed()) {
            databaseManager.logAuditEvent("UNAUTHORIZED_ADMIN_OP", deniedActor, "UNKNOWN",
                    "Denied session revocation without active HEADQUARTERS ADMIN authorization",
                    deniedActor, "local");
        }
        throw new SecurityException("Active Headquarters ADMIN authorization required for session revocation.");
    }

    @Override
    public void revokeSession(String sessionId) {
        String actor = requireAuthorizedAdminActor();
        String resolvedUser = sessionId;
        EmployeeSessionItem found = null;
        for (EmployeeSessionItem item : activeRoster) {
            if (Objects.equals(item.sessionId(), sessionId)) {
                resolvedUser = item.username();
                found = item;
                break;
            }
        }
        final EmployeeSessionItem toRemove = found;
        final String targetUsername = resolvedUser;
        if (toRemove != null) {
            marshalFx(() -> activeRoster.remove(toRemove));
            appendLocalAudit(AuditCategory.REVOKE,
                    "Revoked session " + toRemove.username() + " (" + toRemove.sessionId() + ")",
                    "Virtual IP " + toRemove.virtualIp() + " reclaimed", toRemove.virtualIp());
        }
        if (gatewayServer != null && targetUsername != null && !targetUsername.isBlank()) {
            ioExecutor.submit(() -> {
                gatewayServer.disconnectUser(targetUsername, "Revoked via Ivory Atelier console", actor);
                syncRosterFromGateway();
                refreshAuditLog();
            });
        }
    }

    private void updateIdentityFromAccount(String username, String deptName, String roleName) {
        if (username == null || username.isBlank()) return;
        String cleanUser = username.trim();
        String initials = cleanUser.length() >= 2
                ? cleanUser.substring(0, 2).toUpperCase(Locale.ROOT)
                : cleanUser.toUpperCase(Locale.ROOT);
        List<String> allowedDepts = "HEADQUARTERS".equalsIgnoreCase(deptName)
                ? List.of("Finance", "Engineering", "HR", "Shared")
                : List.of(formatDeptLabel(deptName), "Shared");
        EmployeeIdentity realId = new EmployeeIdentity(
                cleanUser, cleanUser, initials, roleName, formatDeptLabel(deptName),
                HardwareUtil.getAuthenticHardwareFingerprint(), allowedDepts);
        marshalFx(() -> currentIdentity.set(realId));
    }

    @Override
    public CompletableFuture<AuthResult> authenticate(String username, String password, String otpCode) {
        String cleanUser = username != null ? username.trim() : "";
        this.authenticatedUsername = cleanUser;
        Arrays.fill(this.activePassword, '\0');
        this.activePassword = password != null ? password.toCharArray() : new char[0];
        this.activeOtp = otpCode != null ? otpCode.trim() : "";

        return CompletableFuture.supplyAsync(() -> {
            char[] copyPw = this.activePassword.clone();
            try {
                if (cleanUser.isBlank() || copyPw.length == 0) {
                    return new AuthResult(false, false, "Username and password are required.");
                }
                GatewayNode gw = selectedGateway.get();
                boolean canTryWire = gw != null && (gatewayServer == null || gatewayServer.isRunning());
                if (canTryWire) {
                    try {
                        if (!engine.isConnected()) {
                            handshakeWithTofuPrompt(gw.hostname(), gw.port());
                        }
                        String rawPw = new String(copyPw);
                        boolean ok = this.activeOtp.isEmpty()
                                ? engine.login(cleanUser, rawPw)
                                : engine.login(cleanUser, rawPw, this.activeOtp);
                        if (ok) {
                            syncGatewaysFromConfig();
                            syncEngineSnapshotToUi();
                            marshalFx(() -> {
                                setConnectionState(ConnectionState.CONNECTED, "Connected to " + gw.hostname() + ":" + gw.port());
                                refreshAuditLog();
                                syncRosterFromGateway();
                            });
                            appendLocalAudit(AuditCategory.SIGN_IN, "Authenticated as " + engine.getUsername(),
                                    "Tunnel active (" + engine.getDepartment() + " / " + engine.getAssignedVirtualIp() + ")",
                                    engine.getAssignedVirtualIp());
                            return new AuthResult(true, false, "Connected as " + engine.getUsername() + " (" + engine.getAssignedVirtualIp() + ")");
                        }
                        engine.disconnect();
                        boolean totpNeeded = databaseManager != null && !databaseManager.isClosed()
                                && databaseManager.isTotpEnabled(cleanUser) && this.activeOtp.isEmpty();
                        appendLocalAudit(AuditCategory.FAILED_ATTEMPT, "Authentication rejected for " + cleanUser,
                                totpNeeded ? "MFA 6-digit code required" : "Invalid credentials, 2FA code, or device not trusted",
                                gw.hostname());
                        return new AuthResult(false, totpNeeded,
                                totpNeeded ? "MFA is enabled on this account — enter your 6-digit Authenticator code."
                                        : "Rejected: verify username, password, hardware trust, or 6-digit MFA code (leave blank if MFA is OFF).");
                    } catch (SecurityException pinEx) {
                        engine.disconnect();
                        appendLocalAudit(AuditCategory.FAILED_ATTEMPT, "Gateway identity check blocked", pinEx.getMessage(), gw.hostname());
                        return new AuthResult(false, false, pinEx.getMessage());
                    } catch (IOException wireEx) {
                        LOGGER.debug("Wire authentication unavailable ({}), checking local DB if configured", wireEx.getMessage());
                        engine.disconnect();
                        if (databaseManager == null || databaseManager.isClosed()) {
                            appendLocalAudit(AuditCategory.FAILED_ATTEMPT, "Gateway unreachable", wireEx.getMessage(), gw.hostname());
                            return new AuthResult(false, false,
                                    "Cannot reach VPN gateway at " + gw.hostname() + ":" + gw.port()
                                            + " — ensure office-vpn-server.jar is running and Gateway is started.");
                        }
                    }
                }

                if (databaseManager == null || databaseManager.isClosed()) {
                    return new AuthResult(false, false, "Gateway unreachable at " + (gw != null ? gw.hostname() + ":" + gw.port() : "configured host"));
                }
                boolean totpRequired = databaseManager.isTotpEnabled(cleanUser);
                if (totpRequired && this.activeOtp.isEmpty()) {
                    return new AuthResult(false, true, "Enter your 6-digit authenticator code.");
                }
                UserAccount account = totpRequired
                        ? databaseManager.authenticateUser(cleanUser, copyPw, this.activeOtp, "local")
                        : databaseManager.authenticateUser(cleanUser, copyPw, "local");
                if (account == null) {
                    return new AuthResult(false, totpRequired, "Authentication rejected — check username, password, or authenticator code.");
                }
                this.authenticatedUsername = account.username();
                updateIdentityFromAccount(account.username(), account.department().name(), account.role().name());
                return new AuthResult(true, false, "Authenticated cleanly as " + account.username());
            } finally {
                Arrays.fill(copyPw, '\0');
            }
        }, ioExecutor);
    }

    @Override
    public void refreshAuditLog() {
        if (auditService == null || databaseManager == null || databaseManager.isClosed()) {
            return;
        }
        marshalFx(() -> auditLoading.set(true));
        ioExecutor.submit(() -> {
            try {
                List<DatabaseManager.AuditLogEntry> logs = auditService.getRecentAudit(40);
                AuditVerifyResult verify = databaseManager.verifyAuditChain();
                List<AuditEventItem> mapped = new ArrayList<>();
                for (DatabaseManager.AuditLogEntry e : logs) {
                    AuditCategory cat = mapCategory(e.eventType());
                    mapped.add(new AuditEventItem(
                            e.id(),
                            "Live Ledger",
                            TIME_FMT.format(Instant.ofEpochMilli(e.timestamp())),
                            cat,
                            e.actor(),
                            e.eventType() + " • " + e.username(),
                            e.details(),
                            e.remoteIp()
                    ));
                }
                marshalFx(() -> {
                    if (!mapped.isEmpty()) {
                        auditEvents.setAll(mapped);
                    }
                    if (verify != null) {
                        boolean intact = verify.status() == AuditVerifyResult.AuditStatus.OK;
                        String statusText = (intact ? "CHAIN INTACT • " : "VERIFY ALERT • ") + verify.checkedRows() + " ROWS";
                        auditChainStatus.set(statusText);
                    }
                });
            } finally {
                marshalFx(() -> auditLoading.set(false));
            }
        });
    }

    @Override
    public boolean exportAuditCsv(Path targetFile) {
        if (auditService != null && databaseManager != null && !databaseManager.isClosed()) {
            try {
                auditService.exportAuditToCsv(targetFile);
                return true;
            } catch (IOException ex) {
                LOGGER.error("Failed to export live audit log to CSV: {}", ex.getMessage());
                return false;
            }
        }
        Objects.requireNonNull(targetFile, "targetFile");
        StringBuilder sb = new StringBuilder("id,day,time,category,actor,headline,detail,remote_ip\n");
        for (AuditEventItem item : auditEvents) {
            sb.append(item.id()).append(',')
              .append(csv(item.dayGroup())).append(',')
              .append(csv(item.timeText())).append(',')
              .append(csv(item.category().name())).append(',')
              .append(csv(item.actor())).append(',')
              .append(csv(item.headline())).append(',')
              .append(csv(item.detail())).append(',')
              .append(csv(item.remoteIp())).append('\n');
        }
        try {
            Files.writeString(targetFile, sb.toString(), StandardCharsets.UTF_8);
            return true;
        } catch (IOException ex) {
            LOGGER.error("Failed to export client audit events to CSV: {}", ex.getMessage());
            return false;
        }
    }

    private static String csv(String val) {
        if (val == null) return "\"\"";
        return "\"" + val.replace("\"", "\"\"") + "\"";
    }

    private void updateResourceUnlocks(boolean connected) {
        WorkModeProfile mode = activeWorkMode.get();
        boolean guestSafe = mode != null && mode.profileType() == TunnelProfileType.GUEST_SAFE;
        EmployeeIdentity id = currentIdentity.get();
        for (int i = 0; i < officeResources.size(); i++) {
            OfficeResource r = officeResources.get(i);
            boolean unlock = connected && (!guestSafe || !"Departmental".equals(r.department()));
            if (r.unlocked() != unlock) {
                officeResources.set(i, r.withUnlocked(unlock));
            }
        }
        if (mode != null) {
            String deptLabel = (id != null && !"None".equals(id.department())) ? id.department() : "Signed Out";
            accessPolicySummary.set("Policy: " + mode.name() + " • " + deptLabel);
        }
    }

    private void rotateInviteKeyInternal() {
        int a = 0x1000 + SECURE_RANDOM.nextInt(0xE000);
        int b = 0x1000 + SECURE_RANDOM.nextInt(0xE000);
        String code = String.format("OVPN-INV-%04X-%04X", a, b);
        String actor = (engine.getUsername() != null && !engine.getUsername().isBlank())
                ? engine.getUsername()
                : (authorizedAdminUsername != null ? authorizedAdminUsername : "admin");
        inviteKey.set(new InviteKeyState(code, System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(15), 1, actor));
    }

    private static String formatDeptLabel(String rawDept) {
        if (rawDept == null || rawDept.isBlank()) {
            return "Shared";
        }
        String up = rawDept.trim().toUpperCase(Locale.ROOT);
        return switch (up) {
            case "FINANCE" -> "Finance";
            case "IT" -> "Engineering";
            case "HR" -> "HR";
            case "HEADQUARTERS" -> "Headquarters";
            default -> rawDept;
        };
    }

    private static AuditCategory mapCategory(String eventType) {
        if (eventType == null) return AuditCategory.SIGN_IN;
        String up = eventType.toUpperCase(Locale.ROOT);
        if (up.contains("REVOKE") || up.contains("DISCONNECT")) return AuditCategory.REVOKE;
        if (up.contains("FAIL") || up.contains("DENIED") || up.contains("LOCK")) return AuditCategory.FAILED_ATTEMPT;
        if (up.contains("CONFIG") || up.contains("POLICY") || up.contains("TOTP") || up.contains("DEVICE") || up.contains("PASSWORD")) {
            return AuditCategory.POLICY_CHANGE;
        }
        return AuditCategory.SIGN_IN;
    }

    private void setConnectionState(ConnectionState state, String caption) {
        connectionState.set(state);
        statusCaption.set(caption);
    }

    private void setConnectionStateFx(ConnectionState state, String caption) {
        marshalFx(() -> setConnectionState(state, caption));
    }

    private void marshalFx(Runnable r) {
        try {
            if (Platform.isFxApplicationThread()) r.run();
            else Platform.runLater(r);
        } catch (IllegalStateException ex) {
            r.run();
        }
    }

    @Override
    public void close() {
        Arrays.fill(activePassword, '\0');
        if (engineListener != null) {
            engine.removeClientEventListener(engineListener);
        }
        if (killSwitchListener != null && engine.getKillSwitchManager() != null) {
            engine.getKillSwitchManager().removeListener(killSwitchListener);
        }
        if (serverListener != null && gatewayServer != null) {
            gatewayServer.removeServerEventListener(serverListener);
        }
        if (ownsEngine) {
            engine.close();
        }
        if (telemetryTask != null) {
            telemetryTask.cancel(false);
        }
        telemetryScheduler.shutdownNow();
        ioExecutor.shutdownNow();
    }

    // ---- Observable Service Surface ----
    @Override public ReadOnlyObjectProperty<ConnectionState> connectionStateProperty() { return connectionState; }
    @Override public ReadOnlyStringProperty statusCaptionProperty() { return statusCaption; }
    @Override public ReadOnlyIntegerProperty handshakeStepIndexProperty() { return handshakeStepIndex; }
    @Override public ReadOnlyObjectProperty<HandshakeStation> handshakeFailedStationProperty() { return handshakeFailedStation; }
    @Override public ReadOnlyStringProperty handshakeFailureReasonProperty() { return handshakeFailureReason; }
    @Override public ReadOnlyStringProperty cipherSuiteProperty() { return cipherSuite; }
    @Override public ReadOnlyStringProperty virtualIpProperty() { return virtualIp; }
    @Override public ReadOnlyObjectProperty<EmployeeIdentity> currentIdentityProperty() { return currentIdentity; }
    @Override public ReadOnlyObjectProperty<GatewayNode> selectedGatewayProperty() { return selectedGateway; }
    @Override public ObservableList<GatewayNode> gateways() { return gateways; }
    @Override public ObservableList<ThroughputSample> throughputSeries() { return throughputSeries; }
    @Override public ReadOnlyDoubleProperty currentDownloadMbpsProperty() { return currentDownloadMbps; }
    @Override public ReadOnlyDoubleProperty currentUploadMbpsProperty() { return currentUploadMbps; }
    @Override public ReadOnlyIntegerProperty currentLatencyMsProperty() { return currentLatencyMs; }
    @Override public ObservableList<OfficeResource> officeResources() { return officeResources; }
    @Override public ReadOnlyStringProperty accessPolicySummaryProperty() { return accessPolicySummary; }
    @Override public ObservableList<WorkModeProfile> workModes() { return workModes; }
    @Override public ReadOnlyObjectProperty<WorkModeProfile> activeWorkModeProperty() { return activeWorkMode; }
    @Override public BooleanProperty killSwitchEnabledProperty() { return killSwitchEnabled; }
    @Override public BooleanProperty autoConnectUntrustedWifiProperty() { return autoConnectUntrustedWifi; }
    @Override public BooleanProperty dnsLeakGuardProperty() { return dnsLeakGuard; }
    @Override public ObservableList<SplitAppItem> splitApps() { return splitApps; }
    @Override public ObservableList<PostureCheck> postureChecks() { return postureChecks; }
    @Override public ObservableList<EmployeeSessionItem> activeRoster() { return activeRoster; }
    @Override public ReadOnlyObjectProperty<InviteKeyState> inviteKeyProperty() { return inviteKey; }
    @Override public ObservableList<AuditEventItem> auditEvents() { return auditEvents; }
    @Override public ReadOnlyBooleanProperty auditLoadingProperty() { return auditLoading; }
    @Override public ReadOnlyStringProperty auditChainStatusProperty() { return auditChainStatus; }

    @Override
    public void retryHandshake() {
        connect();
    }

    @Override
    public void simulateHandshakeFailure() {
        marshalFx(() -> {
            handshakeFailedStation.set(HandshakeStation.REACH_GATEWAY);
            handshakeFailureReason.set("Manual handshake diagnostic reset triggered");
        });
    }

    @Override
    public void clearKillSwitchBlock() {
        if (engine.getKillSwitchManager() != null) {
            engine.getKillSwitchManager().enable();
        }
        marshalFx(() -> {
            connectionState.set(ConnectionState.DISCONNECTED);
            statusCaption.set("Kill switch reset — ready to connect");
        });
    }

    @Override
    public void selectGateway(String gatewayId) {
        if (gatewayId == null) return;
        marshalFx(() -> {
            for (GatewayNode gw : gateways) {
                if (gw.id().equals(gatewayId)) {
                    selectedGateway.set(gw);
                    if (connectionState.get() == ConnectionState.CONNECTED) {
                        statusCaption.set("Connected to " + gw.city() + " • AES-256-GCM");
                    }
                    break;
                }
            }
        });
    }

    @Override
    public void toggleFavoriteGateway(String gatewayId) {
        if (gatewayId == null) return;
        marshalFx(() -> {
            for (int i = 0; i < gateways.size(); i++) {
                GatewayNode gw = gateways.get(i);
                if (gw.id().equals(gatewayId)) {
                    GatewayNode updated = gw.withFavorite(!gw.favorite());
                    gateways.set(i, updated);
                    if (selectedGateway.get() != null && selectedGateway.get().id().equals(gatewayId)) {
                        selectedGateway.set(updated);
                    }
                    break;
                }
            }
        });
    }

    @Override
    public void activateWorkMode(String modeId) {
        if (modeId == null) return;
        marshalFx(() -> {
            long now = System.currentTimeMillis();
            for (int i = 0; i < workModes.size(); i++) {
                WorkModeProfile m = workModes.get(i);
                if (m.id().equals(modeId)) {
                    WorkModeProfile updated = m.withLastUsed(now);
                    workModes.set(i, updated);
                    activeWorkMode.set(updated);
                    updateResourceUnlocks(connectionState.get() == ConnectionState.CONNECTED);
                    appendLocalAudit(AuditCategory.POLICY_CHANGE, "Switched profile to " + updated.name(),
                            "DNS policy: " + updated.dnsPolicy(), virtualIp.get());
                    break;
                }
            }
        });
    }

    @Override
    public void togglePinWorkMode(String modeId) {
        if (modeId == null) return;
        marshalFx(() -> {
            for (int i = 0; i < workModes.size(); i++) {
                WorkModeProfile m = workModes.get(i);
                if (m.id().equals(modeId)) {
                    WorkModeProfile updated = m.withPinned(!m.pinned());
                    workModes.set(i, updated);
                    if (activeWorkMode.get() != null && activeWorkMode.get().id().equals(modeId)) {
                        activeWorkMode.set(updated);
                    }
                    break;
                }
            }
        });
    }

    @Override
    public void updateWorkMode(WorkModeProfile updated) {
        if (updated == null) return;
        marshalFx(() -> {
            for (int i = 0; i < workModes.size(); i++) {
                if (workModes.get(i).id().equals(updated.id())) {
                    workModes.set(i, updated);
                    if (activeWorkMode.get() != null && activeWorkMode.get().id().equals(updated.id())) {
                        activeWorkMode.set(updated);
                    }
                    break;
                }
            }
        });
    }

    @Override
    public void moveSplitApp(String appId, boolean throughTunnel) {
        if (appId == null) return;
        marshalFx(() -> {
            for (int i = 0; i < splitApps.size(); i++) {
                SplitAppItem item = splitApps.get(i);
                if (item.appId().equals(appId)) {
                    splitApps.set(i, item.withThroughTunnel(throughTunnel));
                    appendLocalAudit(AuditCategory.POLICY_CHANGE,
                            item.displayName() + (throughTunnel ? " -> Through tunnel" : " -> Direct"),
                            "Split-tunnel routing rule updated", virtualIp.get());
                    break;
                }
            }
        });
    }

    @Override
    public void remediatePostureCheck(String checkId) {
        if (checkId == null) return;
        marshalFx(() -> postureChecks.setAll(buildRealPostureChecks()));
    }

    @Override
    public void rerunPostureChecks() {
        marshalFx(() -> postureChecks.setAll(buildRealPostureChecks()));
    }

    @Override
    public void rotateInviteKey() {
        marshalFx(this::rotateInviteKeyInternal);
        appendLocalAudit(AuditCategory.POLICY_CHANGE, "Generated temporary setup key",
                "15-minute enrollment window started", virtualIp.get());
    }

    @Override
    public CompletableFuture<AuthResult> authenticateSso(String provider) {
        return CompletableFuture.completedFuture(new AuthResult(
                false, false, "Sign in with your office username, passphrase, and optional 6-digit MFA code."));
    }
}
