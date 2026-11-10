package com.officevpn.ui.service;

import com.officevpn.admin.AuditService;
import com.officevpn.admin.MetricsCollector;
import com.officevpn.client.VpnClientEngine;
import com.officevpn.config.ConfigUtil;
import com.officevpn.db.DatabaseManager;
import com.officevpn.model.AuditVerifyResult;
import com.officevpn.model.UserAccount;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.security.KillSwitchManager;
import com.officevpn.security.TrustedFingerprintStore;
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
import javafx.beans.property.StringProperty;
import javafx.collections.ObservableList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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

    private final MockVpnService delegate;
    private final VpnClientEngine engine;
    private final boolean ownsEngine;
    private final TrustedFingerprintStore fingerprintStore;
    private final DatabaseManager databaseManager;
    private final VpnGatewayServer gatewayServer;
    private final MetricsCollector metricsCollector;
    private final AuditService auditService;
    private final ExecutorService ioExecutor;

    private VpnClientEngine.ClientEventListener engineListener;
    private KillSwitchManager.KillSwitchListener killSwitchListener;
    private volatile String authenticatedUsername = "";
    private volatile char[] activePassword = new char[0];
    private volatile String activeOtp = "";

    public BackendVpnServiceAdapter(
            VpnClientEngine engine,
            TrustedFingerprintStore fingerprintStore,
            DatabaseManager databaseManager,
            VpnGatewayServer gatewayServer
    ) {
        this.ownsEngine = (engine == null);
        this.engine = (engine != null) ? engine : new VpnClientEngine();
        this.fingerprintStore = fingerprintStore != null ? fingerprintStore : new TrustedFingerprintStore();
        this.databaseManager = databaseManager;
        this.gatewayServer = gatewayServer;
        this.metricsCollector = databaseManager != null
                ? new MetricsCollector(databaseManager, gatewayServer)
                : null;
        this.auditService = databaseManager != null ? new AuditService(databaseManager) : null;
        this.delegate = new MockVpnService(this.engine.isConnected() && this.engine.isAuthenticated());
        this.ioExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "ivory-backend-adapter");
            t.setDaemon(true);
            return t;
        });

        bindPolicyBridges();
        syncGatewaysFromConfig();
        syncEngineSnapshotToUi();
        attachLiveEngineListeners();
        if (databaseManager != null && !databaseManager.isClosed()) {
            refreshAuditLog();
            syncRosterFromGateway();
        }
    }

    @SuppressWarnings("unchecked")
    private void syncEngineSnapshotToUi() {
        marshalFx(() -> {
            if (engine.getUsername() != null && !engine.getUsername().isBlank()) {
                String uname = engine.getUsername().trim();
                String initials = uname.length() >= 2
                        ? uname.substring(0, 2).toUpperCase(Locale.ROOT)
                        : uname.toUpperCase(Locale.ROOT);
                String deptName = engine.getDepartment() != null ? engine.getDepartment().name() : "Shared";
                String roleName = engine.getRole() != null ? engine.getRole().name() : "EMPLOYEE";
                List<String> allowedDepts = "HEADQUARTERS".equalsIgnoreCase(deptName)
                        ? List.of("Finance", "Engineering", "HR", "Shared")
                        : List.of(formatDeptLabel(deptName), "Shared");
                EmployeeIdentity realId = new EmployeeIdentity(
                        uname, uname, initials, roleName, formatDeptLabel(deptName),
                        HardwareUtil.getAuthenticHardwareFingerprint(), allowedDepts);
                if (delegate.currentIdentityProperty() instanceof ObjectProperty<?> op) {
                    ((ObjectProperty<EmployeeIdentity>) op).set(realId);
                }
            }
            if (engine.getAssignedVirtualIp() != null && !engine.getAssignedVirtualIp().isBlank()
                    && !"0.0.0.0".equals(engine.getAssignedVirtualIp())) {
                setStringProp(delegate.virtualIpProperty(), engine.getAssignedVirtualIp());
            }
            if (engine.getKillSwitchManager() != null) {
                KillSwitchManager.State ksState = engine.getKillSwitchManager().getState();
                delegate.killSwitchEnabledProperty().set(ksState != KillSwitchManager.State.DISABLED);
                if (ksState == KillSwitchManager.State.BLOCKING) {
                    setConnectionState(ConnectionState.BLOCKED_BY_KILL_SWITCH,
                            "Unexpected tunnel drop — non-VPN egress blocked by Kill Switch");
                }
            }
            if (engine.getTunnelManager() != null) {
                TunnelManager.TunnelMode tmMode = engine.getTunnelManager().getMode();
                String targetId = (tmMode == TunnelManager.TunnelMode.FULL) ? "mode-full" : "mode-split";
                delegate.activateWorkMode(targetId);
            }
            if (engine.getAutoReconnectManager() != null) {
                delegate.autoConnectUntrustedWifiProperty().set(engine.getAutoReconnectManager().isEnabled());
            }
            delegate.dnsLeakGuardProperty().set(engine.getDnsLeakProtection() != null
                    && engine.getDnsLeakProtection().isLeakProtectionEnabled());
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
                double mbps = Math.max(0.2, ((enc != null ? enc.length : 64) * 8.0) / 1000.0);
                marshalFx(() -> {
                    if ("INCOMING".equalsIgnoreCase(direction)) {
                        setDoubleProp(delegate.currentDownloadMbpsProperty(), mbps);
                    } else {
                        setDoubleProp(delegate.currentUploadMbpsProperty(), mbps);
                    }
                });
            }

            @Override
            public void onConnectionStateChanged(String state) {
                String clean = state != null ? state : "";
                marshalFx(() -> {
                    setStringProp(delegate.statusCaptionProperty(), clean);
                    if (engine.isConnected() && engine.isAuthenticated()) {
                        setConnectionState(ConnectionState.CONNECTED, clean);
                        if (delegate.handshakeStepIndexProperty() instanceof IntegerProperty ip) {
                            ip.set(HandshakeStation.values().length);
                        }
                        if (engine.getAssignedVirtualIp() != null) {
                            setStringProp(delegate.virtualIpProperty(), engine.getAssignedVirtualIp());
                        }
                    } else if (engine.getKillSwitchManager() != null
                            && engine.getKillSwitchManager().getState() == KillSwitchManager.State.BLOCKING) {
                        setConnectionState(ConnectionState.BLOCKED_BY_KILL_SWITCH, clean);
                    } else if (clean.contains("Connecting")) {
                        setConnectionState(ConnectionState.CONNECTING, clean);
                    } else if (clean.contains("Disconnected") || clean.contains("Connection lost")) {
                        setConnectionState(ConnectionState.DISCONNECTED, clean);
                        if (delegate.handshakeStepIndexProperty() instanceof IntegerProperty ip) {
                            ip.set(0);
                        }
                    }
                });
            }
        };
        engine.addClientEventListener(engineListener);

        if (engine.getKillSwitchManager() != null) {
            killSwitchListener = (newState, reason) -> marshalFx(() -> {
                delegate.killSwitchEnabledProperty().set(newState != KillSwitchManager.State.DISABLED);
                if (newState == KillSwitchManager.State.BLOCKING) {
                    setConnectionState(ConnectionState.BLOCKED_BY_KILL_SWITCH, reason);
                }
            });
            engine.getKillSwitchManager().addListener(killSwitchListener);
        }
    }

    private void bindPolicyBridges() {
        delegate.killSwitchEnabledProperty().addListener((obs, o, enabled) -> {
            KillSwitchManager ksm = engine.getKillSwitchManager();
            if (ksm == null) return;
            if (Boolean.TRUE.equals(enabled)) {
                if (ksm.getState() == KillSwitchManager.State.DISABLED) {
                    ksm.enable();
                }
            } else {
                String actor = engine.getUsername() != null ? engine.getUsername() : "local-user";
                ksm.disable(actor, "Disabled via Ivory Atelier Safety Latches");
            }
        });
        delegate.autoConnectUntrustedWifiProperty().addListener((obs, o, enabled) ->
                engine.setAutoReconnect(Boolean.TRUE.equals(enabled)));
        delegate.activeWorkModeProperty().addListener((obs, o, mode) -> {
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
                "gw-live-hq", "Local Gateway", "Primary Office Gateway", "HQ",
                host, port, (int) Math.max(2, metricsCollector != null ? metricsCollector.getAverageLatencyMs() : 4),
                12, true, true, shortFp);
        marshalFx(() -> {
            delegate.gateways().set(0, primary);
            delegate.selectGateway(primary.id());
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
            marshalFx(() -> delegate.activeRoster().setAll(items));
        });
    }

    @Override
    public void connect() {
        GatewayNode gw = delegate.selectedGatewayProperty().get();
        connect(gw != null ? gw.id() : null);
    }

    @Override
    public void connect(String gatewayId) {
        if (gatewayId != null) {
            delegate.selectGateway(gatewayId);
        }
        GatewayNode gw = delegate.selectedGatewayProperty().get();
        if (gw == null) {
            return;
        }
        ioExecutor.submit(() -> {
            try {
                if (!engine.isConnected()) {
                    engine.connectAndHandshake(gw.hostname(), gw.port(), null, fingerprintStore, false);
                }
                if (engine.isAuthenticated()) {
                    marshalFx(() -> {
                        setConnectionState(ConnectionState.CONNECTED, "Connected to " + gw.hostname() + ":" + gw.port());
                        syncRosterFromGateway();
                    });
                    return;
                }
                String user = (authenticatedUsername != null && !authenticatedUsername.isBlank())
                        ? authenticatedUsername
                        : (currentIdentityProperty().get() != null ? currentIdentityProperty().get().username() : "");
                if (!user.isBlank() && activePassword.length > 0) {
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
                        return;
                    }
                }
                engine.disconnect();
                setConnectionStateFx(ConnectionState.DISCONNECTED, "Sign in with valid employee credentials to establish tunnel.");
            } catch (IOException | SecurityException ex) {
                LOGGER.warn("Live tunnel connection failed for {}:{} - {}", gw.hostname(), gw.port(), ex.getMessage());
                setConnectionStateFx(ConnectionState.RECONNECTING, "Gateway connection failed: " + ex.getMessage());
                marshalFx(() -> {
                    if (delegate.handshakeFailedStationProperty() instanceof ObjectProperty<?> op) {
                        @SuppressWarnings("unchecked")
                        ObjectProperty<HandshakeStation> stationProp = (ObjectProperty<HandshakeStation>) op;
                        stationProp.set(HandshakeStation.REACH_GATEWAY);
                    }
                    setStringProp(delegate.handshakeFailureReasonProperty(), ex.getMessage());
                });
            }
        });
    }

    @Override
    public void disconnect() {
        ioExecutor.submit(() -> {
            engine.disconnect();
            delegate.disconnect();
            syncRosterFromGateway();
        });
    }

    @Override
    public void revokeSession(String sessionId) {
        String targetUsername = sessionId;
        for (EmployeeSessionItem item : delegate.activeRoster()) {
            if (Objects.equals(item.sessionId(), sessionId)) {
                targetUsername = item.username();
                break;
            }
        }
        delegate.revokeSession(sessionId);
        if (gatewayServer != null && targetUsername != null && !targetUsername.isBlank()) {
            final String resolvedUser = targetUsername;
            ioExecutor.submit(() -> {
                String actor = engine.getUsername() != null ? engine.getUsername() : "admin";
                gatewayServer.disconnectUser(resolvedUser, "Revoked via Ivory Atelier console", actor);
                syncRosterFromGateway();
                refreshAuditLog();
            });
        }
    }

    @SuppressWarnings("unchecked")
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
        marshalFx(() -> {
            if (delegate.currentIdentityProperty() instanceof ObjectProperty<?> op) {
                ((ObjectProperty<EmployeeIdentity>) op).set(realId);
            }
        });
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
                GatewayNode gw = delegate.selectedGatewayProperty().get();
                boolean canTryWire = gw != null && (gatewayServer == null || gatewayServer.isRunning());
                if (canTryWire) {
                    try {
                        if (!engine.isConnected()) {
                            engine.connectAndHandshake(gw.hostname(), gw.port(), null, fingerprintStore, false);
                        }
                        String rawPw = new String(copyPw);
                        boolean ok = this.activeOtp.isEmpty()
                                ? engine.login(cleanUser, rawPw)
                                : engine.login(cleanUser, rawPw, this.activeOtp);
                        if (ok) {
                            syncEngineSnapshotToUi();
                            marshalFx(() -> {
                                setConnectionState(ConnectionState.CONNECTED, "Connected to " + gw.hostname() + ":" + gw.port());
                                refreshAuditLog();
                                syncRosterFromGateway();
                            });
                            return new AuthResult(true, false, "Authenticated cleanly as " + engine.getUsername());
                        }
                        engine.disconnect();
                        boolean totpNeeded = databaseManager != null && !databaseManager.isClosed()
                                && databaseManager.isTotpEnabled(cleanUser) && this.activeOtp.isEmpty();
                        return new AuthResult(false, totpNeeded,
                                totpNeeded ? "Enter your 6-digit authenticator code." : "Authentication rejected — check username, password, or authenticator code.");
                    } catch (IOException | SecurityException wireEx) {
                        LOGGER.debug("Wire authentication unavailable ({}), checking local DB if configured", wireEx.getMessage());
                        engine.disconnect();
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
            delegate.refreshAuditLog();
            return;
        }
        ioExecutor.submit(() -> {
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
                    delegate.auditEvents().setAll(mapped);
                }
                if (verify != null) {
                    boolean intact = verify.status() == AuditVerifyResult.AuditStatus.OK;
                    String statusText = (intact ? "CHAIN INTACT • " : "VERIFY ALERT • ") + verify.checkedRows() + " ROWS";
                    setStringProp(delegate.auditChainStatusProperty(), statusText);
                }
            });
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
        return delegate.exportAuditCsv(targetFile);
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

    @SuppressWarnings("unchecked")
    private void setConnectionState(ConnectionState state, String caption) {
        if (delegate.connectionStateProperty() instanceof ObjectProperty<?> op) {
            ((ObjectProperty<ConnectionState>) op).set(state);
        }
        setStringProp(delegate.statusCaptionProperty(), caption);
    }

    private void setConnectionStateFx(ConnectionState state, String caption) {
        marshalFx(() -> setConnectionState(state, caption));
    }

    private static void setStringProp(ReadOnlyStringProperty prop, String value) {
        if (prop instanceof StringProperty sp) {
            sp.set(value);
        }
    }

    private static void setDoubleProp(ReadOnlyDoubleProperty prop, double value) {
        if (prop instanceof DoubleProperty dp) {
            dp.set(value);
        }
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
        if (ownsEngine) {
            engine.close();
        }
        delegate.close();
        ioExecutor.shutdownNow();
    }

    // ---- Delegated Observable Surface ----
    @Override public ReadOnlyObjectProperty<ConnectionState> connectionStateProperty() { return delegate.connectionStateProperty(); }
    @Override public ReadOnlyStringProperty statusCaptionProperty() { return delegate.statusCaptionProperty(); }
    @Override public ReadOnlyIntegerProperty handshakeStepIndexProperty() { return delegate.handshakeStepIndexProperty(); }
    @Override public ReadOnlyObjectProperty<HandshakeStation> handshakeFailedStationProperty() { return delegate.handshakeFailedStationProperty(); }
    @Override public ReadOnlyStringProperty handshakeFailureReasonProperty() { return delegate.handshakeFailureReasonProperty(); }
    @Override public ReadOnlyStringProperty cipherSuiteProperty() { return delegate.cipherSuiteProperty(); }
    @Override public ReadOnlyStringProperty virtualIpProperty() { return delegate.virtualIpProperty(); }
    @Override public ReadOnlyObjectProperty<EmployeeIdentity> currentIdentityProperty() { return delegate.currentIdentityProperty(); }
    @Override public ReadOnlyObjectProperty<GatewayNode> selectedGatewayProperty() { return delegate.selectedGatewayProperty(); }
    @Override public ObservableList<GatewayNode> gateways() { return delegate.gateways(); }
    @Override public ObservableList<ThroughputSample> throughputSeries() { return delegate.throughputSeries(); }
    @Override public ReadOnlyDoubleProperty currentDownloadMbpsProperty() { return delegate.currentDownloadMbpsProperty(); }
    @Override public ReadOnlyDoubleProperty currentUploadMbpsProperty() { return delegate.currentUploadMbpsProperty(); }
    @Override public ReadOnlyIntegerProperty currentLatencyMsProperty() { return delegate.currentLatencyMsProperty(); }
    @Override public ObservableList<OfficeResource> officeResources() { return delegate.officeResources(); }
    @Override public ReadOnlyStringProperty accessPolicySummaryProperty() { return delegate.accessPolicySummaryProperty(); }
    @Override public ObservableList<WorkModeProfile> workModes() { return delegate.workModes(); }
    @Override public ReadOnlyObjectProperty<WorkModeProfile> activeWorkModeProperty() { return delegate.activeWorkModeProperty(); }
    @Override public BooleanProperty killSwitchEnabledProperty() { return delegate.killSwitchEnabledProperty(); }
    @Override public BooleanProperty autoConnectUntrustedWifiProperty() { return delegate.autoConnectUntrustedWifiProperty(); }
    @Override public BooleanProperty dnsLeakGuardProperty() { return delegate.dnsLeakGuardProperty(); }
    @Override public ObservableList<SplitAppItem> splitApps() { return delegate.splitApps(); }
    @Override public ObservableList<PostureCheck> postureChecks() { return delegate.postureChecks(); }
    @Override public ObservableList<EmployeeSessionItem> activeRoster() { return delegate.activeRoster(); }
    @Override public ReadOnlyObjectProperty<InviteKeyState> inviteKeyProperty() { return delegate.inviteKeyProperty(); }
    @Override public ObservableList<AuditEventItem> auditEvents() { return delegate.auditEvents(); }
    @Override public ReadOnlyBooleanProperty auditLoadingProperty() { return delegate.auditLoadingProperty(); }
    @Override public ReadOnlyStringProperty auditChainStatusProperty() { return delegate.auditChainStatusProperty(); }
    @Override public void retryHandshake() { connect(); }
    @Override public void simulateHandshakeFailure() { delegate.simulateHandshakeFailure(); }
    @Override public void clearKillSwitchBlock() {
        if (engine.getKillSwitchManager() != null) {
            engine.getKillSwitchManager().enable();
        }
        delegate.clearKillSwitchBlock();
    }
    @Override public void selectGateway(String gatewayId) { delegate.selectGateway(gatewayId); }
    @Override public void toggleFavoriteGateway(String gatewayId) { delegate.toggleFavoriteGateway(gatewayId); }
    @Override public void activateWorkMode(String modeId) { delegate.activateWorkMode(modeId); }
    @Override public void togglePinWorkMode(String modeId) { delegate.togglePinWorkMode(modeId); }
    @Override public void updateWorkMode(WorkModeProfile updated) { delegate.updateWorkMode(updated); }
    @Override public void moveSplitApp(String appId, boolean throughTunnel) { delegate.moveSplitApp(appId, throughTunnel); }
    @Override public void remediatePostureCheck(String checkId) { delegate.remediatePostureCheck(checkId); }
    @Override public void rerunPostureChecks() { delegate.rerunPostureChecks(); }
    @Override public void rotateInviteKey() { delegate.rotateInviteKey(); }
    @Override public CompletableFuture<AuthResult> authenticateSso(String provider) { return delegate.authenticateSso(provider); }
}
