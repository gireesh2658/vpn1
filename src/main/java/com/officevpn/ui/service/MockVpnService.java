package com.officevpn.ui.service;

import com.officevpn.ui.service.VpnModels.*;
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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Self-contained simulated VPN service allowing every Ivory Atelier component and screen
 * to operate standalone with realistic state machines, 60-second telemetry history,
 * branch gateways, office policy locking, posture failures, and live admin roster events.
 */
public final class MockVpnService implements VpnClientService {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm")
            .withZone(ZoneId.systemDefault());

    private final ObjectProperty<ConnectionState> connectionState = new SimpleObjectProperty<>(ConnectionState.DISCONNECTED);
    private final StringProperty statusCaption = new SimpleStringProperty(ConnectionState.DISCONNECTED.defaultCaption());
    private final IntegerProperty handshakeStepIndex = new SimpleIntegerProperty(0);
    private final ObjectProperty<HandshakeStation> handshakeFailedStation = new SimpleObjectProperty<>(null);
    private final StringProperty handshakeFailureReason = new SimpleStringProperty("");
    private final StringProperty cipherSuite = new SimpleStringProperty("AES-256-GCM • ECDH P-256");
    private final StringProperty virtualIp = new SimpleStringProperty("10.8.0.14");

    private final ObjectProperty<EmployeeIdentity> currentIdentity = new SimpleObjectProperty<>(
            new EmployeeIdentity(
                    "a.mehta",
                    "Ananya Mehta",
                    "AM",
                    "Staff Security Engineer",
                    "Engineering",
                    "OVPN-0419",
                    List.of("Engineering", "Shared")
            )
    );
    private final ObjectProperty<GatewayNode> selectedGateway = new SimpleObjectProperty<>();
    private final ObservableList<GatewayNode> gateways = FXCollections.observableArrayList();

    private final ObservableList<ThroughputSample> throughputSeries = FXCollections.observableArrayList();
    private final DoubleProperty currentDownloadMbps = new SimpleDoubleProperty(0.0);
    private final DoubleProperty currentUploadMbps = new SimpleDoubleProperty(0.0);
    private final IntegerProperty currentLatencyMs = new SimpleIntegerProperty(18);

    private final ObservableList<OfficeResource> officeResources = FXCollections.observableArrayList();
    private final StringProperty accessPolicySummary = new SimpleStringProperty("Policy: Engineering + Shared Intranet");

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
    private final StringProperty auditChainStatus = new SimpleStringProperty("CHAIN INTACT • 148 RECORDS");

    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ivory-atelier-mock-service");
        t.setDaemon(true);
        return t;
    });
    private final AtomicLong tickCounter = new AtomicLong(0);
    private final AtomicLong auditSeq = new AtomicLong(100);
    private final AtomicInteger inviteSeq = new AtomicInteger(1);
    private volatile ScheduledFuture<?> activeTransitionTask;
    private final ScheduledFuture<?> telemetryTask;
    private volatile boolean failNextHandshake = false;

    public MockVpnService(boolean startConnected) {
        seedGateways();
        seedOfficeResources();
        seedWorkModes();
        seedSplitApps();
        seedPostureChecks();
        seedRoster();
        seedAuditEvents();
        rotateInviteKeyInternal();
        seedInitialTelemetry(startConnected);

        if (startConnected) {
            connectionState.set(ConnectionState.CONNECTED);
            statusCaption.set("Connected to " + selectedGateway.get().city() + " via AES-256-GCM");
            handshakeStepIndex.set(HandshakeStation.values().length);
            currentDownloadMbps.set(148.6);
            currentUploadMbps.set(42.3);
            updateResourceUnlocks(true);
        }

        killSwitchEnabled.addListener((obs, o, n) -> {
            appendAudit(AuditCategory.POLICY_CHANGE, "Kill switch " + (n ? "armed" : "disarmed"),
                    "Safety latches updated by " + currentIdentity.get().username(), "10.8.0.14");
            if (!n && connectionState.get() == ConnectionState.BLOCKED_BY_KILL_SWITCH) {
                connectionState.set(ConnectionState.DISCONNECTED);
                statusCaption.set(ConnectionState.DISCONNECTED.defaultCaption());
            }
        });
        dnsLeakGuard.addListener((obs, o, n) ->
                appendAudit(AuditCategory.POLICY_CHANGE, "DNS leak guard " + (n ? "enforced (10.8.0.1)" : "paused"),
                        "Internal resolver policy toggled", "10.8.0.14"));

        telemetryTask = scheduler.scheduleAtFixedRate(this::tickTelemetry, 1, 1, TimeUnit.SECONDS);
    }

    private void seedGateways() {
        gateways.setAll(
                new GatewayNode("gw-mun-1", "Munich HQ", "Munich Core 01", "DE", "hq-mun-01.office.internal", 8443, 16, 28, true, true, "de62be7e2624"),
                new GatewayNode("gw-mun-2", "Munich HQ", "Munich Vault Edge", "DE", "hq-mun-02.office.internal", 8443, 21, 52, false, true, "8a44fe9102c1"),
                new GatewayNode("gw-blr-1", "Bengaluru R&D", "Koramangala Core", "IN", "blr-core-01.office.internal", 8443, 34, 61, true, true, "4f90ac1187d2"),
                new GatewayNode("gw-blr-2", "Bengaluru R&D", "Bengaluru Lab 02", "IN", "blr-lab-02.office.internal", 8443, 39, 19, false, true, "2c71db908a44"),
                new GatewayNode("gw-nyc-1", "New York Studio", "Midtown Gateway", "US", "nyc-gw-01.office.internal", 8443, 74, 44, false, true, "91be22f0a871"),
                new GatewayNode("gw-nyc-2", "New York Studio", "SoHo Redundancy", "US", "nyc-gw-02.office.internal", 8443, 81, 86, false, true, "5b12ae7731cd")
        );
        selectedGateway.set(gateways.get(0));
    }

    private void seedOfficeResources() {
        officeResources.setAll(
                // HQ Floorplan rooms (normalized 0..1 coordinates)
                new OfficeResource("hq-fin", OfficeBranch.HQ, "Finance Vault", "Finance", "ledger.office.local, sap.office.local", "TCP 443, 8443", false, 0.05, 0.08, 0.27, 0.36),
                new OfficeResource("hq-eng", OfficeBranch.HQ, "Engineering Lab", "Engineering", "git.office.local, ci.office.local", "TCP 22, 443, 9418", true, 0.36, 0.08, 0.28, 0.36),
                new OfficeResource("hq-hr", OfficeBranch.HQ, "HR Records", "HR", "people.office.local", "TCP 443", false, 0.68, 0.08, 0.27, 0.36),
                new OfficeResource("hq-fs", OfficeBranch.HQ, "File Server", "Shared", "files.office.local (10.8.0.14)", "TCP 445, 443", true, 0.05, 0.56, 0.27, 0.36),
                new OfficeResource("hq-prn", OfficeBranch.HQ, "Printers", "Shared", "print-hq.office.local (10.8.0.22)", "TCP 631, 9100", true, 0.36, 0.56, 0.28, 0.36),
                new OfficeResource("hq-web", OfficeBranch.HQ, "Intranet", "Shared", "wiki.office.local, mail.office.local", "TCP 443", true, 0.68, 0.56, 0.27, 0.36),

                // Bengaluru Branch rooms
                new OfficeResource("blr-eng", OfficeBranch.BLR, "Firmware Rack", "Engineering", "fw-build.blr.office.local", "TCP 22, 443, 8080", true, 0.06, 0.10, 0.41, 0.38),
                new OfficeResource("blr-fs", OfficeBranch.BLR, "Artifact Cache", "Shared", "repo.blr.office.local (10.9.0.12)", "TCP 443, 8081", true, 0.53, 0.10, 0.41, 0.38),
                new OfficeResource("blr-prn", OfficeBranch.BLR, "Plotter & Print", "Shared", "print.blr.office.local", "TCP 631", true, 0.06, 0.56, 0.41, 0.36),
                new OfficeResource("blr-web", OfficeBranch.BLR, "Branch Intranet", "Shared", "blr.office.local", "TCP 443", true, 0.53, 0.56, 0.41, 0.36),

                // NYC Studio rooms
                new OfficeResource("nyc-fin", OfficeBranch.NYC, "Treasury Desk", "Finance", "treasury.nyc.office.local", "TCP 443", false, 0.06, 0.10, 0.41, 0.38),
                new OfficeResource("nyc-web", OfficeBranch.NYC, "Editorial CMS", "Shared", "cms.nyc.office.local", "TCP 443", true, 0.53, 0.10, 0.41, 0.38),
                new OfficeResource("nyc-fs", OfficeBranch.NYC, "Media Vault", "Shared", "media.nyc.office.local", "TCP 445", true, 0.06, 0.56, 0.41, 0.36),
                new OfficeResource("nyc-prn", OfficeBranch.NYC, "Studio Proofs", "Shared", "proof.nyc.office.local", "TCP 631", false, 0.53, 0.56, 0.41, 0.36)
        );
    }

    private void seedWorkModes() {
        long now = System.currentTimeMillis();
        workModes.setAll(
                new WorkModeProfile("mode-split", "Split Tunnel", TunnelProfileType.SPLIT,
                        "Office subnets via AES-256-GCM; public web direct", "https://wiki.office.local", "10.8.0.1 for *.office.local",
                        true, now - 60_000, "peacock"),
                new WorkModeProfile("mode-office", "Office Only", TunnelProfileType.OFFICE_ONLY,
                        "Route corporate VLANs only; zero internet proxy", "https://git.office.local", "10.8.0.1 strict",
                        true, now - 3600_000, "marigold"),
                new WorkModeProfile("mode-full", "Full Tunnel", TunnelProfileType.FULL_TUNNEL,
                        "All device egress encapsulated through HQ gateway", "https://mail.office.local", "10.8.0.1 all queries",
                        false, now - 86_400_000, "lilac"),
                new WorkModeProfile("mode-guest", "Guest-Safe", TunnelProfileType.GUEST_SAFE,
                        "Cafe / airport Wi-Fi strict mode + kill switch", "https://intranet.office.local", "10.8.0.1 + DoH block",
                        false, now - 172_800_000, "coral")
        );
        activeWorkMode.set(workModes.get(0));
    }

    private void seedSplitApps() {
        splitApps.setAll(
                new SplitAppItem("app-git", "Git CLI & SSH", "git.exe / ssh", true),
                new SplitAppItem("app-payroll", "Finance Ledger", "payroll-client.exe", true),
                new SplitAppItem("app-intranet", "Intranet Portal", "edge-corp.exe", true),
                new SplitAppItem("app-smb", "Vault Mount SMB", "explorer.exe //10.8.0.14", true),
                new SplitAppItem("app-zoom", "Video Meetings", "zoom.exe", false),
                new SplitAppItem("app-spotify", "Streaming Audio", "spotify.exe", false),
                new SplitAppItem("app-updates", "OS Update Mirror", "wuauclt.exe", false)
        );
    }

    private void seedPostureChecks() {
        postureChecks.setAll(
                new PostureCheck("posture-os", "OS Patched", true, "Windows 11 24H2 • KB5046617 verified",
                        "Install latest cumulative OS security updates via Windows Update."),
                new PostureCheck("posture-fw", "Firewall On", true, "Domain & Public profiles enforcing inbound drop",
                        "Enable Windows Defender Firewall on Domain and Public network profiles."),
                new PostureCheck("posture-av", "Antivirus Present", true, "Endpoint EDR agent v5.14 healthy",
                        "Start enterprise EDR real-time protection daemon before reconnecting."),
                new PostureCheck("posture-disk", "Disk Encrypted", false, "Secondary D:\\ volume awaiting BitLocker seal",
                        "Open Manage BitLocker and encrypt secondary volume D:\\ to achieve full compliance.")
        );
    }

    private void seedRoster() {
        long now = System.currentTimeMillis();
        activeRoster.setAll(
                new EmployeeSessionItem("sess-101", "a.mehta", "AM", "Engineering", "10.8.0.14", "Munich Core 01", "Windows 11", true, "3/4 Warn", now - 2_340_000, "peacock"),
                new EmployeeSessionItem("sess-102", "r.sharma", "RS", "Finance", "10.8.0.18", "Munich Vault Edge", "macOS 15.2", true, "4/4 Compliant", now - 5_120_000, "marigold"),
                new EmployeeSessionItem("sess-103", "e.schneider", "ES", "HR", "10.8.0.21", "Munich Core 01", "Windows 11", true, "4/4 Compliant", now - 1_450_000, "lilac"),
                new EmployeeSessionItem("sess-104", "k.patel", "KP", "Engineering", "10.9.0.11", "Koramangala Core", "Ubuntu 24.04", false, "2/4 Action", now - 690_000, "coral"),
                new EmployeeSessionItem("sess-105", "m.chen", "MC", "IT Ops", "10.8.0.29", "Midtown Gateway", "macOS 15.1", true, "4/4 Compliant", now - 8_210_000, "peacock")
        );
    }

    private void seedAuditEvents() {
        auditEvents.setAll(
                new AuditEventItem(108, "Today", "16:38", AuditCategory.SIGN_IN, "a.mehta",
                        "Keycard sign-in completed (ECDH P-256)", "Pinned RSA-2048 fingerprint verified: de62be7e2624", "172.24.8.19"),
                new AuditEventItem(107, "Today", "15:14", AuditCategory.POLICY_CHANGE, "m.chen",
                        "WorkMode switched to Split Tunnel", "Assigned DNS 10.8.0.1 for *.office.local", "10.8.0.29"),
                new AuditEventItem(106, "Today", "11:02", AuditCategory.FAILED_ATTEMPT, "unknown@guest",
                        "Rejected expired TOTP token on 2nd attempt", "Progressive MFA throttle counter incremented (2/5)", "203.0.113.44"),
                new AuditEventItem(105, "Yesterday", "18:45", AuditCategory.REVOKE, "m.chen",
                        "Revoked stale contractor session sess-092", "Slide-to-revoke confirmation verified by admin", "10.8.0.29"),
                new AuditEventItem(104, "Yesterday", "09:18", AuditCategory.SIGN_IN, "r.sharma",
                        "Connected to Munich Vault Edge", "Hardware fingerprint HW-7F9A31 trusted", "198.51.100.12"),
                new AuditEventItem(103, "Mon, Nov 9", "14:22", AuditCategory.POLICY_CHANGE, "admin_hq",
                        "Rotated pre-auth enrollment setup key", "Setup token TTL configured to 15 minutes", "10.8.0.1")
        );
    }

    private void seedInitialTelemetry(boolean active) {
        long now = System.currentTimeMillis();
        for (int i = 59; i >= 0; i--) {
            double wave = Math.sin(i * 0.22) * 18.0 + Math.cos(i * 0.47) * 9.0;
            double down = active ? Math.max(12.0, 128.0 + wave) : 0.0;
            double up = active ? Math.max(4.0, 34.0 + wave * 0.38) : 0.0;
            int lat = 16 + (int) Math.abs(Math.sin(i * 0.35) * 7.0);
            throughputSeries.add(new ThroughputSample(now - i * 1000L, down, up, lat));
        }
    }

    private void tickTelemetry() {
        long tick = tickCounter.incrementAndGet();
        ConnectionState state = connectionState.get();
        boolean connected = state == ConnectionState.CONNECTED;

        double down = 0.0;
        double up = 0.0;
        int baseLat = selectedGateway.get() != null ? selectedGateway.get().latencyMs() : 18;
        int lat = baseLat + (int) Math.round(Math.sin(tick * 0.6) * 3.0 + (tick % 7 == 0 ? 5.0 : 0.0));

        if (connected) {
            down = Math.max(8.0, 134.0 + Math.sin(tick * 0.28) * 32.0 + Math.cos(tick * 0.71) * 16.0);
            up = Math.max(3.5, 36.0 + Math.sin(tick * 0.34 + 0.9) * 11.0 + Math.cos(tick * 0.61) * 5.0);
        }

        final double fDown = Math.round(down * 10.0) / 10.0;
        final double fUp = Math.round(up * 10.0) / 10.0;
        final int fLat = Math.max(4, lat);
        final long ts = System.currentTimeMillis();

        marshalFx(() -> {
            if (throughputSeries.size() >= 60) {
                throughputSeries.remove(0);
            }
            throughputSeries.add(new ThroughputSample(ts, fDown, fUp, fLat));
            currentDownloadMbps.set(fDown);
            currentUploadMbps.set(fUp);
            currentLatencyMs.set(fLat);
        });
    }

    private void cancelTransition() {
        ScheduledFuture<?> task = activeTransitionTask;
        if (task != null) {
            task.cancel(false);
        }
    }

    @Override
    public void connect() {
        GatewayNode gw = selectedGateway.get();
        connect(gw != null ? gw.id() : null);
    }

    @Override
    public void connect(String gatewayId) {
        if (gatewayId != null) {
            selectGateway(gatewayId);
        }
        cancelTransition();
        final boolean shouldFail = failNextHandshake;
        failNextHandshake = false;

        marshalFx(() -> {
            handshakeFailedStation.set(null);
            handshakeFailureReason.set("");
            handshakeStepIndex.set(0);
            connectionState.set(ConnectionState.CONNECTING);
            GatewayNode gw = selectedGateway.get();
            statusCaption.set("Dialing " + (gw != null ? gw.city() : "Munich Core 01") + "...");
            updateResourceUnlocks(false);
        });

        activeTransitionTask = scheduler.schedule(() -> runHandshakeSequence(shouldFail), 280, TimeUnit.MILLISECONDS);
    }

    private void runHandshakeSequence(boolean shouldFail) {
        try {
            for (int step = 1; step <= HandshakeStation.values().length; step++) {
                final int idx = step;
                if (connectionState.get() == ConnectionState.DISCONNECTED
                        || connectionState.get() == ConnectionState.BLOCKED_BY_KILL_SWITCH) {
                    return;
                }
                if (shouldFail && step == 3) {
                    marshalFx(() -> {
                        handshakeStepIndex.set(2);
                        handshakeFailedStation.set(HandshakeStation.VERIFY_IDENTITY);
                        handshakeFailureReason.set("Gateway RSA-PSS transcript check timed out");
                        connectionState.set(ConnectionState.RECONNECTING);
                        statusCaption.set("Handshake interrupted — retry or verify gateway fingerprint");
                    });
                    appendAudit(AuditCategory.FAILED_ATTEMPT, "Gateway identity verification interrupted",
                            "Retry offered on HandshakeLoom step 3", "10.8.0.1");
                    return;
                }
                marshalFx(() -> {
                    connectionState.set(idx <= 1 ? ConnectionState.CONNECTING : ConnectionState.HANDSHAKING);
                    handshakeStepIndex.set(idx);
                    statusCaption.set(HandshakeStation.values()[idx - 1].label() + "...");
                });
                Thread.sleep(240L);
            }
            marshalFx(() -> {
                connectionState.set(ConnectionState.CONNECTED);
                GatewayNode gw = selectedGateway.get();
                statusCaption.set("Connected to " + (gw != null ? gw.city() : "HQ Core") + " • AES-256-GCM");
                currentDownloadMbps.set(142.4);
                currentUploadMbps.set(38.9);
                updateResourceUnlocks(true);
            });
            appendAudit(AuditCategory.SIGN_IN, "Encrypted tunnel established",
                    "Gateway: " + (selectedGateway.get() != null ? selectedGateway.get().hostname() : "hq-mun-01"),
                    virtualIp.get());
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void disconnect() {
        cancelTransition();
        marshalFx(() -> {
            handshakeStepIndex.set(0);
            handshakeFailedStation.set(null);
            handshakeFailureReason.set("");
            connectionState.set(ConnectionState.DISCONNECTED);
            statusCaption.set(ConnectionState.DISCONNECTED.defaultCaption());
            currentDownloadMbps.set(0.0);
            currentUploadMbps.set(0.0);
            updateResourceUnlocks(false);
        });
        appendAudit(AuditCategory.SIGN_IN, "Tunnel closed cleanly",
                "User initiated keycard disconnect", virtualIp.get());
    }

    @Override
    public void retryHandshake() {
        failNextHandshake = false;
        connect();
    }

    @Override
    public void simulateHandshakeFailure() {
        failNextHandshake = true;
        connect();
    }

    /**
     * Triggers an immediate blocked kill-switch state for testing/gallery demos.
     */
    public void triggerKillSwitchBlock() {
        cancelTransition();
        marshalFx(() -> {
            killSwitchEnabled.set(true);
            connectionState.set(ConnectionState.BLOCKED_BY_KILL_SWITCH);
            statusCaption.set("Unexpected tunnel drop — non-VPN egress locked by Kill Switch");
            currentDownloadMbps.set(0.0);
            currentUploadMbps.set(0.0);
            updateResourceUnlocks(false);
        });
        appendAudit(AuditCategory.FAILED_ATTEMPT, "Kill switch engaged on tunnel drop",
                "Outbound LAN/WAN egress frozen cleanly", virtualIp.get());
    }

    @Override
    public void clearKillSwitchBlock() {
        marshalFx(() -> {
            connectionState.set(ConnectionState.DISCONNECTED);
            statusCaption.set("Kill switch reset — swipe keycard to reconnect");
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
                    appendAudit(AuditCategory.POLICY_CHANGE, "Switched profile to " + updated.name(),
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
                    appendAudit(AuditCategory.POLICY_CHANGE,
                            item.displayName() + (throughTunnel ? " -> Through tunnel" : " -> Straight out"),
                            "Split-tunnel lane routing rule updated", virtualIp.get());
                    break;
                }
            }
        });
    }

    @Override
    public void remediatePostureCheck(String checkId) {
        if (checkId == null) return;
        marshalFx(() -> {
            for (int i = 0; i < postureChecks.size(); i++) {
                PostureCheck pc = postureChecks.get(i);
                if (pc.id().equals(checkId)) {
                    postureChecks.set(i, pc.withPassed(true, "Volume D:\\ BitLocker XTS-AES-256 verified"));
                    break;
                }
            }
        });
    }

    @Override
    public void rerunPostureChecks() {
        marshalFx(() -> {
            boolean allPassed = postureChecks.stream().allMatch(PostureCheck::passed);
            if (allPassed && !postureChecks.isEmpty()) {
                PostureCheck last = postureChecks.get(postureChecks.size() - 1);
                postureChecks.set(postureChecks.size() - 1,
                        last.withPassed(false, "Secondary D:\\ volume awaiting BitLocker seal"));
            } else {
                for (int i = 0; i < postureChecks.size(); i++) {
                    PostureCheck pc = postureChecks.get(i);
                    if (!pc.passed()) {
                        postureChecks.set(i, pc.withPassed(true, "Verified compliant after quick scan"));
                    }
                }
            }
        });
    }

    @Override
    public void revokeSession(String sessionId) {
        if (sessionId == null) return;
        marshalFx(() -> {
            EmployeeSessionItem target = null;
            for (EmployeeSessionItem item : activeRoster) {
                if (item.sessionId().equals(sessionId)) {
                    target = item;
                    break;
                }
            }
            if (target != null) {
                activeRoster.remove(target);
                appendAudit(AuditCategory.REVOKE,
                        "Revoked session " + target.username() + " (" + target.sessionId() + ")",
                        "Virtual IP " + target.virtualIp() + " reclaimed cleanly", target.virtualIp());
            }
        });
    }

    @Override
    public void rotateInviteKey() {
        marshalFx(this::rotateInviteKeyInternal);
        appendAudit(AuditCategory.POLICY_CHANGE, "Issued fresh single-use device invite key",
                "15-minute enrollment window started", virtualIp.get());
    }

    private void rotateInviteKeyInternal() {
        int n = inviteSeq.getAndIncrement();
        String code = String.format("OVPN-INV-%04X-%04X", 0x4A10 + (n * 7919) % 0x8000, 0x9C20 + (n * 104729) % 0x5000);
        inviteKey.set(new InviteKeyState(code, System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(15), 3, "a.mehta"));
    }

    @Override
    public CompletableFuture<AuthResult> authenticate(String username, String password, String otpCode) {
        CompletableFuture<AuthResult> future = new CompletableFuture<>();
        scheduler.schedule(() -> {
            String cleanUser = username == null ? "" : username.trim();
            String cleanPass = password == null ? "" : password;
            String cleanOtp = otpCode == null ? "" : otpCode.trim();
            if (cleanUser.isEmpty() || cleanPass.length() < 4) {
                future.complete(new AuthResult(false, false, "Enter workspace email and passphrase."));
                return;
            }
            if (cleanOtp.isEmpty()) {
                future.complete(new AuthResult(false, true, "Enter 6-digit authenticator code (demo: 123456)."));
                return;
            }
            if (!"123456".equals(cleanOtp) && !"654321".equals(cleanOtp)) {
                appendAudit(AuditCategory.FAILED_ATTEMPT, "Rejected 6-digit TOTP code for " + cleanUser,
                        "Authenticator mismatch on sign-in card", "172.24.8.19");
                future.complete(new AuthResult(false, true, "Code incorrect — check authenticator time drift."));
                return;
            }
            appendAudit(AuditCategory.SIGN_IN, "Authenticated " + cleanUser + " with TOTP 2FA",
                    "Hardware token binding confirmed", virtualIp.get());
            future.complete(new AuthResult(true, false, "Signed in cleanly as " + cleanUser));
        }, 180, TimeUnit.MILLISECONDS);
        return future;
    }

    @Override
    public CompletableFuture<AuthResult> authenticateSso(String provider) {
        CompletableFuture<AuthResult> future = new CompletableFuture<>();
        scheduler.schedule(() -> {
            appendAudit(AuditCategory.SIGN_IN, "OIDC SSO assertion verified via " + provider,
                    "Short-lived PKCE token bound to keycard", virtualIp.get());
            future.complete(new AuthResult(true, false, "SSO verified with " + provider));
        }, 220, TimeUnit.MILLISECONDS);
        return future;
    }

    @Override
    public void refreshAuditLog() {
        marshalFx(() -> auditLoading.set(true));
        scheduler.schedule(() -> marshalFx(() -> auditLoading.set(false)), 650, TimeUnit.MILLISECONDS);
    }

    @Override
    public boolean exportAuditCsv(Path targetFile) {
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
        } catch (IOException e) {
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
            boolean deptAllowed = id != null && id.allowedDepartments().contains(r.department());
            boolean unlock = connected && deptAllowed && (!guestSafe || "Shared".equals(r.department()));
            if (r.unlocked() != unlock) {
                officeResources.set(i, r.withUnlocked(unlock));
            }
        }
        if (mode != null) {
            accessPolicySummary.set("Policy: " + mode.name() + " • " + (id != null ? id.department() : "Employee"));
        }
    }

    private void appendAudit(AuditCategory cat, String headline, String detail, String ip) {
        long id = auditSeq.incrementAndGet();
        String now = TIME_FMT.format(Instant.now());
        AuditEventItem entry = new AuditEventItem(id, "Today", now, cat,
                currentIdentity.get() != null ? currentIdentity.get().username() : "system",
                headline, detail, ip);
        marshalFx(() -> auditEvents.add(0, entry));
    }

    private void marshalFx(Runnable r) {
        try {
            if (Platform.isFxApplicationThread()) {
                r.run();
            } else {
                Platform.runLater(r);
            }
        } catch (IllegalStateException toolkitNotInitialized) {
            r.run();
        }
    }

    @Override
    public void close() {
        cancelTransition();
        telemetryTask.cancel(false);
        scheduler.shutdownNow();
    }

    // ---- Property Accessors ----
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
}
