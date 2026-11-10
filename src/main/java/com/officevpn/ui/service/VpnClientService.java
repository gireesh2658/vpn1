package com.officevpn.ui.service;

import com.officevpn.ui.service.VpnModels.*;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.IntegerProperty;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.ReadOnlyBooleanProperty;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.beans.property.ReadOnlyIntegerProperty;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.beans.property.ReadOnlyStringProperty;
import javafx.collections.ObservableList;

import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;

/**
 * Strict UI-to-daemon service boundary decoupling JavaFX views/components from
 * cryptographic protocol engines, MySQL persistence, or simulated backends.
 * <p>
 * Implementations must marshal all property and list updates onto the JavaFX Application Thread.
 */
public interface VpnClientService extends AutoCloseable {

    // ---- Connection & Handshake ----
    ReadOnlyObjectProperty<ConnectionState> connectionStateProperty();

    ReadOnlyStringProperty statusCaptionProperty();

    ReadOnlyIntegerProperty handshakeStepIndexProperty();

    ReadOnlyObjectProperty<HandshakeStation> handshakeFailedStationProperty();

    ReadOnlyStringProperty handshakeFailureReasonProperty();

    ReadOnlyStringProperty cipherSuiteProperty();

    ReadOnlyStringProperty virtualIpProperty();

    // ---- Identity & Gateways ----
    ReadOnlyObjectProperty<EmployeeIdentity> currentIdentityProperty();

    ReadOnlyObjectProperty<GatewayNode> selectedGatewayProperty();

    ObservableList<GatewayNode> gateways();

    // ---- Throughput & Latency Telemetry ----
    ObservableList<ThroughputSample> throughputSeries();

    ReadOnlyDoubleProperty currentDownloadMbpsProperty();

    ReadOnlyDoubleProperty currentUploadMbpsProperty();

    ReadOnlyIntegerProperty currentLatencyMsProperty();

    // ---- Floorplan Resources & Policy ----
    ObservableList<OfficeResource> officeResources();

    ReadOnlyStringProperty accessPolicySummaryProperty();

    // ---- Work Modes ----
    ObservableList<WorkModeProfile> workModes();

    ReadOnlyObjectProperty<WorkModeProfile> activeWorkModeProperty();

    // ---- Safety Latches & Split Tunneling ----
    BooleanProperty killSwitchEnabledProperty();

    BooleanProperty autoConnectUntrustedWifiProperty();

    BooleanProperty dnsLeakGuardProperty();

    ObservableList<SplitAppItem> splitApps();

    // ---- Device Posture ----
    ObservableList<PostureCheck> postureChecks();

    // ---- Admin Roster, Invites & Audit Thread ----
    ObservableList<EmployeeSessionItem> activeRoster();

    ReadOnlyObjectProperty<InviteKeyState> inviteKeyProperty();

    ObservableList<AuditEventItem> auditEvents();

    ReadOnlyBooleanProperty auditLoadingProperty();

    ReadOnlyStringProperty auditChainStatusProperty();

    // ---- Commands ----
    void connect();

    void connect(String gatewayId);

    void disconnect();

    void retryHandshake();

    void simulateHandshakeFailure();

    void clearKillSwitchBlock();

    void selectGateway(String gatewayId);

    void toggleFavoriteGateway(String gatewayId);

    void activateWorkMode(String modeId);

    void togglePinWorkMode(String modeId);

    void updateWorkMode(WorkModeProfile updated);

    void moveSplitApp(String appId, boolean throughTunnel);

    void remediatePostureCheck(String checkId);

    void rerunPostureChecks();

    void revokeSession(String sessionId);

    void rotateInviteKey();

    CompletableFuture<AuthResult> authenticate(String username, String password, String otpCode);

    CompletableFuture<AuthResult> authenticateSso(String provider);

    void refreshAuditLog();

    boolean exportAuditCsv(Path targetFile);

    @Override
    default void close() {
    }
}

