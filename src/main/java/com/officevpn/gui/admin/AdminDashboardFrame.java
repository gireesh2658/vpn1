package com.officevpn.gui.admin;

import com.officevpn.admin.AlertManager;
import com.officevpn.admin.ConfigManager;
import com.officevpn.admin.DeviceManager;
import com.officevpn.admin.MetricsCollector;
import com.officevpn.admin.ServerManager;
import com.officevpn.config.ConfigUtil;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.AuditVerifyResult;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.server.ServerEventListener;
import com.officevpn.server.VpnGatewayServer;
import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.util.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Headquarters Administrator Control Deck &amp; Multi-View Gateway Console.
 */
public final class AdminDashboardFrame {

    private static final Logger LOGGER = LoggerFactory.getLogger(AdminDashboardFrame.class);

    private final Stage stage;
    private final DatabaseManager db;
    private final VpnGatewayServer gatewayServer;
    private final ServerManager serverManager;
    private final MetricsCollector metricsCollector;
    private final AlertManager alertManager;
    private final DeviceManager deviceManager;
    private final ConfigManager configManager;
    private final String adminUsername;

    private final OverviewPanel overviewPanel;
    private final ConnectedClientsPanel connectedClientsPanel;
    private final UserManagementPanel userManagementPanel;
    private final DevicesPanel devicesPanel;
    private final AlertsPanel alertsPanel;
    private final ConfigPanel configPanel;
    private final AuditLogPanel auditLogPanel;
    private final ServerLogPanel serverLogPanel;
    private final PacketMonitorPanel packetMonitorPanel;

    private final StackPane contentHost = new StackPane();
    private final Map<String, Button> navButtons = new LinkedHashMap<>();

    private final Label serverStatePill = new Label("STOPPED");
    private final Label alertsNavBadge = new Label("0");
    private final Label clientsNavBadge = new Label("0");
    private final Label dbBadge = new Label("MySQL Pool");
    private final Button startBtn = new Button("Start Gateway");
    private final Button stopBtn = new Button("Stop Gateway");
    private final Button restartBtn = new Button("Restart");

    private final ServerEventListener serverListener;
    private Timeline refreshTimeline;
    private volatile boolean shutDownStarted = false;

    public AdminDashboardFrame(
            Stage stage,
            DatabaseManager db,
            VpnGatewayServer gatewayServer,
            String adminUsername,
            CompletableFuture<AuditVerifyResult> startupVerifyFuture
    ) {
        this.stage = stage;
        this.db = db;
        this.gatewayServer = gatewayServer;
        this.adminUsername = (adminUsername != null && !adminUsername.isBlank()) ? adminUsername : "admin_hq";

        this.serverManager = new ServerManager(gatewayServer);
        this.metricsCollector = new MetricsCollector(db, gatewayServer);
        this.alertManager = new AlertManager(db);
        this.deviceManager = new DeviceManager(db);
        this.configManager = new ConfigManager(db, alertManager);

        this.overviewPanel = new OverviewPanel(db, metricsCollector, alertManager, gatewayServer);
        this.connectedClientsPanel = new ConnectedClientsPanel(gatewayServer, this.adminUsername);
        this.userManagementPanel = new UserManagementPanel(db, gatewayServer, this.adminUsername, this::refreshAllLightweight);
        this.devicesPanel = new DevicesPanel(db, deviceManager);
        this.alertsPanel = new AlertsPanel(alertManager, this::updateTopAndNavBadges);
        this.configPanel = new ConfigPanel(configManager, this.adminUsername);
        this.auditLogPanel = new AuditLogPanel(db, alertManager);
        this.serverLogPanel = new ServerLogPanel();
        this.packetMonitorPanel = new PacketMonitorPanel();

        this.serverListener = createEventListener();
        this.gatewayServer.addServerEventListener(serverListener);

        buildScene();
        wireStartupAuditCheck(startupVerifyFuture);
        startAutoRefreshLoop();
        updateServerControlStates();
    }

    public void show() {
        stage.show();
        stage.toFront();
    }

    private void buildScene() {
        BorderPane root = new BorderPane();
        root.getStyleClass().add("app-root");

        root.setLeft(buildSidebar());
        root.setTop(buildTopBar());

        contentHost.setPadding(new Insets(0));
        switchView("Overview", overviewPanel);
        root.setCenter(contentHost);

        Scene scene = new Scene(root, 1280, 820);
        UiSafe.applyTheme(scene);

        stage.setTitle("Office VPN System — Headquarters Governance Deck (" + adminUsername + ")");
        stage.setMinWidth(1040);
        stage.setMinHeight(700);
        stage.setScene(scene);
        stage.setOnCloseRequest(event -> {
            if (gatewayServer.isRunning()) {
                boolean confirm = UiSafe.showConfirm(stage, "Shutdown VPN Gateway?",
                        "Stop active VPN Gateway Server and exit Governance Deck?",
                        "Active client tunnels will be closed cleanly.");
                if (!confirm) {
                    event.consume();
                    return;
                }
            }
            shutdown();
        });
    }

    private VBox buildSidebar() {
        VBox sidebar = new VBox(6);
        sidebar.getStyleClass().add("sidebar");
        sidebar.setPrefWidth(245);
        sidebar.setMinWidth(230);

        VBox brand = new VBox(3);
        brand.getStyleClass().add("brand-box");
        Label bTitle = new Label("OFFICE VPN HQ");
        bTitle.getStyleClass().add("brand-title");
        Label bSub = new Label("OFFICE-VPN-2.0  ·  MYSQL 8+");
        bSub.getStyleClass().add("brand-subtitle");
        brand.getChildren().addAll(bTitle, bSub);

        Label secCore = new Label("COMMAND & TELEMETRY");
        secCore.getStyleClass().add("nav-section-label");

        Button navOverview = makeNavButton("Overview", overviewPanel, null);
        Button navClients = makeNavButton("Connected Clients", connectedClientsPanel, clientsNavBadge);
        Button navAlerts = makeNavButton("Security Alerts", alertsPanel, alertsNavBadge);

        Label secGov = new Label("GOVERNANCE & POLICY");
        secGov.getStyleClass().add("nav-section-label");

        Button navUsers = makeNavButton("User Management", userManagementPanel, null);
        Button navDevices = makeNavButton("Trusted Devices", devicesPanel, null);
        Button navConfig = makeNavButton("Configuration", configPanel, null);

        Label secSec = new Label("FORENSICS & WIRE");
        secSec.getStyleClass().add("nav-section-label");

        Button navAudit = makeNavButton("Audit Trail", auditLogPanel, null);
        Button navConsole = makeNavButton("Server Console", serverLogPanel, null);
        Button navSniffer = makeNavButton("Packet Sniffer", packetMonitorPanel, null);

        Region flex = new Region();
        VBox.setVgrow(flex, Priority.ALWAYS);

        Label adminChip = new Label("Admin: " + UiSafe.text(adminUsername, 24));
        adminChip.getStyleClass().addAll("pill", "pill-info");
        adminChip.setMaxWidth(Double.MAX_VALUE);

        sidebar.getChildren().addAll(
                brand,
                secCore, navOverview, navClients, navAlerts,
                secGov, navUsers, navDevices, navConfig,
                secSec, navAudit, navConsole, navSniffer,
                flex, adminChip
        );
        return sidebar;
    }

    private Button makeNavButton(String label, Node targetView, Label badge) {
        Button btn = new Button();
        btn.getStyleClass().add("nav-button");
        btn.setMaxWidth(Double.MAX_VALUE);

        if (badge != null) {
            HBox row = new HBox(8);
            row.setAlignment(Pos.CENTER_LEFT);
            Label textLbl = new Label(label);
            textLbl.getStyleClass().add("nav-text");
            Region sp = new Region();
            HBox.setHgrow(sp, Priority.ALWAYS);
            badge.getStyleClass().addAll("pill", "pill-muted");
            row.getChildren().addAll(textLbl, sp, badge);
            btn.setGraphic(row);
        } else {
            btn.setText(label);
        }

        btn.setOnAction(e -> switchView(label, targetView));
        navButtons.put(label, btn);
        return btn;
    }

    private HBox buildTopBar() {
        HBox topbar = new HBox(12);
        topbar.getStyleClass().add("topbar");
        topbar.setAlignment(Pos.CENTER_LEFT);

        serverStatePill.getStyleClass().addAll("pill", "pill-muted");
        dbBadge.getStyleClass().addAll("pill", "pill-info");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        startBtn.getStyleClass().add("btn-success");
        startBtn.setOnAction(e -> startGatewayAsync());

        stopBtn.getStyleClass().add("btn-danger");
        stopBtn.setOnAction(e -> stopGatewayAsync());

        restartBtn.getStyleClass().add("btn-warning");
        restartBtn.setOnAction(e -> restartGatewayAsync());

        Button refreshAllBtn = new Button("Refresh All");
        refreshAllBtn.getStyleClass().add("btn-secondary");
        refreshAllBtn.setOnAction(e -> refreshAllViews());

        topbar.getChildren().addAll(
                serverStatePill, dbBadge, spacer,
                startBtn, stopBtn, restartBtn, refreshAllBtn
        );
        return topbar;
    }

    private void switchView(String name, Node view) {
        contentHost.getChildren().setAll(view);
        navButtons.forEach((key, btn) -> {
            btn.getStyleClass().remove("nav-button-active");
            if (key.equals(name)) {
                btn.getStyleClass().add("nav-button-active");
            }
        });
        if (view == overviewPanel) overviewPanel.refresh();
        else if (view == connectedClientsPanel) connectedClientsPanel.refresh();
        else if (view == userManagementPanel) userManagementPanel.refresh();
        else if (view == devicesPanel) devicesPanel.refresh();
        else if (view == alertsPanel) alertsPanel.refresh();
        else if (view == configPanel) configPanel.refresh();
        else if (view == auditLogPanel) auditLogPanel.refresh();
    }

    private ServerEventListener createEventListener() {
        return new ServerEventListener() {
            @Override
            public void onServerLog(String message) {
                serverLogPanel.appendLog(message);
            }

            @Override
            public void onPacketSniffed(VpnPacket rawPacket, String direction) {
                packetMonitorPanel.appendPacket(rawPacket, direction);
            }

            @Override
            public void onSessionUpdated() {
                UiSafe.runOnFxThread(() -> {
                    connectedClientsPanel.refresh();
                    overviewPanel.refresh();
                    devicesPanel.refresh();
                    alertsPanel.refresh();
                    updateTopAndNavBadges();
                });
            }

            @Override
            public void onChatBroadcast(String senderUser, String senderDept, String senderVip, String message) {
                serverLogPanel.appendLog("[CHAT BROADCAST] " + senderUser + " (" + senderDept + "@" + senderVip + "): " + message);
            }
        };
    }

    private void startGatewayAsync() {
        int port = ConfigUtil.getPort();
        startBtn.setDisable(true);
        CompletableFuture.runAsync(() -> {
            try {
                serverManager.startServer(port);
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }).whenComplete((v, err) -> Platform.runLater(() -> {
            if (err != null) {
                Throwable cause = err.getCause() != null ? err.getCause() : err;
                UiSafe.showError(stage, "Gateway Start Failed", cause.getMessage());
            }
            updateServerControlStates();
            refreshAllViews();
        }));
    }

    private void stopGatewayAsync() {
        stopBtn.setDisable(true);
        CompletableFuture.runAsync(serverManager::stopServer).thenRun(() -> Platform.runLater(() -> {
            updateServerControlStates();
            refreshAllViews();
        }));
    }

    private void restartGatewayAsync() {
        int port = ConfigUtil.getPort();
        restartBtn.setDisable(true);
        CompletableFuture.runAsync(() -> {
            try {
                serverManager.restartServer(port);
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }).whenComplete((v, err) -> Platform.runLater(() -> {
            if (err != null) {
                Throwable cause = err.getCause() != null ? err.getCause() : err;
                UiSafe.showError(stage, "Gateway Restart Failed", cause.getMessage());
            }
            updateServerControlStates();
            refreshAllViews();
        }));
    }

    private void updateServerControlStates() {
        boolean running = gatewayServer.isRunning();
        startBtn.setDisable(running);
        stopBtn.setDisable(!running);
        restartBtn.setDisable(!running);

        serverStatePill.getStyleClass().removeAll("pill-success", "pill-danger", "pill-muted");
        if (running) {
            serverStatePill.setText("GATEWAY LIVE  :" + gatewayServer.getBoundPort());
            serverStatePill.getStyleClass().add("pill-success");
        } else {
            serverStatePill.setText("GATEWAY STOPPED");
            serverStatePill.getStyleClass().add("pill-danger");
        }
        updateTopAndNavBadges();
    }

    private void updateTopAndNavBadges() {
        if (shutDownStarted || db.isClosed()) {
            return;
        }
        int sessions = gatewayServer.isRunning() ? gatewayServer.getActiveSessions().size() : 0;
        clientsNavBadge.setText(String.valueOf(sessions));
        CompletableFuture.supplyAsync(() -> {
            if (shutDownStarted || db.isClosed()) return null;
            return new int[]{alertManager.getUnreadCount(), alertManager.getUnreadCriticalCount()};
        }).thenAccept(counts -> Platform.runLater(() -> {
            if (counts == null || shutDownStarted) return;
            alertsNavBadge.setText(String.valueOf(counts[0]));
            alertsNavBadge.getStyleClass().removeAll("pill-danger", "pill-warning", "pill-muted");
            alertsNavBadge.getStyleClass().add(counts[1] > 0 ? "pill-danger" : (counts[0] > 0 ? "pill-warning" : "pill-muted"));
        }));
    }

    private void refreshAllLightweight() {
        overviewPanel.refresh();
        connectedClientsPanel.refresh();
        devicesPanel.refresh();
        alertsPanel.refresh();
        auditLogPanel.refresh();
        updateServerControlStates();
    }

    private void refreshAllViews() {
        userManagementPanel.refresh();
        configPanel.refresh();
        refreshAllLightweight();
    }

    private void startAutoRefreshLoop() {
        refreshTimeline = new Timeline(new KeyFrame(Duration.seconds(2), e -> {
            overviewPanel.refresh();
            connectedClientsPanel.refresh();
            updateServerControlStates();
        }));
        refreshTimeline.setCycleCount(Timeline.INDEFINITE);
        refreshTimeline.play();
    }

    private void wireStartupAuditCheck(CompletableFuture<AuditVerifyResult> startupVerifyFuture) {
        if (startupVerifyFuture == null) return;
        startupVerifyFuture.whenComplete((res, err) -> {
            if (err != null || res == null) return;
            Platform.runLater(() -> {
                auditLogPanel.updateStartupVerifyResult(res);
                if (res.status() != AuditVerifyResult.AuditStatus.OK) {
                    UiSafe.showError(stage, "AUDIT CHAIN INTEGRITY WARNING",
                            "Startup HMAC audit verification reported: " + res.status()
                                    + "\nSequence: " + res.firstBadSeq() + "\n" + res.details());
                }
            });
        });
    }

    public void shutdown() {
        if (shutDownStarted) {
            return;
        }
        shutDownStarted = true;
        if (refreshTimeline != null) {
            refreshTimeline.stop();
        }
        try {
            gatewayServer.removeServerEventListener(serverListener);
        } catch (Exception ex) {
            LOGGER.debug("Error detaching server event listener on shutdown: {}", ex.getMessage());
        }
        try {
            gatewayServer.stop();
        } catch (Exception ex) {
            LOGGER.warn("Error stopping gateway server on shutdown: {}", ex.getMessage());
        }
        try {
            db.close();
        } catch (Exception ex) {
            LOGGER.warn("Error closing database pool on shutdown: {}", ex.getMessage());
        }
        Platform.exit();
    }
}
