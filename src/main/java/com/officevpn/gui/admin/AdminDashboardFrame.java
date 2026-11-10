package com.officevpn.gui.admin;

import com.officevpn.admin.AlertManager;
import com.officevpn.admin.ConfigManager;
import com.officevpn.admin.DeviceManager;
import com.officevpn.admin.MetricsCollector;
import com.officevpn.admin.ServerManager;
import com.officevpn.config.ConfigUtil;
import com.officevpn.config.Messages;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.AuditVerifyResult;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.server.ServerEventListener;
import com.officevpn.server.VpnGatewayServer;
import com.officevpn.ui.AppShell;
import com.officevpn.ui.service.BackendVpnServiceAdapter;
import com.officevpn.ui.theme.IvoryTheme;
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

    private final Label serverStatePill = new Label(Messages.get("admin.state.stopped"));
    private final Label alertsNavBadge = new Label("0");
    private final Label clientsNavBadge = new Label("0");
    private final Label dbBadge = new Label("MySQL Pool");
    private final Button startGatewayButton = new Button(Messages.get("admin.button.startGateway"));
    private final Button stopGatewayButton = new Button(Messages.get("admin.button.stopGateway"));
    private final Button restartGatewayButton = new Button(Messages.get("admin.button.restartGateway"));
    private final Button openAtelierButton = new Button(Messages.get("admin.button.openAtelier"));

    private Stage atelierStage;
    private BackendVpnServiceAdapter atelierService;

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
        if (adminUsername == null || adminUsername.isBlank()) {
            throw new IllegalArgumentException("Authenticated administrator username is required");
        }
        this.adminUsername = adminUsername.trim();

        this.serverManager = new ServerManager(gatewayServer);
        this.metricsCollector = new MetricsCollector(db, gatewayServer);
        this.alertManager = new AlertManager(db);
        this.deviceManager = new DeviceManager(db);
        this.configManager = new ConfigManager(db, alertManager);

        this.overviewPanel = new OverviewPanel(db, metricsCollector, alertManager, gatewayServer);
        this.connectedClientsPanel = new ConnectedClientsPanel(gatewayServer, this.adminUsername);
        this.userManagementPanel = new UserManagementPanel(db, gatewayServer, this.adminUsername, this::refreshAllLightweight);
        this.devicesPanel = new DevicesPanel(db, deviceManager, this.adminUsername);
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
        switchView(Messages.get("admin.nav.overview"), overviewPanel);
        root.setCenter(contentHost);

        Scene scene = new Scene(root, 1280, 820);
        UiSafe.applyTheme(scene);

        stage.setTitle(Messages.format("app.title.admin.dashboard", adminUsername));
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
        Label bTitle = new Label(Messages.get("brand.admin.title"));
        bTitle.getStyleClass().add("brand-title");
        Label bSub = new Label(Messages.get("brand.admin.subtitle"));
        bSub.getStyleClass().add("brand-subtitle");
        brand.getChildren().addAll(bTitle, bSub);

        Label secCore = new Label(Messages.get("admin.nav.section.command"));
        secCore.getStyleClass().add("nav-section-label");

        Button navOverview = makeNavButton(Messages.get("admin.nav.overview"), overviewPanel, null);
        Button navClients = makeNavButton(Messages.get("admin.nav.clients"), connectedClientsPanel, clientsNavBadge);
        Button navAlerts = makeNavButton(Messages.get("admin.nav.alerts"), alertsPanel, alertsNavBadge);

        Label secGov = new Label(Messages.get("admin.nav.section.governance"));
        secGov.getStyleClass().add("nav-section-label");

        Button navUsers = makeNavButton(Messages.get("admin.nav.users"), userManagementPanel, null);
        Button navDevices = makeNavButton(Messages.get("admin.nav.devices"), devicesPanel, null);
        Button navConfig = makeNavButton(Messages.get("admin.nav.config"), configPanel, null);

        Label secSec = new Label(Messages.get("admin.nav.section.forensics"));
        secSec.getStyleClass().add("nav-section-label");

        Button navAudit = makeNavButton(Messages.get("admin.nav.audit"), auditLogPanel, null);
        Button navConsole = makeNavButton(Messages.get("admin.nav.console"), serverLogPanel, null);
        Button navSniffer = makeNavButton(Messages.get("admin.nav.sniffer"), packetMonitorPanel, null);

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

        btn.setOnAction(_ -> switchView(label, targetView));
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

        startGatewayButton.getStyleClass().add("btn-success");
        Messages.configureAccessibleControl(startGatewayButton,
                Messages.get("admin.button.startGateway"),
                Messages.get("admin.tooltip.startGateway"));
        startGatewayButton.setOnAction(_ -> startGatewayAsync());

        stopGatewayButton.getStyleClass().add("btn-danger");
        Messages.configureAccessibleControl(stopGatewayButton,
                Messages.get("admin.button.stopGateway"),
                Messages.get("admin.tooltip.stopGateway"));
        stopGatewayButton.setOnAction(_ -> stopGatewayAsync());

        restartGatewayButton.getStyleClass().add("btn-warning");
        Messages.configureAccessibleControl(restartGatewayButton,
                Messages.get("admin.button.restartGateway"),
                Messages.get("admin.tooltip.restartGateway"));
        restartGatewayButton.setOnAction(_ -> restartGatewayAsync());

        Button refreshAllButton = new Button(Messages.get("admin.button.refreshAll"));
        refreshAllButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(refreshAllButton,
                Messages.get("admin.button.refreshAll"),
                Messages.get("admin.tooltip.refreshAll"));
        refreshAllButton.setOnAction(_ -> refreshAllViews());

        openAtelierButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(openAtelierButton,
                Messages.get("admin.button.openAtelier"),
                Messages.get("admin.tooltip.openAtelier"));
        openAtelierButton.setOnAction(_ -> handleOpenAtelierGovernance());

        topbar.getChildren().addAll(
                serverStatePill, dbBadge, spacer,
                startGatewayButton, stopGatewayButton, restartGatewayButton, refreshAllButton, openAtelierButton
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
                    if (atelierService != null) {
                        atelierService.syncRosterFromGateway();
                        atelierService.refreshAuditLog();
                    }
                });
            }

            @Override
            public void onChatBroadcast(String senderUser, String senderDept, String senderVip, String message) {
                serverLogPanel.appendLog("[CHAT BROADCAST] " + senderUser + " (" + senderDept + "@" + senderVip + "): " + message);
            }
        };
    }

    private void handleOpenAtelierGovernance() {
        if (atelierStage != null && atelierStage.isShowing()) {
            atelierStage.toFront();
            return;
        }
        atelierService = new BackendVpnServiceAdapter(null, null, db, gatewayServer, this.adminUsername);
        AppShell shell = new AppShell(atelierService);
        shell.switchTo(AppShell.Section.ADMIN);
        Scene scene = new Scene(shell, 1220, 800);
        IvoryTheme.apply(scene);

        atelierStage = new Stage();
        atelierStage.setTitle(Messages.format("app.title.admin.atelier", adminUsername));
        atelierStage.setMinWidth(960);
        atelierStage.setMinHeight(640);
        atelierStage.setScene(scene);
        atelierStage.setOnHidden(_ -> {
            shell.close();
            if (atelierService != null) {
                atelierService.close();
                atelierService = null;
            }
        });
        atelierStage.show();
    }

    private void startGatewayAsync() {
        int port = ConfigUtil.getPort();
        startGatewayButton.setDisable(true);
        CompletableFuture.runAsync(() -> {
            try {
                serverManager.startServer(port);
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }).whenComplete((_, err) -> Platform.runLater(() -> {
            if (err != null) {
                Throwable cause = err.getCause() != null ? err.getCause() : err;
                UiSafe.showError(stage, "Gateway Start Failed", cause.getMessage());
            }
            updateServerControlStates();
            refreshAllViews();
        }));
    }

    private void stopGatewayAsync() {
        stopGatewayButton.setDisable(true);
        CompletableFuture.runAsync(serverManager::stopServer).thenRun(() -> Platform.runLater(() -> {
            updateServerControlStates();
            refreshAllViews();
        }));
    }

    private void restartGatewayAsync() {
        int port = ConfigUtil.getPort();
        restartGatewayButton.setDisable(true);
        CompletableFuture.runAsync(() -> {
            try {
                serverManager.restartServer(port);
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }).whenComplete((_, err) -> Platform.runLater(() -> {
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
        startGatewayButton.setDisable(running);
        stopGatewayButton.setDisable(!running);
        restartGatewayButton.setDisable(!running);

        serverStatePill.getStyleClass().removeAll("pill-success", "pill-danger", "pill-muted");
        if (running) {
            serverStatePill.setText(Messages.format("admin.state.live", String.valueOf(gatewayServer.getBoundPort())));
            serverStatePill.getStyleClass().add("pill-success");
        } else {
            serverStatePill.setText(Messages.get("admin.state.stopped"));
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
        refreshTimeline = new Timeline(new KeyFrame(Duration.seconds(2), _ -> {
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
        if (atelierStage != null) {
            atelierStage.close();
        }
        if (atelierService != null) {
            atelierService.close();
            atelierService = null;
        }
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
