package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.gui.UiSafe;
import com.officevpn.protocol.VpnPacket;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Client Encrypted Intranet Dashboard &amp; Multi-Panel Workspace.
 */
public final class ClientDashboardFrame {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientDashboardFrame.class);

    private final Stage stage;
    private final VpnClientEngine engine;
    private final com.officevpn.security.TrustedFingerprintStore fingerprintStore;
    private final FileVaultPanel fileVaultPanel;
    private final ChatPanel chatPanel;
    private final ConnectionStatusPanel connectionStatusPanel;
    private final MyDevicesPanel myDevicesPanel;

    private final StackPane contentHost = new StackPane();
    private final Map<String, Button> navButtons = new LinkedHashMap<>();
    private final Label tunnelPill = new Label("TUNNEL CONNECTED");
    private final Label deptPill = new Label("");
    private final Label pingStatusLabel = new Label("Gateway Latency: OK");

    private final VpnClientEngine.ClientEventListener engineListener;
    private volatile boolean closing = false;

    public ClientDashboardFrame(Stage stage, VpnClientEngine engine) {
        this(stage, engine, com.officevpn.security.TrustedFingerprintStore.getDefault());
    }

    public ClientDashboardFrame(Stage stage, VpnClientEngine engine, com.officevpn.security.TrustedFingerprintStore fingerprintStore) {
        this.stage = stage;
        this.engine = engine;
        this.fingerprintStore = (fingerprintStore != null)
                ? fingerprintStore
                : com.officevpn.security.TrustedFingerprintStore.getDefault();

        this.fileVaultPanel = new FileVaultPanel(engine);
        this.chatPanel = new ChatPanel(engine);
        this.connectionStatusPanel = new ConnectionStatusPanel(engine);
        this.myDevicesPanel = new MyDevicesPanel(engine);

        this.engineListener = createClientListener();
        this.engine.addClientEventListener(engineListener);

        buildScene();
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

        switchView("File Vault", fileVaultPanel);
        root.setCenter(contentHost);

        Scene scene = new Scene(root, 1140, 740);
        UiSafe.applyTheme(scene);

        String uname = UiSafe.text(engine.getUsername(), 32);
        stage.setTitle("Office VPN Client — " + uname + " (" + engine.getDepartment() + ")");
        stage.setMinWidth(920);
        stage.setMinHeight(640);
        stage.setScene(scene);
        stage.setOnCloseRequest(e -> shutdownAndExit());
    }

    private VBox buildSidebar() {
        VBox sidebar = new VBox(6);
        sidebar.getStyleClass().add("sidebar");
        sidebar.setPrefWidth(235);
        sidebar.setMinWidth(220);

        VBox brand = new VBox(3);
        brand.getStyleClass().add("brand-box");
        Label bTitle = new Label("OFFICE VPN CLIENT");
        bTitle.getStyleClass().add("brand-title");
        Label bSub = new Label("PFS ECDH  ·  AES-256-GCM");
        bSub.getStyleClass().add("brand-subtitle");
        brand.getChildren().addAll(bTitle, bSub);

        Label secWorkspace = new Label("ENCRYPTED WORKSPACE");
        secWorkspace.getStyleClass().add("nav-section-label");

        Button navVault = makeNavButton("File Vault", fileVaultPanel);
        Button navChat = makeNavButton("Secure Chat", chatPanel);

        Label secSecurity = new Label("TUNNEL & IDENTITY");
        secSecurity.getStyleClass().add("nav-section-label");

        Button navTunnel = makeNavButton("Tunnel & Defenses", connectionStatusPanel);
        Button navDevices = makeNavButton("My Hardware", myDevicesPanel);

        Region flex = new Region();
        VBox.setVgrow(flex, Priority.ALWAYS);

        VBox identityBox = new VBox(4);
        identityBox.getStyleClass().add("card");
        identityBox.setPadding(new Insets(10, 12, 10, 12));
        Label idUser = new Label(UiSafe.text(engine.getUsername(), 32));
        idUser.setStyle("-fx-font-weight: bold; -fx-text-fill: #f8fafc;");
        Label idMeta = new Label((engine.getRole() != null ? engine.getRole().name() : "-")
                + " · " + (engine.getDepartment() != null ? engine.getDepartment().name() : "-"));
        idMeta.getStyleClass().add("muted-label");
        Label idVip = new Label("VIP: " + UiSafe.text(engine.getAssignedVirtualIp(), 32));
        idVip.getStyleClass().add("mono-text");
        idVip.setStyle("-fx-text-fill: #22d3ee; -fx-font-weight: bold;");
        identityBox.getChildren().addAll(idUser, idMeta, idVip);

        sidebar.getChildren().addAll(
                brand,
                secWorkspace, navVault, navChat,
                secSecurity, navTunnel, navDevices,
                flex, identityBox
        );
        return sidebar;
    }

    private Button makeNavButton(String name, Node view) {
        Button btn = new Button(name);
        btn.getStyleClass().add("nav-button");
        btn.setMaxWidth(Double.MAX_VALUE);
        btn.setOnAction(e -> switchView(name, view));
        navButtons.put(name, btn);
        return btn;
    }

    private HBox buildTopBar() {
        HBox topbar = new HBox(12);
        topbar.getStyleClass().add("topbar");
        topbar.setAlignment(Pos.CENTER_LEFT);

        String vip = UiSafe.text(engine.getAssignedVirtualIp(), 32);
        tunnelPill.setText("ENCRYPTED TUNNEL ACTIVE  ·  " + vip);
        tunnelPill.getStyleClass().addAll("pill", "pill-success");

        deptPill.setText("VAULT: " + (engine.getDepartment() != null ? engine.getDepartment().name() : "-"));
        deptPill.getStyleClass().addAll("pill", "pill-info");

        pingStatusLabel.getStyleClass().add("muted-label");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button copyVipBtn = new Button("Copy VIP");
        copyVipBtn.getStyleClass().add("btn-secondary");
        copyVipBtn.setOnAction(e -> UiSafe.copyToClipboard(vip));

        Button pingBtn = new Button("Ping Gateway");
        pingBtn.getStyleClass().add("btn-secondary");
        pingBtn.setOnAction(e -> handlePing(pingBtn));

        Button disconnectBtn = new Button("Disconnect");
        disconnectBtn.getStyleClass().add("btn-danger");
        disconnectBtn.setOnAction(e -> handleDisconnectToLogin());

        topbar.getChildren().addAll(tunnelPill, deptPill, pingStatusLabel, spacer, copyVipBtn, pingBtn, disconnectBtn);
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
    }

    private void handlePing(Button pingBtn) {
        pingBtn.setDisable(true);
        long startNs = System.nanoTime();
        CompletableFuture.supplyAsync(() -> {
            try {
                return engine.ping();
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }).whenComplete((alive, err) -> Platform.runLater(() -> {
            pingBtn.setDisable(false);
            long ms = Math.max(1, (System.nanoTime() - startNs) / 1_000_000L);
            if (err != null || !Boolean.TRUE.equals(alive)) {
                pingStatusLabel.setText("Ping Failed");
                connectionStatusPanel.appendStateMessage("Gateway PING failed: " + (err != null ? err.getMessage() : "no reply"));
            } else {
                pingStatusLabel.setText("Gateway RTT: " + ms + " ms");
                connectionStatusPanel.appendStateMessage("Gateway PING verified (" + ms + " ms RTT)");
            }
        }));
    }

    private VpnClientEngine.ClientEventListener createClientListener() {
        return new VpnClientEngine.ClientEventListener() {
            @Override
            public void onChatMessage(String senderUser, String senderDept, String senderVip, String message) {
                chatPanel.appendChatMessage(senderUser, senderDept, senderVip, message);
            }

            @Override
            public void onPacketSniffed(VpnPacket packet, String direction) {
                connectionStatusPanel.appendPacketSniffer(packet, direction);
            }

            @Override
            public void onConnectionStateChanged(String state) {
                connectionStatusPanel.appendStateMessage(state);
                UiSafe.runOnFxThread(() -> {
                    connectionStatusPanel.refreshControls();
                    if (!closing && !engine.isConnected()) {
                        tunnelPill.setText("DISCONNECTED");
                        tunnelPill.getStyleClass().removeAll("pill-success", "pill-danger");
                        tunnelPill.getStyleClass().add("pill-danger");
                        pingStatusLabel.setText(UiSafe.text(state, 96));
                    }
                });
            }
        };
    }

    private void handleDisconnectToLogin() {
        cleanupEngine();
        LoginFrame login = new LoginFrame(new Stage(), fingerprintStore);
        login.show();
        stage.close();
    }

    private void shutdownAndExit() {
        cleanupEngine();
        Platform.exit();
    }

    private void cleanupEngine() {
        closing = true;
        connectionStatusPanel.dispose();
        try {
            engine.removeClientEventListener(engineListener);
        } catch (Exception ex) {
            LOGGER.debug("Error detaching client event listener: {}", ex.getMessage());
        }
        try {
            engine.close();
        } catch (Exception ex) {
            LOGGER.debug("Error closing VPN client engine: {}", ex.getMessage());
        }
    }
}
