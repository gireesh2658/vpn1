package com.officevpn.gui.client;

import com.officevpn.admin.PasswordPolicy;
import com.officevpn.client.VpnClientEngine;
import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.security.TrustedFingerprintStore;
import com.officevpn.ui.AppShell;
import com.officevpn.ui.service.BackendVpnServiceAdapter;
import com.officevpn.ui.theme.IvoryTheme;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Client Encrypted Intranet Dashboard &amp; Multi-Panel Workspace.
 */
public final class ClientDashboardFrame {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientDashboardFrame.class);

    private final Stage stage;
    private final VpnClientEngine engine;
    private final TrustedFingerprintStore fingerprintStore;
    private final FileVaultPanel fileVaultPanel;
    private final ChatPanel chatPanel;
    private final ConnectionStatusPanel connectionStatusPanel;
    private final MyDevicesPanel myDevicesPanel;

    private final StackPane contentHost = new StackPane();
    private final Map<String, Button> navButtons = new LinkedHashMap<>();
    private final Label tunnelStatusPill = new Label(Messages.get("client.top.tunnel.disconnected"));
    private final Label departmentVaultPill = new Label("");
    private final Label connectionLatencyLabel = new Label(Messages.get("client.top.latency.ok"));

    private final Button reconnectButton = new Button(Messages.get("client.button.reconnect"));
    private final Button testConnectionButton = new Button(Messages.get("client.button.testConnection"));
    private final Button changePasswordButton = new Button(Messages.get("client.button.changePassword"));
    private final Button openAtelierButton = new Button(Messages.get("client.button.openAtelier"));
    private final Button disconnectButton = new Button(Messages.get("client.button.disconnect"));

    private final VpnClientEngine.ClientEventListener engineListener;
    private Stage atelierStage;
    private BackendVpnServiceAdapter atelierService;
    private volatile boolean closing = false;

    public ClientDashboardFrame(Stage stage, VpnClientEngine engine) {
        this(stage, engine, TrustedFingerprintStore.getDefault());
    }

    public ClientDashboardFrame(Stage stage, VpnClientEngine engine, TrustedFingerprintStore fingerprintStore) {
        this.stage = stage;
        this.engine = engine;
        this.fingerprintStore = (fingerprintStore != null)
                ? fingerprintStore
                : TrustedFingerprintStore.getDefault();

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

        switchView(Messages.get("client.nav.vault"), fileVaultPanel);
        root.setCenter(contentHost);

        Scene scene = new Scene(root, 1200, 750);
        UiSafe.applyTheme(scene);

        String uname = UiSafe.text(engine.getUsername(), 32);
        String dept = engine.getDepartment() != null ? engine.getDepartment().name() : "-";
        stage.setTitle(Messages.format("app.title.client.dashboard", uname, dept));
        stage.setMinWidth(960);
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
        Label brandTitle = new Label(Messages.get("brand.client.title"));
        brandTitle.getStyleClass().add("brand-title");
        Label brandSubtitle = new Label(Messages.get("brand.client.subtitle"));
        brandSubtitle.getStyleClass().add("brand-subtitle");
        brand.getChildren().addAll(brandTitle, brandSubtitle);

        Label sectionWorkspace = new Label(Messages.get("client.nav.section.workspace"));
        sectionWorkspace.getStyleClass().add("nav-section-label");

        Button navVault = makeNavButton(Messages.get("client.nav.vault"), fileVaultPanel);
        Button navNotices = makeNavButton(Messages.get("client.nav.notices"), chatPanel);

        Label sectionSecurity = new Label(Messages.get("client.nav.section.security"));
        sectionSecurity.getStyleClass().add("nav-section-label");

        Button navTunnel = makeNavButton(Messages.get("client.nav.tunnel"), connectionStatusPanel);
        Button navHardware = makeNavButton(Messages.get("client.nav.hardware"), myDevicesPanel);

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
                sectionWorkspace, navVault, navNotices,
                sectionSecurity, navTunnel, navHardware,
                flex, identityBox
        );
        return sidebar;
    }

    private Button makeNavButton(String name, Node view) {
        Button btn = new Button(name);
        btn.getStyleClass().add("nav-button");
        btn.setMaxWidth(Double.MAX_VALUE);
        Messages.configureAccessibleControl(btn, name, null);
        btn.setOnAction(e -> switchView(name, view));
        navButtons.put(name, btn);
        return btn;
    }

    private HBox buildTopBar() {
        HBox topbar = new HBox(10);
        topbar.getStyleClass().add("topbar");
        topbar.setAlignment(Pos.CENTER_LEFT);

        String vip = UiSafe.text(engine.getAssignedVirtualIp(), 32);
        tunnelStatusPill.setText(Messages.format("client.top.tunnel.active", vip));
        tunnelStatusPill.getStyleClass().addAll("pill", "pill-success");

        String dept = engine.getDepartment() != null ? engine.getDepartment().name() : "-";
        departmentVaultPill.setText(Messages.format("client.top.vault", dept));
        departmentVaultPill.getStyleClass().addAll("pill", "pill-info");

        connectionLatencyLabel.getStyleClass().add("muted-label");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button copyVirtualIpButton = new Button(Messages.get("client.button.copyVip"));
        copyVirtualIpButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(copyVirtualIpButton,
                Messages.get("client.button.copyVip"),
                Messages.get("client.tooltip.copyVip"));
        copyVirtualIpButton.setOnAction(e -> UiSafe.copyToClipboard(engine.getAssignedVirtualIp()));

        testConnectionButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(testConnectionButton,
                Messages.get("client.button.testConnection"),
                Messages.get("client.tooltip.testConnection"));
        testConnectionButton.setOnAction(e -> handleTestConnection());

        reconnectButton.getStyleClass().add("btn-warning");
        reconnectButton.setDisable(engine.isConnected() && engine.isAuthenticated());
        Messages.configureAccessibleControl(reconnectButton,
                Messages.get("client.button.reconnect"),
                Messages.get("client.tooltip.reconnect"));
        reconnectButton.setOnAction(e -> handleReconnect());

        changePasswordButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(changePasswordButton,
                Messages.get("client.button.changePassword"),
                Messages.get("client.tooltip.changePassword"));
        changePasswordButton.setOnAction(e -> handleChangePassword());

        openAtelierButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(openAtelierButton,
                Messages.get("client.button.openAtelier"),
                Messages.get("client.tooltip.openAtelier"));
        openAtelierButton.setOnAction(e -> handleOpenAtelierWorkspace());

        disconnectButton.getStyleClass().add("btn-danger");
        Messages.configureAccessibleControl(disconnectButton,
                Messages.get("client.button.disconnect"),
                Messages.get("client.tooltip.disconnect"));
        disconnectButton.setOnAction(e -> handleDisconnect());

        topbar.getChildren().addAll(
                tunnelStatusPill, departmentVaultPill, connectionLatencyLabel, spacer,
                copyVirtualIpButton, testConnectionButton, reconnectButton,
                changePasswordButton, openAtelierButton, disconnectButton
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
    }

    private void handleTestConnection() {
        testConnectionButton.setDisable(true);
        long startNs = System.nanoTime();
        CompletableFuture.supplyAsync(() -> {
            try {
                return engine.ping();
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }).whenComplete((alive, err) -> Platform.runLater(() -> {
            testConnectionButton.setDisable(false);
            long ms = Math.max(1, (System.nanoTime() - startNs) / 1_000_000L);
            if (err != null || !Boolean.TRUE.equals(alive)) {
                connectionLatencyLabel.setText(Messages.get("client.top.latency.failed"));
                connectionStatusPanel.appendStateMessage("Gateway PING failed: " + (err != null ? err.getMessage() : "no reply"));
            } else {
                connectionLatencyLabel.setText(Messages.format("client.top.latency.rtt", ms));
                connectionStatusPanel.appendStateMessage("Gateway PING verified (" + ms + " ms RTT)");
            }
        }));
    }

    private void handleReconnect() {
        String host = engine.getConnectedHost();
        int port = engine.getConnectedPort();
        if (host == null || host.isBlank() || port <= 0) {
            UiSafe.showWarning(stage, Messages.get("client.reconnect.dialog.title"),
                    Messages.get("client.reconnect.error.noEndpoint"));
            return;
        }

        PasswordField pwField = new PasswordField();
        pwField.setPromptText(Messages.get("login.client.prompt.password"));
        TextField totpField = new TextField();
        totpField.setPromptText(Messages.get("login.client.prompt.totp"));

        VBox content = new VBox(8,
                new Label(Messages.get("login.client.label.password")), pwField,
                new Label(Messages.get("login.client.label.totp")), totpField);
        content.setPrefWidth(380);

        Dialog<ButtonType> dialog = UiSafe.createDialog(stage,
                Messages.get("client.reconnect.dialog.title"),
                Messages.format("client.reconnect.dialog.header", host, String.valueOf(port)),
                content);
        ButtonType reconnectType = new ButtonType(Messages.get("client.button.reconnect"), ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(reconnectType, ButtonType.CANCEL);
        UiSafe.stylePrimaryDialogButton(dialog, reconnectType);

        Optional<ButtonType> choice = dialog.showAndWait();
        if (choice.isEmpty() || choice.get() != reconnectType) {
            return;
        }

        char[] pw = pwField.getText().toCharArray();
        String otp = totpField.getText() != null ? totpField.getText().trim() : "";
        String user = engine.getUsername();
        if (pw.length == 0 || user == null || user.isBlank()) {
            Arrays.fill(pw, '\0');
            UiSafe.showError(stage, Messages.get("client.reconnect.dialog.title"),
                    Messages.get("login.client.error.missingCredentials"));
            return;
        }

        reconnectButton.setDisable(true);
        CompletableFuture.runAsync(() -> {
            try {
                engine.disconnect();
                engine.connectAndHandshake(host, port, null, fingerprintStore, false);
                String pwStr = new String(pw);
                boolean ok = otp.isEmpty() ? engine.login(user, pwStr) : engine.login(user, pwStr, otp);
                if (!ok) {
                    engine.disconnect();
                    throw new SecurityException(Messages.get("login.client.error.authRejected"));
                }
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            } finally {
                Arrays.fill(pw, '\0');
            }
        }).whenComplete((v, err) -> Platform.runLater(() -> {
            if (err != null) {
                Throwable cause = err.getCause() != null ? err.getCause() : err;
                reconnectButton.setDisable(false);
                UiSafe.showError(stage, Messages.get("client.reconnect.dialog.title"),
                        Messages.format("client.reconnect.error.failed", cause.getMessage()));
            } else {
                String activeVip = UiSafe.text(engine.getAssignedVirtualIp(), 32);
                tunnelStatusPill.setText(Messages.format("client.top.tunnel.active", activeVip));
                tunnelStatusPill.getStyleClass().removeAll("pill-danger", "pill-success");
                tunnelStatusPill.getStyleClass().add("pill-success");
                connectionLatencyLabel.setText(Messages.get("client.top.latency.ok"));
                reconnectButton.setDisable(true);
                connectionStatusPanel.refreshControls();
            }
        }));
    }

    private void handleChangePassword() {
        if (!engine.isConnected() || !engine.isAuthenticated()) {
            UiSafe.showWarning(stage, Messages.get("client.password.dialog.title"),
                    Messages.get("client.password.error.disconnected"));
            return;
        }

        PasswordField currentField = new PasswordField();
        currentField.setPromptText(Messages.get("client.password.label.current"));
        PasswordField nextField = new PasswordField();
        nextField.setPromptText("Min " + PasswordPolicy.MIN_LENGTH + " chars (strong passphrase)");
        PasswordField confirmField = new PasswordField();
        confirmField.setPromptText(Messages.get("client.password.label.confirm"));

        VBox content = new VBox(8,
                new Label(Messages.get("client.password.label.current")), currentField,
                new Label(Messages.get("client.password.label.new")), nextField,
                new Label(Messages.get("client.password.label.confirm")), confirmField);
        content.setPrefWidth(400);

        Dialog<ButtonType> dialog = UiSafe.createDialog(stage,
                Messages.get("client.password.dialog.title"),
                Messages.format("client.password.dialog.header", UiSafe.text(engine.getUsername(), 32)),
                content);
        ButtonType saveType = new ButtonType(Messages.get("client.password.button.save"), ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(saveType, ButtonType.CANCEL);
        UiSafe.stylePrimaryDialogButton(dialog, saveType);

        if (dialog.showAndWait().orElse(ButtonType.CANCEL) != saveType) {
            return;
        }

        char[] curPw = currentField.getText().toCharArray();
        char[] newPw = nextField.getText().toCharArray();
        char[] confPw = confirmField.getText().toCharArray();

        try {
            if (!Arrays.equals(newPw, confPw)) {
                throw new IllegalArgumentException(Messages.get("client.password.error.mismatch"));
            }
            PasswordPolicy.validatePassword(newPw, engine.getUsername());
        } catch (IllegalArgumentException ex) {
            Arrays.fill(curPw, '\0');
            Arrays.fill(newPw, '\0');
            Arrays.fill(confPw, '\0');
            UiSafe.showError(stage, Messages.get("client.password.dialog.title"), ex.getMessage());
            return;
        } finally {
            Arrays.fill(confPw, '\0');
        }

        changePasswordButton.setDisable(true);
        CompletableFuture.runAsync(() -> {
            try {
                engine.changePassword(curPw, newPw);
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            } finally {
                Arrays.fill(curPw, '\0');
                Arrays.fill(newPw, '\0');
            }
        }).whenComplete((v, err) -> Platform.runLater(() -> {
            changePasswordButton.setDisable(false);
            if (err != null) {
                Throwable cause = err.getCause() != null ? err.getCause() : err;
                UiSafe.showError(stage, Messages.get("client.password.dialog.title"), cause.getMessage());
            } else {
                UiSafe.showInfo(stage, Messages.get("client.password.dialog.title"),
                        Messages.get("client.password.success"));
            }
        }));
    }

    private void handleOpenAtelierWorkspace() {
        if (atelierStage != null && atelierStage.isShowing()) {
            atelierStage.toFront();
            return;
        }
        atelierService = new BackendVpnServiceAdapter(engine, fingerprintStore, null, null);
        AppShell shell = new AppShell(atelierService);
        Scene scene = new Scene(shell, 1180, 780);
        IvoryTheme.apply(scene);

        atelierStage = new Stage();
        atelierStage.setTitle(Messages.format("app.title.client.atelier", UiSafe.text(engine.getUsername(), 32)));
        atelierStage.setMinWidth(960);
        atelierStage.setMinHeight(640);
        atelierStage.setScene(scene);
        atelierStage.setOnHidden(e -> {
            if (atelierService != null) {
                atelierService.close();
                atelierService = null;
            }
        });
        atelierStage.show();
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
                    boolean up = engine.isConnected() && engine.isAuthenticated();
                    reconnectButton.setDisable(up);
                    if (!closing && !up) {
                        tunnelStatusPill.setText(Messages.get("client.top.tunnel.disconnected"));
                        tunnelStatusPill.getStyleClass().removeAll("pill-success", "pill-danger");
                        tunnelStatusPill.getStyleClass().add("pill-danger");
                        connectionLatencyLabel.setText(UiSafe.text(state, 96));
                    } else if (up) {
                        String activeVip = UiSafe.text(engine.getAssignedVirtualIp(), 32);
                        tunnelStatusPill.setText(Messages.format("client.top.tunnel.active", activeVip));
                        tunnelStatusPill.getStyleClass().removeAll("pill-danger", "pill-success");
                        tunnelStatusPill.getStyleClass().add("pill-success");
                    }
                });
            }
        };
    }

    private void handleDisconnect() {
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
        if (atelierStage != null) {
            atelierStage.close();
        }
        if (atelierService != null) {
            atelierService.close();
            atelierService = null;
        }
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
