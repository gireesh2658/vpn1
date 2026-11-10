package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.config.ConfigUtil;
import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import com.officevpn.security.TrustedFingerprintStore;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * JavaFX Encrypted VPN Client Sign-In, TOFU Pinning &amp; 2FA Authentication Window.
 */
public final class LoginFrame {

    private final Stage stage;
    private final TrustedFingerprintStore fingerprintStore;

    private final TextField gatewayHostField = new TextField(ConfigUtil.getClientDefaultHost());
    private final TextField gatewayPortField = new TextField(String.valueOf(ConfigUtil.getPort()));
    private final TextField expectedFingerprintField = new TextField();
    private final TextField usernameField = new TextField();
    private final PasswordField passwordField = new PasswordField();
    private final TextField totpCodeField = new TextField();

    private final Label pinStatusLabel = new Label("");
    private final Label errorLabel = new Label("");
    private final ProgressBar progressBar = new ProgressBar(0);
    private final Button connectButton = new Button(Messages.get("login.client.button.connect"));
    private final Button clearPinButton = new Button(Messages.get("login.client.button.clearPin"));

    public LoginFrame(Stage stage) {
        this(stage, TrustedFingerprintStore.getDefault());
    }

    public LoginFrame(Stage stage, TrustedFingerprintStore fingerprintStore) {
        this.stage = stage;
        this.fingerprintStore = (fingerprintStore != null) ? fingerprintStore : TrustedFingerprintStore.getDefault();
        buildScene();
        refreshStoredPinIndicator();
    }

    public void show() {
        stage.show();
        stage.toFront();
    }

    private void buildScene() {
        VBox root = new VBox(14);
        root.getStyleClass().add("app-root");
        root.setPadding(new Insets(24));
        root.setPrefWidth(520);

        VBox headerBox = new VBox(4);
        Label titleLabel = new Label(Messages.get("login.client.heading"));
        titleLabel.getStyleClass().add("page-title");
        Label subtitleLabel = new Label(Messages.get("login.client.subheading"));
        subtitleLabel.getStyleClass().add("page-subtitle");
        headerBox.getChildren().addAll(titleLabel, subtitleLabel);

        GridPane networkGrid = new GridPane();
        networkGrid.setHgap(12);
        networkGrid.setVgap(8);
        ColumnConstraints c0 = new ColumnConstraints();
        c0.setPercentWidth(70);
        ColumnConstraints c1 = new ColumnConstraints();
        c1.setPercentWidth(30);
        networkGrid.getColumnConstraints().addAll(c0, c1);

        gatewayHostField.setPromptText(Messages.get("login.client.prompt.host"));
        gatewayPortField.setPromptText(String.valueOf(ConfigUtil.getPort()));
        Messages.configureAccessibleControl(gatewayHostField, Messages.get("login.client.label.host"), null);
        Messages.configureAccessibleControl(gatewayPortField, Messages.get("login.client.label.port"), null);
        gatewayHostField.textProperty().addListener((obs, o, n) -> refreshStoredPinIndicator());
        gatewayPortField.textProperty().addListener((obs, o, n) -> refreshStoredPinIndicator());

        networkGrid.add(new Label(Messages.get("login.client.label.host")), 0, 0);
        networkGrid.add(new Label(Messages.get("login.client.label.port")), 1, 0);
        networkGrid.add(gatewayHostField, 0, 1);
        networkGrid.add(gatewayPortField, 1, 1);

        expectedFingerprintField.setPromptText(Messages.get("login.client.prompt.expectedFp"));
        expectedFingerprintField.getStyleClass().add("mono-text");
        Messages.configureAccessibleControl(expectedFingerprintField, Messages.get("login.client.label.expectedFp"), null);

        pinStatusLabel.getStyleClass().add("muted-label");
        clearPinButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(clearPinButton,
                Messages.get("login.client.button.clearPin"),
                Messages.get("login.client.tooltip.clearPin"));
        clearPinButton.setOnAction(e -> handleClearPin());
        HBox pinRow = new HBox(10, pinStatusLabel, new Region(), clearPinButton);
        HBox.setHgrow(pinRow.getChildren().get(1), Priority.ALWAYS);
        pinRow.setAlignment(Pos.CENTER_LEFT);

        VBox gatewayCard = new VBox(8,
                new Label(Messages.get("login.client.section.gateway")),
                networkGrid,
                new Label(Messages.get("login.client.label.expectedFp")),
                expectedFingerprintField,
                pinRow
        );
        gatewayCard.getStyleClass().add("card");

        usernameField.setPromptText(Messages.get("login.client.prompt.username"));
        passwordField.setPromptText(Messages.get("login.client.prompt.password"));
        totpCodeField.setPromptText(Messages.get("login.client.prompt.totp"));
        Messages.configureAccessibleControl(usernameField, Messages.get("login.client.label.username"), null);
        Messages.configureAccessibleControl(passwordField, Messages.get("login.client.label.password"), null);
        Messages.configureAccessibleControl(totpCodeField, Messages.get("login.client.label.totp"), null);

        VBox authCard = new VBox(8,
                new Label(Messages.get("login.client.section.credentials")),
                new Label(Messages.get("login.client.label.username")), usernameField,
                new Label(Messages.get("login.client.label.password")), passwordField,
                new Label(Messages.get("login.client.label.totp")), totpCodeField
        );
        authCard.getStyleClass().add("card");

        errorLabel.setStyle("-fx-text-fill: #f87171; -fx-font-weight: bold;");
        errorLabel.setWrapText(true);

        progressBar.setMaxWidth(Double.MAX_VALUE);
        progressBar.setPrefHeight(6);
        progressBar.setVisible(false);

        connectButton.getStyleClass().add("btn-primary");
        connectButton.setMaxWidth(Double.MAX_VALUE);
        connectButton.setDefaultButton(true);
        Messages.configureAccessibleControl(connectButton,
                Messages.get("login.client.button.connect"),
                Messages.get("login.client.tooltip.connect"));
        connectButton.setOnAction(e -> handleConnect());

        root.getChildren().addAll(headerBox, gatewayCard, authCard, errorLabel, progressBar, connectButton);

        Scene scene = new Scene(root);
        UiSafe.applyTheme(scene);
        stage.setTitle(Messages.get("app.title.client.login"));
        stage.setResizable(false);
        stage.setScene(scene);
        stage.setOnCloseRequest(e -> Platform.exit());
    }

    private void handleClearPin() {
        String host = safeHost();
        int port = safePort();
        if (port > 0) {
            fingerprintStore.removePin(host, port);
            refreshStoredPinIndicator();
        }
    }

    private void refreshStoredPinIndicator() {
        String host = safeHost();
        int port = safePort();
        if (host.isEmpty() || port <= 0) {
            pinStatusLabel.setText(Messages.get("login.client.pin.invalidEndpoint"));
            clearPinButton.setDisable(true);
            return;
        }
        Optional<String> existing = fingerprintStore.getPinnedFingerprint(host, port);
        if (existing.isPresent()) {
            String fp = existing.get();
            String preview = fp.length() > 24 ? fp.substring(0, 24) + "..." : fp;
            pinStatusLabel.setText(Messages.format("login.client.pin.stored", preview));
            clearPinButton.setDisable(false);
        } else {
            pinStatusLabel.setText(Messages.format("login.client.pin.none", host, String.valueOf(port)));
            clearPinButton.setDisable(true);
        }
    }

    private String safeHost() {
        return gatewayHostField.getText() != null ? gatewayHostField.getText().trim() : "";
    }

    private int safePort() {
        try {
            int p = Integer.parseInt(gatewayPortField.getText().trim());
            return (p >= 1 && p <= 65535) ? p : -1;
        } catch (Exception e) {
            return -1;
        }
    }

    private void handleConnect() {
        String host = safeHost();
        int port = safePort();
        String username = usernameField.getText() != null ? usernameField.getText().trim() : "";
        String password = passwordField.getText() != null ? passwordField.getText() : "";
        String totp = totpCodeField.getText() != null ? totpCodeField.getText().trim() : "";
        String typedFp = expectedFingerprintField.getText() != null ? expectedFingerprintField.getText().trim() : "";

        if (host.isEmpty() || port <= 0) {
            errorLabel.setText(Messages.get("login.client.error.invalidEndpoint"));
            return;
        }
        if (username.isEmpty() || password.isEmpty()) {
            errorLabel.setText(Messages.get("login.client.error.missingCredentials"));
            return;
        }

        errorLabel.setText("");
        setBusy(true, Messages.get("login.client.button.connecting"));

        CompletableFuture.supplyAsync(() -> connectAndAuthenticate(host, port, typedFp, username, password, totp))
                .whenComplete((engine, err) -> Platform.runLater(() -> {
                    if (err != null) {
                        setBusy(false, "");
                        Throwable cause = err.getCause() != null ? err.getCause() : err;
                        errorLabel.setText(cause.getMessage());
                        passwordField.clear();
                        refreshStoredPinIndicator();
                    } else {
                        setBusy(false, "");
                        ClientDashboardFrame dashboard = new ClientDashboardFrame(new Stage(), engine, fingerprintStore);
                        dashboard.show();
                        stage.close();
                    }
                }));
    }

    private VpnClientEngine connectAndAuthenticate(
            String host,
            int port,
            String typedFp,
            String username,
            String password,
            String totp
    ) {
        String cleanFp = typedFp.isEmpty() ? null : typedFp;
        VpnClientEngine activeEngine;
        try {
            activeEngine = openHandshake(host, port, cleanFp, false);
        } catch (SecurityException pinEx) {
            if (pinEx.getMessage() != null && pinEx.getMessage().contains("GATEWAY IDENTITY CHANGED")) {
                boolean approved = askConfirmPinReplaceOnFx(pinEx.getMessage());
                if (!approved) {
                    throw pinEx;
                }
                activeEngine = openHandshake(host, port, cleanFp, true);
            } else {
                throw pinEx;
            }
        }

        boolean handoff = false;
        try {
            boolean authed = activeEngine.login(username, password, totp.isEmpty() ? null : totp);
            if (!authed) {
                throw new SecurityException(Messages.get("login.client.error.authRejected"));
            }
            handoff = true;
            return activeEngine;
        } catch (Exception ex) {
            throw (ex instanceof RuntimeException re) ? re : new IllegalStateException(ex.getMessage(), ex);
        } finally {
            if (!handoff) {
                activeEngine.close();
            }
        }
    }

    private VpnClientEngine openHandshake(String host, int port, String typedFp, boolean confirmReplace) {
        VpnClientEngine eng = new VpnClientEngine();
        boolean ok = false;
        try {
            eng.connectAndHandshake(host, port, typedFp, fingerprintStore, confirmReplace);
            ok = true;
            return eng;
        } catch (Exception ex) {
            throw (ex instanceof RuntimeException re) ? re : new IllegalStateException(ex.getMessage(), ex);
        } finally {
            if (!ok) {
                eng.close();
            }
        }
    }

    private boolean askConfirmPinReplaceOnFx(String details) {
        CompletableFuture<Boolean> decision = new CompletableFuture<>();
        Platform.runLater(() -> {
            boolean yes = UiSafe.showConfirm(stage,
                    Messages.get("login.client.warning.pinChanged.title"),
                    Messages.get("login.client.warning.pinChanged.header"),
                    details + "\n\n" + Messages.get("login.client.warning.pinChanged.footer"));
            decision.complete(yes);
        });
        try {
            return decision.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (ExecutionException e) {
            return false;
        }
    }

    private void setBusy(boolean busy, String text) {
        gatewayHostField.setDisable(busy);
        gatewayPortField.setDisable(busy);
        expectedFingerprintField.setDisable(busy);
        usernameField.setDisable(busy);
        passwordField.setDisable(busy);
        totpCodeField.setDisable(busy);
        clearPinButton.setDisable(busy);
        connectButton.setDisable(busy);
        progressBar.setVisible(busy);
        progressBar.setProgress(busy ? ProgressBar.INDETERMINATE_PROGRESS : 0);
        connectButton.setText(busy ? text : Messages.get("login.client.button.connect"));
    }
}
