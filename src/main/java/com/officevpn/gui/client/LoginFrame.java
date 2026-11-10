package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.config.ConfigUtil;
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
 * JavaFX Encrypted VPN Client Login, TOFU Pinning &amp; 2FA Authentication Window.
 */
public final class LoginFrame {

    private final Stage stage;
    private final TrustedFingerprintStore fingerprintStore;

    private final TextField hostField = new TextField(ConfigUtil.getClientDefaultHost());
    private final TextField portField = new TextField(String.valueOf(ConfigUtil.getPort()));
    private final TextField expectedFpField = new TextField();
    private final TextField usernameField = new TextField();
    private final PasswordField passwordField = new PasswordField();
    private final TextField totpField = new TextField();

    private final Label pinStatusLabel = new Label("");
    private final Label errorLabel = new Label("");
    private final ProgressBar progressBar = new ProgressBar(0);
    private final Button connectBtn = new Button("Connect & Establish Encrypted Tunnel");
    private final Button clearPinBtn = new Button("Clear Pin");

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
        Label title = new Label("Office VPN Secure Client");
        title.getStyleClass().add("page-title");
        Label subtitle = new Label("OFFICE-VPN-2.0 Hybrid ECDH PFS · RSASSA-PSS TOFU · AES-256-GCM Tunnel");
        subtitle.getStyleClass().add("page-subtitle");
        headerBox.getChildren().addAll(title, subtitle);

        GridPane netGrid = new GridPane();
        netGrid.setHgap(12);
        netGrid.setVgap(8);
        ColumnConstraints c0 = new ColumnConstraints();
        c0.setPercentWidth(70);
        ColumnConstraints c1 = new ColumnConstraints();
        c1.setPercentWidth(30);
        netGrid.getColumnConstraints().addAll(c0, c1);

        hostField.setPromptText("Gateway host or IP");
        portField.setPromptText(String.valueOf(ConfigUtil.getPort()));
        hostField.textProperty().addListener((obs, o, n) -> refreshStoredPinIndicator());
        portField.textProperty().addListener((obs, o, n) -> refreshStoredPinIndicator());

        netGrid.add(new Label("Gateway Host"), 0, 0);
        netGrid.add(new Label("Port"), 1, 0);
        netGrid.add(hostField, 0, 1);
        netGrid.add(portField, 1, 1);

        expectedFpField.setPromptText("Optional expected SHA-256 hex fingerprint for strict first-use pinning");
        expectedFpField.getStyleClass().add("mono-text");

        pinStatusLabel.getStyleClass().add("muted-label");
        clearPinBtn.getStyleClass().add("btn-secondary");
        clearPinBtn.setOnAction(e -> {
            String host = safeHost();
            int port = safePort();
            if (port > 0) {
                fingerprintStore.removePin(host, port);
                refreshStoredPinIndicator();
            }
        });
        HBox pinRow = new HBox(10, pinStatusLabel, new Region(), clearPinBtn);
        HBox.setHgrow(pinRow.getChildren().get(1), Priority.ALWAYS);
        pinRow.setAlignment(Pos.CENTER_LEFT);

        VBox gatewayCard = new VBox(8,
                new Label("GATEWAY ENDPOINT & IDENTITY PINNING"),
                netGrid,
                new Label("Expected Server Fingerprint (Optional TOFU Pre-Check)"),
                expectedFpField,
                pinRow
        );
        gatewayCard.getStyleClass().add("card");

        usernameField.setPromptText("e.g. alice_fin or admin_hq");
        passwordField.setPromptText("Account passphrase");
        totpField.setPromptText("Optional 6-digit TOTP 2FA code (if MFA enabled)");

        VBox authCard = new VBox(8,
                new Label("ZERO-TRUST CREDENTIALS"),
                new Label("Username"), usernameField,
                new Label("Passphrase"), passwordField,
                new Label("Authenticator 2FA Code (Optional)"), totpField
        );
        authCard.getStyleClass().add("card");

        errorLabel.setStyle("-fx-text-fill: #f87171; -fx-font-weight: bold;");
        errorLabel.setWrapText(true);

        progressBar.setMaxWidth(Double.MAX_VALUE);
        progressBar.setPrefHeight(6);
        progressBar.setVisible(false);

        connectBtn.getStyleClass().add("btn-primary");
        connectBtn.setMaxWidth(Double.MAX_VALUE);
        connectBtn.setDefaultButton(true);
        connectBtn.setOnAction(e -> initiateLogin());

        root.getChildren().addAll(headerBox, gatewayCard, authCard, errorLabel, progressBar, connectBtn);

        Scene scene = new Scene(root);
        UiSafe.applyTheme(scene);
        stage.setTitle("Office VPN Client — Encrypted Access Portal");
        stage.setResizable(false);
        stage.setScene(scene);
        stage.setOnCloseRequest(e -> Platform.exit());
    }

    private void refreshStoredPinIndicator() {
        String host = safeHost();
        int port = safePort();
        if (host.isEmpty() || port <= 0) {
            pinStatusLabel.setText("Enter valid host and port.");
            clearPinBtn.setDisable(true);
            return;
        }
        Optional<String> existing = fingerprintStore.getPinnedFingerprint(host, port);
        if (existing.isPresent()) {
            String fp = existing.get();
            String preview = fp.length() > 24 ? fp.substring(0, 24) + "..." : fp;
            pinStatusLabel.setText("Stored TOFU Pin: " + preview);
            clearPinBtn.setDisable(false);
        } else {
            pinStatusLabel.setText("No saved pin for " + host + ":" + port + " (TOFU on connect)");
            clearPinBtn.setDisable(true);
        }
    }

    private String safeHost() {
        return hostField.getText() != null ? hostField.getText().trim() : "";
    }

    private int safePort() {
        try {
            int p = Integer.parseInt(portField.getText().trim());
            return (p >= 1 && p <= 65535) ? p : -1;
        } catch (Exception e) {
            return -1;
        }
    }

    private void initiateLogin() {
        String host = safeHost();
        int port = safePort();
        String username = usernameField.getText() != null ? usernameField.getText().trim() : "";
        String password = passwordField.getText() != null ? passwordField.getText() : "";
        String totp = totpField.getText() != null ? totpField.getText().trim() : "";
        String typedFp = expectedFpField.getText() != null ? expectedFpField.getText().trim() : "";

        if (host.isEmpty() || port <= 0) {
            errorLabel.setText("Enter a valid gateway host and port (1-65535).");
            return;
        }
        if (username.isEmpty() || password.isEmpty()) {
            errorLabel.setText("Username and passphrase are required.");
            return;
        }

        errorLabel.setText("");
        setBusy(true, "Performing ECDH Handshake & Verify...");

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
                throw new SecurityException("Authentication rejected: invalid credentials, TOTP code, untrusted device, or account locked.");
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
                    "SECURITY WARNING: Server Key Changed",
                    "The gateway server's RSA public key fingerprint differs from your stored TOFU pin!",
                    details + "\n\nOnly click OK if the gateway identity was intentionally rotated by your administrator.");
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
        hostField.setDisable(busy);
        portField.setDisable(busy);
        expectedFpField.setDisable(busy);
        usernameField.setDisable(busy);
        passwordField.setDisable(busy);
        totpField.setDisable(busy);
        clearPinBtn.setDisable(busy);
        connectBtn.setDisable(busy);
        progressBar.setVisible(busy);
        progressBar.setProgress(busy ? ProgressBar.INDETERMINATE_PROGRESS : 0);
        connectBtn.setText(busy ? text : "Connect & Establish Encrypted Tunnel");
    }
}
