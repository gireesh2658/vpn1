package com.officevpn.ui.components;

import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.AuthResult;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.css.PseudoClass;
import javafx.geometry.Pos;
import javafx.scene.AccessibleRole;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.Skin;
import javafx.scene.control.SkinBase;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.util.Duration;
import org.kordamp.ikonli.feather.Feather;

import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * SignInCard featuring corporate credentials, an interactive six-cell OTP input
 * (digit auto-advance, clipboard paste across all 6 cells, Backspace backward traversal,
 * and damped shake + coral underline on error), plus OIDC SSO providers.
 */
public final class SignInCard extends Control {

    @FunctionalInterface
    public interface CredentialVerifier {
        CompletableFuture<AuthResult> verify(String username, String password, String otpCode);
    }

    private static final PseudoClass PC_OTP_ERROR = PseudoClass.getPseudoClass("otp-error");

    private final ObjectProperty<CredentialVerifier> verifier = new SimpleObjectProperty<>(
            (_, _, _) -> CompletableFuture.completedFuture(new AuthResult(false, false,
                    "Bind SignInCard to a live VpnClientService before authenticating")));
    private final ObjectProperty<Consumer<String>> onSsoRequested = new SimpleObjectProperty<>(_ -> {});
    private final ObjectProperty<Consumer<AuthResult>> onAuthenticated = new SimpleObjectProperty<>(_ -> {});

    public SignInCard() {
        getStyleClass().setAll("signin-card");
        setFocusTraversable(false);
        setAccessibleRole(AccessibleRole.PARENT);
        setAccessibleText("Corporate Sign-In Card with 6-digit OTP and SSO");
        setMaxWidth(440);
    }

    public void bindService(VpnClientService service, Consumer<String> toastCallback) {
        if (service == null) return;
        verifier.set(service::authenticate);
        onSsoRequested.set(provider -> service.authenticateSso(provider).thenAccept(res ->
                Platform.runLater(() -> {
                    if (toastCallback != null) toastCallback.accept(res.message());
                    var cb = onAuthenticated.get();
                    if (cb != null) cb.accept(res);
                })));
    }

    public static Node createStandaloneDemo(VpnClientService service) {
        SignInCard card = new SignInCard();
        card.bindService(service, null);
        return card;
    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new SignInCardSkin(this);
    }

    public ObjectProperty<CredentialVerifier> verifierProperty() { return verifier; }
    public ObjectProperty<Consumer<String>> onSsoRequestedProperty() { return onSsoRequested; }
    public ObjectProperty<Consumer<AuthResult>> onAuthenticatedProperty() { return onAuthenticated; }

    private void setOtpErrorState(boolean err) {
        pseudoClassStateChanged(PC_OTP_ERROR, err);
    }

    private static final class SignInCardSkin extends SkinBase<SignInCard> {

        private final VBox root = new VBox(14);
        private final TextField userField = new TextField();
        private final PasswordField passField = new PasswordField();
        private final HBox otpRow = new HBox(6);
        private final TextField[] otpCells = new TextField[6];
        private final Label feedbackLabel = new Label("Enter your 6-digit authenticator code (if MFA is enabled)");
        private final Button signInBtn = new Button("Verify & Authenticate");

        SignInCardSkin(SignInCard control) {
            super(control);

            Label badge = new Label("ZERO-TRUST IDENTITY");
            badge.getStyleClass().addAll("ia-pill", "ia-pill-lilac");

            Label title = new Label("Sign in to Corporate Gateway");
            title.getStyleClass().add("ia-display-md");

            Label sub = new Label("Sign in with your Office VPN employee account");
            sub.getStyleClass().add("ia-subtitle");

            Label uLbl = new Label("Workspace Username");
            uLbl.getStyleClass().add("ia-section-label");
            userField.setPromptText("Employee username");

            Label pLbl = new Label("Passphrase");
            pLbl.getStyleClass().add("ia-section-label");
            passField.setPromptText("Account passphrase");

            Label oLbl = new Label("6-Digit MFA Code (Optional)");
            oLbl.getStyleClass().add("ia-section-label");

            setupOtpCells();

            feedbackLabel.setText("Leave the 6 digits blank if MFA is OFF for your account. Enter your Authenticator app code only if 2FA is enabled.");
            feedbackLabel.getStyleClass().add("ia-subtitle");
            feedbackLabel.setWrapText(true);

            signInBtn.getStyleClass().add("ia-btn-marigold");
            signInBtn.setGraphic(Icons.ink(Feather.SHIELD, 14));
            signInBtn.setMaxWidth(Double.MAX_VALUE);
            signInBtn.setOnAction(_ -> submitCredentials());
            passField.setOnAction(_ -> submitCredentials());

            root.getChildren().addAll(
                    badge, title, sub,
                    uLbl, userField,
                    pLbl, passField,
                    oLbl, otpRow,
                    feedbackLabel,
                    signInBtn
            );
            getChildren().add(root);
        }

        private void setupOtpCells() {
            otpRow.setAlignment(Pos.CENTER_LEFT);
            for (int i = 0; i < 6; i++) {
                final int idx = i;
                TextField cell = new TextField("");
                cell.getStyleClass().add("otp-cell");
                cell.setPrefSize(44, 48);
                cell.setMinSize(36, 44);
                cell.setAccessibleText("OTP digit " + (i + 1) + " of 6");

                cell.textProperty().addListener((_, _, newVal) -> {
                    clearOtpError();
                    if (newVal == null) return;
                    String digitsOnly = newVal.replaceAll("\\D+", "");
                    if (digitsOnly.length() > 1) {
                        // Paste or multi-char entry distributes cleanly from current index
                        distributeDigits(idx, digitsOnly);
                        return;
                    }
                    if (!digitsOnly.equals(newVal)) {
                        cell.setText(digitsOnly);
                        return;
                    }
                    if (digitsOnly.length() == 1 && idx < 5) {
                        otpCells[idx + 1].requestFocus();
                    }
                });

                cell.addEventHandler(KeyEvent.KEY_PRESSED, e -> {
                    if (e.getCode() == KeyCode.BACK_SPACE && cell.getText().isEmpty() && idx > 0) {
                        otpCells[idx - 1].clear();
                        otpCells[idx - 1].requestFocus();
                        e.consume();
                    } else if (e.getCode() == KeyCode.LEFT && idx > 0) {
                        otpCells[idx - 1].requestFocus();
                        e.consume();
                    } else if (e.getCode() == KeyCode.RIGHT && idx < 5) {
                        otpCells[idx + 1].requestFocus();
                        e.consume();
                    } else if (e.getCode() == KeyCode.ENTER) {
                        submitCredentials();
                        e.consume();
                    }
                });

                otpCells[i] = cell;
                otpRow.getChildren().add(cell);
            }
        }

        private void distributeDigits(int startIdx, String digits) {
            int pos = startIdx;
            for (int i = 0; i < digits.length() && pos < 6; i++, pos++) {
                otpCells[pos].setText(String.valueOf(digits.charAt(i)));
            }
            int focusIdx = Math.min(5, startIdx + digits.length());
            Platform.runLater(() -> otpCells[focusIdx].requestFocus());
        }

        private String collectOtp() {
            StringBuilder sb = new StringBuilder(6);
            for (TextField c : otpCells) {
                sb.append(c.getText() == null ? "" : c.getText().trim());
            }
            return sb.toString();
        }

        private void submitCredentials() {
            clearOtpError();
            String user = userField.getText();
            String pass = passField.getText();
            String otp = collectOtp();
            var v = getSkinnable().verifierProperty().get();
            if (v == null) return;

            signInBtn.setDisable(true);
            v.verify(user, pass, otp).thenAccept(res -> Platform.runLater(() -> {
                signInBtn.setDisable(false);
                if (res.success()) {
                    feedbackLabel.setText(res.message());
                    feedbackLabel.setTextFill(Tokens.PEACOCK_TEXT);
                    var cb = getSkinnable().onAuthenticatedProperty().get();
                    if (cb != null) cb.accept(res);
                } else {
                    triggerOtpError(res.message());
                }
            }));
        }

        public void triggerOtpError(String message) {
            getSkinnable().setOtpErrorState(true);
            for (TextField c : otpCells) {
                if (!c.getStyleClass().contains("otp-cell-error")) {
                    c.getStyleClass().add("otp-cell-error");
                }
            }
            feedbackLabel.setText(message);
            feedbackLabel.setTextFill(Tokens.CORAL_TEXT);
            if (!Motion.isReduceMotion()) {
                Timeline shake = new Timeline(
                        new KeyFrame(Duration.millis(0), new KeyValue(otpRow.translateXProperty(), 0)),
                        new KeyFrame(Duration.millis(45), new KeyValue(otpRow.translateXProperty(), -8)),
                        new KeyFrame(Duration.millis(95), new KeyValue(otpRow.translateXProperty(), 8)),
                        new KeyFrame(Duration.millis(145), new KeyValue(otpRow.translateXProperty(), -5)),
                        new KeyFrame(Duration.millis(195), new KeyValue(otpRow.translateXProperty(), 4)),
                        new KeyFrame(Duration.millis(240), new KeyValue(otpRow.translateXProperty(), 0))
                );
                shake.play();
            }
        }

        private void clearOtpError() {
            getSkinnable().setOtpErrorState(false);
            for (TextField c : otpCells) {
                c.getStyleClass().remove("otp-cell-error");
            }
            feedbackLabel.setTextFill(Tokens.SOFT_INK);
        }
    }

    /**
     * Exposes programmatic error shake trigger for unit tests.
     */
    public void showErrorShake(String reason) {
        if (getSkin() instanceof SignInCardSkin skin) {
            skin.triggerOtpError(reason);
        }
    }
}
