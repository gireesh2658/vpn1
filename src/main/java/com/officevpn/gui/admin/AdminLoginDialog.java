package com.officevpn.gui.admin;

import com.officevpn.admin.AdminLoginPolicy;
import com.officevpn.config.Messages;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.UserAccount;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.Window;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Headquarters Administrator Authentication Dialog.
 * Runs 600,000-iteration PBKDF2 authentication asynchronously to keep the UI responsive.
 */
public final class AdminLoginDialog {

    private static final Logger LOGGER = LoggerFactory.getLogger(AdminLoginDialog.class);

    private AdminLoginDialog() {}

    public static Optional<UserAccount> showLoginDialog(Window owner, DatabaseManager db) {
        Stage stage = new Stage();
        if (owner != null) {
            stage.initOwner(owner);
            stage.initModality(Modality.WINDOW_MODAL);
        } else {
            stage.initModality(Modality.APPLICATION_MODAL);
        }
        stage.setTitle(Messages.get("app.title.admin.login"));
        stage.setResizable(false);

        Label title = new Label(Messages.get("admin.login.header"));
        title.getStyleClass().add("page-title");

        Label subtitle = new Label(Messages.get("admin.login.sub"));
        subtitle.getStyleClass().add("page-subtitle");
        subtitle.setWrapText(true);

        TextField userField = new TextField();
        userField.setPromptText("Enter administrator username");

        PasswordField passField = new PasswordField();
        passField.setPromptText("Administrator passphrase");

        TextField totpField = new TextField();
        totpField.setPromptText(Messages.get("admin.login.prompt.totp"));

        Label totpHint = new Label("Leave empty if TOTP 2FA is OFF for this admin. Required only after enabling 2FA in Users -> Manage 2FA.");
        totpHint.getStyleClass().add("muted-label");
        totpHint.setWrapText(true);

        Label errorLabel = new Label("");
        errorLabel.setStyle("-fx-text-fill: #BA2A1A; -fx-font-weight: bold;");
        errorLabel.setWrapText(true);

        VBox root = new VBox(14);
        root.getStyleClass().add("app-root");
        root.setPadding(new Insets(22));
        root.setPrefWidth(490);

        Button cancelButton = new Button(Messages.get("common.exit"));
        cancelButton.getStyleClass().add("btn-secondary");

        Button signInButton = new Button(Messages.get("admin.login.button.signIn"));
        signInButton.getStyleClass().add("btn-primary");
        signInButton.setDefaultButton(true);

        final UserAccount[] authenticatedRef = new UserAccount[1];

        cancelButton.setOnAction(_ -> stage.close());

        signInButton.setOnAction(_ -> {
            String uname = userField.getText() != null ? userField.getText().trim() : "";
            char[] pw = passField.getText().toCharArray();
            String totp = totpField.getText() != null ? totpField.getText().trim() : "";
            if (uname.isEmpty() || pw.length == 0) {
                Arrays.fill(pw, '\0');
                errorLabel.setText(Messages.get("login.client.error.missingCredentials"));
                return;
            }

            errorLabel.setText("");
            signInButton.setDisable(true);
            cancelButton.setDisable(true);
            signInButton.setText("Verifying (PBKDF2)...");

            CompletableFuture.supplyAsync(() -> {
                try {
                    return AdminLoginPolicy.authenticateAdmin(db, uname, pw, totp, "local");
                } finally {
                    Arrays.fill(pw, '\0');
                }
            }).whenComplete((account, err) -> Platform.runLater(() -> {
                signInButton.setDisable(false);
                cancelButton.setDisable(false);
                signInButton.setText(Messages.get("admin.login.button.signIn"));
                if (err != null) {
                    Throwable cause = err.getCause() != null ? err.getCause() : err;
                    LOGGER.error("Administrator sign-in failed unexpectedly: {}", cause.getMessage(), cause);
                    errorLabel.setText("Authentication service unavailable. Check local MySQL connectivity and retry.");
                    passField.clear();
                } else if (account == null) {
                    errorLabel.setText("Invalid credentials, missing 2FA code, account locked, or insufficient Headquarters ADMIN privilege.");
                    passField.clear();
                } else {
                    authenticatedRef[0] = account;
                    stage.close();
                }
            }));
        });

        HBox actions = new HBox(10);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        actions.getChildren().addAll(spacer, cancelButton, signInButton);

        VBox formCard = new VBox(10,
                new Label(Messages.get("admin.dialog.label.adminUsername")), userField,
                new Label(Messages.get("admin.dialog.label.passphrase")), passField,
                new Label(Messages.get("admin.login.label.totp")), totpField, totpHint,
                errorLabel
        );
        formCard.getStyleClass().add("card");

        root.getChildren().addAll(title, subtitle, formCard, actions);

        Scene scene = new Scene(root);
        UiSafe.applyTheme(scene);
        stage.setScene(scene);
        stage.showAndWait();
        return Optional.ofNullable(authenticatedRef[0]);
    }
}
