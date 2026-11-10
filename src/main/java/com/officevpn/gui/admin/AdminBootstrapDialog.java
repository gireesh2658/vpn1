package com.officevpn.gui.admin;

import com.officevpn.admin.AdminBootstrap;
import com.officevpn.admin.PasswordPolicy;
import com.officevpn.admin.UsernamePolicy;
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
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.Window;

import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * First-run JavaFX Administrator Bootstrap Setup wizard.
 * Enforces {@link UsernamePolicy} and {@link PasswordPolicy} with live strength feedback.
 */
public final class AdminBootstrapDialog {

    private AdminBootstrapDialog() {}

    public static Optional<UserAccount> showSetupDialog(Window owner, DatabaseManager db) {
        Stage stage = new Stage();
        if (owner != null) {
            stage.initOwner(owner);
            stage.initModality(Modality.WINDOW_MODAL);
        } else {
            stage.initModality(Modality.APPLICATION_MODAL);
        }
        stage.setTitle(Messages.get("app.title.admin.bootstrap"));
        stage.setResizable(false);

        Label header = new Label(Messages.get("admin.bootstrap.header"));
        header.getStyleClass().add("page-title");

        Label sub = new Label(Messages.get("admin.bootstrap.sub"));
        sub.getStyleClass().add("page-subtitle");
        sub.setWrapText(true);

        TextField userField = new TextField();
        userField.setPromptText("Administrator username (3-32 chars)");

        PasswordField passField = new PasswordField();
        passField.setPromptText("Minimum 12 chars: upper, lower, number, symbol");

        PasswordField confirmField = new PasswordField();
        confirmField.setPromptText("Confirm passphrase");

        ProgressBar strengthBar = new ProgressBar(0);
        strengthBar.setMaxWidth(Double.MAX_VALUE);
        strengthBar.setPrefHeight(7);
        Label strengthLabel = new Label("Strength: Enter a 12+ character passphrase");
        strengthLabel.getStyleClass().add("muted-label");

        Label errorLabel = new Label("");
        errorLabel.setStyle("-fx-text-fill: #BA2A1A; -fx-font-weight: bold;");
        errorLabel.setWrapText(true);

        passField.textProperty().addListener((obs, o, n) -> updateStrength(n, strengthBar, strengthLabel));

        Button cancelButton = new Button(Messages.get("common.exit"));
        cancelButton.getStyleClass().add("btn-secondary");

        Button createAdminButton = new Button(Messages.get("admin.bootstrap.button.create"));
        createAdminButton.getStyleClass().add("btn-primary");
        createAdminButton.setDefaultButton(true);

        final UserAccount[] createdRef = new UserAccount[1];

        cancelButton.setOnAction(e -> stage.close());

        createAdminButton.setOnAction(e -> {
            String uname = userField.getText() != null ? userField.getText().trim() : "";
            char[] pw = passField.getText().toCharArray();
            char[] confirm = confirmField.getText().toCharArray();

            errorLabel.setText("");
            try {
                UsernamePolicy.validateUsername(uname);
                PasswordPolicy.validatePassword(pw, uname);
                if (!Arrays.equals(pw, confirm)) {
                    throw new IllegalArgumentException("Passwords do not match.");
                }
            } catch (IllegalArgumentException ex) {
                Arrays.fill(pw, '\0');
                Arrays.fill(confirm, '\0');
                errorLabel.setText(ex.getMessage());
                return;
            }

            createAdminButton.setDisable(true);
            cancelButton.setDisable(true);
            createAdminButton.setText("Provisioning (PBKDF2)...");

            CompletableFuture.supplyAsync(() -> {
                try {
                    return AdminBootstrap.createInitialAdmin(db, uname, pw, confirm);
                } finally {
                    Arrays.fill(pw, '\0');
                    Arrays.fill(confirm, '\0');
                }
            }).whenComplete((account, err) -> Platform.runLater(() -> {
                createAdminButton.setDisable(false);
                cancelButton.setDisable(false);
                createAdminButton.setText(Messages.get("admin.bootstrap.button.create"));
                if (err != null) {
                    Throwable cause = err.getCause() != null ? err.getCause() : err;
                    errorLabel.setText(cause instanceof IllegalArgumentException
                            ? cause.getMessage()
                            : "Unable to create administrator account. Verify MySQL connection and retry.");
                } else {
                    createdRef[0] = account;
                    stage.close();
                }
            }));
        });

        HBox actions = new HBox(10);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        actions.getChildren().addAll(spacer, cancelButton, createAdminButton);

        VBox formCard = new VBox(10,
                new Label(Messages.get("admin.dialog.label.adminUsername")), userField,
                new Label(Messages.get("admin.dialog.label.masterPassphrase")), passField,
                strengthBar, strengthLabel,
                new Label(Messages.get("admin.dialog.label.confirmMasterPassphrase")), confirmField,
                errorLabel
        );
        formCard.getStyleClass().add("card");

        VBox root = new VBox(14, header, sub, formCard, actions);
        root.getStyleClass().add("app-root");
        root.setPadding(new Insets(22));
        root.setPrefWidth(480);

        Scene scene = new Scene(root);
        UiSafe.applyTheme(scene);
        stage.setScene(scene);
        stage.showAndWait();
        return Optional.ofNullable(createdRef[0]);
    }

    private static void updateStrength(String pw, ProgressBar bar, Label label) {
        if (pw == null || pw.isEmpty()) {
            bar.setProgress(0);
            label.setText("Strength: Enter a 12+ character passphrase");
            return;
        }
        int score = 0;
        if (pw.length() >= 12) score++;
        if (pw.length() >= 16) score++;
        if (pw.chars().anyMatch(Character::isUpperCase)) score++;
        if (pw.chars().anyMatch(Character::isLowerCase)) score++;
        if (pw.chars().anyMatch(Character::isDigit)) score++;
        if (pw.chars().anyMatch(c -> !Character.isLetterOrDigit(c))) score++;
        double progress = Math.min(1.0, score / 6.0);
        bar.setProgress(progress);
        if (score <= 2) {
            label.setText("Strength: Weak — must include upper, lower, digit & symbol (min 12 chars)");
        } else if (score <= 4) {
            label.setText("Strength: Fair — add complexity or length");
        } else {
            label.setText("Strength: Strong enterprise passphrase");
        }
    }
}
