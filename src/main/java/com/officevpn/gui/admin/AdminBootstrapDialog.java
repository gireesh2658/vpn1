package com.officevpn.gui.admin;

import com.officevpn.admin.AdminBootstrap;
import com.officevpn.admin.PasswordPolicy;
import com.officevpn.admin.UsernamePolicy;
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
        stage.setTitle("Office VPN — Initial Administrator Setup");
        stage.setResizable(false);

        Label header = new Label("First-Run Headquarters Bootstrap");
        header.getStyleClass().add("page-title");

        Label sub = new Label("No active Headquarters Administrator exists in MySQL. Create the root governance account to initialize the gateway.");
        sub.getStyleClass().add("page-subtitle");
        sub.setWrapText(true);

        TextField userField = new TextField("admin_hq");
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
        errorLabel.setStyle("-fx-text-fill: #f87171; -fx-font-weight: bold;");
        errorLabel.setWrapText(true);

        passField.textProperty().addListener((obs, o, n) -> updateStrength(n, strengthBar, strengthLabel));

        Button cancelBtn = new Button("Exit");
        cancelBtn.getStyleClass().add("btn-secondary");

        Button createBtn = new Button("Create Administrator");
        createBtn.getStyleClass().add("btn-primary");
        createBtn.setDefaultButton(true);

        final UserAccount[] createdRef = new UserAccount[1];

        cancelBtn.setOnAction(e -> stage.close());

        createBtn.setOnAction(e -> {
            String uname = userField.getText() != null ? userField.getText().trim() : "";
            char[] pw = passField.getText().toCharArray();
            char[] confirm = confirmField.getText().toCharArray();

            errorLabel.setText("");
            try {
                UsernamePolicy.validateUsername(uname);
                PasswordPolicy.validatePassword(pw, uname);
                if (!Arrays.equals(pw, confirm)) {
                    throw new IllegalArgumentException("Passphrases do not match.");
                }
            } catch (IllegalArgumentException ex) {
                Arrays.fill(pw, '\0');
                Arrays.fill(confirm, '\0');
                errorLabel.setText(ex.getMessage());
                return;
            }

            createBtn.setDisable(true);
            cancelBtn.setDisable(true);
            createBtn.setText("Provisioning (PBKDF2)...");

            CompletableFuture.supplyAsync(() -> {
                try {
                    return AdminBootstrap.createInitialAdmin(db, uname, pw, confirm);
                } finally {
                    Arrays.fill(pw, '\0');
                    Arrays.fill(confirm, '\0');
                }
            }).whenComplete((account, err) -> Platform.runLater(() -> {
                createBtn.setDisable(false);
                cancelBtn.setDisable(false);
                createBtn.setText("Create Administrator");
                if (err != null) {
                    Throwable cause = err.getCause() != null ? err.getCause() : err;
                    errorLabel.setText("Bootstrap failed: " + cause.getMessage());
                } else {
                    createdRef[0] = account;
                    stage.close();
                }
            }));
        });

        HBox actions = new HBox(10);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        actions.getChildren().addAll(spacer, cancelBtn, createBtn);

        VBox formCard = new VBox(10,
                new Label("Administrator Username"), userField,
                new Label("Master Passphrase"), passField,
                strengthBar, strengthLabel,
                new Label("Confirm Master Passphrase"), confirmField,
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
