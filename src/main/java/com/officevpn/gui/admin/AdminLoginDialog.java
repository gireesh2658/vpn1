package com.officevpn.gui.admin;

import com.officevpn.admin.AdminLoginPolicy;
import com.officevpn.admin.DemoSeeder;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.Window;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Headquarters Administrator Authentication Dialog.
 * Runs 600,000-iteration PBKDF2 authentication asynchronously to keep the UI responsive.
 */
public final class AdminLoginDialog {

    private AdminLoginDialog() {}

    public static Optional<UserAccount> showLoginDialog(
            Window owner,
            DatabaseManager db,
            List<DemoSeeder.DemoAccount> seededDemoAccounts
    ) {
        Stage stage = new Stage();
        if (owner != null) {
            stage.initOwner(owner);
            stage.initModality(Modality.WINDOW_MODAL);
        } else {
            stage.initModality(Modality.APPLICATION_MODAL);
        }
        stage.setTitle("Office VPN — Headquarters Administrator Login");
        stage.setResizable(false);

        Label title = new Label("Gateway Governance Sign-In");
        title.getStyleClass().add("page-title");

        Label subtitle = new Label("Authenticate with a Headquarters ADMIN account backed by MySQL.");
        subtitle.getStyleClass().add("page-subtitle");
        subtitle.setWrapText(true);

        TextField userField = new TextField();
        userField.setPromptText("e.g. admin_hq");

        PasswordField passField = new PasswordField();
        passField.setPromptText("Administrator passphrase");

        Label errorLabel = new Label("");
        errorLabel.setStyle("-fx-text-fill: #f87171; -fx-font-weight: bold;");
        errorLabel.setWrapText(true);

        VBox root = new VBox(14);
        root.getStyleClass().add("app-root");
        root.setPadding(new Insets(22));
        root.setPrefWidth(490);

        VBox demoBanner = null;
        if (seededDemoAccounts != null && !seededDemoAccounts.isEmpty()) {
            Label demoHdr = new Label("DEMO MODE ACTIVE — Seeded Test Credentials");
            demoHdr.getStyleClass().addAll("pill", "pill-warning");

            StringBuilder sb = new StringBuilder();
            DemoSeeder.DemoAccount adminAccount = null;
            for (DemoSeeder.DemoAccount acc : seededDemoAccounts) {
                if (acc.role() == Role.ADMIN && adminAccount == null) {
                    adminAccount = acc;
                }
                sb.append(String.format("%-15s | %-12s | %-8s | %s%n",
                        acc.username(), acc.department(), acc.role(), acc.password()));
            }
            TextArea credsBox = new TextArea(sb.toString());
            credsBox.setEditable(false);
            credsBox.getStyleClass().add("console-area");
            credsBox.setPrefRowCount(Math.min(6, seededDemoAccounts.size() + 1));

            Button fillBtn = new Button("Auto-Fill HQ Admin");
            fillBtn.getStyleClass().add("btn-secondary");
            final DemoSeeder.DemoAccount finalAdmin = adminAccount;
            fillBtn.setOnAction(e -> {
                if (finalAdmin != null) {
                    userField.setText(finalAdmin.username());
                    passField.setText(finalAdmin.password());
                }
            });

            demoBanner = new VBox(8, demoHdr, credsBox, fillBtn);
            demoBanner.getStyleClass().add("card");
        }

        Button cancelBtn = new Button("Exit");
        cancelBtn.getStyleClass().add("btn-secondary");

        Button loginBtn = new Button("Authenticate & Launch");
        loginBtn.getStyleClass().add("btn-primary");
        loginBtn.setDefaultButton(true);

        final UserAccount[] authenticatedRef = new UserAccount[1];

        cancelBtn.setOnAction(e -> stage.close());

        loginBtn.setOnAction(e -> {
            String uname = userField.getText() != null ? userField.getText().trim() : "";
            char[] pw = passField.getText().toCharArray();
            if (uname.isEmpty() || pw.length == 0) {
                Arrays.fill(pw, '\0');
                errorLabel.setText("Username and passphrase are required.");
                return;
            }

            errorLabel.setText("");
            loginBtn.setDisable(true);
            cancelBtn.setDisable(true);
            loginBtn.setText("Verifying (PBKDF2)...");

            CompletableFuture.supplyAsync(() -> {
                try {
                    return AdminLoginPolicy.authenticateAdmin(db, uname, pw, "local");
                } finally {
                    Arrays.fill(pw, '\0');
                }
            }).whenComplete((account, err) -> Platform.runLater(() -> {
                loginBtn.setDisable(false);
                cancelBtn.setDisable(false);
                loginBtn.setText("Authenticate & Launch");
                if (err != null) {
                    Throwable cause = err.getCause() != null ? err.getCause() : err;
                    errorLabel.setText("Authentication error: " + cause.getMessage());
                    passField.clear();
                } else if (account == null) {
                    errorLabel.setText("Invalid credentials, account locked, or insufficient Headquarters ADMIN privilege.");
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
        actions.getChildren().addAll(spacer, cancelBtn, loginBtn);

        VBox formCard = new VBox(10,
                new Label("Administrator Username"), userField,
                new Label("Passphrase"), passField,
                errorLabel
        );
        formCard.getStyleClass().add("card");

        root.getChildren().addAll(title, subtitle);
        if (demoBanner != null) {
            root.getChildren().add(demoBanner);
        }
        root.getChildren().addAll(formCard, actions);

        Scene scene = new Scene(root);
        UiSafe.applyTheme(scene);
        stage.setScene(scene);
        stage.showAndWait();
        return Optional.ofNullable(authenticatedRef[0]);
    }
}
