package com.officevpn.gui.admin;

import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import com.officevpn.security.IdentityException;
import com.officevpn.security.ServerIdentity;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;
import javafx.stage.Window;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Server RSA-2048 Keystore Identity Loader &amp; Creator Dialog.
 */
public final class AdminIdentityDialog {

    private AdminIdentityDialog() {}

    public static Optional<ServerIdentity> resolveIdentity(Window owner, Path dataDir) {
        String envPass = System.getenv("OFFICEVPN_KEYSTORE_PASS");
        if (envPass != null && !envPass.isBlank()) {
            char[] chars = envPass.toCharArray();
            try {
                return Optional.of(ServerIdentity.loadOrCreate(dataDir, chars, true));
            } catch (IdentityException ex) {
                UiSafe.showError(owner, "Server Keystore Error",
                        "Failed to unlock server keystore via OFFICEVPN_KEYSTORE_PASS: " + ex.getMessage());
            } finally {
                Arrays.fill(chars, '\0');
            }
        }

        Path ksPath = dataDir.resolve(ServerIdentity.IDENTITY_FILE_NAME);
        boolean exists = Files.exists(ksPath);

        Stage stage = new Stage();
        if (owner != null) {
            stage.initOwner(owner);
            stage.initModality(Modality.WINDOW_MODAL);
        } else {
            stage.initModality(Modality.APPLICATION_MODAL);
        }
        stage.setTitle(exists
                ? com.officevpn.config.Messages.get("app.title.admin.identity.unlock")
                : com.officevpn.config.Messages.get("app.title.admin.identity.create"));
        stage.setResizable(false);

        Label title = new Label(exists
                ? com.officevpn.config.Messages.get("admin.identity.unlock.header")
                : com.officevpn.config.Messages.get("admin.identity.create.header"));
        title.getStyleClass().add("page-title");

        Label subtitle = new Label(exists
                ? com.officevpn.config.Messages.format("admin.identity.unlock.sub", ksPath.toString())
                : com.officevpn.config.Messages.format("admin.identity.create.sub", ksPath.toString()));
        subtitle.getStyleClass().add("page-subtitle");
        subtitle.setWrapText(true);

        PasswordField passField = new PasswordField();
        passField.setPromptText("Keystore passphrase (min " + ServerIdentity.MIN_PASSPHRASE_LENGTH + " chars)");

        PasswordField confirmField = new PasswordField();
        confirmField.setPromptText("Confirm keystore passphrase");

        CheckBox ephemeralCheck = new CheckBox(Messages.get("admin.identity.checkbox.ephemeral"));
        ephemeralCheck.setWrapText(true);
        ephemeralCheck.setSelected(false);
        ephemeralCheck.setVisible(!exists);
        ephemeralCheck.setManaged(!exists);

        Label errorLabel = new Label("");
        errorLabel.setStyle("-fx-text-fill: #f87171; -fx-font-weight: bold;");
        errorLabel.setWrapText(true);

        VBox form = new VBox(10);
        form.getStyleClass().add("card");
        form.getChildren().addAll(new Label(Messages.get("admin.dialog.label.keystorePassphrase")), passField);
        if (!exists) {
            form.getChildren().addAll(new Label(Messages.get("admin.dialog.label.confirmKeystorePassphrase")), confirmField);
            form.getChildren().add(ephemeralCheck);
        }
        form.getChildren().add(errorLabel);

        ephemeralCheck.selectedProperty().addListener((obs, o, sel) -> {
            passField.setDisable(sel);
            confirmField.setDisable(sel);
        });

        Button cancelBtn = new Button(Messages.get("common.cancel"));
        cancelBtn.getStyleClass().add("btn-secondary");

        Button okBtn = new Button(exists
                ? Messages.get("admin.identity.button.unlock")
                : Messages.get("admin.identity.button.create"));
        okBtn.getStyleClass().add("btn-primary");
        okBtn.setDefaultButton(true);

        final ServerIdentity[] resolvedRef = new ServerIdentity[1];

        cancelBtn.setOnAction(e -> stage.close());

        okBtn.setOnAction(e -> {
            if (ephemeralCheck.isSelected()) {
                resolvedRef[0] = ServerIdentity.createEphemeral();
                stage.close();
                return;
            }
            char[] pass = passField.getText().toCharArray();
            char[] conf = confirmField.getText().toCharArray();
            if (pass.length < ServerIdentity.MIN_PASSPHRASE_LENGTH) {
                Arrays.fill(pass, '\0');
                Arrays.fill(conf, '\0');
                errorLabel.setText(Messages.format(
                        "admin.identity.error.length", ServerIdentity.MIN_PASSPHRASE_LENGTH));
                return;
            }
            if (!exists && !Arrays.equals(pass, conf)) {
                Arrays.fill(pass, '\0');
                Arrays.fill(conf, '\0');
                errorLabel.setText(Messages.get("admin.identity.error.mismatch"));
                return;
            }
            Arrays.fill(conf, '\0');

            errorLabel.setText("");
            okBtn.setDisable(true);
            cancelBtn.setDisable(true);
            okBtn.setText(exists ? "Unlocking..." : "Generating RSA-2048...");

            CompletableFuture.supplyAsync(() -> {
                try {
                    return ServerIdentity.loadOrCreate(dataDir, pass, true);
                } catch (IdentityException ex) {
                    throw new IllegalStateException(ex.getMessage(), ex);
                } finally {
                    Arrays.fill(pass, '\0');
                }
            }).whenComplete((id, err) -> Platform.runLater(() -> {
                okBtn.setDisable(false);
                cancelBtn.setDisable(false);
                okBtn.setText(exists
                        ? Messages.get("admin.identity.button.unlock")
                        : Messages.get("admin.identity.button.create"));
                if (err != null) {
                    Throwable cause = err.getCause() != null ? err.getCause() : err;
                    errorLabel.setText("Identity error: " + cause.getMessage());
                    passField.clear();
                } else {
                    resolvedRef[0] = id;
                    stage.close();
                }
            }));
        });

        HBox actions = new HBox(10);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        actions.getChildren().addAll(spacer, cancelBtn, okBtn);

        VBox root = new VBox(14, title, subtitle, form, actions);
        root.getStyleClass().add("app-root");
        root.setPadding(new Insets(22));
        root.setPrefWidth(480);

        Scene scene = new Scene(root);
        UiSafe.applyTheme(scene);
        stage.setScene(scene);
        stage.showAndWait();
        return Optional.ofNullable(resolvedRef[0]);
    }
}
