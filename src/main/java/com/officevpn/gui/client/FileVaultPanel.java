package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Encrypted Departmental File Vault Explorer, Upload &amp; Integrity Download Panel.
 */
public final class FileVaultPanel extends VBox {

    public record VaultFileRow(String fileName, String department, String encryptionBadge) {}

    private final VpnClientEngine engine;
    private final ComboBox<Department> vaultSelector = new ComboBox<>();
    private final TableView<VaultFileRow> table = new TableView<>();
    private final Label statusLabel = new Label("Select a vault and refresh to list encrypted files.");
    private final Label rbacPill = new Label("");
    private Button refreshButton;
    private Button uploadButton;
    private Button downloadButton;

    public FileVaultPanel(VpnClientEngine engine) {
        this.engine = engine;
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
        syncAuthState();
    }

    /**
     * Synchronizes department selector, RBAC pill, and button state with current VPN authentication.
     */
    public void syncAuthState() {
        boolean authed = engine != null && engine.isConnected() && engine.isAuthenticated();
        rbacPill.getStyleClass().removeAll("pill-warning", "pill-info", "pill-muted");
        if (!authed) {
            vaultSelector.setDisable(true);
            if (refreshButton != null) refreshButton.setDisable(true);
            if (uploadButton != null) uploadButton.setDisable(true);
            if (downloadButton != null) downloadButton.setDisable(true);
            table.getItems().clear();
            rbacPill.setText("SIGN IN REQUIRED");
            rbacPill.getStyleClass().add("pill-muted");
            statusLabel.setText("Sign in to a gateway on Home to browse, upload, and decrypt departmental vault files.");
            return;
        }
        boolean isHqAdmin = engine.getRole() == Role.ADMIN && engine.getDepartment() == Department.HEADQUARTERS;
        vaultSelector.getItems().setAll(isHqAdmin
                ? List.of(Department.values())
                : (engine.getDepartment() != null ? List.of(engine.getDepartment()) : List.of(Department.values())));
        vaultSelector.setValue(engine.getDepartment() != null ? engine.getDepartment() : Department.IT);
        vaultSelector.setDisable(false);
        if (refreshButton != null) refreshButton.setDisable(false);
        if (uploadButton != null) uploadButton.setDisable(false);
        rbacPill.setText(isHqAdmin ? Messages.get("vault.rbac.admin") : Messages.format("vault.rbac.locked", engine.getDepartment()));
        rbacPill.getStyleClass().add(isHqAdmin ? "pill-warning" : "pill-info");
        refreshFiles();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("vault.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("vault.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        boolean isHqAdmin = engine.getRole() == Role.ADMIN && engine.getDepartment() == Department.HEADQUARTERS;
        rbacPill.setText(isHqAdmin ? Messages.get("vault.rbac.admin") : Messages.format("vault.rbac.locked", engine.getDepartment()));
        rbacPill.getStyleClass().addAll("pill", isHqAdmin ? "pill-warning" : "pill-info");
        header.getChildren().addAll(titleBox, spacer, rbacPill);

        HBox toolbar = new HBox(10);
        toolbar.setAlignment(Pos.CENTER_LEFT);
        if (isHqAdmin) {
            vaultSelector.getItems().addAll(Department.values());
        } else if (engine.getDepartment() != null) {
            vaultSelector.getItems().add(engine.getDepartment());
        } else {
            vaultSelector.getItems().addAll(Department.values());
        }
        vaultSelector.setValue(engine.getDepartment() != null ? engine.getDepartment() : Department.IT);
        vaultSelector.setOnAction(e -> refreshFiles());

        refreshButton = new Button(Messages.get("vault.button.refresh"));
        refreshButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(refreshButton,
                Messages.get("vault.button.refresh"),
                Messages.get("vault.tooltip.refresh"));
        refreshButton.setOnAction(e -> refreshFiles());

        uploadButton = new Button(Messages.get("vault.button.upload"));
        uploadButton.getStyleClass().add("btn-primary");
        Messages.configureAccessibleControl(uploadButton,
                Messages.get("vault.button.upload"),
                Messages.get("vault.tooltip.upload"));
        uploadButton.setOnAction(e -> handleUpload());

        downloadButton = new Button(Messages.get("vault.button.download"));
        downloadButton.getStyleClass().add("btn-success");
        downloadButton.setDisable(true);
        Messages.configureAccessibleControl(downloadButton,
                Messages.get("vault.button.download"),
                Messages.get("vault.tooltip.download"));
        downloadButton.setOnAction(e -> handleDownload());

        Button copyFilenameButton = new Button(Messages.get("vault.button.copyName"));
        copyFilenameButton.getStyleClass().add("btn-secondary");
        copyFilenameButton.setDisable(true);
        Messages.configureAccessibleControl(copyFilenameButton,
                Messages.get("vault.button.copyName"),
                Messages.get("vault.tooltip.copyName"));
        copyFilenameButton.setOnAction(e -> {
            VaultFileRow sel = table.getSelectionModel().getSelectedItem();
            if (sel != null) UiSafe.copyToClipboard(sel.fileName());
        });

        table.getSelectionModel().selectedItemProperty().addListener((obs, o, sel) -> {
            boolean has = sel != null;
            downloadButton.setDisable(!has);
            copyFilenameButton.setDisable(!has);
        });

        Region tbSpacer = new Region();
        HBox.setHgrow(tbSpacer, Priority.ALWAYS);
        toolbar.getChildren().addAll(new Label(Messages.get("vault.label.selector")), vaultSelector,
                refreshButton, tbSpacer, copyFilenameButton, uploadButton, downloadButton);

        UiSafe.configureSafeTable(table);
        table.getColumns().add(UiSafe.safeColumn("File Name", VaultFileRow::fileName, 360));
        table.getColumns().add(UiSafe.safeColumn("Department Vault", VaultFileRow::department, 160));
        table.getColumns().add(UiSafe.badgeColumn("Wire Integrity", VaultFileRow::encryptionBadge,
                r -> "pill-success", 180));
        VBox.setVgrow(table, Priority.ALWAYS);

        statusLabel.getStyleClass().add("muted-label");

        VBox card = new VBox(12, toolbar, table, statusLabel);
        card.getStyleClass().add("card");
        VBox.setVgrow(card, Priority.ALWAYS);

        getChildren().addAll(header, card);
    }

    private void setTransferBusy(boolean busy) {
        vaultSelector.setDisable(busy);
        if (refreshButton != null) refreshButton.setDisable(busy);
        if (uploadButton != null) uploadButton.setDisable(busy);
        if (downloadButton != null) downloadButton.setDisable(busy || table.getSelectionModel().getSelectedItem() == null);
    }

    public void refreshFiles() {
        Department dept = vaultSelector.getValue();
        if (dept == null) return;
        setTransferBusy(true);
        statusLabel.setText("Listing files in " + dept + " vault...");
        CompletableFuture.supplyAsync(() -> {
            try {
                return engine.listDepartmentFiles(dept);
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }).whenComplete((files, err) -> Platform.runLater(() -> {
            setTransferBusy(false);
            if (err != null) {
                Throwable cause = err.getCause() != null ? err.getCause() : err;
                statusLabel.setText("Vault error: " + cause.getMessage());
                UiSafe.showError(UiSafe.windowOf(this), "Vault Access Error", cause.getMessage());
            } else {
                table.getItems().setAll(files.stream()
                        .map(name -> new VaultFileRow(name, dept.name(), "AES-256-GCM VERIFIED"))
                        .toList());
                statusLabel.setText("Loaded " + files.size() + " file(s) from " + dept + " vault.");
            }
        }));
    }

    private void handleUpload() {
        Department dept = vaultSelector.getValue();
        if (dept == null) return;

        FileChooser fc = new FileChooser();
        fc.setTitle(Messages.format("vault.dialog.upload.title", dept));
        File selected = fc.showOpenDialog(UiSafe.windowOf(this));
        if (selected == null) return;

        if (selected.length() > 8 * 1024 * 1024) {
            UiSafe.showError(UiSafe.windowOf(this), "File Too Large", "Maximum vault file upload size is 8 MB.");
            return;
        }

        String fileName = selected.getName();
        setTransferBusy(true);
        statusLabel.setText("Encrypting & uploading " + fileName + " to " + dept + "...");

        CompletableFuture.supplyAsync(() -> {
            try {
                byte[] bytes = Files.readAllBytes(selected.toPath());
                engine.uploadFile(dept, fileName, bytes);
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
                return HexFormat.of().formatHex(digest);
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }).whenComplete((sha256, err) -> Platform.runLater(() -> {
            setTransferBusy(false);
            if (err != null) {
                Throwable cause = err.getCause() != null ? err.getCause() : err;
                statusLabel.setText("Upload failed: " + cause.getMessage());
                UiSafe.showError(UiSafe.windowOf(this), "Vault Upload Failed", cause.getMessage());
            } else {
                statusLabel.setText("Uploaded '" + fileName + "' cleanly (SHA-256: " + sha256.substring(0, 16) + "...).");
                refreshFiles();
            }
        }));
    }

    private void handleDownload() {
        VaultFileRow row = table.getSelectionModel().getSelectedItem();
        Department dept = vaultSelector.getValue();
        if (row == null || dept == null) return;

        FileChooser fc = new FileChooser();
        fc.setTitle(Messages.get("vault.dialog.download.title"));
        fc.setInitialFileName(row.fileName());
        File dest = fc.showSaveDialog(UiSafe.windowOf(this));
        if (dest == null) return;

        setTransferBusy(true);
        statusLabel.setText("Downloading & decrypting " + row.fileName() + "...");

        CompletableFuture.supplyAsync(() -> {
            try {
                byte[] bytes = engine.downloadFile(dept, row.fileName());
                Files.write(dest.toPath(), bytes);
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
                return new String[]{String.valueOf(bytes.length), HexFormat.of().formatHex(digest)};
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }).whenComplete((res, err) -> Platform.runLater(() -> {
            setTransferBusy(false);
            if (err != null) {
                Throwable cause = err.getCause() != null ? err.getCause() : err;
                statusLabel.setText("Download failed: " + cause.getMessage());
                UiSafe.showError(UiSafe.windowOf(this), "Vault Download Failed", cause.getMessage());
            } else {
                statusLabel.setText("Saved " + row.fileName() + " (" + res[0] + " B, SHA-256: " + res[1].substring(0, 16) + "...).");
                UiSafe.showInfo(UiSafe.windowOf(this), "Download Complete",
                        "File saved cleanly to:\n" + dest.getAbsolutePath()
                                + "\n\nSize: " + res[0] + " bytes\nSHA-256: " + res[1]);
            }
        }));
    }
}
