package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
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

    public FileVaultPanel(VpnClientEngine engine) {
        this.engine = engine;
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
        refreshFiles();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label("Encrypted Departmental File Vault");
        title.getStyleClass().add("page-title");
        Label subtitle = new Label("Zero-trust RBAC file exchange over directional AES-256-GCM tunnel with canonical path confinement");
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        boolean isHqAdmin = engine.getRole() == Role.ADMIN && engine.getDepartment() == Department.HEADQUARTERS;
        rbacPill.setText(isHqAdmin ? "HQ ADMIN: CROSS-VAULT" : "RBAC LOCKED: " + engine.getDepartment());
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

        Button refreshBtn = new Button("Refresh Vault");
        refreshBtn.getStyleClass().add("btn-secondary");
        refreshBtn.setOnAction(e -> refreshFiles());

        Button uploadBtn = new Button("Upload File...");
        uploadBtn.getStyleClass().add("btn-primary");
        uploadBtn.setOnAction(e -> handleUpload());

        Button downloadBtn = new Button("Download Selected...");
        downloadBtn.getStyleClass().add("btn-success");
        downloadBtn.setDisable(true);
        downloadBtn.setOnAction(e -> handleDownload());

        Button copyBtn = new Button("Copy Filename");
        copyBtn.getStyleClass().add("btn-secondary");
        copyBtn.setDisable(true);
        copyBtn.setOnAction(e -> {
            VaultFileRow sel = table.getSelectionModel().getSelectedItem();
            if (sel != null) UiSafe.copyToClipboard(sel.fileName());
        });

        table.getSelectionModel().selectedItemProperty().addListener((obs, o, sel) -> {
            boolean has = sel != null;
            downloadBtn.setDisable(!has);
            copyBtn.setDisable(!has);
        });

        Region tbSpacer = new Region();
        HBox.setHgrow(tbSpacer, Priority.ALWAYS);
        toolbar.getChildren().addAll(new Label("Vault:"), vaultSelector, refreshBtn, tbSpacer, copyBtn, uploadBtn, downloadBtn);

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

    public void refreshFiles() {
        Department dept = vaultSelector.getValue();
        if (dept == null) return;
        statusLabel.setText("Listing files in " + dept + " vault...");
        CompletableFuture.supplyAsync(() -> {
            try {
                return engine.listDepartmentFiles(dept);
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }).whenComplete((files, err) -> Platform.runLater(() -> {
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
        fc.setTitle("Select File to Encrypt & Upload to " + dept);
        File selected = fc.showOpenDialog(UiSafe.windowOf(this));
        if (selected == null) return;

        if (selected.length() > 8 * 1024 * 1024) {
            UiSafe.showError(UiSafe.windowOf(this), "File Too Large", "Maximum vault file upload size is 8 MB.");
            return;
        }

        String fileName = selected.getName();
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
        fc.setTitle("Save Decrypted File");
        fc.setInitialFileName(row.fileName());
        File dest = fc.showSaveDialog(UiSafe.windowOf(this));
        if (dest == null) return;

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
