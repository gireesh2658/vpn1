package com.officevpn.gui.admin;

import com.officevpn.admin.DeviceManager;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Hardware Device Trust Registry &amp; Governance Panel.
 */
public final class DevicesPanel extends VBox {

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    private final DatabaseManager db;
    private final DeviceManager deviceManager;

    private final TextField filterField = new TextField();
    private final TableView<DatabaseManager.UserDeviceRecord> table = new TableView<>();
    private final List<DatabaseManager.UserDeviceRecord> allDevices = new ArrayList<>();
    private final Label statusPill = new Label("0 Devices");

    public DevicesPanel(DatabaseManager db, DeviceManager deviceManager) {
        this.db = db;
        this.deviceManager = deviceManager;
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
        refresh();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label("Trusted Hardware Devices");
        title.getStyleClass().add("page-title");
        Label subtitle = new Label("Monitor device fingerprints, enforce per-user enrollment quotas, and trust or revoke hardware");
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        statusPill.getStyleClass().addAll("pill", "pill-info");
        header.getChildren().addAll(titleBox, spacer, statusPill);

        HBox filterBar = new HBox(10);
        filterBar.setAlignment(Pos.CENTER_LEFT);
        filterField.setPromptText("Filter by username, device name, or fingerprint...");
        filterField.setPrefWidth(320);
        filterField.textProperty().addListener((obs, o, n) -> applyFilter());

        Button refreshBtn = new Button("Refresh");
        refreshBtn.getStyleClass().add("btn-secondary");
        refreshBtn.setOnAction(e -> refresh());

        Button enrollBtn = new Button("+ Enroll Device");
        enrollBtn.getStyleClass().add("btn-primary");
        enrollBtn.setOnAction(e -> handleEnrollDialog());

        Region fSpacer = new Region();
        HBox.setHgrow(fSpacer, Priority.ALWAYS);
        filterBar.getChildren().addAll(filterField, refreshBtn, fSpacer, enrollBtn);

        FlowPane actionBar = new FlowPane(8, 8);
        Button trustBtn = new Button("Trust Selected");
        trustBtn.getStyleClass().add("btn-success");
        Button revokeBtn = new Button("Revoke Selected");
        revokeBtn.getStyleClass().add("btn-warning");
        Button copyFpBtn = new Button("Copy Fingerprint");
        Button deleteBtn = new Button("Delete Record");
        deleteBtn.getStyleClass().add("btn-danger");

        List<Button> selBtns = List.of(trustBtn, revokeBtn, copyFpBtn, deleteBtn);
        selBtns.forEach(b -> b.setDisable(true));
        table.getSelectionModel().selectedItemProperty().addListener((obs, o, sel) -> {
            boolean has = sel != null;
            selBtns.forEach(b -> b.setDisable(!has));
        });

        trustBtn.setOnAction(e -> {
            var d = table.getSelectionModel().getSelectedItem();
            if (d == null) return;
            CompletableFuture.runAsync(() -> deviceManager.trustDevice(d.username(), d.deviceFingerprint()))
                    .thenRun(() -> Platform.runLater(this::refresh));
        });

        revokeBtn.setOnAction(e -> {
            var d = table.getSelectionModel().getSelectedItem();
            if (d == null) return;
            CompletableFuture.runAsync(() -> deviceManager.revokeDevice(d.username(), d.deviceFingerprint()))
                    .thenRun(() -> Platform.runLater(this::refresh));
        });

        copyFpBtn.setOnAction(e -> {
            var d = table.getSelectionModel().getSelectedItem();
            if (d != null) {
                UiSafe.copyToClipboard(d.deviceFingerprint());
            }
        });

        deleteBtn.setOnAction(e -> {
            var d = table.getSelectionModel().getSelectedItem();
            if (d == null) return;
            if (UiSafe.showConfirm(UiSafe.windowOf(this), "Delete Device Record",
                    "Permanently delete hardware record '" + d.deviceName() + "' for '" + d.username() + "'?",
                    "This removes the enrollment slot so the user may re-enroll under cap.")) {
                CompletableFuture.runAsync(() -> deviceManager.deleteDevice(d.username(), d.deviceFingerprint()))
                        .thenRun(() -> Platform.runLater(this::refresh));
            }
        });

        actionBar.getChildren().addAll(trustBtn, revokeBtn, copyFpBtn, deleteBtn);

        UiSafe.configureSafeTable(table);
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("ID", d -> String.valueOf(d.id()), 55), 45, 65));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Username", DatabaseManager.UserDeviceRecord::username, 120), 105, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Device Name", DatabaseManager.UserDeviceRecord::deviceName, 195), 160, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Hardware Fingerprint", DatabaseManager.UserDeviceRecord::deviceFingerprint, 250), 185, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.badgeColumn("Trust State", d -> d.isTrusted() ? "TRUSTED" : "REVOKED",
                d -> d.isTrusted() ? "pill-success" : "pill-danger", 110), 100, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("First Seen", d -> TS_FMT.format(Instant.ofEpochMilli(d.firstSeenAt())), 138), 132, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Last Seen", d -> TS_FMT.format(Instant.ofEpochMilli(d.lastSeenAt())), 138), 132, 0));
        VBox.setVgrow(table, Priority.ALWAYS);

        VBox card = new VBox(12, filterBar, actionBar, table);
        card.getStyleClass().add("card");
        VBox.setVgrow(card, Priority.ALWAYS);

        getChildren().addAll(header, card);
    }

    private void handleEnrollDialog() {
        TextField userField = new TextField();
        userField.setPromptText("Existing username");
        TextField fpField = new TextField();
        fpField.setPromptText("Hardware SHA-256 fingerprint");
        TextField nameField = new TextField();
        nameField.setPromptText("Workstation label (e.g. Corp-Laptop-04)");

        VBox box = new VBox(8,
                new Label("Username"), userField,
                new Label("Device Fingerprint"), fpField,
                new Label("Device Name"), nameField
        );
        box.setPrefWidth(420);
        Dialog<ButtonType> dialog = UiSafe.createDialog(UiSafe.windowOf(this), "Enroll Trusted Device",
                "Manually enroll & trust a hardware fingerprint", box);
        ButtonType addType = new ButtonType("Enroll Device", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(addType, ButtonType.CANCEL);
        UiSafe.stylePrimaryDialogButton(dialog, addType);

        if (dialog.showAndWait().orElse(ButtonType.CANCEL) != addType) return;
        String u = userField.getText() != null ? userField.getText().trim() : "";
        String fp = fpField.getText() != null ? fpField.getText().trim() : "";
        String name = nameField.getText() != null ? nameField.getText().trim() : "Authorized-Workstation";
        if (u.isEmpty() || fp.isEmpty()) {
            UiSafe.showError(UiSafe.windowOf(this), "Validation Error", "Username and device fingerprint are required.");
            return;
        }
        CompletableFuture.runAsync(() -> deviceManager.registerAndTrustDevice(u, fp, name))
                .thenRun(() -> Platform.runLater(this::refresh));
    }

    public void refresh() {
        CompletableFuture.supplyAsync(db::listAllDevices).thenAccept(list -> Platform.runLater(() -> {
            allDevices.clear();
            allDevices.addAll(list);
            statusPill.setText(allDevices.size() + " Devices");
            applyFilter();
        }));
    }

    private void applyFilter() {
        String q = filterField.getText() != null ? filterField.getText().trim().toLowerCase(Locale.ROOT) : "";
        if (q.isEmpty()) {
            table.getItems().setAll(allDevices);
            return;
        }
        table.getItems().setAll(allDevices.stream().filter(d ->
                (d.username() != null && d.username().toLowerCase(Locale.ROOT).contains(q))
                        || (d.deviceName() != null && d.deviceName().toLowerCase(Locale.ROOT).contains(q))
                        || (d.deviceFingerprint() != null && d.deviceFingerprint().toLowerCase(Locale.ROOT).contains(q))
        ).toList());
    }
}
