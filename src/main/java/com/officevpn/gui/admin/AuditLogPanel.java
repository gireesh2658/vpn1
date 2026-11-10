package com.officevpn.gui.admin;

import com.officevpn.admin.AlertManager;
import com.officevpn.admin.AuditService;
import com.officevpn.config.Messages;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.AuditVerifyResult;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

import java.io.File;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Tamper-Evident Cryptographic Audit Log Viewer, Search, CSV Exporter &amp; HMAC Verifier.
 */
public final class AuditLogPanel extends VBox {

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final DatabaseManager db;
    private final AuditService auditService;

    private final TextField usernameFilter = new TextField();
    private final ComboBox<String> eventFilter = new ComboBox<>();
    private final Label integrityBadge = new Label("Chain Status: Pending");
    private final Label countPill = new Label("0 Events");
    private final Label detailPreview = new Label("Select an audit record to inspect full details.");
    private final TableView<DatabaseManager.AuditLogEntry> table = new TableView<>();

    public AuditLogPanel(DatabaseManager db, AlertManager alertManager) {
        this.db = db;
        this.auditService = new AuditService(db, alertManager);
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
        refresh();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("admin.audit.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("admin.audit.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        integrityBadge.getStyleClass().addAll("pill", "pill-muted");
        countPill.getStyleClass().addAll("pill", "pill-info");
        header.getChildren().addAll(titleBox, spacer, integrityBadge, countPill);

        HBox toolbar = new HBox(10);
        toolbar.setAlignment(Pos.CENTER_LEFT);
        usernameFilter.setPromptText("Username filter...");
        usernameFilter.setPrefWidth(175);

        eventFilter.setEditable(true);
        eventFilter.getItems().addAll(
                "ALL EVENTS", "AUTH_SUCCESS", "AUTH_FAILURE", "AUTH_TOTP_FAILED",
                "AUTH_LOCKOUT_BLOCKED", "AUTH_USERNAME_UNDER_ATTACK", "TUNNEL_ESTABLISHED",
                "FILE_UPLOAD", "FILE_DOWNLOAD", "FILE_ACCESS_DENIED",
                "ADMIN_USER_CREATED", "ADMIN_PASSWORD_RESET", "ADMIN_ROLE_CHANGED",
                "ADMIN_DEPARTMENT_CHANGED", "ADMIN_USER_STATUS_CHANGED", "ADMIN_UNLOCK_ACCOUNT",
                "DEVICE_ENROLLED", "DEVICE_CAP_EXCEEDED", "CONFIG_CHANGED", "AUDIT_CHAIN_GENESIS"
        );
        eventFilter.getSelectionModel().selectFirst();
        eventFilter.setPrefWidth(220);

        Button searchLogButton = new Button(Messages.get("admin.audit.button.search"));
        searchLogButton.getStyleClass().add("btn-primary");
        searchLogButton.setOnAction(_ -> refresh());

        Button resetFiltersButton = new Button(Messages.get("admin.audit.button.reset"));
        resetFiltersButton.getStyleClass().add("btn-secondary");
        resetFiltersButton.setOnAction(_ -> {
            usernameFilter.clear();
            eventFilter.getSelectionModel().selectFirst();
            refresh();
        });

        Button verifyChainButton = new Button(Messages.get("admin.audit.button.verify"));
        verifyChainButton.getStyleClass().add("btn-success");
        verifyChainButton.setOnAction(_ -> runChainVerify());

        Button exportLogButton = new Button(Messages.get("admin.audit.button.export"));
        exportLogButton.getStyleClass().add("btn-secondary");
        exportLogButton.setOnAction(_ -> handleExportCsv());

        Region tbSpacer = new Region();
        HBox.setHgrow(tbSpacer, Priority.ALWAYS);
        toolbar.getChildren().addAll(usernameFilter, eventFilter, searchLogButton, resetFiltersButton, tbSpacer, verifyChainButton, exportLogButton);

        UiSafe.configureSafeTable(table);
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Seq", e -> String.valueOf(e.seq()), 58), 48, 65));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Timestamp", e -> TS_FMT.format(Instant.ofEpochMilli(e.timestamp())), 152), 148, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.badgeColumn("Event Type", DatabaseManager.AuditLogEntry::eventType,
                AuditLogPanel::badgeForEvent, 215), 195, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Username", DatabaseManager.AuditLogEntry::username, 120), 105, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Dept", DatabaseManager.AuditLogEntry::department, 125), 115, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Actor", e -> e.actor() != null ? e.actor() : "-", 105), 95, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Remote IP", DatabaseManager.AuditLogEntry::ipAddress, 105), 95, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Details", DatabaseManager.AuditLogEntry::details, 280), 220, 0));
        VBox.setVgrow(table, Priority.ALWAYS);

        table.getSelectionModel().selectedItemProperty().addListener((_, _, sel) -> {
            if (sel == null) {
                detailPreview.setText("Select an audit record to inspect full details.");
            } else {
                detailPreview.setText(String.format("Seq #%d | %s | User=%s (%s) | Actor=%s | IP=%s | %s",
                        sel.seq(), sel.eventType(), sel.username(), sel.department(),
                        sel.actor(), sel.ipAddress(), UiSafe.text(sel.details(), 512)));
            }
        });

        detailPreview.getStyleClass().addAll("muted-label", "mono-text");
        detailPreview.setWrapText(true);

        VBox card = new VBox(12, toolbar, table, detailPreview);
        card.getStyleClass().add("card");
        VBox.setVgrow(card, Priority.ALWAYS);

        getChildren().addAll(header, card);
    }

    public void updateStartupVerifyResult(AuditVerifyResult result) {
        if (result == null) return;
        applyVerifyBadge(result);
    }

    private void runChainVerify() {
        integrityBadge.setText("Verifying...");
        CompletableFuture.supplyAsync(db::verifyAuditChain).thenAccept(res -> Platform.runLater(() -> {
            applyVerifyBadge(res);
            if (res.status() == AuditVerifyResult.AuditStatus.OK) {
                UiSafe.showInfo(UiSafe.windowOf(this), "Audit Integrity Verified", res.details());
            } else {
                UiSafe.showError(UiSafe.windowOf(this), "AUDIT INTEGRITY ALERT",
                        "Status: " + res.status() + "\nFirst bad seq: " + res.firstBadSeq() + "\n" + res.details());
            }
        }));
    }

    private void applyVerifyBadge(AuditVerifyResult res) {
        integrityBadge.getStyleClass().removeAll("pill-success", "pill-danger", "pill-warning", "pill-muted");
        if (res.status() == AuditVerifyResult.AuditStatus.OK) {
            integrityBadge.setText("CHAIN INTACT (" + res.rowsChecked() + " rows)");
            integrityBadge.getStyleClass().add("pill-success");
        } else {
            integrityBadge.setText("CHAIN ALERT: " + res.status());
            integrityBadge.getStyleClass().add("pill-danger");
        }
    }

    private void handleExportCsv() {
        FileChooser fc = new FileChooser();
        fc.setTitle(Messages.get("admin.audit.dialog.export.title"));
        fc.setInitialFileName("officevpn-audit-trail.csv");
        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Files", "*.csv"));
        File file = fc.showSaveDialog(UiSafe.windowOf(this));
        if (file == null) return;

        CompletableFuture.supplyAsync(() -> {
            try {
                return auditService.exportAuditToCsv(file.toPath());
            } catch (Exception ex) {
                throw new IllegalStateException(ex.getMessage(), ex);
            }
        }).whenComplete((count, err) -> Platform.runLater(() -> {
            if (err != null) {
                UiSafe.showError(UiSafe.windowOf(this), "Export Failed", err.getMessage());
            } else {
                UiSafe.showInfo(UiSafe.windowOf(this), "CSV Export Complete",
                        "Exported " + count + " audit rows to:\n" + file.getAbsolutePath());
            }
        }));
    }

    public void refresh() {
        if (db.isClosed()) return;
        String userQ = usernameFilter.getText() != null ? usernameFilter.getText().trim() : "";
        String evRaw = eventFilter.getEditor() != null && eventFilter.getEditor().getText() != null
                ? eventFilter.getEditor().getText().trim()
                : (eventFilter.getValue() != null ? eventFilter.getValue().trim() : "");
        String evQ = ("ALL EVENTS".equalsIgnoreCase(evRaw) || evRaw.isEmpty()) ? null : evRaw;

        CompletableFuture.supplyAsync(() -> {
            if (db.isClosed()) return null;
            if (userQ.isEmpty() && evQ == null) {
                return db.getRecentAuditLogs(400);
            }
            List<DatabaseManager.AuditLogEntry> found = auditService.searchAudit(
                    userQ.isEmpty() ? null : userQ, evQ, null, null);
            return found.size() > 500 ? found.subList(0, 500) : found;
        }).thenAccept(list -> Platform.runLater(() -> {
            if (list == null) return;
            table.getItems().setAll(list);
            countPill.setText(list.size() + " Events");
        }));
    }

    private static String badgeForEvent(DatabaseManager.AuditLogEntry e) {
        String ev = e.eventType() != null ? e.eventType() : "";
        if (ev.contains("FAILURE") || ev.contains("FAILED") || ev.contains("DENIED")
                || ev.contains("ATTACK") || ev.contains("LOCKOUT") || ev.contains("CORRUPT")
                || ev.contains("EXCEEDED") || ev.contains("DELETED")) {
            return "pill-danger";
        }
        if (ev.contains("DISABLED") || ev.contains("REVOKED") || ev.contains("RESET") || ev.contains("CONFIG")) {
            return "pill-warning";
        }
        if (ev.contains("SUCCESS") || ev.contains("ESTABLISHED") || ev.contains("CREATED")
                || ev.contains("ENROLLED") || ev.contains("GENESIS")) {
            return "pill-success";
        }
        return "pill-info";
    }
}
