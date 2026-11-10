package com.officevpn.gui.admin;

import com.officevpn.admin.AlertManager;
import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Real-Time Security Incident &amp; Alert Triage Panel.
 */
public final class AlertsPanel extends VBox {

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    private final AlertManager alertManager;
    private final Runnable onAlertsChanged;

    private final CheckBox unreadOnlyCheck = new CheckBox(Messages.get("admin.alerts.check.unreadOnly"));
    private final ComboBox<String> severityFilter = new ComboBox<>();
    private final Label summaryPill = new Label("0 Unread");
    private final TableView<AlertManager.SystemAlert> table = new TableView<>();

    public AlertsPanel(AlertManager alertManager, Runnable onAlertsChanged) {
        this.alertManager = alertManager;
        this.onAlertsChanged = onAlertsChanged;
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
        refresh();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("admin.alerts.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("admin.alerts.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        summaryPill.getStyleClass().addAll("pill", "pill-muted");
        header.getChildren().addAll(titleBox, spacer, summaryPill);

        HBox toolbar = new HBox(10);
        toolbar.setAlignment(Pos.CENTER_LEFT);
        unreadOnlyCheck.setOnAction(e -> refresh());

        severityFilter.getItems().addAll("ALL SEVERITIES", "CRITICAL", "WARNING", "INFO");
        severityFilter.getSelectionModel().selectFirst();
        severityFilter.setOnAction(e -> refresh());

        Button refreshButton = new Button(Messages.get("common.refresh"));
        refreshButton.getStyleClass().add("btn-secondary");
        refreshButton.setOnAction(e -> refresh());

        Button markReadButton = new Button(Messages.get("admin.alerts.button.markRead"));
        markReadButton.getStyleClass().add("btn-primary");
        markReadButton.setDisable(true);
        table.getSelectionModel().selectedItemProperty().addListener((obs, o, sel) -> markReadButton.setDisable(sel == null));
        markReadButton.setOnAction(e -> {
            AlertManager.SystemAlert sel = table.getSelectionModel().getSelectedItem();
            if (sel == null) return;
            CompletableFuture.runAsync(() -> alertManager.markAlertRead(sel.id()))
                    .thenRun(() -> Platform.runLater(this::notifyRefresh));
        });

        Button markAllReadButton = new Button(Messages.get("admin.alerts.button.markAllRead"));
        markAllReadButton.getStyleClass().add("btn-secondary");
        markAllReadButton.setOnAction(e -> {
            List<AlertManager.SystemAlert> items = List.copyOf(table.getItems());
            CompletableFuture.runAsync(() -> items.stream().filter(a -> !a.isRead()).forEach(a -> alertManager.markAlertRead(a.id())))
                    .thenRun(() -> Platform.runLater(this::notifyRefresh));
        });

        Button purgeAlertsButton = new Button(Messages.get("admin.alerts.button.purge"));
        purgeAlertsButton.getStyleClass().add("btn-warning");
        purgeAlertsButton.setOnAction(e -> {
            Optional<String> daysOpt = UiSafe.promptText(UiSafe.windowOf(this),
                    "Purge Historical Alerts",
                    "Delete alerts older than N days:",
                    "Retention Days", "30");
            daysOpt.ifPresent(s -> {
                try {
                    int days = Integer.parseInt(s.trim());
                    if (days < 1) throw new NumberFormatException();
                    CompletableFuture.supplyAsync(() -> alertManager.clearOldAlerts(days))
                            .thenAccept(removed -> Platform.runLater(() -> {
                                notifyRefresh();
                                UiSafe.showInfo(UiSafe.windowOf(this), "Alerts Purged",
                                        "Removed " + removed + " alert(s) older than " + days + " days.");
                            }));
                } catch (NumberFormatException ex) {
                    UiSafe.showError(UiSafe.windowOf(this), "Invalid Days", "Enter a positive integer >= 1.");
                }
            });
        });

        Region tbSpacer = new Region();
        HBox.setHgrow(tbSpacer, Priority.ALWAYS);
        toolbar.getChildren().addAll(unreadOnlyCheck, severityFilter, refreshButton, tbSpacer, markReadButton, markAllReadButton, purgeAlertsButton);

        UiSafe.configureSafeTable(table);
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("ID", a -> String.valueOf(a.id()), 55), 45, 65));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Timestamp", a -> TS_FMT.format(Instant.ofEpochMilli(a.timestamp())), 152), 148, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.badgeColumn("Severity", a -> a.severity().name(),
                a -> switch (a.severity()) {
                    case CRITICAL -> "pill-danger";
                    case WARNING -> "pill-warning";
                    case INFO -> "pill-info";
                }, 110), 100, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Type", a -> a.type().name(), 155), 135, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("User", AlertManager.SystemAlert::username, 115), 95, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Message", AlertManager.SystemAlert::message, 360), 240, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.badgeColumn("State", a -> a.isRead() ? "READ" : "UNREAD",
                a -> a.isRead() ? "pill-muted" : "pill-warning", 95), 85, 0));
        VBox.setVgrow(table, Priority.ALWAYS);

        VBox card = new VBox(12, toolbar, table);
        card.getStyleClass().add("card");
        VBox.setVgrow(card, Priority.ALWAYS);

        getChildren().addAll(header, card);
    }

    private void notifyRefresh() {
        refresh();
        if (onAlertsChanged != null) {
            onAlertsChanged.run();
        }
    }

    public void refresh() {
        boolean unreadOnly = unreadOnlyCheck.isSelected();
        String sev = severityFilter.getValue();
        CompletableFuture.supplyAsync(() -> {
            List<AlertManager.SystemAlert> raw;
            if (sev != null && !"ALL SEVERITIES".equals(sev)) {
                raw = alertManager.getAlertsBySeverity(AlertManager.AlertSeverity.valueOf(sev));
            } else if (unreadOnly) {
                raw = alertManager.getUnreadAlerts();
            } else {
                raw = alertManager.getAllAlerts();
            }
            if (unreadOnly) {
                raw = raw.stream().filter(a -> !a.isRead()).toList();
            }
            int unread = alertManager.getUnreadCount();
            int critical = alertManager.getUnreadCriticalCount();
            return new AlertSnapshot(raw, unread, critical);
        }).thenAccept(snap -> Platform.runLater(() -> {
            table.getItems().setAll(snap.alerts());
            summaryPill.setText(snap.critical() > 0
                    ? snap.critical() + " CRITICAL  ·  " + snap.unread() + " Unread"
                    : snap.unread() + " Unread Alerts");
            summaryPill.getStyleClass().removeAll("pill-danger", "pill-warning", "pill-success", "pill-muted");
            summaryPill.getStyleClass().add(
                    snap.critical() > 0 ? "pill-danger" : (snap.unread() > 0 ? "pill-warning" : "pill-success"));
        }));
    }

    private record AlertSnapshot(List<AlertManager.SystemAlert> alerts, int unread, int critical) {}
}
