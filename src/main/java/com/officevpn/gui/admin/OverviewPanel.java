package com.officevpn.gui.admin;

import com.officevpn.admin.AlertManager;
import com.officevpn.admin.MetricsCollector;
import com.officevpn.config.ConfigUtil;
import com.officevpn.config.Messages;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import com.officevpn.server.VpnGatewayServer;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Real-Time Gateway Overview &amp; Telemetry KPI Dashboard.
 */
public final class OverviewPanel extends VBox {

    private final DatabaseManager db;
    private final MetricsCollector metrics;
    private final AlertManager alertManager;
    private volatile VpnGatewayServer gatewayServer;

    private final Label activeSessionsValue = new Label("0");
    private final Label totalUsersValue = new Label("0");
    private final Label connectionsTodayValue = new Label("0");
    private final Label bandwidthTodayValue = new Label("0 B");
    private final Label avgLatencyValue = new Label("0 ms");
    private final Label uptimeValue = new Label("0s");

    private final Label fingerprintLabel = new Label("Not started");
    private final Label poolInfoLabel = new Label("-");
    private final Label unreadAlertsBadge = new Label("0 Unread Alerts");
    private final TableView<DatabaseManager.UserBandwidthStat> topBandwidthTable = new TableView<>();

    public OverviewPanel(DatabaseManager db, MetricsCollector metrics, AlertManager alertManager, VpnGatewayServer gatewayServer) {
        this.db = db;
        this.metrics = metrics;
        this.alertManager = alertManager;
        this.gatewayServer = gatewayServer;

        setSpacing(16);
        setPadding(new Insets(18));
        buildUi();
        refresh();
    }

    public void setGatewayServer(VpnGatewayServer server) {
        this.gatewayServer = server;
        refresh();
    }

    private void buildUi() {
        HBox headerRow = new HBox(10);
        headerRow.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("admin.overview.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("admin.overview.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        Button refreshMetricsButton = new Button(Messages.get("admin.overview.button.refresh"));
        refreshMetricsButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(refreshMetricsButton, Messages.get("admin.overview.button.refresh"), null);
        refreshMetricsButton.setOnAction(e -> refresh());
        headerRow.getChildren().addAll(titleBox, spacer, refreshMetricsButton);

        GridPane kpiGrid = new GridPane();
        kpiGrid.setHgap(14);
        kpiGrid.setVgap(14);
        for (int i = 0; i < 3; i++) {
            ColumnConstraints cc = new ColumnConstraints();
            cc.setPercentWidth(33.33);
            kpiGrid.getColumnConstraints().add(cc);
        }

        kpiGrid.add(createKpiCard("ACTIVE SESSIONS", activeSessionsValue, "kpi-card-cyan"), 0, 0);
        kpiGrid.add(createKpiCard("REGISTERED USERS", totalUsersValue, "kpi-card-emerald"), 1, 0);
        kpiGrid.add(createKpiCard("CONNECTIONS TODAY", connectionsTodayValue, "kpi-card-indigo"), 2, 0);
        kpiGrid.add(createKpiCard("BANDWIDTH TODAY", bandwidthTodayValue, "kpi-card-amber"), 0, 1);
        kpiGrid.add(createKpiCard("AVG LATENCY", avgLatencyValue, "kpi-card-rose"), 1, 1);
        kpiGrid.add(createKpiCard("GATEWAY UPTIME", uptimeValue, "kpi-card-teal"), 2, 1);

        // RSA Fingerprint & Environment Strip
        VBox identityCard = new VBox(8);
        identityCard.getStyleClass().add("card");
        HBox fpHeader = new HBox(10);
        fpHeader.setAlignment(Pos.CENTER_LEFT);
        Label fpTitle = new Label(Messages.get("admin.overview.section.fingerprint"));
        fpTitle.getStyleClass().add("section-title");
        Region fpSpacer = new Region();
        HBox.setHgrow(fpSpacer, Priority.ALWAYS);
        Button copyFingerprintButton = new Button(Messages.get("admin.overview.button.copyFp"));
        copyFingerprintButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(copyFingerprintButton, Messages.get("admin.overview.button.copyFp"), null);
        copyFingerprintButton.setOnAction(e -> UiSafe.copyToClipboard(fingerprintLabel.getText()));
        fpHeader.getChildren().addAll(fpTitle, fpSpacer, copyFingerprintButton);

        fingerprintLabel.getStyleClass().add("mono-text");
        fingerprintLabel.setStyle("-fx-text-fill: #096B67; -fx-font-size: 13px; -fx-font-weight: bold;");
        fingerprintLabel.setWrapText(true);

        HBox runtimeStrip = new HBox(12);
        runtimeStrip.setAlignment(Pos.CENTER_LEFT);
        poolInfoLabel.getStyleClass().add("muted-label");
        unreadAlertsBadge.getStyleClass().addAll("pill", "pill-muted");
        runtimeStrip.getChildren().addAll(poolInfoLabel, unreadAlertsBadge);

        identityCard.getChildren().addAll(fpHeader, fingerprintLabel, runtimeStrip);

        // Bottom Bandwidth Leaderboard Table
        VBox bwCard = new VBox(10);
        bwCard.getStyleClass().add("card");
        VBox.setVgrow(bwCard, Priority.ALWAYS);
        Label bwTitle = new Label(Messages.get("admin.overview.section.topBandwidth"));
        bwTitle.getStyleClass().add("section-title");

        UiSafe.configureSafeTable(topBandwidthTable);
        topBandwidthTable.getColumns().add(UiSafe.safeColumn("Username", DatabaseManager.UserBandwidthStat::username, 220));
        topBandwidthTable.getColumns().add(UiSafe.safeColumn("Transferred Bytes", s -> String.valueOf(s.totalBytes()), 160));
        topBandwidthTable.getColumns().add(UiSafe.safeColumn("Formatted Volume", s -> formatBytes(s.totalBytes()), 180));
        VBox.setVgrow(topBandwidthTable, Priority.ALWAYS);

        bwCard.getChildren().addAll(bwTitle, topBandwidthTable);
        getChildren().addAll(headerRow, kpiGrid, identityCard, bwCard);
    }

    private VBox createKpiCard(String titleText, Label valueLabel, String accentClass) {
        VBox card = new VBox(6);
        card.getStyleClass().addAll("kpi-card", accentClass);
        Label lbl = new Label(titleText);
        lbl.getStyleClass().add("kpi-label");
        valueLabel.getStyleClass().add("kpi-value");
        card.getChildren().addAll(lbl, valueLabel);
        return card;
    }

    public void refresh() {
        if (db.isClosed()) {
            return;
        }
        CompletableFuture.supplyAsync(() -> {
            if (db.isClosed()) {
                return null;
            }
            int active = metrics.getActiveSessionCount();
            int totalUsers = metrics.getTotalUsers();
            int connsToday = metrics.getConnectionsToday();
            long bwToday = metrics.getBandwidthUsedToday();
            long latency = metrics.getAverageLatencyMs();
            long uptime = metrics.getUptimeSeconds();
            int unread = alertManager.getUnreadCount();
            int unreadCrit = alertManager.getUnreadCriticalCount();
            List<DatabaseManager.UserBandwidthStat> topUsers = metrics.getTopUsersByBandwidth(8);
            VpnGatewayServer srv = this.gatewayServer;
            String fp = (srv != null && srv.getServerIdentity() != null)
                    ? srv.getServerPublicKeyFingerprintHex()
                    : "Gateway not started";
            String poolText = String.format("MySQL HikariCP Pool Max: %d  |  Tunnel: %s  |  DNS Guard: %s",
                    db.getPoolMaxSize(),
                    ConfigUtil.getTunnelMode(),
                    ConfigUtil.isDnsLeakProtectionEnabled() ? ConfigUtil.getVpnDns() : "Disabled");
            return new OverviewSnapshot(active, totalUsers, connsToday, bwToday, latency, uptime, unread, unreadCrit, fp, poolText, topUsers);
        }).thenAccept(snap -> Platform.runLater(() -> {
            if (snap == null) return;
            activeSessionsValue.setText(String.valueOf(snap.active()));
            totalUsersValue.setText(String.valueOf(snap.totalUsers()));
            connectionsTodayValue.setText(String.valueOf(snap.connsToday()));
            bandwidthTodayValue.setText(formatBytes(snap.bwToday()));
            avgLatencyValue.setText(snap.latency() + " ms");
            uptimeValue.setText(formatUptime(snap.uptime()));
            fingerprintLabel.setText(snap.fingerprint());
            poolInfoLabel.setText(snap.poolText());
            unreadAlertsBadge.setText(snap.unreadCrit() > 0
                    ? snap.unreadCrit() + " CRITICAL / " + snap.unread() + " Unread Alerts"
                    : snap.unread() + " Unread Alerts");
            unreadAlertsBadge.getStyleClass().removeAll("pill-danger", "pill-warning", "pill-muted", "pill-success");
            unreadAlertsBadge.getStyleClass().add(
                    snap.unreadCrit() > 0 ? "pill-danger" : (snap.unread() > 0 ? "pill-warning" : "pill-success"));
            topBandwidthTable.getItems().setAll(snap.topUsers());
        }));
    }

    private record OverviewSnapshot(
            int active,
            int totalUsers,
            int connsToday,
            long bwToday,
            long latency,
            long uptime,
            int unread,
            int unreadCrit,
            String fingerprint,
            String poolText,
            List<DatabaseManager.UserBandwidthStat> topUsers
    ) {}

    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024L * 1024L * 1024L) return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
        return String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }

    private static String formatUptime(long seconds) {
        long h = seconds / 3600;
        long m = (seconds % 3600) / 60;
        long s = seconds % 60;
        if (h > 0) return String.format("%dh %dm %ds", h, m, s);
        if (m > 0) return String.format("%dm %ds", m, s);
        return s + "s";
    }
}
