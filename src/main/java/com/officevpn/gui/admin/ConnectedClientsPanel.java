package com.officevpn.gui.admin;

import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.UserAccount;
import com.officevpn.server.VpnGatewayServer;
import com.officevpn.server.VpnSession;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
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
import java.util.Map;
import java.util.Optional;

/**
 * JavaFX Live Connected VPN Clients Panel with Disconnect &amp; Broadcast controls.
 */
public final class ConnectedClientsPanel extends VBox {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    public record SessionRow(
            String username,
            String department,
            String role,
            String virtualIp,
            String socketIp,
            String connectedAt,
            String lastActivity,
            long idleSeconds
    ) {}

    private volatile VpnGatewayServer gatewayServer;
    private final String adminUsername;

    private final TextField searchField = new TextField();
    private final Label countPill = new Label("0 Active Clients");
    private final TableView<SessionRow> table = new TableView<>();
    private final List<SessionRow> allRows = new ArrayList<>();

    public ConnectedClientsPanel(VpnGatewayServer gatewayServer, String adminUsername) {
        this.gatewayServer = gatewayServer;
        this.adminUsername = adminUsername != null ? adminUsername : "admin_hq";
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
        refresh();
    }

    public void setGatewayServer(VpnGatewayServer server) {
        this.gatewayServer = server;
        refresh();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("admin.clients.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("admin.clients.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        countPill.getStyleClass().addAll("pill", "pill-info");
        header.getChildren().addAll(titleBox, spacer, countPill);

        HBox toolbar = new HBox(10);
        toolbar.setAlignment(Pos.CENTER_LEFT);
        searchField.setPromptText(Messages.get("admin.clients.search.prompt"));
        searchField.setPrefWidth(280);
        searchField.textProperty().addListener((obs, o, n) -> applyFilter());

        Button refreshButton = new Button(Messages.get("common.refresh"));
        refreshButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(refreshButton, Messages.get("common.refresh"), null);
        refreshButton.setOnAction(e -> refresh());

        Button copyVirtualIpButton = new Button(Messages.get("admin.clients.button.copyIp"));
        copyVirtualIpButton.getStyleClass().add("btn-secondary");
        copyVirtualIpButton.setDisable(true);
        Messages.configureAccessibleControl(copyVirtualIpButton, Messages.get("admin.clients.button.copyIp"), null);
        copyVirtualIpButton.setOnAction(e -> {
            SessionRow row = table.getSelectionModel().getSelectedItem();
            if (row != null) {
                UiSafe.copyToClipboard(row.virtualIp());
            }
        });

        Button broadcastNoticeButton = new Button(Messages.get("admin.clients.button.broadcast"));
        broadcastNoticeButton.getStyleClass().add("btn-primary");
        Messages.configureAccessibleControl(broadcastNoticeButton, Messages.get("admin.clients.button.broadcast"), null);
        broadcastNoticeButton.setOnAction(e -> {
            VpnGatewayServer srv = this.gatewayServer;
            if (srv == null || !srv.isRunning()) {
                UiSafe.showWarning(UiSafe.windowOf(this), "Gateway Offline", "Start the VPN gateway before broadcasting notices.");
                return;
            }
            Optional<String> msg = UiSafe.promptText(UiSafe.windowOf(this),
                    "Broadcast System Notice",
                    "Send an encrypted system message to all connected clients:",
                    "Announcement", "");
            msg.map(String::trim).filter(s -> !s.isEmpty()).ifPresent(text -> {
                srv.broadcastSystemMessage(text, adminUsername);
                UiSafe.showInfo(UiSafe.windowOf(this), "Broadcast Dispatched",
                        "Encrypted system notice transmitted to all active clients.");
            });
        });

        Button revokeAccessButton = new Button(Messages.get("admin.clients.button.revoke"));
        revokeAccessButton.getStyleClass().add("btn-danger");
        revokeAccessButton.setDisable(true);
        Messages.configureAccessibleControl(revokeAccessButton, Messages.get("admin.clients.button.revoke"), null);
        revokeAccessButton.setOnAction(e -> handleRevokeSelectedSession());

        table.getSelectionModel().selectedItemProperty().addListener((obs, o, sel) -> {
            boolean hasSel = sel != null;
            revokeAccessButton.setDisable(!hasSel);
            copyVirtualIpButton.setDisable(!hasSel);
        });

        Region tbSpacer = new Region();
        HBox.setHgrow(tbSpacer, Priority.ALWAYS);
        toolbar.getChildren().addAll(searchField, refreshButton, tbSpacer, copyVirtualIpButton, broadcastNoticeButton, revokeAccessButton);

        UiSafe.configureSafeTable(table);
        table.getColumns().add(UiSafe.safeColumn("Username", SessionRow::username, 140));
        table.getColumns().add(UiSafe.safeColumn("Department", SessionRow::department, 120));
        table.getColumns().add(UiSafe.badgeColumn("Role", SessionRow::role,
                r -> "ADMIN".equals(r.role()) ? "pill-danger" : ("AUDITOR".equals(r.role()) ? "pill-warning" : "pill-info"), 110));
        table.getColumns().add(UiSafe.safeColumn("Virtual IP", SessionRow::virtualIp, 120));
        table.getColumns().add(UiSafe.safeColumn("Remote Socket", SessionRow::socketIp, 160));
        table.getColumns().add(UiSafe.safeColumn("Connected", SessionRow::connectedAt, 100));
        table.getColumns().add(UiSafe.safeColumn("Last Activity", SessionRow::lastActivity, 100));
        table.getColumns().add(UiSafe.safeColumn("Idle (s)", r -> String.valueOf(r.idleSeconds()), 80));
        VBox.setVgrow(table, Priority.ALWAYS);

        VBox card = new VBox(12, toolbar, table);
        card.getStyleClass().add("card");
        VBox.setVgrow(card, Priority.ALWAYS);

        getChildren().addAll(header, card);
    }

    private void handleRevokeSelectedSession() {
        SessionRow selected = table.getSelectionModel().getSelectedItem();
        VpnGatewayServer srv = this.gatewayServer;
        if (selected == null || srv == null) {
            return;
        }
        boolean ok = UiSafe.showConfirm(UiSafe.windowOf(this),
                "Revoke Client Access",
                "Terminate active VPN session for '" + selected.username() + "'?",
                "The client socket will be closed and the virtual IP (" + selected.virtualIp() + ") reclaimed.");
        if (ok) {
            srv.disconnectUser(selected.username(), "Administratively terminated via dashboard", adminUsername);
            refresh();
        }
    }

    public void refresh() {
        VpnGatewayServer srv = this.gatewayServer;
        List<SessionRow> updated = new ArrayList<>();
        if (srv != null && srv.isRunning()) {
            long now = System.currentTimeMillis();
            Map<String, VpnSession> sessions = srv.getActiveSessions();
            for (VpnSession s : sessions.values()) {
                UserAccount u = s.getAuthenticatedUser();
                String uname = u != null ? u.username() : s.getSessionId();
                String dept = u != null ? u.department().name() : "-";
                String role = u != null ? u.role().name() : "-";
                String vip = s.getAssignedVirtualIp() != null ? s.getAssignedVirtualIp() : "-";
                String sock = s.getClientSocketAddress() != null ? s.getClientSocketAddress() : "-";
                String connStr = TIME_FMT.format(Instant.ofEpochMilli(s.getConnectedAt()));
                String lastStr = TIME_FMT.format(Instant.ofEpochMilli(s.getLastActivityAt()));
                long idle = Math.max(0, (now - s.getLastActivityAt()) / 1000L);
                updated.add(new SessionRow(uname, dept, role, vip, sock, connStr, lastStr, idle));
            }
        }
        allRows.clear();
        allRows.addAll(updated);
        countPill.setText(allRows.size() + " Active Clients");
        applyFilter();
    }

    private void applyFilter() {
        String q = searchField.getText() != null ? searchField.getText().trim().toLowerCase(Locale.ROOT) : "";
        if (q.isEmpty()) {
            table.getItems().setAll(allRows);
            return;
        }
        table.getItems().setAll(allRows.stream().filter(r ->
                r.username().toLowerCase(Locale.ROOT).contains(q)
                        || r.department().toLowerCase(Locale.ROOT).contains(q)
                        || r.virtualIp().toLowerCase(Locale.ROOT).contains(q)
                        || r.socketIp().toLowerCase(Locale.ROOT).contains(q)
        ).toList());
    }
}
