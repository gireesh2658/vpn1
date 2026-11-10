package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.security.KillSwitchManager;
import com.officevpn.tunnel.TunnelManager;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * JavaFX Client Cryptographic Tunnel Diagnostics, Kill Switch, Split/Full Tunneling &amp; Live Sniffer Console.
 */
public final class ConnectionStatusPanel extends VBox {

    private static final int MAX_CONSOLE_LINES = 600;
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final VpnClientEngine engine;
    private final Deque<String> lineBuffer = new ArrayDeque<>(MAX_CONSOLE_LINES + 1);

    private final Label tunnelModePill = new Label("-");
    private final Button switchTunnelModeButton = new Button(Messages.get("tunnel.button.switchFull"));
    private final Label routesInfoLabel = new Label("-");

    private final Label killSwitchPill = new Label("-");
    private final Button killSwitchButton = new Button(Messages.get("tunnel.button.enableKillSwitch"));

    private final Label dnsGuardPill = new Label("-");
    private final CheckBox autoReconnectCheck = new CheckBox(Messages.get("tunnel.check.autoReconnect"));

    private final Label serverFpLabel = new Label("-");
    private final TextArea telemetryConsole = new TextArea();

    private KillSwitchManager.KillSwitchListener ksListener;

    public ConnectionStatusPanel(VpnClientEngine engine) {
        this.engine = engine;
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
        attachKillSwitchListener();
        refreshControls();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("tunnel.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("tunnel.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        Button refreshButton = new Button(Messages.get("tunnel.button.sync"));
        refreshButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(refreshButton,
                Messages.get("tunnel.button.sync"),
                Messages.get("tunnel.tooltip.sync"));
        refreshButton.setOnAction(_ -> refreshControls());
        header.getChildren().addAll(titleBox, spacer, refreshButton);

        GridPane controlsGrid = new GridPane();
        controlsGrid.setHgap(14);
        controlsGrid.setVgap(14);
        for (int i = 0; i < 3; i++) {
            ColumnConstraints cc = new ColumnConstraints();
            cc.setPercentWidth(33.33);
            controlsGrid.getColumnConstraints().add(cc);
        }

        // Card 1: Tunnel Mode (Split / Full)
        VBox tunnelCard = new VBox(8);
        tunnelCard.getStyleClass().add("card");
        Label tTitle = new Label(Messages.get("tunnel.card.mode"));
        tTitle.getStyleClass().add("kpi-label");
        tunnelModePill.getStyleClass().addAll("pill", "pill-info");
        routesInfoLabel.getStyleClass().add("muted-label");
        routesInfoLabel.setWrapText(true);
        switchTunnelModeButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(switchTunnelModeButton,
                Messages.get("tunnel.button.switchFull"),
                Messages.get("tunnel.tooltip.switchMode"));
        switchTunnelModeButton.setOnAction(_ -> {
            TunnelManager tm = engine.getTunnelManager();
            if (tm == null) return;
            TunnelManager.TunnelMode next = (tm.getMode() == TunnelManager.TunnelMode.FULL)
                    ? TunnelManager.TunnelMode.SPLIT
                    : TunnelManager.TunnelMode.FULL;
            tm.setMode(next);
            appendStateMessage("Switched tunnel routing mode to " + next);
            refreshControls();
        });
        tunnelCard.getChildren().addAll(tTitle, tunnelModePill, routesInfoLabel, switchTunnelModeButton);

        // Card 2: Kill Switch
        VBox ksCard = new VBox(8);
        ksCard.getStyleClass().add("card");
        Label kTitle = new Label(Messages.get("tunnel.card.killSwitch"));
        kTitle.getStyleClass().add("kpi-label");
        killSwitchPill.getStyleClass().addAll("pill", "pill-muted");
        Label ksDesc = new Label(Messages.get("tunnel.killSwitch.desc"));
        ksDesc.getStyleClass().add("muted-label");
        ksDesc.setWrapText(true);
        killSwitchButton.getStyleClass().add("btn-warning");
        Messages.configureAccessibleControl(killSwitchButton,
                Messages.get("tunnel.button.enableKillSwitch"),
                Messages.get("tunnel.tooltip.killSwitch"));
        killSwitchButton.setOnAction(_ -> {
            KillSwitchManager ks = engine.getKillSwitchManager();
            if (ks == null) return;
            if (ks.getState() == KillSwitchManager.State.DISABLED) {
                ks.enable();
                appendStateMessage("Kill Switch ENABLED by user");
            } else {
                String uname = engine.getUsername() != null ? engine.getUsername() : "client";
                ks.disable(uname, "Manually disengaged by user");
                appendStateMessage("Kill Switch DISABLED by user");
            }
            refreshControls();
        });
        ksCard.getChildren().addAll(kTitle, killSwitchPill, ksDesc, killSwitchButton);

        // Card 3: DNS Leak Guard & Auto-Reconnect
        VBox dnsCard = new VBox(8);
        dnsCard.getStyleClass().add("card");
        Label dTitle = new Label(Messages.get("tunnel.card.dns"));
        dTitle.getStyleClass().add("kpi-label");
        dnsGuardPill.getStyleClass().addAll("pill", "pill-success");
        autoReconnectCheck.setSelected(engine.getAutoReconnectManager() != null && engine.getAutoReconnectManager().isEnabled());
        Messages.configureAccessibleControl(autoReconnectCheck, Messages.get("tunnel.check.autoReconnect"), null);
        autoReconnectCheck.setOnAction(_ -> {
            boolean en = autoReconnectCheck.isSelected();
            engine.setAutoReconnect(en);
            appendStateMessage("Auto-reconnect set to " + (en ? "ENABLED" : "DISABLED"));
        });
        serverFpLabel.getStyleClass().addAll("muted-label", "mono-text");
        serverFpLabel.setWrapText(true);
        dnsCard.getChildren().addAll(dTitle, dnsGuardPill, autoReconnectCheck, serverFpLabel);

        controlsGrid.add(tunnelCard, 0, 0);
        controlsGrid.add(ksCard, 1, 0);
        controlsGrid.add(dnsCard, 2, 0);

        // Telemetry Sniffer Console
        VBox consoleCard = new VBox(10);
        consoleCard.getStyleClass().add("card");
        VBox.setVgrow(consoleCard, Priority.ALWAYS);

        HBox consoleBar = new HBox(10);
        consoleBar.setAlignment(Pos.CENTER_LEFT);
        Label cTitle = new Label(Messages.get("tunnel.sniffer.title"));
        cTitle.getStyleClass().add("section-title");
        Region cSpacer = new Region();
        HBox.setHgrow(cSpacer, Priority.ALWAYS);
        Button copyLogButton = new Button(Messages.get("tunnel.button.copyLog"));
        copyLogButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(copyLogButton,
                Messages.get("tunnel.button.copyLog"),
                Messages.get("tunnel.tooltip.copyLog"));
        copyLogButton.setOnAction(_ -> UiSafe.copyToClipboard(telemetryConsole.getText()));
        Button clearLogButton = new Button(Messages.get("tunnel.button.clearLog"));
        clearLogButton.getStyleClass().add("btn-danger");
        Messages.configureAccessibleControl(clearLogButton,
                Messages.get("tunnel.button.clearLog"),
                Messages.get("tunnel.tooltip.clearLog"));
        clearLogButton.setOnAction(_ -> {
            lineBuffer.clear();
            telemetryConsole.clear();
        });
        consoleBar.getChildren().addAll(cTitle, cSpacer, copyLogButton, clearLogButton);

        telemetryConsole.setEditable(false);
        telemetryConsole.setWrapText(false);
        telemetryConsole.getStyleClass().add("console-area");
        VBox.setVgrow(telemetryConsole, Priority.ALWAYS);

        consoleCard.getChildren().addAll(consoleBar, telemetryConsole);

        getChildren().addAll(header, controlsGrid, consoleCard);
    }

    private void attachKillSwitchListener() {
        KillSwitchManager ks = engine.getKillSwitchManager();
        if (ks == null) return;
        this.ksListener = (newState, reason) -> UiSafe.runOnFxThread(() -> {
            refreshControls();
            appendStateMessage("Kill Switch -> " + newState + " (" + UiSafe.text(reason, 128) + ")");
        });
        ks.addListener(this.ksListener);
    }

    public void dispose() {
        KillSwitchManager ks = engine.getKillSwitchManager();
        if (ks != null && ksListener != null) {
            ks.removeListener(ksListener);
        }
    }

    public void refreshControls() {
        TunnelManager tm = engine.getTunnelManager();
        if (tm != null) {
            tunnelModePill.setText("MODE: " + tm.getMode().name());
            tunnelModePill.getStyleClass().removeAll("pill-info", "pill-warning");
            tunnelModePill.getStyleClass().add(tm.getMode() == TunnelManager.TunnelMode.FULL ? "pill-warning" : "pill-info");
            String nextModeLabel = tm.getMode() == TunnelManager.TunnelMode.FULL
                    ? Messages.get("tunnel.button.switchSplit")
                    : Messages.get("tunnel.button.switchFull");
            switchTunnelModeButton.setText(nextModeLabel);
            switchTunnelModeButton.setAccessibleText(nextModeLabel);
            routesInfoLabel.setText("Office Routes: " + String.join(", ", tm.getOfficeRoutes()));
        }

        KillSwitchManager ks = engine.getKillSwitchManager();
        if (ks != null) {
            KillSwitchManager.State st = ks.getState();
            killSwitchPill.setText("STATE: " + st.name());
            killSwitchPill.getStyleClass().removeAll("pill-success", "pill-danger", "pill-muted");
            killSwitchPill.getStyleClass().add(switch (st) {
                case ENABLED -> "pill-success";
                case BLOCKING -> "pill-danger";
                case DISABLED -> "pill-muted";
            });
            String nextKsLabel = st == KillSwitchManager.State.DISABLED
                    ? Messages.get("tunnel.button.enableKillSwitch")
                    : Messages.get("tunnel.button.disableKillSwitch");
            killSwitchButton.setText(nextKsLabel);
            killSwitchButton.setAccessibleText(nextKsLabel);
        }

        dnsGuardPill.setText(UiSafe.text(engine.getDnsStatus(), 64));
        String fp = engine.getServerFingerprint();
        serverFpLabel.setText("Pinned Gateway FP: " + (fp != null && fp.length() > 24 ? fp.substring(0, 24) + "..." : fp));
    }

    public void appendPacketSniffer(VpnPacket packet, String direction) {
        if (packet == null) return;
        byte[] enc = packet.getEncryptedPayload();
        int len = enc != null ? enc.length : 0;
        appendLine(String.format("[%s] [%-8s] %-22s | seq=%d | %d B encrypted",
                TIME_FMT.format(Instant.now()),
                direction,
                packet.getType(),
                packet.getSequenceNumber(),
                len));
    }

    public void appendStateMessage(String msg) {
        appendLine("[" + TIME_FMT.format(Instant.now()) + "] [STATE] " + UiSafe.text(msg, 256));
    }

    private void appendLine(String line) {
        UiSafe.runOnFxThread(() -> {
            if (lineBuffer.size() >= MAX_CONSOLE_LINES) {
                lineBuffer.removeFirst();
            }
            lineBuffer.addLast(line);
            telemetryConsole.appendText(line + "\n");
            telemetryConsole.positionCaret(telemetryConsole.getLength());
        });
    }
}
