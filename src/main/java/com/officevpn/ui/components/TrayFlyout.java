package com.officevpn.ui.components;

import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.ConnectionState;
import com.officevpn.ui.service.VpnModels.GatewayNode;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.FxPngWriter;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.IvoryTheme;
import com.officevpn.ui.theme.Tokens;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.geometry.Rectangle2D;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.SnapshotParameters;
import javafx.scene.canvas.Canvas;
import javafx.scene.canvas.GraphicsContext;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.image.WritableImage;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;
import javafx.stage.Screen;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import org.kordamp.ikonli.feather.Feather;

import java.awt.GraphicsEnvironment;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.Toolkit;
import java.awt.TrayIcon;
import java.io.IOException;

/**
 * TrayFlyout provides a compact taskbar mini-panel anchored to the Windows notification area
 * via {@link java.awt.SystemTray} with {@code Platform.setImplicitExit(false)} and a
 * {@link StageStyle#TRANSPARENT} undecorated stage used solely for crisp rounded corners
 * over an opaque solid light paper surface ({@code #FFFFFF}).
 */
public final class TrayFlyout {

    private Stage flyoutStage;
    private TrayIcon trayIcon;

    /**
     * Installs Windows SystemTray integration safely (no-op in headless or unsupported sessions).
     */
    public boolean install(VpnClientService service, Runnable onOpenConsole, Runnable onQuitApp) {
        if (GraphicsEnvironment.isHeadless() || !SystemTray.isSupported()) {
            return false;
        }
        try {
            Platform.setImplicitExit(false);
            ensureFlyoutStage(service, onOpenConsole, onQuitApp);

            byte[] iconBytes = renderTrayShieldPng();
            java.awt.Image awtImg = Toolkit.getDefaultToolkit().createImage(iconBytes);

            PopupMenu menu = new PopupMenu();
            MenuItem toggleItem = new MenuItem("Toggle Quick Panel");
            toggleItem.addActionListener(e -> Platform.runLater(this::toggleFlyout));
            MenuItem openItem = new MenuItem("Open Office VPN Console");
            openItem.addActionListener(e -> Platform.runLater(onOpenConsole));
            MenuItem quitItem = new MenuItem("Quit Office VPN");
            quitItem.addActionListener(e -> Platform.runLater(() -> {
                uninstall();
                onQuitApp.run();
            }));
            menu.add(toggleItem);
            menu.add(openItem);
            menu.addSeparator();
            menu.add(quitItem);

            trayIcon = new TrayIcon(awtImg, "Office VPN — Ivory Atelier", menu);
            trayIcon.setImageAutoSize(true);
            trayIcon.addActionListener(e -> Platform.runLater(this::toggleFlyout));
            SystemTray.getSystemTray().add(trayIcon);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public void showFlyout(VpnClientService service, Runnable onOpenConsole, Runnable onQuitApp) {
        ensureFlyoutStage(service, onOpenConsole, onQuitApp);
        positionNearTaskbar(flyoutStage, 336, 268);
        flyoutStage.show();
        flyoutStage.toFront();
    }

    public void toggleFlyout() {
        if (flyoutStage == null) return;
        if (flyoutStage.isShowing()) {
            flyoutStage.hide();
        } else {
            positionNearTaskbar(flyoutStage, 336, 268);
            flyoutStage.show();
            flyoutStage.toFront();
        }
    }

    public void uninstall() {
        if (trayIcon != null && !GraphicsEnvironment.isHeadless() && SystemTray.isSupported()) {
            try {
                SystemTray.getSystemTray().remove(trayIcon);
            } catch (Exception ignored) {
            }
            trayIcon = null;
        }
        if (flyoutStage != null) {
            flyoutStage.close();
            flyoutStage = null;
        }
    }

    private void ensureFlyoutStage(VpnClientService service, Runnable onOpenConsole, Runnable onQuitApp) {
        if (flyoutStage != null) return;
        Stage stage = new Stage(StageStyle.TRANSPARENT);
        stage.setAlwaysOnTop(true);

        VBox content = createFlyoutContent(service, () -> {
            stage.hide();
            if (onOpenConsole != null) onOpenConsole.run();
        }, () -> {
            uninstall();
            if (onQuitApp != null) onQuitApp.run();
        });
        // Solid opaque rounded surface clipped cleanly for transparent-stage corner antialiasing
        Rectangle clip = new Rectangle(336, 268);
        clip.setArcWidth(32);
        clip.setArcHeight(32);
        content.setClip(clip);

        Scene scene = new Scene(content, 336, 268, Color.TRANSPARENT);
        IvoryTheme.apply(scene);
        stage.setScene(scene);
        stage.focusedProperty().addListener((obs, o, focused) -> {
            if (Boolean.FALSE.equals(focused)) stage.hide();
        });
        this.flyoutStage = stage;
    }

    /**
     * Builds the reusable light solid-paper TrayFlyout mini-panel UI for live tray popovers,
     * ComponentGallery inspection, and PreviewExporter snapshots.
     */
    public static VBox createFlyoutContent(VpnClientService service, Runnable onOpenConsole, Runnable onQuitApp) {
        VBox panel = new VBox(12);
        panel.getStyleClass().add("tray-flyout-surface");
        panel.setMinSize(324, 244);
        panel.setPrefSize(336, 264);

        Label brand = new Label("Office VPN");
        brand.getStyleClass().add("ia-display-md");
        Label statusPill = new Label();
        statusPill.getStyleClass().addAll("ia-pill", "ia-pill-sand");

        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);
        HBox hdr = new HBox(8, Icons.peacock(Feather.SHIELD, 16), brand, sp, statusPill);
        hdr.setAlignment(Pos.CENTER_LEFT);

        Label gwLbl = new Label();
        gwLbl.setFont(Fonts.uiSemiBold(13));
        gwLbl.setTextFill(Tokens.INK);
        Label ipLbl = new Label();
        ipLbl.getStyleClass().add("ia-mono-soft");
        VBox gwBox = new VBox(2, gwLbl, ipLbl);
        gwBox.setPadding(new Insets(9, 12, 9, 12));
        gwBox.getStyleClass().add("ia-card-sand");

        Label throughputLbl = new Label("↓ 0.0 Mbps   ↑ 0.0 Mbps   •   18 ms");
        throughputLbl.setFont(Fonts.monoMedium(11.5));
        throughputLbl.setTextFill(Tokens.INK);

        Button toggleBtn = new Button("Swipe Keycard");
        toggleBtn.getStyleClass().add("ia-btn-marigold");
        toggleBtn.setMaxWidth(Double.MAX_VALUE);

        Button openBtn = new Button("Open Console");
        openBtn.setGraphic(Icons.ink(Feather.EXTERNAL_LINK, 12));
        HBox.setHgrow(openBtn, Priority.ALWAYS);
        openBtn.setMaxWidth(Double.MAX_VALUE);
        openBtn.setOnAction(e -> {
            if (onOpenConsole != null) onOpenConsole.run();
        });

        Button quitBtn = new Button("Quit");
        quitBtn.getStyleClass().add("ia-btn-coral");
        quitBtn.setOnAction(e -> {
            if (onQuitApp != null) onQuitApp.run();
        });

        HBox footer = new HBox(8, openBtn, quitBtn);

        if (service != null) {
            Runnable refresh = () -> {
                ConnectionState st = service.connectionStateProperty().get();
                GatewayNode gw = service.selectedGatewayProperty().get();
                statusPill.getStyleClass().removeAll("ia-pill-peacock", "ia-pill-marigold", "ia-pill-coral", "ia-pill-sand");
                if (st == ConnectionState.CONNECTED) {
                    statusPill.setText("Connected");
                    statusPill.getStyleClass().add("ia-pill-peacock");
                    toggleBtn.setText("Disconnect Tunnel");
                    toggleBtn.getStyleClass().setAll("button", "ia-btn-peacock");
                } else if (st == ConnectionState.BLOCKED_BY_KILL_SWITCH) {
                    statusPill.setText("Blocked");
                    statusPill.getStyleClass().add("ia-pill-coral");
                    toggleBtn.setText("Reset Kill Switch");
                    toggleBtn.getStyleClass().setAll("button", "ia-btn-coral");
                } else {
                    statusPill.setText(st != null ? st.title() : "Disconnected");
                    statusPill.getStyleClass().add("ia-pill-sand");
                    toggleBtn.setText("Connect Keycard");
                    toggleBtn.getStyleClass().setAll("button", "ia-btn-marigold");
                }
                gwLbl.setText(gw != null ? gw.city() + " (" + gw.branch() + ")" : "No gateway selected");
                ipLbl.setText("VIP " + service.virtualIpProperty().get()
                        + (gw != null ? "  •  " + gw.hostname() : ""));
                throughputLbl.setText(String.format("↓ %.1f Mbps   ↑ %.1f Mbps   •   %d ms",
                        service.currentDownloadMbpsProperty().get(),
                        service.currentUploadMbpsProperty().get(),
                        service.currentLatencyMsProperty().get()));
            };
            service.connectionStateProperty().addListener((obs, o, n) -> refresh.run());
            service.selectedGatewayProperty().addListener((obs, o, n) -> refresh.run());
            service.currentDownloadMbpsProperty().addListener((obs, o, n) -> refresh.run());
            toggleBtn.setOnAction(e -> {
                if (service.connectionStateProperty().get() == ConnectionState.CONNECTED) {
                    service.disconnect();
                } else if (service.connectionStateProperty().get() == ConnectionState.BLOCKED_BY_KILL_SWITCH) {
                    service.clearKillSwitchBlock();
                } else {
                    service.connect();
                }
            });
            refresh.run();
        }

        panel.getChildren().addAll(hdr, gwBox, throughputLbl, toggleBtn, footer);
        return panel;
    }

    public static Node createStandaloneDemo(VpnClientService service) {
        return createFlyoutContent(service, () -> {}, () -> {});
    }

    private static void positionNearTaskbar(Stage stage, double w, double h) {
        Rectangle2D bounds = Screen.getPrimary().getVisualBounds();
        stage.setX(bounds.getMaxX() - w - 16);
        stage.setY(bounds.getMaxY() - h - 14);
    }

    private static byte[] renderTrayShieldPng() throws IOException {
        Canvas c = new Canvas(24, 24);
        GraphicsContext g = c.getGraphicsContext2D();
        g.setFill(Tokens.PEACOCK);
        g.fillRoundRect(2, 2, 20, 20, 8, 8);
        g.setFill(Tokens.MARIGOLD);
        g.fillOval(7, 7, 10, 10);
        g.setFill(Color.WHITE);
        g.fillOval(10, 10, 4, 4);

        SnapshotParameters sp = new SnapshotParameters();
        sp.setFill(Color.TRANSPARENT);
        WritableImage wi = c.snapshot(sp, null);
        return FxPngWriter.encode(wi);
    }
}

