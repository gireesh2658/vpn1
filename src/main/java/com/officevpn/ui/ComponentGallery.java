package com.officevpn.ui;

import com.officevpn.ui.components.AuditThread;
import com.officevpn.ui.components.GatewayShelf;
import com.officevpn.ui.components.HandshakeLoom;
import com.officevpn.ui.components.KeycardGate;
import com.officevpn.ui.components.LiveRoster;
import com.officevpn.ui.components.OfficeAtlas;
import com.officevpn.ui.components.PostureSeal;
import com.officevpn.ui.components.PulseRibbon;
import com.officevpn.ui.components.SafetyLatches;
import com.officevpn.ui.components.SignInCard;
import com.officevpn.ui.components.Toasts;
import com.officevpn.ui.components.TrayFlyout;
import com.officevpn.ui.components.WorkModes;
import com.officevpn.ui.service.MockVpnService;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.IvoryTheme;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.kordamp.ikonli.feather.Feather;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Interactive standalone showcase of every Ivory Atelier component and screen in isolation
 * with live state switchers, full keyboard navigation, and direct preview export.
 * <p>
 * Separate non-{@link Application} launcher ensures direct execution from the shaded JAR on Java 25.
 */
public final class ComponentGallery {

    private ComponentGallery() {
    }

    public static void main(String[] args) {
        Application.launch(GalleryApp.class, args);
    }

    public static final class GalleryApp extends Application {
        private MockVpnService service;
        private Stage shellStage;

        @Override
        public void start(Stage primaryStage) {
        IvoryTheme.installBase();
        service = new MockVpnService(false);

        BorderPane layout = new BorderPane();
        layout.setStyle("-fx-background-color: " + Tokens.CANVAS_HEX + ";");

        VBox sidebar = new VBox(6);
        sidebar.getStyleClass().add("app-shell-rail");
        sidebar.setPadding(new Insets(16, 12, 16, 12));
        sidebar.setMinWidth(220);
        sidebar.setPrefWidth(226);

        Label brand = new Label("Ivory Atelier");
        brand.getStyleClass().add("ia-display-md");
        Label sub = new Label("COMPONENT GALLERY");
        sub.getStyleClass().add("ia-section-label");

        StackPane stageCanvas = new StackPane();
        stageCanvas.setPadding(new Insets(22));
        stageCanvas.setStyle("-fx-background-color: " + Tokens.CANVAS_HEX + ";");

        ScrollPane stageScroll = new ScrollPane(stageCanvas);
        stageScroll.setFitToWidth(true);

        // State switcher bar at top
        HBox stateBar = buildStateSwitcherBar(primaryStage, stageCanvas);

        Map<String, Node> entries = buildEntries();
        SignInCard signInInstance = (SignInCard) entries.get("SignInCard");

        Button errShakeBtn = new Button("Trigger OTP Error");
        errShakeBtn.getStyleClass().add("ia-btn-coral");
        errShakeBtn.setOnAction(e -> signInInstance.showErrorShake("Invalid authenticator code — try 123456"));
        stateBar.getChildren().add(errShakeBtn);

        VBox navList = new VBox(4);
        Map<String, Button> navBtns = new LinkedHashMap<>();
        for (var entry : entries.entrySet()) {
            Button b = new Button(entry.getKey());
            b.getStyleClass().add("rail-nav-btn");
            b.setMaxWidth(Double.MAX_VALUE);
            b.setOnAction(e -> {
                navBtns.values().forEach(x -> x.getStyleClass().remove("rail-nav-btn-active"));
                b.getStyleClass().add("rail-nav-btn-active");
                stageCanvas.getChildren().setAll(entry.getValue());
            });
            navBtns.put(entry.getKey(), b);
            navList.getChildren().add(b);
        }

        ScrollPane navScroll = new ScrollPane(navList);
        navScroll.setFitToWidth(true);
        VBox.setVgrow(navScroll, Priority.ALWAYS);

        Button launchShellBtn = new Button("Launch Full AppShell", Icons.ink(Feather.LAYOUT, 14));
        launchShellBtn.getStyleClass().add("ia-btn-marigold");
        launchShellBtn.setMaxWidth(Double.MAX_VALUE);
        launchShellBtn.setOnAction(e -> openAppShellWindow());

        sidebar.getChildren().addAll(new VBox(2, brand, sub), navScroll, launchShellBtn);

        VBox centerCol = new VBox(stateBar, stageScroll);
        VBox.setVgrow(stageScroll, Priority.ALWAYS);

        layout.setLeft(sidebar);
        layout.setCenter(centerCol);

        // Select KeycardGate initially
        Button first = navBtns.get("KeycardGate");
        if (first != null) first.fire();

        Scene scene = new Scene(layout, 1280, 820);
        IvoryTheme.apply(scene);
        primaryStage.setTitle("Ivory Atelier — Office VPN Component Gallery");
        primaryStage.setMinWidth(960);
        primaryStage.setMinHeight(640);
        primaryStage.setScene(scene);
        primaryStage.setOnCloseRequest(e -> shutdown());
        primaryStage.show();
    }

    private HBox buildStateSwitcherBar(Stage primaryStage, StackPane stageCanvas) {
        Label lbl = new Label("State:");
        lbl.getStyleClass().add("ia-section-label");

        Button bDisc = new Button("Disconnected");
        bDisc.setOnAction(e -> service.disconnect());

        Button bConn = new Button("Connected");
        bConn.getStyleClass().add("ia-btn-peacock");
        bConn.setOnAction(e -> service.connect());

        Button bFail = new Button("Fault Loom");
        bFail.getStyleClass().add("ia-btn-coral");
        bFail.setOnAction(e -> service.simulateHandshakeFailure());

        Button bKill = new Button("Kill Switch Block");
        bKill.getStyleClass().add("ia-btn-coral");
        bKill.setOnAction(e -> service.triggerKillSwitchBlock());

        Button bShimmer = new Button("Audit Shimmer");
        bShimmer.setOnAction(e -> service.refreshAuditLog());

        Button bExport = new Button("Export PNGs", Icons.ink(Feather.CAMERA, 13));
        bExport.getStyleClass().add("ia-btn-marigold");
        bExport.setOnAction(e -> {
            try {
                int count = PreviewExporter.exportAll(Path.of("docs/ui-previews"));
                bExport.setText("Exported " + count + " PNGs");
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        });

        CheckBox reduceMotion = new CheckBox("Reduce Motion");
        reduceMotion.setFont(Fonts.uiMedium(12));
        reduceMotion.selectedProperty().bindBidirectional(Motion.reduceMotionProperty());

        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);

        HBox bar = new HBox(8, lbl, bDisc, bConn, bFail, bKill, bShimmer, reduceMotion, sp, bExport);
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.setPadding(new Insets(12, 18, 12, 18));
        bar.setStyle("-fx-background-color: #FFFFFF; -fx-border-color: transparent transparent #E6DCC6 transparent; -fx-border-width: 0 0 1px 0;");
        return bar;
    }

    private Map<String, Node> buildEntries() {
        Map<String, Node> map = new LinkedHashMap<>();
        map.put("KeycardGate", KeycardGate.createStandaloneDemo(service));
        map.put("HandshakeLoom", HandshakeLoom.createStandaloneDemo(service));
        map.put("OfficeAtlas", OfficeAtlas.createStandaloneDemo(service));
        map.put("PulseRibbon", PulseRibbon.createStandaloneDemo(service));
        map.put("GatewayShelf", GatewayShelf.createStandaloneDemo(service));
        map.put("WorkModes", WorkModes.createStandaloneDemo(service));
        map.put("SafetyLatches & SplitLanes", SafetyLatches.createStandaloneDemo(service));
        map.put("PostureSeal", PostureSeal.createStandaloneDemo(service));
        map.put("LiveRoster & SessionTable", LiveRoster.createStandaloneDemo(service));
        map.put("AuditThread", AuditThread.createStandaloneDemo(service));
        map.put("SignInCard", SignInCard.createStandaloneDemo(service));
        map.put("Toasts", Toasts.createStandaloneDemo());
        map.put("TrayFlyout", TrayFlyout.createStandaloneDemo(service));
        return map;
    }

    private void openAppShellWindow() {
        if (shellStage != null && shellStage.isShowing()) {
            shellStage.toFront();
            return;
        }
        AppShell shell = new AppShell(service);
        Scene sc = new Scene(shell, 1280, 820);
        IvoryTheme.apply(sc);
        shellStage = new Stage();
        shellStage.setTitle("Office VPN — Ivory Atelier AppShell");
        shellStage.setMinWidth(960);
        shellStage.setMinHeight(640);
        shellStage.setScene(sc);
        shellStage.show();
    }

    private void shutdown() {
        if (shellStage != null) {
            shellStage.close();
        }
        if (service != null) {
            service.close();
        }
        Platform.exit();
    }

        @Override
        public void stop() {
            if (service != null) {
                service.close();
            }
        }
    }
}
