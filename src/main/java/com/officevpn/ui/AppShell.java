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
import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.ConnectionState;
import com.officevpn.ui.service.VpnModels.GatewayNode;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCodeCombination;
import javafx.scene.input.KeyCombination;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.RowConstraints;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.stage.Screen;
import org.kordamp.ikonli.feather.Feather;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Primary Ivory Atelier workspace shell unifying the client and administrative VPN suite.
 * <p>
 * Features a warm sand left navigation rail (Home, Gateways, Modes, Access, Admin, Logs, Settings)
 * with a spring-animated sliding marigold indicator, a Ctrl+K fuzzy CommandPalette overlay,
 * paper-slip Toasts, and an intentionally asymmetrical bento Home composition.
 */
public final class AppShell extends StackPane {

    public enum Section {
        HOME("Home", Feather.HOME),
        GATEWAYS("Gateways", Feather.MAP),
        MODES("Modes", Feather.LAYERS),
        ACCESS("Access", Feather.SLIDERS),
        ADMIN("Admin", Feather.USERS),
        LOGS("Logs", Feather.FILE_TEXT),
        SETTINGS("Settings", Feather.SETTINGS);

        private final String label;
        private final Feather icon;

        Section(String label, Feather icon) {
            this.label = label;
            this.icon = icon;
        }

        public String label() { return label; }
        public Feather icon() { return icon; }
    }

    private static final KeyCombination CTRL_K = new KeyCodeCombination(KeyCode.K, KeyCombination.CONTROL_DOWN);

    private final VpnClientService service;
    private final BorderPane chrome = new BorderPane();
    private final StackPane contentHost = new StackPane();
    private final Toasts toasts = new Toasts();
    private StackPane paletteOverlay;

    private final ObjectProperty<Section> activeSection = new SimpleObjectProperty<>(Section.HOME);
    private final Map<Section, Button> navButtons = new LinkedHashMap<>();
    private final Map<Section, Node> views = new LinkedHashMap<>();
    private final Region slidingIndicator = new Region();
    private final TrayFlyout trayFlyout = new TrayFlyout();

    private Timeline indicatorAnim;

    public AppShell(VpnClientService service) {
        this.service = service;
        setStyle("-fx-background-color: " + Tokens.CANVAS_HEX + ";");
        setMinSize(920, 620);

        VBox rail = buildNavigationRail();
        chrome.setLeft(rail);
        chrome.setCenter(contentHost);
        contentHost.setStyle("-fx-background-color: " + Tokens.CANVAS_HEX + ";");

        buildAllViews();

        getChildren().addAll(chrome, toasts);

        addEventFilter(KeyEvent.KEY_PRESSED, e -> {
            if (CTRL_K.match(e)) {
                openCommandPalette();
                e.consume();
            }
        });

        switchTo(Section.HOME);
    }

    public VpnClientService getService() {
        return service;
    }

    public Section getActiveSection() {
        return activeSection.get();
    }

    public void switchTo(Section section) {
        activeSection.set(section);
        Node view = views.get(section);
        if (view != null) {
            contentHost.getChildren().setAll(view);
            Motion.staggerEnter(List.of(view), Motion.FAST);
        }
        updateNavHighlights(section);
    }

    public void pushToast(Toasts.Severity severity, String title, String message) {
        toasts.push(severity, title, message);
    }

    public void openCommandPalette() {
        if (paletteOverlay != null && getChildren().contains(paletteOverlay)) {
            closeCommandPalette();
            return;
        }
        paletteOverlay = GatewayShelf.createCommandPaletteOverlay(
                service,
                tabName -> {
                    for (Section s : Section.values()) {
                        if (s.label().equalsIgnoreCase(tabName)) {
                            switchTo(s);
                            break;
                        }
                    }
                },
                this::closeCommandPalette
        );
        getChildren().add(paletteOverlay);
        GatewayShelf.focusCommandPalette(paletteOverlay);
    }

    public void closeCommandPalette() {
        if (paletteOverlay != null) {
            getChildren().remove(paletteOverlay);
            paletteOverlay = null;
        }
    }

    public TrayFlyout getTrayFlyout() {
        return trayFlyout;
    }

    private VBox buildNavigationRail() {
        VBox rail = new VBox(12);
        rail.getStyleClass().add("app-shell-rail");
        rail.setPadding(new Insets(18, 12, 16, 12));
        rail.setMinWidth(198);
        rail.setPrefWidth(206);
        rail.setMaxWidth(214);

        Label brand = new Label("Ivory Atelier");
        brand.getStyleClass().add("ia-display-md");
        Label subtitle = new Label("OFFICE VPN SUITE");
        subtitle.getStyleClass().add("ia-section-label");
        VBox brandBox = new VBox(2, brand, subtitle);
        brandBox.setPadding(new Insets(0, 6, 6, 6));

        // Nav stack + sliding marigold indicator bar in left gutter
        VBox buttonsList = new VBox(4);
        for (Section s : Section.values()) {
            Button btn = new Button(s.label(), Icons.soft(s.icon(), 15));
            btn.getStyleClass().add("rail-nav-btn");
            btn.setMaxWidth(Double.MAX_VALUE);
            btn.setGraphicTextGap(10);
            btn.setOnAction(e -> switchTo(s));
            navButtons.put(s, btn);
            buttonsList.getChildren().add(btn);
        }

        slidingIndicator.setManaged(false);
        slidingIndicator.setPrefSize(4, 24);
        slidingIndicator.setStyle("-fx-background-color: " + Tokens.MARIGOLD_HEX + "; -fx-background-radius: 999px;");

        Pane indicatorGutter = new Pane(slidingIndicator);
        indicatorGutter.setMinWidth(6);
        indicatorGutter.setMaxWidth(6);

        HBox navWrapper = new HBox(4, indicatorGutter, buttonsList);
        HBox.setHgrow(buttonsList, Priority.ALWAYS);

        Region spacer = new Region();
        VBox.setVgrow(spacer, Priority.ALWAYS);

        // Quick Ctrl+K button & status footer chip
        Button cmdBtn = new Button("Quick Command", Icons.ink(Feather.COMMAND, 13));
        cmdBtn.getStyleClass().add("ia-pill-sand");
        cmdBtn.setMaxWidth(Double.MAX_VALUE);
        cmdBtn.setOnAction(e -> openCommandPalette());
        Label shortcutHint = new Label("Ctrl+K");
        shortcutHint.getStyleClass().add("ia-mono-soft");
        HBox cmdMeta = new HBox(6, cmdBtn, shortcutHint);
        cmdMeta.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(cmdBtn, Priority.ALWAYS);

        Label statusChip = new Label("Disconnected");
        statusChip.getStyleClass().addAll("ia-pill", "ia-pill-sand");
        statusChip.setMaxWidth(Double.MAX_VALUE);
        Label vipChip = new Label("VIP " + service.virtualIpProperty().get());
        vipChip.getStyleClass().add("ia-mono-soft");

        service.connectionStateProperty().addListener((obs, o, n) -> syncFooterChip(statusChip, vipChip, n));
        service.selectedGatewayProperty().addListener((obs, o, n) -> syncFooterChip(statusChip, vipChip, service.connectionStateProperty().get()));
        syncFooterChip(statusChip, vipChip, service.connectionStateProperty().get());

        VBox statusCard = new VBox(5, statusChip, vipChip);
        statusCard.getStyleClass().add("ia-card-paper");
        statusCard.setPadding(new Insets(10));

        rail.getChildren().addAll(brandBox, navWrapper, spacer, cmdBtn, statusCard);
        return rail;
    }

    private void syncFooterChip(Label statusChip, Label vipChip, ConnectionState st) {
        statusChip.getStyleClass().removeAll("ia-pill-peacock", "ia-pill-marigold", "ia-pill-coral", "ia-pill-lilac", "ia-pill-sand");
        if (st == ConnectionState.CONNECTED) {
            GatewayNode gw = service.selectedGatewayProperty().get();
            statusChip.setText("Live • " + (gw != null ? gw.countryCode() : "HQ"));
            statusChip.getStyleClass().add("ia-pill-peacock");
        } else if (st == ConnectionState.BLOCKED_BY_KILL_SWITCH) {
            statusChip.setText("Kill Switch Locked");
            statusChip.getStyleClass().add("ia-pill-coral");
        } else if (st == ConnectionState.CONNECTING || st == ConnectionState.HANDSHAKING) {
            statusChip.setText(st.title() + "...");
            statusChip.getStyleClass().add("ia-pill-marigold");
        } else {
            statusChip.setText(st != null ? st.title() : "Disconnected");
            statusChip.getStyleClass().add("ia-pill-sand");
        }
        vipChip.setText("VIP " + service.virtualIpProperty().get());
    }

    private void updateNavHighlights(Section active) {
        navButtons.forEach((sec, btn) -> {
            btn.getStyleClass().remove("rail-nav-btn-active");
            btn.setGraphic(Icons.soft(sec.icon(), 15));
            if (sec == active) {
                btn.getStyleClass().add("rail-nav-btn-active");
                btn.setGraphic(Icons.ink(sec.icon(), 15));
            }
        });
        int idx = active.ordinal();
        double targetY = idx * 39.0 + 7.0;
        if (Motion.isReduceMotion()) {
            slidingIndicator.resizeRelocate(1, targetY, 4, 24);
        } else {
            if (indicatorAnim != null) indicatorAnim.stop();
            slidingIndicator.setLayoutX(1);
            slidingIndicator.setPrefSize(4, 24);
            indicatorAnim = new Timeline(new KeyFrame(Motion.FAST,
                    new KeyValue(slidingIndicator.layoutYProperty(), targetY, Motion.spring())));
            indicatorAnim.play();
        }
    }

    private void buildAllViews() {
        views.put(Section.HOME, buildHomeBentoView());
        views.put(Section.GATEWAYS, wrapScroll("Gateway Directory", "Branch edges with live load vials, fuzzy search, and favorites.", buildGatewaysView()));
        views.put(Section.MODES, wrapScroll("Work Modes", "Switch routing swatches, pin priority profiles, and configure Connect-and-Go.", buildModesView()));
        views.put(Section.ACCESS, wrapScroll("Access & Safety Latches", "Mechanical egress protection latches and drag-and-drop SplitLanes routing.", buildAccessView()));
        views.put(Section.ADMIN, wrapScroll("Administration & Zero-Trust Roster", "Connected employee presence, Slide-to-Revoke governance, and 6-digit MFA card.", buildAdminView()));
        views.put(Section.LOGS, wrapScroll("Forensic Audit Thread", "Tamper-evident chronological event thread grouped by day.", buildLogsView()));
        views.put(Section.SETTINGS, wrapScroll("Atelier Preferences & Diagnostics", "Accessibility motion controls, taskbar tray integration, and DPI scaling.", buildSettingsView()));
    }

    /**
     * Builds the Home bento composition with deliberately asymmetric column weights (57% / 43%)
     * and non-uniform card proportions composing KeycardGate, OfficeAtlas, PulseRibbon, PostureSeal,
     * and the dynamic HandshakeLoom strip.
     */
    private Node buildHomeBentoView() {
        VBox page = new VBox(14);
        page.setPadding(new Insets(18, 22, 18, 22));
        page.setStyle("-fx-background-color: " + Tokens.CANVAS_HEX + ";");

        Label heading = new Label("Corporate Access Atelier");
        heading.getStyleClass().add("ia-display-lg");
        Label caption = new Label();
        caption.textProperty().bind(service.statusCaptionProperty());
        caption.getStyleClass().add("ia-subtitle");

        Button simulateFailBtn = new Button("Test Fault Loom");
        simulateFailBtn.setGraphic(Icons.coral(Feather.ALERT_CIRCLE, 13));
        simulateFailBtn.setOnAction(e -> {
            service.simulateHandshakeFailure();
            pushToast(Toasts.Severity.WARNING, "Simulated Fault", "HandshakeLoom will pause at station 3 with Retry.");
        });

        Button killBtn = new Button("Trip Kill Switch");
        killBtn.getStyleClass().add("ia-btn-coral");
        killBtn.setOnAction(e -> {
            if (service instanceof MockVpnService mock) {
                mock.triggerKillSwitchBlock();
            } else {
                service.killSwitchEnabledProperty().set(true);
            }
            pushToast(Toasts.Severity.ERROR, "Kill Switch Active", "Non-tunnel egress sealed cleanly.");
        });

        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);
        HBox topRow = new HBox(10, new VBox(2, heading, caption), sp, simulateFailBtn, killBtn);
        topRow.setAlignment(Pos.CENTER_LEFT);

        HandshakeLoom loom = new HandshakeLoom();
        loom.bindService(service);
        loom.setMinWidth(0);

        KeycardGate gate = new KeycardGate();
        gate.bindService(service);
        StackPane gateCard = Tokens.wrapPaperCard(gate, true);
        gateCard.setMinWidth(0);

        OfficeAtlas atlas = new OfficeAtlas();
        atlas.bindService(service);
        StackPane atlasCard = Tokens.wrapPaperCard(atlas, false);
        atlasCard.setMinWidth(0);
        VBox.setVgrow(atlasCard, Priority.ALWAYS);

        PulseRibbon ribbon = new PulseRibbon();
        ribbon.bindService(service);
        StackPane ribbonCard = Tokens.wrapPaperCard(ribbon, false);
        ribbonCard.setMinWidth(0);

        PostureSeal posture = new PostureSeal();
        posture.bindService(service);
        StackPane postureCard = Tokens.wrapPaperCard(posture, true);
        postureCard.setMinWidth(0);
        VBox.setVgrow(postureCard, Priority.ALWAYS);

        // Deliberately asymmetrical Bento GridPane: 56% Left / 44% Right on >= 880px viewport,
        // collapsing smoothly to vertical stacked bento at compact widths like 960x640
        GridPane bento = new GridPane();
        bento.setHgap(16);
        bento.setVgap(16);
        ColumnConstraints leftCol = new ColumnConstraints();
        leftCol.setPercentWidth(56.0);
        ColumnConstraints rightCol = new ColumnConstraints();
        rightCol.setPercentWidth(44.0);
        bento.getColumnConstraints().setAll(leftCol, rightCol);

        VBox leftColumn = new VBox(16);
        leftColumn.setMinWidth(0);
        VBox rightColumn = new VBox(16);
        rightColumn.setMinWidth(0);
        GridPane.setVgrow(leftColumn, Priority.ALWAYS);
        GridPane.setVgrow(rightColumn, Priority.ALWAYS);
        RowConstraints fullRow = new RowConstraints();
        fullRow.setVgrow(Priority.ALWAYS);
        bento.getRowConstraints().add(fullRow);

        StackPane bentoHost = new StackPane();
        VBox.setVgrow(bentoHost, Priority.ALWAYS);

        VBox compactStack = new VBox(14);

        page.getChildren().addAll(topRow, loom, bentoHost);

        ScrollPane sc = new ScrollPane(page);
        sc.setFitToWidth(true);
        sc.setFitToHeight(false);

        Runnable applyResponsiveBento = () -> {
            double vw = sc.getWidth();
            boolean compact = vw > 0 && vw < 860.0;
            leftColumn.getChildren().clear();
            rightColumn.getChildren().clear();
            bento.getChildren().clear();
            compactStack.getChildren().clear();
            if (compact) {
                compactStack.getChildren().setAll(gateCard, ribbonCard, atlasCard, postureCard);
                bentoHost.getChildren().setAll(compactStack);
            } else {
                leftColumn.getChildren().setAll(gateCard, atlasCard);
                rightColumn.getChildren().setAll(ribbonCard, postureCard);
                bento.add(leftColumn, 0, 0);
                bento.add(rightColumn, 1, 0);
                bentoHost.getChildren().setAll(bento);
            }
        };
        sc.widthProperty().addListener((obs, o, n) -> applyResponsiveBento.run());
        applyResponsiveBento.run();
        return sc;
    }

    private Node buildGatewaysView() {
        GatewayShelf shelf = new GatewayShelf();
        shelf.bindService(service);
        shelf.onOpenCommandPaletteProperty().set(this::openCommandPalette);
        return shelf;
    }

    private Node buildModesView() {
        WorkModes modes = new WorkModes();
        modes.bindService(service, msg -> pushToast(Toasts.Severity.SUCCESS, "Connect & Go", msg));
        return modes;
    }

    private Node buildAccessView() {
        SafetyLatches latches = new SafetyLatches();
        latches.bindService(service);
        HandshakeLoom loom = new HandshakeLoom();
        loom.bindService(service);
        return new VBox(16, Tokens.wrapPaperCard(loom, false), latches);
    }

    private Node buildAdminView() {
        LiveRoster roster = new LiveRoster();
        roster.bindService(service, msg -> pushToast(Toasts.Severity.INFO, "Roster Governance", msg));
        roster.setMinWidth(0);

        SignInCard signIn = new SignInCard();
        signIn.bindService(service, msg -> pushToast(Toasts.Severity.SUCCESS, "Authentication", msg));
        signIn.setMinWidth(320);
        signIn.setPrefWidth(350);
        signIn.setMaxWidth(365);

        HBox row = new HBox(16, roster, signIn);
        HBox.setHgrow(roster, Priority.ALWAYS);
        return row;
    }

    private Node buildLogsView() {
        AuditThread thread = new AuditThread();
        thread.bindService(service, msg -> pushToast(Toasts.Severity.SUCCESS, "Audit Ledger", msg));
        return thread;
    }

    private Node buildSettingsView() {
        CheckBox reduceMotion = new CheckBox("Reduce Motion (pause springs, shimmer, and flowing tunnel sweeps)");
        reduceMotion.setFont(Fonts.uiMedium(13));
        reduceMotion.selectedProperty().bindBidirectional(Motion.reduceMotionProperty());

        Button openTrayBtn = new Button("Open TrayFlyout Mini-Panel", Icons.peacock(Feather.SIDEBAR, 14));
        openTrayBtn.getStyleClass().add("ia-btn-peacock");
        openTrayBtn.setOnAction(e -> trayFlyout.showFlyout(service, this::requestFocus, () -> {}));

        Button toastTestBtn = new Button("Test Paper Toast Slip", Icons.ink(Feather.BELL, 14));
        toastTestBtn.getStyleClass().add("ia-btn-marigold");
        toastTestBtn.setOnAction(e -> pushToast(Toasts.Severity.SUCCESS,
                "Ivory Atelier Notice", "Layered paper slip notifications pause auto-hide on hover."));

        Screen primary = Screen.getPrimary();
        Label dpiInfo = new Label(String.format("Detected OS Scale: %.0f%% (OutputScale %.2fx) • Bundled Fonts: Fraunces + Manrope + JetBrains Mono (OFL)",
                primary.getOutputScaleX() * 100.0, primary.getOutputScaleX()));
        dpiInfo.getStyleClass().add("ia-mono-soft");

        HBox btns = new HBox(10, openTrayBtn, toastTestBtn);
        VBox cardContent = new VBox(14, reduceMotion, btns, dpiInfo);
        cardContent.setPadding(new Insets(18));
        return Tokens.wrapPaperCard(cardContent, true);
    }

    private ScrollPane wrapScroll(String title, String subtitle, Node inner) {
        Label h = new Label(title);
        h.getStyleClass().add("ia-display-lg");
        Label s = new Label(subtitle);
        s.getStyleClass().add("ia-subtitle");

        VBox page = new VBox(16, new VBox(2, h, s), inner);
        page.setPadding(new Insets(20, 24, 24, 24));
        page.setStyle("-fx-background-color: " + Tokens.CANVAS_HEX + ";");

        ScrollPane sc = new ScrollPane(page);
        sc.setFitToWidth(true);
        return sc;
    }
}
