package com.officevpn.ui;

import com.officevpn.admin.PasswordPolicy;
import com.officevpn.client.VpnClientEngine;
import com.officevpn.config.ConfigUtil;
import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import com.officevpn.gui.client.ChatPanel;
import com.officevpn.gui.client.ConnectionStatusPanel;
import com.officevpn.gui.client.FileVaultPanel;
import com.officevpn.gui.client.MyDevicesPanel;
import com.officevpn.protocol.VpnPacket;
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
import com.officevpn.ui.service.BackendVpnServiceAdapter;
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
import javafx.application.Platform;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextField;
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

import java.net.URL;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * Unified Ivory Atelier Office VPN workspace shell.
 * Combines gateway TOFU endpoint setup, Zero-Trust keycard + optional MFA sign-in,
 * live throughput/handshake telemetry, encrypted File Vault, secure intranet chat,
 * device posture &amp; MFA guidance, tunnel defenses, and real-time audit logs.
 */
public final class AppShell extends StackPane implements AutoCloseable {

    public enum Section {
        HOME("Home", Feather.HOME),
        VAULT("File Vault", Feather.FOLDER),
        CHAT("Secure Chat", Feather.MESSAGE_SQUARE),
        DEVICES("Devices & MFA", Feather.CPU),
        GATEWAYS("Gateways", Feather.MAP),
        MODES("Tunnel Modes", Feather.LAYERS),
        ACCESS("Safety & Sniffer", Feather.SLIDERS),
        ADMIN("Roster & Auth", Feather.USERS),
        LOGS("Activity Log", Feather.FILE_TEXT),
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
    private final BackendVpnServiceAdapter backend;
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

    // Integrated live client panels & listeners
    private FileVaultPanel fileVaultPanel;
    private ChatPanel chatPanel;
    private MyDevicesPanel myDevicesPanel;
    private ConnectionStatusPanel connectionStatusPanel;
    private VpnClientEngine.ClientEventListener liveClientListener;

    // Home dynamic auth / active-session swap state
    private final StackPane homeConnectionSlot = new StackPane();
    private VBox homeCredentialsPane;
    private VBox homeSessionPane;
    private Label homeSessionUserLabel;
    private Label homeSessionDeptLabel;
    private Label homeSessionVipLabel;
    private Label homeSessionFpLabel;
    private Label homeSessionPingLabel;

    public AppShell(VpnClientService service) {
        this.service = service;
        this.backend = (service instanceof BackendVpnServiceAdapter b) ? b : null;

        setStyle("-fx-background-color: " + Tokens.CANVAS_HEX + ";");
        setMinSize(920, 620);

        wireBackendConfirmers();
        VBox rail = buildNavigationRail();
        chrome.setLeft(rail);
        chrome.setCenter(contentHost);
        contentHost.setStyle("-fx-background-color: " + Tokens.CANVAS_HEX + ";");

        buildAllViews();
        wireLiveEngineSync();

        getChildren().addAll(chrome, toasts);

        addEventFilter(KeyEvent.KEY_PRESSED, e -> {
            if (CTRL_K.match(e)) {
                openCommandPalette();
                e.consume();
            }
        });

        switchTo(Section.HOME);
        Platform.runLater(() -> updateNavHighlights(activeSection.get()));
    }

    private void wireBackendConfirmers() {
        if (backend == null) return;
        backend.setPinReplaceConfirmer(details -> {
            if (Platform.isFxApplicationThread()) {
                return UiSafe.showConfirm(UiSafe.windowOf(this),
                        Messages.get("login.client.warning.pinChanged.title"),
                        Messages.get("login.client.warning.pinChanged.header"),
                        details + "\n\n" + Messages.get("login.client.warning.pinChanged.footer"));
            }
            CompletableFuture<Boolean> decision = new CompletableFuture<>();
            Platform.runLater(() -> decision.complete(UiSafe.showConfirm(UiSafe.windowOf(this),
                    Messages.get("login.client.warning.pinChanged.title"),
                    Messages.get("login.client.warning.pinChanged.header"),
                    details + "\n\n" + Messages.get("login.client.warning.pinChanged.footer"))));
            try {
                return decision.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            } catch (ExecutionException e) {
                return false;
            }
        });
    }

    private void wireLiveEngineSync() {
        service.connectionStateProperty().addListener((obs, o, st) -> syncAuthDrivenViews());
        service.virtualIpProperty().addListener((obs, o, v) -> syncAuthDrivenViews());

        if (backend != null) {
            VpnClientEngine eng = backend.getEngine();
            liveClientListener = new VpnClientEngine.ClientEventListener() {
                @Override
                public void onChatMessage(String senderUser, String senderDept, String senderVip, String message) {
                    if (chatPanel != null) {
                        chatPanel.appendChatMessage(senderUser, senderDept, senderVip, message);
                    }
                }

                @Override
                public void onPacketSniffed(VpnPacket packet, String direction) {
                    if (connectionStatusPanel != null) {
                        connectionStatusPanel.appendPacketSniffer(packet, direction);
                    }
                }

                @Override
                public void onConnectionStateChanged(String state) {
                    if (connectionStatusPanel != null) {
                        connectionStatusPanel.appendStateMessage(state);
                        Platform.runLater(() -> connectionStatusPanel.refreshControls());
                    }
                    Platform.runLater(() -> syncAuthDrivenViews());
                }
            };
            eng.addClientEventListener(liveClientListener);
        }
        syncAuthDrivenViews();
    }

    private void syncAuthDrivenViews() {
        boolean authed = backend != null && backend.getEngine().isConnected() && backend.getEngine().isAuthenticated();
        if (homeCredentialsPane != null && homeSessionPane != null) {
            homeConnectionSlot.getChildren().setAll(authed ? homeSessionPane : homeCredentialsPane);
        }
        if (authed && homeSessionUserLabel != null && backend != null) {
            VpnClientEngine eng = backend.getEngine();
            String u = UiSafe.text(eng.getUsername(), 32);
            String dept = eng.getDepartment() != null ? eng.getDepartment().name() : "-";
            String role = eng.getRole() != null ? eng.getRole().name() : "-";
            String vip = UiSafe.text(eng.getAssignedVirtualIp(), 32);
            String fp = eng.getServerFingerprint() != null ? eng.getServerFingerprint() : "-";
            homeSessionUserLabel.setText(u);
            homeSessionDeptLabel.setText(role + " · " + dept);
            homeSessionVipLabel.setText("VIP: " + vip);
            homeSessionFpLabel.setText("Pinned Gateway FP: " + (fp.length() > 28 ? fp.substring(0, 28) + "..." : fp));
        }
        if (fileVaultPanel != null) fileVaultPanel.syncAuthState();
        if (chatPanel != null) chatPanel.syncAuthState();
        if (myDevicesPanel != null) myDevicesPanel.refresh();
        if (connectionStatusPanel != null) connectionStatusPanel.refreshControls();
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
        VBox rail = new VBox(8);
        rail.getStyleClass().add("app-shell-rail");
        rail.setPadding(new Insets(14, 12, 14, 12));
        rail.setMinWidth(198);
        rail.setPrefWidth(210);
        rail.setMaxWidth(218);

        Label brand = new Label("Ivory Atelier");
        brand.getStyleClass().add("ia-display-md");
        Label subtitle = new Label("OFFICE VPN SUITE");
        subtitle.getStyleClass().add("ia-section-label");
        VBox brandBox = new VBox(2, brand, subtitle);
        brandBox.setPadding(new Insets(0, 6, 4, 6));

        VBox buttonsList = new VBox(3);
        for (Section s : Section.values()) {
            Button btn = new Button(s.label(), Icons.soft(s.icon(), 14));
            btn.getStyleClass().add("rail-nav-btn");
            btn.setPadding(new Insets(7, 11, 7, 11));
            btn.setMaxWidth(Double.MAX_VALUE);
            btn.setGraphicTextGap(10);
            btn.setOnAction(e -> switchTo(s));
            navButtons.put(s, btn);
            buttonsList.getChildren().add(btn);
        }

        slidingIndicator.setManaged(false);
        slidingIndicator.setPrefSize(4, 22);
        slidingIndicator.setStyle("-fx-background-color: " + Tokens.MARIGOLD_HEX + "; -fx-background-radius: 999px;");

        Pane indicatorGutter = new Pane(slidingIndicator);
        indicatorGutter.setMinWidth(6);
        indicatorGutter.setMaxWidth(6);

        HBox navWrapper = new HBox(4, indicatorGutter, buttonsList);
        HBox.setHgrow(buttonsList, Priority.ALWAYS);

        Region spacer = new Region();
        VBox.setVgrow(spacer, Priority.ALWAYS);

        Button cmdBtn = new Button("Quick Command", Icons.ink(Feather.COMMAND, 13));
        cmdBtn.getStyleClass().add("ia-pill-sand");
        cmdBtn.setMaxWidth(Double.MAX_VALUE);
        cmdBtn.setOnAction(e -> openCommandPalette());

        Label statusChip = new Label("Disconnected");
        statusChip.getStyleClass().addAll("ia-pill", "ia-pill-sand");
        statusChip.setMaxWidth(Double.MAX_VALUE);
        Label vipChip = new Label("VIP " + service.virtualIpProperty().get());
        vipChip.getStyleClass().add("ia-mono-soft");

        service.connectionStateProperty().addListener((obs, o, n) -> syncFooterChip(statusChip, vipChip, n));
        service.selectedGatewayProperty().addListener((obs, o, n) -> syncFooterChip(statusChip, vipChip, service.connectionStateProperty().get()));
        service.virtualIpProperty().addListener((obs, o, n) -> syncFooterChip(statusChip, vipChip, service.connectionStateProperty().get()));
        syncFooterChip(statusChip, vipChip, service.connectionStateProperty().get());

        VBox statusCard = new VBox(5, statusChip, vipChip);
        statusCard.getStyleClass().add("ia-card-paper");
        statusCard.setPadding(new Insets(9));

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
            btn.setGraphic(Icons.soft(sec.icon(), 14));
            if (sec == active) {
                btn.getStyleClass().add("rail-nav-btn-active");
                btn.setGraphic(Icons.ink(sec.icon(), 14));
            }
        });
        Button targetBtn = navButtons.get(active);
        double targetY = (targetBtn != null && targetBtn.getHeight() > 0)
                ? targetBtn.getLayoutY() + (targetBtn.getHeight() - 22.0) / 2.0
                : active.ordinal() * 35.0 + 6.0;
        if (Motion.isReduceMotion()) {
            slidingIndicator.resizeRelocate(1, targetY, 4, 22);
        } else {
            if (indicatorAnim != null) indicatorAnim.stop();
            slidingIndicator.setLayoutX(1);
            slidingIndicator.setPrefSize(4, 22);
            indicatorAnim = new Timeline(new KeyFrame(Motion.FAST,
                    new KeyValue(slidingIndicator.layoutYProperty(), targetY, Motion.spring())));
            indicatorAnim.play();
        }
    }

    private void buildAllViews() {
        views.put(Section.HOME, buildHomeBentoView());
        views.put(Section.VAULT, buildVaultView());
        views.put(Section.CHAT, buildChatView());
        views.put(Section.DEVICES, buildDevicesAndMfaView());
        views.put(Section.GATEWAYS, wrapScroll("Gateway Directory", "Configured gateway endpoint, TOFU RSA pin status, and fuzzy lookup.", buildGatewaysView()));
        views.put(Section.MODES, wrapScroll("Work Modes", "Switch Split/Full routing profiles cleanly.", buildModesView()));
        views.put(Section.ACCESS, wrapScroll("Access, Kill Switch & Packet Telemetry", "Egress safety latches, SplitLanes routing, and live encrypted packet stream.", buildAccessView()));
        views.put(Section.ADMIN, wrapScroll("Session Roster & Sign-In", "Connected employee presence (when running gateway) and user authentication.", buildAdminView()));
        views.put(Section.LOGS, wrapScroll("Activity & Audit Ledger", "Cryptographic verification and live encrypted session history.", buildLogsView()));
        views.put(Section.SETTINGS, wrapScroll("Preferences & Security Tools", "Motion accessibility, password rotation, TOFU pin management, and tray panel.", buildSettingsView()));
    }

    private Node buildHomeBentoView() {
        VBox page = new VBox(14);
        page.setPadding(new Insets(18, 22, 18, 22));
        page.setStyle("-fx-background-color: " + Tokens.CANVAS_HEX + ";");

        Label heading = new Label("Office VPN Workspace");
        heading.getStyleClass().add("ia-display-lg");
        Label caption = new Label();
        caption.textProperty().bind(service.statusCaptionProperty());
        caption.getStyleClass().add("ia-subtitle");

        Button pingBtn = new Button("Test Ping", Icons.peacock(Feather.ACTIVITY, 13));
        pingBtn.getStyleClass().add("ia-btn-peacock");
        pingBtn.setOnAction(e -> handleTestPing());

        Button killBtn = new Button("Toggle Kill Switch", Icons.coral(Feather.SHIELD_OFF, 13));
        killBtn.getStyleClass().add("ia-btn-coral");
        killBtn.setOnAction(e -> {
            boolean next = !service.killSwitchEnabledProperty().get();
            service.killSwitchEnabledProperty().set(next);
            pushToast(next ? Toasts.Severity.WARNING : Toasts.Severity.INFO,
                    next ? "Kill Switch Armed" : "Kill Switch Disarmed",
                    next ? "Non-tunnel egress blocked until tunnel restores." : "Standard egress policy restored.");
        });

        Region sp = new Region();
        HBox.setHgrow(sp, Priority.ALWAYS);
        HBox topRow = new HBox(10, new VBox(2, heading, caption), sp, pingBtn, killBtn);
        topRow.setAlignment(Pos.CENTER_LEFT);

        HandshakeLoom loom = new HandshakeLoom();
        loom.bindService(service);
        loom.setMinWidth(0);

        KeycardGate gate = new KeycardGate();
        gate.bindService(service);
        StackPane gateCard = Tokens.wrapPaperCard(gate, true);
        gateCard.setMinWidth(0);

        buildHomeConnectionSlot();
        StackPane connectCard = Tokens.wrapPaperCard(homeConnectionSlot, true);
        connectCard.setMinWidth(0);

        PulseRibbon ribbon = new PulseRibbon();
        ribbon.bindService(service);
        StackPane ribbonCard = Tokens.wrapPaperCard(ribbon, false);
        ribbonCard.setMinWidth(0);

        OfficeAtlas atlas = new OfficeAtlas();
        atlas.bindService(service);
        StackPane atlasCard = Tokens.wrapPaperCard(atlas, false);
        atlasCard.setMinWidth(0);

        PostureSeal posture = new PostureSeal();
        posture.bindService(service);
        StackPane postureCard = Tokens.wrapPaperCard(posture, true);
        postureCard.setMinWidth(0);

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
                compactStack.getChildren().setAll(connectCard, gateCard, ribbonCard, postureCard, atlasCard);
                bentoHost.getChildren().setAll(compactStack);
            } else {
                leftColumn.getChildren().setAll(connectCard, gateCard, atlasCard);
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

    private void buildHomeConnectionSlot() {
        GatewayNode initGw = service.selectedGatewayProperty().get();
        String initHost = (initGw != null && initGw.hostname() != null && !initGw.hostname().isBlank())
                ? initGw.hostname() : ConfigUtil.getClientDefaultHost();
        int initPort = (initGw != null && initGw.port() > 0) ? initGw.port() : ConfigUtil.getPort();
        TextField hostField = new TextField(initHost);
        hostField.setPromptText("Gateway host or IP");
        TextField portField = new TextField(String.valueOf(initPort));
        portField.setPromptText("Port");
        portField.setPrefWidth(88);
        TextField expectedFpField = new TextField();
        expectedFpField.setPromptText("Optional expected 64-char SHA-256 server fingerprint");
        expectedFpField.getStyleClass().add("ia-mono");

        Label pinStatusLbl = new Label("");
        pinStatusLbl.getStyleClass().add("ia-subtitle");
        Button clearPinBtn = new Button("Clear Pin");
        Runnable updatePinStatus = () -> {
            if (backend == null) {
                pinStatusLbl.setText("Simulated mode");
                clearPinBtn.setDisable(true);
                return;
            }
            String h = hostField.getText() != null ? hostField.getText().trim() : "";
            int p = parsePort(portField.getText());
            if (h.isEmpty() || p <= 0) {
                pinStatusLbl.setText("Enter valid host and port");
                clearPinBtn.setDisable(true);
                return;
            }
            Optional<String> existing = backend.getPinnedFingerprint(h, p);
            if (existing.isPresent()) {
                String fp = existing.get();
                pinStatusLbl.setText("Stored TOFU Pin: " + (fp.length() > 20 ? fp.substring(0, 20) + "..." : fp));
                clearPinBtn.setDisable(false);
            } else {
                pinStatusLbl.setText("No saved pin for " + h + ":" + p + " (TOFU on first connect)");
                clearPinBtn.setDisable(true);
            }
        };

        Runnable applyEndpoint = () -> {
            if (backend != null) {
                backend.configureGatewayEndpoint(
                        hostField.getText(),
                        parsePort(portField.getText()),
                        expectedFpField.getText());
            }
            updatePinStatus.run();
        };
        hostField.textProperty().addListener((obs, o, n) -> applyEndpoint.run());
        portField.textProperty().addListener((obs, o, n) -> applyEndpoint.run());
        expectedFpField.textProperty().addListener((obs, o, n) -> applyEndpoint.run());
        clearPinBtn.setOnAction(e -> {
            if (backend != null) {
                backend.clearGatewayPin(hostField.getText(), parsePort(portField.getText()));
                updatePinStatus.run();
                pushToast(Toasts.Severity.INFO, "TOFU Pin Cleared", "Next handshake will pin the gateway certificate cleanly.");
            }
        });
        updatePinStatus.run();

        HBox hostPortRow = new HBox(8, hostField, portField);
        HBox.setHgrow(hostField, Priority.ALWAYS);
        HBox pinRow = new HBox(8, pinStatusLbl, new Region(), clearPinBtn);
        HBox.setHgrow(pinRow.getChildren().get(1), Priority.ALWAYS);
        pinRow.setAlignment(Pos.CENTER_LEFT);

        Label gwLbl = new Label("GATEWAY ENDPOINT & IDENTITY PINNING");
        gwLbl.getStyleClass().add("ia-section-label");

        VBox endpointBox = new VBox(8, gwLbl, hostPortRow, expectedFpField, pinRow);
        endpointBox.getStyleClass().add("ia-card-sand");
        endpointBox.setPadding(new Insets(12));

        SignInCard signIn = new SignInCard();
        signIn.setMaxWidth(Double.MAX_VALUE);
        signIn.verifierProperty().set((user, pass, otp) -> {
            applyEndpoint.run();
            return service.authenticate(user, pass, otp);
        });
        signIn.onAuthenticatedProperty().set(res -> {
            updatePinStatus.run();
            syncAuthDrivenViews();
            pushToast(Toasts.Severity.SUCCESS, "Tunnel Authenticated", res.message());
        });

        homeCredentialsPane = new VBox(12, endpointBox, signIn);
        homeCredentialsPane.setPadding(new Insets(14));

        // 2) Connected Active Session Summary Card
        Label activeBadge = new Label("ENCRYPTED TUNNEL ACTIVE");
        activeBadge.getStyleClass().addAll("ia-pill", "ia-pill-peacock");

        homeSessionUserLabel = new Label("-");
        homeSessionUserLabel.getStyleClass().add("ia-display-md");
        homeSessionDeptLabel = new Label("-");
        homeSessionDeptLabel.getStyleClass().add("ia-subtitle");
        homeSessionVipLabel = new Label("VIP: 0.0.0.0");
        homeSessionVipLabel.getStyleClass().add("ia-mono");
        homeSessionFpLabel = new Label("Pinned Gateway FP: -");
        homeSessionFpLabel.getStyleClass().add("ia-mono-soft");
        homeSessionPingLabel = new Label("Latency: ready to probe");
        homeSessionPingLabel.getStyleClass().add("ia-subtitle");

        Button copyVipBtn = new Button("Copy Virtual IP", Icons.ink(Feather.COPY, 13));
        copyVipBtn.setOnAction(e -> {
            UiSafe.copyToClipboard(service.virtualIpProperty().get());
            pushToast(Toasts.Severity.INFO, "Copied Virtual IP", service.virtualIpProperty().get());
        });
        Button sessionPingBtn = new Button("Test Ping", Icons.peacock(Feather.ACTIVITY, 13));
        sessionPingBtn.getStyleClass().add("ia-btn-peacock");
        sessionPingBtn.setOnAction(e -> handleTestPing());

        Button changePwBtn = new Button("Change Password", Icons.ink(Feather.KEY, 13));
        changePwBtn.setOnAction(e -> handleChangePassword());

        Button disconnectBtn = new Button("Disconnect", Icons.coral(Feather.POWER, 13));
        disconnectBtn.getStyleClass().add("ia-btn-coral");
        disconnectBtn.setOnAction(e -> service.disconnect());

        HBox actionRow1 = new HBox(8, copyVipBtn, sessionPingBtn);
        HBox actionRow2 = new HBox(8, changePwBtn, disconnectBtn);

        homeSessionPane = new VBox(10,
                activeBadge,
                homeSessionUserLabel,
                homeSessionDeptLabel,
                homeSessionVipLabel,
                homeSessionFpLabel,
                homeSessionPingLabel,
                actionRow1,
                actionRow2
        );
        homeSessionPane.setPadding(new Insets(16));

        homeConnectionSlot.getChildren().setAll(homeCredentialsPane);
    }

    private Node buildVaultView() {
        if (backend == null) {
            return wrapScroll("Encrypted File Vault", "Connect via BackendVpnServiceAdapter to access departmental files.",
                    Tokens.wrapPaperCard(new Label("File Vault is active in live client sessions."), false));
        }
        fileVaultPanel = new FileVaultPanel(backend.getEngine());
        applyThemeCssToSubpanel(fileVaultPanel);
        VBox.setVgrow(fileVaultPanel, Priority.ALWAYS);
        return fileVaultPanel;
    }

    private Node buildChatView() {
        if (backend == null) {
            return wrapScroll("Secure Intranet Chat", "Connect to gateway to exchange department messages.",
                    Tokens.wrapPaperCard(new Label("Secure Chat is active in live client sessions."), false));
        }
        chatPanel = new ChatPanel(backend.getEngine());
        applyThemeCssToSubpanel(chatPanel);
        VBox.setVgrow(chatPanel, Priority.ALWAYS);
        return chatPanel;
    }

    private Node buildDevicesAndMfaView() {
        VBox container = new VBox(16);
        container.setPadding(new Insets(18));
        container.setStyle("-fx-background-color: " + Tokens.CANVAS_HEX + ";");

        if (backend != null) {
            myDevicesPanel = new MyDevicesPanel(backend.getEngine());
            applyThemeCssToSubpanel(myDevicesPanel);
            myDevicesPanel.setPadding(new Insets(0));
            VBox.setVgrow(myDevicesPanel, Priority.ALWAYS);
            container.getChildren().add(myDevicesPanel);
        }

        Label mfaTitle = new Label("Two-Factor Authentication (MFA / TOTP) Guide & Account Security");
        mfaTitle.getStyleClass().add("ia-card-title");
        Label mfaBody = new Label(
                "What does 'MFA Enabled' mean?\n"
                        + "• When MFA is OFF (default for new accounts): sign in with Username + Password only — leave the 6-digit MFA code boxes blank.\n"
                        + "• When MFA is ENABLED (by Admin in Admin Deck -> Users -> Manage 2FA): scan the Admin's enrollment QR code using Google Authenticator, Microsoft Authenticator, or FreeOTP, then enter the 6-digit code shown in your app during sign-in.");
        mfaBody.getStyleClass().add("ia-subtitle");
        mfaBody.setWrapText(true);

        Button changePwBtn = new Button("Change My Password Over Tunnel", Icons.ink(Feather.LOCK, 13));
        changePwBtn.getStyleClass().add("ia-btn-marigold");
        changePwBtn.setOnAction(e -> handleChangePassword());

        VBox mfaContent = new VBox(10, mfaTitle, mfaBody, changePwBtn);
        mfaContent.setPadding(new Insets(16));
        container.getChildren().add(Tokens.wrapPaperCard(mfaContent, false));

        ScrollPane sc = new ScrollPane(container);
        sc.setFitToWidth(true);
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
        modes.bindService(service, msg -> pushToast(Toasts.Severity.SUCCESS, "Tunnel Mode Updated", msg));
        return modes;
    }

    private Node buildAccessView() {
        SafetyLatches latches = new SafetyLatches();
        latches.bindService(service);
        HandshakeLoom loom = new HandshakeLoom();
        loom.bindService(service);

        VBox stack = new VBox(16, Tokens.wrapPaperCard(loom, false), latches);
        if (backend != null) {
            connectionStatusPanel = new ConnectionStatusPanel(backend.getEngine());
            applyThemeCssToSubpanel(connectionStatusPanel);
            connectionStatusPanel.setPadding(new Insets(0));
            connectionStatusPanel.setPrefHeight(360);
            stack.getChildren().add(connectionStatusPanel);
        }
        return stack;
    }

    private Node buildAdminView() {
        LiveRoster roster = new LiveRoster();
        roster.bindService(service, msg -> pushToast(Toasts.Severity.INFO, "Roster Governance", msg));
        roster.setMinWidth(0);

        SignInCard signIn = new SignInCard();
        signIn.bindService(service, msg -> pushToast(Toasts.Severity.SUCCESS, "Authentication", msg));
        signIn.onAuthenticatedProperty().set(res -> {
            syncAuthDrivenViews();
            pushToast(Toasts.Severity.SUCCESS, "Signed In", res.message());
        });
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

        Button changePwBtn = new Button("Change Account Password", Icons.ink(Feather.KEY, 14));
        changePwBtn.getStyleClass().add("ia-btn-marigold");
        changePwBtn.setOnAction(e -> handleChangePassword());

        Screen primary = Screen.getPrimary();
        Label dpiInfo = new Label(String.format("Detected OS Scale: %.0f%% (OutputScale %.2fx) • Bundled Fonts: Fraunces + Manrope + JetBrains Mono (OFL)",
                primary.getOutputScaleX() * 100.0, primary.getOutputScaleX()));
        dpiInfo.getStyleClass().add("ia-mono-soft");

        HBox btns = new HBox(10, openTrayBtn, changePwBtn);
        VBox cardContent = new VBox(14, reduceMotion, btns, dpiInfo);
        cardContent.setPadding(new Insets(18));
        return Tokens.wrapPaperCard(cardContent, true);
    }

    private void handleTestPing() {
        if (backend == null) {
            pushToast(Toasts.Severity.INFO, "Latency Probe", "Current RTT: " + service.currentLatencyMsProperty().get() + " ms");
            return;
        }
        backend.pingGateway().whenComplete((ms, err) -> Platform.runLater(() -> {
            if (err != null) {
                Throwable cause = err.getCause() != null ? err.getCause() : err;
                pushToast(Toasts.Severity.ERROR, "Ping Failed", cause.getMessage());
                if (homeSessionPingLabel != null) {
                    homeSessionPingLabel.setText("Latency check failed: " + cause.getMessage());
                }
            } else {
                String msg = "Encrypted PING/PONG RTT: " + ms + " ms";
                pushToast(Toasts.Severity.SUCCESS, "Gateway Ping Verified", msg);
                if (homeSessionPingLabel != null) {
                    homeSessionPingLabel.setText(msg);
                }
            }
        }));
    }

    private void handleChangePassword() {
        if (backend == null) {
            UiSafe.showInfo(UiSafe.windowOf(this), Messages.get("client.password.dialog.title"),
                    "Password change requires an active gateway tunnel connection.");
            return;
        }
        VpnClientEngine eng = backend.getEngine();
        if (!eng.isConnected() || !eng.isAuthenticated()) {
            UiSafe.showWarning(UiSafe.windowOf(this), Messages.get("client.password.dialog.title"),
                    Messages.get("client.password.error.disconnected"));
            return;
        }

        PasswordField currentField = new PasswordField();
        currentField.setPromptText(Messages.get("client.password.label.current"));
        PasswordField nextField = new PasswordField();
        nextField.setPromptText("Min " + PasswordPolicy.MIN_LENGTH + " chars (strong passphrase)");
        PasswordField confirmField = new PasswordField();
        confirmField.setPromptText(Messages.get("client.password.label.confirm"));

        VBox content = new VBox(8,
                new Label(Messages.get("client.password.label.current")), currentField,
                new Label(Messages.get("client.password.label.new")), nextField,
                new Label(Messages.get("client.password.label.confirm")), confirmField);
        content.setPrefWidth(400);

        Dialog<ButtonType> dialog = UiSafe.createDialog(UiSafe.windowOf(this),
                Messages.get("client.password.dialog.title"),
                Messages.format("client.password.dialog.header", UiSafe.text(eng.getUsername(), 32)),
                content);
        ButtonType saveType = new ButtonType(Messages.get("client.password.button.save"), ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(saveType, ButtonType.CANCEL);
        UiSafe.stylePrimaryDialogButton(dialog, saveType);

        if (dialog.showAndWait().orElse(ButtonType.CANCEL) != saveType) {
            return;
        }

        char[] curPw = currentField.getText().toCharArray();
        char[] newPw = nextField.getText().toCharArray();
        char[] confPw = confirmField.getText().toCharArray();
        try {
            if (!Arrays.equals(newPw, confPw)) {
                throw new IllegalArgumentException(Messages.get("client.password.error.mismatch"));
            }
            PasswordPolicy.validatePassword(newPw, eng.getUsername());
        } catch (IllegalArgumentException ex) {
            Arrays.fill(curPw, '\0');
            Arrays.fill(newPw, '\0');
            Arrays.fill(confPw, '\0');
            UiSafe.showError(UiSafe.windowOf(this), Messages.get("client.password.dialog.title"), ex.getMessage());
            return;
        } finally {
            Arrays.fill(confPw, '\0');
        }

        backend.changePassword(curPw, newPw).whenComplete((v, err) -> {
            Arrays.fill(curPw, '\0');
            Arrays.fill(newPw, '\0');
            Platform.runLater(() -> {
                if (err != null) {
                    Throwable cause = err.getCause() != null ? err.getCause() : err;
                    UiSafe.showError(UiSafe.windowOf(this), Messages.get("client.password.dialog.title"), cause.getMessage());
                } else {
                    pushToast(Toasts.Severity.SUCCESS, Messages.get("client.password.dialog.title"), Messages.get("client.password.success"));
                }
            });
        });
    }

    private static void applyThemeCssToSubpanel(Parent node) {
        URL cssUrl = AppShell.class.getResource(UiSafe.THEME_CSS_RESOURCE);
        if (cssUrl != null) {
            String urlStr = cssUrl.toExternalForm();
            if (!node.getStylesheets().contains(urlStr)) {
                node.getStylesheets().add(urlStr);
            }
        }
    }

    private static int parsePort(String raw) {
        try {
            int p = Integer.parseInt(raw != null ? raw.trim() : "");
            return (p >= 1 && p <= 65535) ? p : -1;
        } catch (NumberFormatException ex) {
            return -1;
        }
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

    @Override
    public void close() {
        if (backend != null && liveClientListener != null) {
            backend.getEngine().removeClientEventListener(liveClientListener);
            liveClientListener = null;
        }
        if (connectionStatusPanel != null) {
            connectionStatusPanel.dispose();
        }
    }
}
