package com.officevpn.ui.components;

import com.officevpn.ui.service.MockVpnService;
import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.ConnectionState;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.css.CssMetaData;
import javafx.css.PseudoClass;
import javafx.css.SimpleStyleableDoubleProperty;
import javafx.css.Styleable;
import javafx.css.StyleableDoubleProperty;
import javafx.css.StyleablePropertyFactory;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.AccessibleAction;
import javafx.scene.AccessibleRole;
import javafx.scene.Node;
import javafx.scene.canvas.Canvas;
import javafx.scene.canvas.GraphicsContext;
import javafx.scene.control.Button;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.Skin;
import javafx.scene.control.SkinBase;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.paint.CycleMethod;
import javafx.scene.paint.LinearGradient;
import javafx.scene.paint.Stop;
import javafx.scene.shape.ArcType;
import javafx.scene.shape.StrokeLineCap;
import javafx.util.Duration;
import org.kordamp.ikonli.feather.Feather;

import java.util.List;

/**
 * Tactile corporate KeycardGate control replacing a plain connect button.
 * <p>
 * Users drag the embossed employee ID keycard horizontally into the brass-trimmed reader slot
 * with spring snapping, or focus the control and hold Space/Enter for 600 ms while a radial
 * marigold progress arc sweeps to engage the tunnel. Disconnecting draws the card cleanly back out.
 */
public final class KeycardGate extends Control {

    private static final StyleablePropertyFactory<KeycardGate> FACTORY =
            new StyleablePropertyFactory<>(Control.getClassCssMetaData());

    private static final CssMetaData<KeycardGate, Number> TRACK_HEIGHT_META =
            FACTORY.createSizeCssMetaData("-ia-track-height", s -> s.trackHeight, 108.0);

    private static final PseudoClass PC_DISCONNECTED = PseudoClass.getPseudoClass("disconnected");
    private static final PseudoClass PC_CONNECTING   = PseudoClass.getPseudoClass("connecting");
    private static final PseudoClass PC_HANDSHAKING  = PseudoClass.getPseudoClass("handshaking");
    private static final PseudoClass PC_CONNECTED    = PseudoClass.getPseudoClass("connected");
    private static final PseudoClass PC_RECONNECTING = PseudoClass.getPseudoClass("reconnecting");
    private static final PseudoClass PC_BLOCKED      = PseudoClass.getPseudoClass("blocked");

    private final StyleableDoubleProperty trackHeight =
            new SimpleStyleableDoubleProperty(TRACK_HEIGHT_META, this, "trackHeight", 108.0);

    private final ObjectProperty<ConnectionState> connectionState = new SimpleObjectProperty<>(ConnectionState.DISCONNECTED);
    private final StringProperty statusCaption = new SimpleStringProperty(ConnectionState.DISCONNECTED.defaultCaption());
    private final StringProperty cardInitials = new SimpleStringProperty("AM");
    private final StringProperty cardHolderName = new SimpleStringProperty("Ananya Mehta");
    private final StringProperty cardHolderRole = new SimpleStringProperty("Staff Security Engineer");
    private final StringProperty cardBadgeId = new SimpleStringProperty("OVPN-0419");
    private final StringProperty targetGatewayLabel = new SimpleStringProperty("Munich Core 01");

    private final ObjectProperty<Runnable> onConnectRequested = new SimpleObjectProperty<>(() -> {});
    private final ObjectProperty<Runnable> onDisconnectRequested = new SimpleObjectProperty<>(() -> {});
    private final ObjectProperty<Runnable> onResetKillSwitchRequested = new SimpleObjectProperty<>(() -> {});

    public KeycardGate() {
        getStyleClass().setAll("keycard-gate");
        setFocusTraversable(true);
        setAccessibleRole(AccessibleRole.BUTTON);
        setMinSize(320, Region.USE_PREF_SIZE);

        connectionState.addListener((obs, o, n) -> syncPseudoClasses(n));
        syncPseudoClasses(connectionState.get());
        updateAccessibleText();
        connectionState.addListener((obs, o, n) -> updateAccessibleText());
        statusCaption.addListener((obs, o, n) -> updateAccessibleText());
    }

    /**
     * Binds this gate directly to a {@link VpnClientService}.
     */
    public void bindService(VpnClientService service) {
        if (service == null) return;
        connectionState.bind(service.connectionStateProperty());
        statusCaption.bind(service.statusCaptionProperty());
        service.currentIdentityProperty().addListener((obs, o, id) -> {
            if (id != null) {
                cardInitials.set(id.initials());
                cardHolderName.set(id.displayName());
                cardHolderRole.set(id.role());
                cardBadgeId.set(id.badgeId());
            }
        });
        if (service.currentIdentityProperty().get() != null) {
            var id = service.currentIdentityProperty().get();
            cardInitials.set(id.initials());
            cardHolderName.set(id.displayName());
            cardHolderRole.set(id.role());
            cardBadgeId.set(id.badgeId());
        }
        service.selectedGatewayProperty().addListener((obs, o, gw) -> {
            if (gw != null) targetGatewayLabel.set(gw.city());
        });
        if (service.selectedGatewayProperty().get() != null) {
            targetGatewayLabel.set(service.selectedGatewayProperty().get().city());
        }
        onConnectRequested.set(service::connect);
        onDisconnectRequested.set(service::disconnect);
        onResetKillSwitchRequested.set(service::clearKillSwitchBlock);
    }

    /**
     * Creates a standalone demo wrapper showcasing state switching outside AppShell.
     */
    public static Node createStandaloneDemo(VpnClientService service) {
        KeycardGate gate = new KeycardGate();
        gate.bindService(service);
        return gate;
    }

    private void syncPseudoClasses(ConnectionState state) {
        pseudoClassStateChanged(PC_DISCONNECTED, state == ConnectionState.DISCONNECTED);
        pseudoClassStateChanged(PC_CONNECTING, state == ConnectionState.CONNECTING);
        pseudoClassStateChanged(PC_HANDSHAKING, state == ConnectionState.HANDSHAKING);
        pseudoClassStateChanged(PC_CONNECTED, state == ConnectionState.CONNECTED);
        pseudoClassStateChanged(PC_RECONNECTING, state == ConnectionState.RECONNECTING);
        pseudoClassStateChanged(PC_BLOCKED, state == ConnectionState.BLOCKED_BY_KILL_SWITCH);
    }

    private void updateAccessibleText() {
        ConnectionState st = connectionState.get();
        setAccessibleText("Corporate Keycard Gate, state " + (st != null ? st.title() : "Disconnected")
                + ". " + statusCaption.get() + ". Hold Space or Enter for 600 milliseconds to swipe.");
    }

    @Override
    public void executeAccessibleAction(AccessibleAction action, Object... parameters) {
        if (action == AccessibleAction.FIRE) {
            toggleFromKeyboard();
        } else {
            super.executeAccessibleAction(action, parameters);
        }
    }

    public void toggleFromKeyboard() {
        ConnectionState st = connectionState.get();
        if (st == ConnectionState.CONNECTED) {
            Runnable d = onDisconnectRequested.get();
            if (d != null) d.run();
        } else if (st == ConnectionState.BLOCKED_BY_KILL_SWITCH) {
            Runnable r = onResetKillSwitchRequested.get();
            if (r != null) r.run();
        } else if (st == ConnectionState.DISCONNECTED || st == ConnectionState.RECONNECTING) {
            Runnable c = onConnectRequested.get();
            if (c != null) c.run();
        }
    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new KeycardGateSkin(this);
    }

    public static List<CssMetaData<? extends Styleable, ?>> getClassCssMetaData() {
        return FACTORY.getCssMetaData();
    }

    @Override
    public List<CssMetaData<? extends Styleable, ?>> getControlCssMetaData() {
        return getClassCssMetaData();
    }

    public ObjectProperty<ConnectionState> connectionStateProperty() { return connectionState; }
    public StringProperty statusCaptionProperty() { return statusCaption; }
    public StringProperty cardInitialsProperty() { return cardInitials; }
    public StringProperty cardHolderNameProperty() { return cardHolderName; }
    public StringProperty cardHolderRoleProperty() { return cardHolderRole; }
    public StringProperty cardBadgeIdProperty() { return cardBadgeId; }
    public StringProperty targetGatewayLabelProperty() { return targetGatewayLabel; }
    public ObjectProperty<Runnable> onConnectRequestedProperty() { return onConnectRequested; }
    public ObjectProperty<Runnable> onDisconnectRequestedProperty() { return onDisconnectRequested; }
    public ObjectProperty<Runnable> onResetKillSwitchRequestedProperty() { return onResetKillSwitchRequested; }
    public StyleableDoubleProperty trackHeightProperty() { return trackHeight; }

    // =========================================================================
    // Skin Implementation
    // =========================================================================
    private static final class KeycardGateSkin extends SkinBase<KeycardGate> {

        private final VBox root = new VBox(12);
        private final Label titleLabel = new Label("Corporate Keycard Gate");
        private final Label statePill = new Label();
        private final Label captionLabel = new Label();
        private final Button quickActionBtn = new Button();

        private final Pane stagePane = new Pane();
        private final Canvas stageCanvas = new Canvas();
        private final StackPane cardNode = new StackPane();
        private final Region readerSlotBg = new Region();

        private final DoubleProperty cardProgress = new SimpleDoubleProperty(0.0); // 0 = rest left, 1 = seated right
        private final DoubleProperty holdArcProgress = new SimpleDoubleProperty(0.0); // 0..1 during 600ms Space/Enter hold
        private final DoubleProperty gateOpenProgress = new SimpleDoubleProperty(0.0); // 0 = bars shut, 1 = parted + sweep

        private double dragStartX;
        private double dragBaseProgress;
        private double stitchPhase = 0.0;
        private Timeline holdTimeline;
        private Timeline snapTimeline;
        private Timeline gateTimeline;
        private Motion.CappedAnimationTimer stitchTimer;
        private boolean keyHolding = false;

        KeycardGateSkin(KeycardGate control) {
            super(control);

            titleLabel.getStyleClass().add("ia-card-title");
            statePill.getStyleClass().addAll("ia-pill", "ia-pill-sand");
            captionLabel.getStyleClass().add("ia-subtitle");

            Region spacer = new Region();
            HBox.setHgrow(spacer, Priority.ALWAYS);

            quickActionBtn.setFocusTraversable(false);
            quickActionBtn.setMinWidth(Region.USE_PREF_SIZE);
            quickActionBtn.getStyleClass().add("ia-btn-marigold");
            quickActionBtn.setOnAction(e -> control.toggleFromKeyboard());

            titleLabel.setMinWidth(Region.USE_PREF_SIZE);
            statePill.setMinWidth(Region.USE_PREF_SIZE);

            HBox header = new HBox(10, titleLabel, statePill, spacer, quickActionBtn);
            header.setAlignment(Pos.CENTER_LEFT);

            setupCardNode(control);
            readerSlotBg.getStyleClass().add("keycard-reader-slot");

            stagePane.setMinSize(260, 108);
            stagePane.prefHeightProperty().bind(control.trackHeightProperty());
            stagePane.setMaxWidth(Double.MAX_VALUE);
            stageCanvas.setManaged(false);
            readerSlotBg.setManaged(false);
            cardNode.setManaged(false);

            stagePane.getChildren().addAll(readerSlotBg, stageCanvas, cardNode);

            HBox footer = new HBox(8, captionLabel);
            footer.setAlignment(Pos.CENTER_LEFT);

            root.getChildren().addAll(header, stagePane, footer);
            getChildren().add(root);

            stitchTimer = new Motion.CappedAnimationTimer(control) {
                @Override
                protected void onTick(long nowNs, double dtSeconds) {
                    stitchPhase = (stitchPhase + dtSeconds * 36.0) % 24.0;
                    drawStageCanvas();
                }
            };
            stitchTimer.bind();

            wireInteractions(control);
            bindStateUpdates(control);

            stagePane.widthProperty().addListener((obs, o, n) -> layoutAndRedraw());
            stagePane.heightProperty().addListener((obs, o, n) -> layoutAndRedraw());
            cardProgress.addListener((obs, o, n) -> layoutAndRedraw());
            holdArcProgress.addListener((obs, o, n) -> drawStageCanvas());
            gateOpenProgress.addListener((obs, o, n) -> drawStageCanvas());
        }

        private void setupCardNode(KeycardGate control) {
            cardNode.getStyleClass().add("keycard-badge");
            cardNode.setPadding(new Insets(10, 12, 10, 12));

            // Tactile gold metallic chip emblem + initials + name/role
            Label initialsLbl = new Label();
            initialsLbl.textProperty().bind(control.cardInitialsProperty());
            initialsLbl.setFont(Fonts.displaySemiBold(15));
            initialsLbl.setTextFill(Tokens.INK);
            StackPane avatar = new StackPane(initialsLbl);
            avatar.setMinSize(32, 32);
            avatar.setMaxSize(32, 32);
            avatar.setStyle("-fx-background-color: #FFFFFF; -fx-background-radius: 999px; -fx-border-color: #D7CAAF; -fx-border-radius: 999px;");

            Label nameLbl = new Label();
            nameLbl.textProperty().bind(control.cardHolderNameProperty());
            nameLbl.setFont(Fonts.uiSemiBold(12.5));
            nameLbl.setTextFill(Tokens.INK);

            Label roleLbl = new Label();
            roleLbl.textProperty().bind(control.cardHolderRoleProperty());
            roleLbl.setFont(Fonts.uiRegular(10.5));
            roleLbl.setTextFill(Tokens.SOFT_INK);

            Label badgeLbl = new Label();
            badgeLbl.textProperty().bind(control.cardBadgeIdProperty());
            badgeLbl.setFont(Fonts.monoMedium(10));
            badgeLbl.setTextFill(Tokens.SOFT_INK);

            VBox info = new VBox(1, nameLbl, roleLbl, badgeLbl);
            info.setAlignment(Pos.CENTER_LEFT);

            // Physical EMV contact chip
            Pane chip = buildContactChip();

            HBox cardContent = new HBox(9, avatar, info, chip);
            cardContent.setAlignment(Pos.CENTER_LEFT);
            cardNode.getChildren().add(cardContent);
            cardNode.setEffect(Tokens.createContactShadow());
        }

        private Pane buildContactChip() {
            Canvas c = new Canvas(22, 18);
            GraphicsContext g = c.getGraphicsContext2D();
            g.setFill(Color.web("#F7D47A"));
            g.fillRoundRect(1, 1, 20, 16, 4, 4);
            g.setStroke(Color.web("#B38629"));
            g.setLineWidth(1.0);
            g.strokeRoundRect(1, 1, 20, 16, 4, 4);
            g.strokeLine(7, 1, 7, 17);
            g.strokeLine(15, 1, 15, 17);
            g.strokeLine(1, 9, 7, 9);
            g.strokeLine(15, 9, 21, 9);
            return new StackPane(c);
        }

        private void wireInteractions(KeycardGate control) {
            cardNode.setOnMousePressed(e -> {
                if (control.connectionState.get() == ConnectionState.BLOCKED_BY_KILL_SWITCH) return;
                dragStartX = e.getSceneX();
                dragBaseProgress = cardProgress.get();
                if (snapTimeline != null) snapTimeline.stop();
                e.consume();
            });

            cardNode.setOnMouseDragged(e -> {
                if (control.connectionState.get() == ConnectionState.BLOCKED_BY_KILL_SWITCH) return;
                double maxTravel = Math.max(40.0, stagePane.getWidth() - cardNode.getWidth() - 28.0);
                double delta = (e.getSceneX() - dragStartX) / maxTravel;
                double clamped = Math.max(0.0, Math.min(1.0, dragBaseProgress + delta));
                cardProgress.set(clamped);
                drawStageCanvas();
                e.consume();
            });

            cardNode.setOnMouseReleased(e -> {
                ConnectionState st = control.connectionState.get();
                if (st == ConnectionState.BLOCKED_BY_KILL_SWITCH) return;
                double p = cardProgress.get();
                if (st == ConnectionState.CONNECTED) {
                    if (p < 0.45) {
                        animateCardTo(0.0);
                        Runnable d = control.onDisconnectRequested.get();
                        if (d != null) d.run();
                    } else {
                        animateCardTo(1.0);
                    }
                } else if (st == ConnectionState.DISCONNECTED || st == ConnectionState.RECONNECTING) {
                    if (p >= 0.56) {
                        animateCardTo(1.0);
                        Runnable c = control.onConnectRequested.get();
                        if (c != null) c.run();
                    } else {
                        animateCardTo(0.0);
                    }
                }
                e.consume();
            });

            control.addEventHandler(KeyEvent.KEY_PRESSED, e -> {
                if ((e.getCode() == KeyCode.SPACE || e.getCode() == KeyCode.ENTER) && !keyHolding) {
                    keyHolding = true;
                    e.consume();
                    ConnectionState st = control.connectionState.get();
                    if (st == ConnectionState.CONNECTED || st == ConnectionState.BLOCKED_BY_KILL_SWITCH) {
                        control.toggleFromKeyboard();
                        return;
                    }
                    startHoldProgress(control);
                }
            });

            control.addEventHandler(KeyEvent.KEY_RELEASED, e -> {
                if (e.getCode() == KeyCode.SPACE || e.getCode() == KeyCode.ENTER) {
                    keyHolding = false;
                    cancelHoldProgress();
                    e.consume();
                }
            });
        }

        private void startHoldProgress(KeycardGate control) {
            if (holdTimeline != null) holdTimeline.stop();
            holdArcProgress.set(0.0);
            if (Motion.isReduceMotion()) {
                holdArcProgress.set(1.0);
                control.toggleFromKeyboard();
                holdArcProgress.set(0.0);
                return;
            }
            holdTimeline = new Timeline(
                    new KeyFrame(Duration.ZERO, new KeyValue(holdArcProgress, 0.0)),
                    new KeyFrame(Duration.millis(600), new KeyValue(holdArcProgress, 1.0))
            );
            holdTimeline.setOnFinished(ev -> {
                holdArcProgress.set(0.0);
                animateCardTo(1.0);
                Runnable c = control.onConnectRequested.get();
                if (c != null) c.run();
            });
            holdTimeline.play();
        }

        private void cancelHoldProgress() {
            if (holdTimeline != null && holdTimeline.getStatus() == javafx.animation.Animation.Status.RUNNING) {
                holdTimeline.stop();
            }
            holdArcProgress.set(0.0);
        }

        private void bindStateUpdates(KeycardGate control) {
            captionLabel.textProperty().bind(control.statusCaptionProperty());
            control.connectionStateProperty().addListener((obs, o, n) -> applyStateVisuals(n));
            applyStateVisuals(control.connectionStateProperty().get());
        }

        private void applyStateVisuals(ConnectionState state) {
            statePill.getStyleClass().removeAll("ia-pill-sand", "ia-pill-marigold", "ia-pill-peacock", "ia-pill-coral", "ia-pill-lilac");
            quickActionBtn.getStyleClass().removeAll("ia-btn-marigold", "ia-btn-peacock", "ia-btn-coral");

            switch (state) {
                case DISCONNECTED -> {
                    statePill.setText("Disconnected");
                    statePill.getStyleClass().add("ia-pill-sand");
                    quickActionBtn.setText("Swipe Keycard");
                    quickActionBtn.setGraphic(Icons.ink(Feather.KEY, 13));
                    quickActionBtn.getStyleClass().add("ia-btn-marigold");
                    animateCardTo(0.0);
                    animateGate(0.0);
                }
                case CONNECTING, HANDSHAKING -> {
                    statePill.setText(state == ConnectionState.CONNECTING ? "Connecting" : "Handshaking");
                    statePill.getStyleClass().add("ia-pill-marigold");
                    quickActionBtn.setText("Cancel");
                    quickActionBtn.setGraphic(Icons.ink(Feather.X, 13));
                    animateCardTo(1.0);
                    animateGate(0.28);
                }
                case CONNECTED -> {
                    statePill.setText("Connected");
                    statePill.getStyleClass().add("ia-pill-peacock");
                    quickActionBtn.setText("Draw Out");
                    quickActionBtn.setGraphic(Icons.peacock(Feather.UNLOCK, 13));
                    quickActionBtn.getStyleClass().add("ia-btn-peacock");
                    animateCardTo(1.0);
                    animateGate(1.0);
                }
                case RECONNECTING -> {
                    statePill.setText("Reconnecting");
                    statePill.getStyleClass().add("ia-pill-lilac");
                    quickActionBtn.setText("Retry Swipe");
                    quickActionBtn.setGraphic(Icons.lilac(Feather.REFRESH_CW, 13));
                    quickActionBtn.getStyleClass().add("ia-btn-marigold");
                    animateCardTo(0.45);
                    animateGate(0.15);
                }
                case BLOCKED_BY_KILL_SWITCH -> {
                    statePill.setText("Blocked • Kill Switch");
                    statePill.getStyleClass().add("ia-pill-coral");
                    quickActionBtn.setText("Reset Lock");
                    quickActionBtn.setGraphic(Icons.coral(Feather.ALERT_TRIANGLE, 13));
                    quickActionBtn.getStyleClass().add("ia-btn-coral");
                    animateCardTo(0.0);
                    animateGate(0.0);
                }
            }
            drawStageCanvas();
        }

        private void animateCardTo(double target) {
            if (snapTimeline != null) snapTimeline.stop();
            if (Motion.isReduceMotion()) {
                cardProgress.set(target);
                return;
            }
            snapTimeline = new Timeline(new KeyFrame(Motion.MEDIUM,
                    new KeyValue(cardProgress, target, Motion.spring())));
            snapTimeline.play();
        }

        private void animateGate(double target) {
            if (gateTimeline != null) gateTimeline.stop();
            if (Motion.isReduceMotion()) {
                gateOpenProgress.set(target);
                return;
            }
            gateTimeline = new Timeline(new KeyFrame(Motion.SLOW,
                    new KeyValue(gateOpenProgress, target, Motion.spring())));
            gateTimeline.play();
        }

        private void layoutAndRedraw() {
            double w = stagePane.getWidth();
            double h = stagePane.getHeight();
            if (w <= 10 || h <= 10) return;

            stageCanvas.setWidth(w);
            stageCanvas.setHeight(h);

            double cardW = Math.min(208.0, Math.max(170.0, w * 0.44));
            double cardH = Math.min(82.0, h - 20.0);
            cardNode.resizeRelocate(0, 0, cardW, cardH);

            double slotW = cardW + 20.0;
            double slotH = cardH + 14.0;
            double slotX = Math.max(12.0, w - slotW - 10.0);
            double slotY = (h - slotH) * 0.5;
            readerSlotBg.resizeRelocate(slotX, slotY, slotW, slotH);

            double startX = 10.0;
            double endX = slotX + 10.0;
            double x = startX + (endX - startX) * cardProgress.get();
            double y = (h - cardH) * 0.5;
            cardNode.relocate(x, y);

            drawStageCanvas();
        }

        private void drawStageCanvas() {
            double w = stageCanvas.getWidth();
            double h = stageCanvas.getHeight();
            if (w <= 10 || h <= 10) return;

            GraphicsContext g = stageCanvas.getGraphicsContext2D();
            g.clearRect(0, 0, w, h);

            ConnectionState state = getSkinnable().connectionStateProperty().get();
            double gateOpen = gateOpenProgress.get();

            // Marigold-to-peacock sweep banner when connected / parting
            if (gateOpen > 0.02) {
                LinearGradient sweep = new LinearGradient(0, 0, 1, 0, true, CycleMethod.NO_CYCLE,
                        new Stop(0.0, Color.rgb(255, 178, 36, 0.14 * gateOpen)),
                        new Stop(0.65, Color.rgb(14, 159, 154, 0.16 * gateOpen)),
                        new Stop(1.0, Color.rgb(14, 159, 154, 0.08 * gateOpen)));
                g.setFill(sweep);
                g.fillRoundRect(4, 4, (w - 8) * Math.min(1.0, gateOpen * 1.1), h - 8, 12, 12);
            }

            // Track guide rail with subtle arrow hints
            double trackY = h * 0.5;
            double leftX = 32;
            double rightX = Math.max(leftX + 30, readerSlotBg.getLayoutX() - 14);
            g.setStroke(Tokens.HAIRLINE);
            g.setLineWidth(1.5);
            g.setLineDashes(5, 5);
            g.strokeLine(leftX, trackY, rightX, trackY);
            g.setLineDashes((double[]) null);

            // Reader slot perimeter & stitch seam while connecting/handshaking
            double rx = readerSlotBg.getLayoutX();
            double ry = readerSlotBg.getLayoutY();
            double rw = readerSlotBg.getWidth();
            double rh = readerSlotBg.getHeight();

            if (state == ConnectionState.CONNECTING || state == ConnectionState.HANDSHAKING || state == ConnectionState.RECONNECTING) {
                g.setStroke(state == ConnectionState.RECONNECTING ? Tokens.LILAC : Tokens.MARIGOLD);
                g.setLineWidth(2.2);
                g.setLineDashes(7, 5);
                g.setLineDashOffset(-stitchPhase);
                g.strokeRoundRect(rx, ry, rw, rh, 12, 12);
                g.setLineDashes((double[]) null);
                g.setLineDashOffset(0);
            } else if (state == ConnectionState.CONNECTED) {
                g.setStroke(Tokens.PEACOCK);
                g.setLineWidth(1.8);
                g.strokeRoundRect(rx, ry, rw, rh, 12, 12);
            } else if (state == ConnectionState.BLOCKED_BY_KILL_SWITCH) {
                g.setStroke(Tokens.CORAL);
                g.setLineWidth(2.0);
                g.strokeRoundRect(rx, ry, rw, rh, 12, 12);
            }

            // Mechanical Gate Bars on the right edge that smoothly part on success
            double barX = w - 8.0;
            double halfGap = 6.0 + gateOpen * (h * 0.36);
            double upperBarBottom = Math.max(8.0, (h * 0.5) - halfGap);
            double lowerBarTop = Math.min(h - 8.0, (h * 0.5) + halfGap);
            Color barColor = state == ConnectionState.CONNECTED ? Tokens.PEACOCK
                    : (state == ConnectionState.BLOCKED_BY_KILL_SWITCH ? Tokens.CORAL : Tokens.SOFT_INK);
            g.setStroke(barColor);
            g.setLineCap(StrokeLineCap.ROUND);
            g.setLineWidth(4.0);
            if (upperBarBottom > 10.0) {
                g.strokeLine(barX, 10.0, barX, upperBarBottom);
            }
            if (h - 10.0 > lowerBarTop) {
                g.strokeLine(barX, lowerBarTop, barX, h - 10.0);
            }

            // Reader prompt microcopy inside empty slot
            if (cardProgress.get() < 0.72) {
                g.setFill(Tokens.SOFT_INK);
                g.setFont(Fonts.uiMedium(11.5));
                String hint = state == ConnectionState.BLOCKED_BY_KILL_SWITCH
                        ? "Kill Switch Engaged"
                        : "Drag card here or hold Space";
                g.fillText(hint, rx + 18, ry + rh * 0.54);
            }

            // Hold-Space/Enter 600 ms radial progress arc centered at reader lock marker
            double hold = holdArcProgress.get();
            if (hold > 0.01) {
                double cx = rx + rw - 24;
                double cy = ry + 20;
                g.setStroke(Tokens.HAIRLINE);
                g.setLineWidth(3.0);
                g.strokeOval(cx - 11, cy - 11, 22, 22);
                g.setStroke(Tokens.MARIGOLD);
                g.setLineWidth(3.0);
                g.strokeArc(cx - 11, cy - 11, 22, 22, 90, -360.0 * hold, ArcType.OPEN);
            }
        }
    }
}
