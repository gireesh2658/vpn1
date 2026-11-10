package com.officevpn.ui.components;

import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.SplitAppItem;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.css.PseudoClass;
import javafx.geometry.Pos;
import javafx.scene.AccessibleRole;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.Skin;
import javafx.scene.control.SkinBase;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.Dragboard;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.input.TransferMode;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import org.kordamp.ikonli.feather.Feather;

import java.util.function.BiConsumer;

/**
 * SafetyLatches combining mechanical spring-bolt toggles (Kill Switch, Auto-Connect on
 * Untrusted Wi-Fi, DNS Leak Guard) with the interactive two-lane SplitLanes router where
 * application chips are dragged cleanly between "Through the tunnel" and "Straight out".
 */
public final class SafetyLatches extends Control {

    /**
     * Reusable mechanical latch toggle control with spring bolt physics and keyboard operation.
     */
    public static final class MechanicalLatch extends Control {
        private static final PseudoClass PC_ARMED = PseudoClass.getPseudoClass("armed");
        private final BooleanProperty armed = new SimpleBooleanProperty(true);
        private final boolean dangerAccent;

        public MechanicalLatch(boolean initialArmed, boolean dangerAccent, String accessibleName) {
            this.dangerAccent = dangerAccent;
            setFocusTraversable(true);
            setAccessibleRole(AccessibleRole.CHECK_BOX);
            setAccessibleText(accessibleName);
            setMinSize(60, 30);
            setMaxSize(60, 30);
            armed.set(initialArmed);
            armed.addListener((_, _, n) -> pseudoClassStateChanged(PC_ARMED, Boolean.TRUE.equals(n)));
            pseudoClassStateChanged(PC_ARMED, initialArmed);
        }

        public BooleanProperty armedProperty() { return armed; }
        public boolean isDangerAccent() { return dangerAccent; }

        public void toggle() {
            armed.set(!armed.get());
        }

        @Override
        protected Skin<?> createDefaultSkin() {
            return new MechanicalLatchSkin(this);
        }
    }

    private static final class MechanicalLatchSkin extends SkinBase<MechanicalLatch> {
        private final StackPane track = new StackPane();
        private final Region bolt = new Region();
        private final DoubleProperty boltPos = new SimpleDoubleProperty(0.0);
        private Timeline boltAnim;

        MechanicalLatchSkin(MechanicalLatch control) {
            super(control);
            track.setMinSize(60, 30);
            track.setMaxSize(60, 30);
            bolt.setMinSize(22, 22);
            bolt.setMaxSize(22, 22);
            bolt.setManaged(false);
            bolt.setStyle("-fx-background-color: #FFFFFF; -fx-background-radius: 7px; -fx-border-color: #D6C9B0; -fx-border-radius: 7px;");
            bolt.setEffect(Tokens.createContactShadow());

            // Grip notch accent inside bolt
            Region notch = new Region();
            notch.setMaxSize(2, 10);
            notch.setStyle("-fx-background-color: #D7CCB5; -fx-background-radius: 1px;");
            StackPane.setAlignment(notch, Pos.CENTER);

            Pane host = new Pane(track, bolt);
            host.setMinSize(60, 30);
            host.setMaxSize(60, 30);
            getChildren().add(host);

            Runnable paintState = () -> {
                boolean isArmed = control.armedProperty().get();
                String trackColor = !isArmed ? "#F2EBDC"
                        : (control.isDangerAccent() ? "#0E9F9A" : "#FFB224");
                String border = !isArmed ? "#E6DCC6" : (control.isDangerAccent() ? "#096B67" : "#D69111");
                track.setStyle("-fx-background-color: " + trackColor + "; -fx-background-radius: 10px; -fx-border-color: " + border + "; -fx-border-radius: 10px;");
            };

            boltPos.addListener((_, _, n) -> {
                double x = 4.0 + n.doubleValue() * 30.0;
                bolt.resizeRelocate(x, 4.0, 22.0, 22.0);
            });

            control.armedProperty().addListener((_, _, n) -> {
                paintState.run();
                double target = Boolean.TRUE.equals(n) ? 1.0 : 0.0;
                if (boltAnim != null) boltAnim.stop();
                if (Motion.isReduceMotion()) {
                    boltPos.set(target);
                } else {
                    boltAnim = new Timeline(new KeyFrame(Motion.FAST,
                            new KeyValue(boltPos, target, Motion.spring())));
                    boltAnim.play();
                }
            });

            boltPos.set(control.armedProperty().get() ? 1.0 : 0.0);
            paintState.run();

            host.setOnMouseClicked(e -> {
                control.requestFocus();
                control.toggle();
                e.consume();
            });
            control.addEventHandler(KeyEvent.KEY_PRESSED, e -> {
                if (e.getCode() == KeyCode.SPACE || e.getCode() == KeyCode.ENTER) {
                    control.toggle();
                    e.consume();
                }
            });
        }
    }

    private final BooleanProperty killSwitch = new SimpleBooleanProperty(true);
    private final BooleanProperty autoConnectUntrustedWifi = new SimpleBooleanProperty(true);
    private final BooleanProperty dnsLeakGuard = new SimpleBooleanProperty(true);
    private final ObservableList<SplitAppItem> splitApps = FXCollections.observableArrayList();
    private final ObjectProperty<BiConsumer<String, Boolean>> onMoveSplitApp = new SimpleObjectProperty<>((_, _) -> {});

    public SafetyLatches() {
        getStyleClass().setAll("safety-latches");
        setFocusTraversable(false);
        setAccessibleRole(AccessibleRole.PARENT);
        setAccessibleText("Safety Latches and Split-Tunnel Application Lanes");
    }

    public void bindService(VpnClientService service) {
        if (service == null) return;
        killSwitch.bindBidirectional(service.killSwitchEnabledProperty());
        autoConnectUntrustedWifi.bindBidirectional(service.autoConnectUntrustedWifiProperty());
        dnsLeakGuard.bindBidirectional(service.dnsLeakGuardProperty());

        Runnable syncApps = () -> splitApps.setAll(service.splitApps());
        service.splitApps().addListener((ListChangeListener<SplitAppItem>) _ -> syncApps.run());
        syncApps.run();
        onMoveSplitApp.set(service::moveSplitApp);
    }

    public static Node createStandaloneDemo(VpnClientService service) {
        SafetyLatches sl = new SafetyLatches();
        sl.bindService(service);
        return sl;
    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new SafetyLatchesSkin(this);
    }

    public BooleanProperty killSwitchProperty() { return killSwitch; }
    public BooleanProperty autoConnectUntrustedWifiProperty() { return autoConnectUntrustedWifi; }
    public BooleanProperty dnsLeakGuardProperty() { return dnsLeakGuard; }
    public ObservableList<SplitAppItem> splitApps() { return splitApps; }
    public ObjectProperty<BiConsumer<String, Boolean>> onMoveSplitAppProperty() { return onMoveSplitApp; }

    private static final class SafetyLatchesSkin extends SkinBase<SafetyLatches> {

        private final VBox root = new VBox(16);
        private final VBox tunnelCards = new VBox(8);
        private final VBox bypassCards = new VBox(8);

        SafetyLatchesSkin(SafetyLatches control) {
            super(control);

            Label latchesTitle = new Label("Mechanical Safety Latches");
            latchesTitle.getStyleClass().add("ia-card-title");

            VBox latchList = new VBox(10,
                    createLatchRow("Kill Switch", Feather.SHIELD_OFF,
                            "Blocks all non-tunnel traffic when gateway connectivity drops.",
                            "Armed • Egress sealed on drop", "Disarmed • Fallback allowed",
                            control.killSwitchProperty(), true),
                    createLatchRow("Untrusted Wi-Fi Auto-Shield", Feather.WIFI,
                            "Automatically swipes keycard when joining open airport or cafe SSIDs.",
                            "Auto-connect armed", "Manual connection only",
                            control.autoConnectUntrustedWifiProperty(), false),
                    createLatchRow("DNS Leak Guard (10.8.0.1)", Feather.GLOBE,
                            "Forwards *.office.local and internal lookups strictly inside tunnel.",
                            "Enforced • 10.8.0.1 DNS", "System OS resolver active",
                            control.dnsLeakGuardProperty(), true)
            );

            // SplitLanes section
            Label splitTitle = new Label("SplitLanes — Application Routing");
            splitTitle.getStyleClass().add("ia-card-title");
            Label splitSub = new Label("Drag any app chip between lanes or click arrow controls.");
            splitSub.getStyleClass().add("ia-subtitle");

            VBox tunnelLane = buildLaneColumn("Through the tunnel", "ia-pill-peacock", tunnelCards, true);
            VBox bypassLane = buildLaneColumn("Straight out", "ia-pill-sand", bypassCards, false);
            HBox.setHgrow(tunnelLane, Priority.ALWAYS);
            HBox.setHgrow(bypassLane, Priority.ALWAYS);

            HBox lanesRow = new HBox(14, tunnelLane, bypassLane);
            root.getChildren().addAll(latchesTitle, latchList, splitTitle, splitSub, lanesRow);
            getChildren().add(root);

            control.splitApps().addListener((ListChangeListener<SplitAppItem>) _ -> rebuildSplitChips());
            rebuildSplitChips();
        }

        private HBox createLatchRow(
                String name, Feather icon, String desc,
                String armedCaption, String disarmedCaption,
                BooleanProperty prop, boolean peacockWhenArmed
        ) {
            MechanicalLatch latch = new MechanicalLatch(prop.get(), peacockWhenArmed, name);
            latch.armedProperty().bindBidirectional(prop);

            Label title = new Label(name);
            title.setFont(Fonts.uiSemiBold(13.5));
            title.setTextFill(Tokens.INK);

            Label caption = new Label(prop.get() ? armedCaption : disarmedCaption);
            caption.getStyleClass().addAll("ia-pill", prop.get() ? "ia-pill-peacock" : "ia-pill-sand");
            prop.addListener((_, _, n) -> {
                caption.setText(Boolean.TRUE.equals(n) ? armedCaption : disarmedCaption);
                caption.getStyleClass().removeAll("ia-pill-peacock", "ia-pill-sand");
                caption.getStyleClass().add(Boolean.TRUE.equals(n) ? "ia-pill-peacock" : "ia-pill-sand");
            });

            HBox titleRow = new HBox(8, Icons.ink(icon, 15), title, caption);
            titleRow.setAlignment(Pos.CENTER_LEFT);

            Label descLbl = new Label(desc);
            descLbl.getStyleClass().add("ia-subtitle");
            descLbl.setWrapText(true);

            VBox textCol = new VBox(4, titleRow, descLbl);
            HBox.setHgrow(textCol, Priority.ALWAYS);

            HBox row = new HBox(14, textCol, latch);
            row.getStyleClass().add("latch-row");
            row.setAlignment(Pos.CENTER_LEFT);
            return row;
        }

        private VBox buildLaneColumn(String title, String badgeClass, VBox cardsTarget, boolean targetTunnelState) {
            Label badge = new Label(title);
            badge.getStyleClass().addAll("ia-pill", badgeClass);

            VBox lane = new VBox(10, badge, cardsTarget);
            lane.getStyleClass().add("split-lane");
            lane.setMinHeight(210);

            lane.setOnDragOver(e -> {
                if (e.getDragboard().hasString()) {
                    e.acceptTransferModes(TransferMode.MOVE);
                    if (!lane.getStyleClass().contains("split-lane-drop-active")) {
                        lane.getStyleClass().add("split-lane-drop-active");
                    }
                }
                e.consume();
            });
            lane.setOnDragExited(_ -> lane.getStyleClass().remove("split-lane-drop-active"));
            lane.setOnDragDropped(e -> {
                Dragboard db = e.getDragboard();
                boolean ok = false;
                if (db.hasString()) {
                    String appId = db.getString();
                    var cb = getSkinnable().onMoveSplitAppProperty().get();
                    if (cb != null) cb.accept(appId, targetTunnelState);
                    ok = true;
                }
                lane.getStyleClass().remove("split-lane-drop-active");
                e.setDropCompleted(ok);
                e.consume();
            });
            return lane;
        }

        private void rebuildSplitChips() {
            tunnelCards.getChildren().clear();
            bypassCards.getChildren().clear();
            for (SplitAppItem item : getSkinnable().splitApps()) {
                HBox chip = buildAppChip(item);
                if (item.throughTunnel()) {
                    tunnelCards.getChildren().add(chip);
                } else {
                    bypassCards.getChildren().add(chip);
                }
            }
        }

        private HBox buildAppChip(SplitAppItem item) {
            Label name = new Label(item.displayName());
            name.setFont(Fonts.uiSemiBold(12.5));
            name.setTextFill(Tokens.INK);

            Label proc = new Label(item.processHint());
            proc.setFont(Fonts.monoRegular(10.5));
            proc.setTextFill(Tokens.SOFT_INK);

            VBox meta = new VBox(1, name, proc);
            Region sp = new Region();
            HBox.setHgrow(sp, Priority.ALWAYS);

            Button moveBtn = new Button();
            moveBtn.setGraphic(Icons.ink(item.throughTunnel() ? Feather.ARROW_RIGHT : Feather.ARROW_LEFT, 13));
            moveBtn.setAccessibleText("Move " + item.displayName()
                    + (item.throughTunnel() ? " straight out" : " through tunnel"));
            moveBtn.setOnAction(_ -> {
                var cb = getSkinnable().onMoveSplitAppProperty().get();
                if (cb != null) cb.accept(item.appId(), !item.throughTunnel());
            });

            HBox chip = new HBox(8, Icons.soft(Feather.BOX, 14), meta, sp, moveBtn);
            chip.getStyleClass().add("split-app-chip");
            chip.setAlignment(Pos.CENTER_LEFT);
            chip.setOnDragDetected(e -> {
                Dragboard db = chip.startDragAndDrop(TransferMode.MOVE);
                ClipboardContent content = new ClipboardContent();
                content.putString(item.appId());
                db.setContent(content);
                e.consume();
            });
            return chip;
        }
    }
}
