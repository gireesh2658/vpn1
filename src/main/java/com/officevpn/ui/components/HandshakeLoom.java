package com.officevpn.ui.components;

import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.ConnectionState;
import com.officevpn.ui.service.VpnModels.HandshakeStation;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.beans.property.IntegerProperty;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.css.CssMetaData;
import javafx.css.PseudoClass;
import javafx.css.SimpleStyleableDoubleProperty;
import javafx.css.Styleable;
import javafx.css.StyleableDoubleProperty;
import javafx.css.StyleablePropertyFactory;
import javafx.geometry.Pos;
import javafx.scene.AccessibleRole;
import javafx.scene.Node;
import javafx.scene.canvas.Canvas;
import javafx.scene.canvas.GraphicsContext;
import javafx.scene.control.Button;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.Skin;
import javafx.scene.control.SkinBase;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.StrokeLineCap;
import org.kordamp.ikonli.feather.Feather;

import java.util.List;

/**
 * Five-station handshake loom visualizing the corporate tunnel negotiation thread:
 * (1) Reach gateway, (2) Exchange keys, (3) Verify identity, (4) Check posture, (5) Tunnel open.
 * <p>
 * Stamped circular seals fill sequentially beside a cipher badge; handshake faults render a
 * frayed coral thread at the failing station with an inline Retry trigger.
 */
public final class HandshakeLoom extends Control {

    private static final StyleablePropertyFactory<HandshakeLoom> FACTORY =
            new StyleablePropertyFactory<>(Control.getClassCssMetaData());

    private static final CssMetaData<HandshakeLoom, Number> SEAL_RADIUS_META =
            FACTORY.createSizeCssMetaData("-ia-seal-radius", s -> s.sealRadius, 14.0);

    private static final PseudoClass PC_RUNNING  = PseudoClass.getPseudoClass("running");
    private static final PseudoClass PC_COMPLETE = PseudoClass.getPseudoClass("complete");
    private static final PseudoClass PC_FAILED   = PseudoClass.getPseudoClass("failed");

    private final StyleableDoubleProperty sealRadius =
            new SimpleStyleableDoubleProperty(SEAL_RADIUS_META, this, "sealRadius", 14.0);

    private final IntegerProperty completedStations = new SimpleIntegerProperty(0);
    private final ObjectProperty<HandshakeStation> failedStation = new SimpleObjectProperty<>(null);
    private final StringProperty failureReason = new SimpleStringProperty("");
    private final StringProperty cipherSuite = new SimpleStringProperty("AES-256-GCM • ECDH P-256");
    private final ObjectProperty<Runnable> onRetryRequested = new SimpleObjectProperty<>(() -> {});

    public HandshakeLoom() {
        getStyleClass().setAll("handshake-loom");
        setFocusTraversable(true);
        setAccessibleRole(AccessibleRole.PROGRESS_INDICATOR);
        setMinSize(260, Region.USE_PREF_SIZE);

        completedStations.addListener((obs, o, n) -> syncPseudoClasses());
        failedStation.addListener((obs, o, n) -> syncPseudoClasses());
        syncPseudoClasses();
    }

    public void bindService(VpnClientService service) {
        if (service == null) return;
        completedStations.bind(service.handshakeStepIndexProperty());
        failedStation.bind(service.handshakeFailedStationProperty());
        failureReason.bind(service.handshakeFailureReasonProperty());
        cipherSuite.bind(service.cipherSuiteProperty());
        onRetryRequested.set(service::retryHandshake);
    }

    public static Node createStandaloneDemo(VpnClientService service) {
        HandshakeLoom loom = new HandshakeLoom();
        loom.bindService(service);
        return loom;
    }

    private void syncPseudoClasses() {
        HandshakeStation fail = failedStation.get();
        int step = completedStations.get();
        pseudoClassStateChanged(PC_FAILED, fail != null);
        pseudoClassStateChanged(PC_COMPLETE, fail == null && step >= HandshakeStation.values().length);
        pseudoClassStateChanged(PC_RUNNING, fail == null && step > 0 && step < HandshakeStation.values().length);
        setAccessibleText("Handshake Loom: " + (fail != null
                ? "Failed at " + fail.label() + ". " + failureReason.get()
                : step + " of 5 stations verified using " + cipherSuite.get()));
    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new HandshakeLoomSkin(this);
    }

    public static List<CssMetaData<? extends Styleable, ?>> getClassCssMetaData() {
        return FACTORY.getCssMetaData();
    }

    @Override
    public List<CssMetaData<? extends Styleable, ?>> getControlCssMetaData() {
        return getClassCssMetaData();
    }

    public IntegerProperty completedStationsProperty() { return completedStations; }
    public ObjectProperty<HandshakeStation> failedStationProperty() { return failedStation; }
    public StringProperty failureReasonProperty() { return failureReason; }
    public StringProperty cipherSuiteProperty() { return cipherSuite; }
    public ObjectProperty<Runnable> onRetryRequestedProperty() { return onRetryRequested; }
    public StyleableDoubleProperty sealRadiusProperty() { return sealRadius; }

    private static final class HandshakeLoomSkin extends SkinBase<HandshakeLoom> {

        private final VBox root = new VBox(8);
        private final Label cipherChip = new Label();
        private final Label errorBanner = new Label();
        private final Button retryBtn = new Button("Retry");
        private final HBox failureRow = new HBox(10);
        private final javafx.scene.layout.Pane loomPane = new javafx.scene.layout.Pane();
        private final Canvas loomCanvas = new Canvas();

        private double weavePhase = 0.0;

        HandshakeLoomSkin(HandshakeLoom control) {
            super(control);

            Label title = new Label("Handshake Loom");
            title.getStyleClass().add("ia-card-title");
            title.setMinWidth(Region.USE_PREF_SIZE);

            cipherChip.textProperty().bind(control.cipherSuiteProperty());
            cipherChip.getStyleClass().addAll("ia-pill", "ia-pill-peacock");
            cipherChip.setFont(Fonts.monoMedium(11));
            cipherChip.setMinWidth(Region.USE_PREF_SIZE);

            Region spacer = new Region();
            HBox.setHgrow(spacer, Priority.ALWAYS);

            HBox topBar = new HBox(10, title, spacer, cipherChip);
            topBar.setAlignment(Pos.CENTER_LEFT);

            loomCanvas.setManaged(false);
            loomPane.setMinSize(0, 62);
            loomPane.setPrefHeight(62);
            loomPane.setMaxWidth(Double.MAX_VALUE);
            loomPane.getChildren().add(loomCanvas);
            loomPane.widthProperty().addListener((obs, o, n) -> {
                loomCanvas.setWidth(Math.max(120, n.doubleValue()));
                loomCanvas.setHeight(62);
                drawLoom();
            });

            errorBanner.getStyleClass().add("ia-subtitle");
            errorBanner.setTextFill(Tokens.CORAL_TEXT);
            errorBanner.textProperty().bind(control.failureReasonProperty());

            retryBtn.getStyleClass().add("ia-btn-coral");
            retryBtn.setGraphic(Icons.coral(Feather.REFRESH_CW, 13));
            retryBtn.setOnAction(e -> {
                Runnable r = control.onRetryRequestedProperty().get();
                if (r != null) r.run();
            });

            Region failSpacer = new Region();
            HBox.setHgrow(failSpacer, Priority.ALWAYS);
            failureRow.setAlignment(Pos.CENTER_LEFT);
            failureRow.getChildren().addAll(Icons.coral(Feather.ALERT_CIRCLE, 14), errorBanner, failSpacer, retryBtn);

            root.getChildren().addAll(topBar, loomPane, failureRow);
            getChildren().add(root);

            Motion.CappedAnimationTimer timer = new Motion.CappedAnimationTimer(control) {
                @Override
                protected void onTick(long nowNs, double dtSeconds) {
                    int completed = control.completedStationsProperty().get();
                    if (completed > 0 && completed < HandshakeStation.values().length
                            && control.failedStationProperty().get() == null) {
                        weavePhase = (weavePhase + dtSeconds * 4.5) % (Math.PI * 2.0);
                        drawLoom();
                    }
                }
            };
            timer.bind();

            control.completedStationsProperty().addListener((obs, o, n) -> drawLoom());
            control.failedStationProperty().addListener((obs, o, n) -> syncFailureRow());
            control.sealRadiusProperty().addListener((obs, o, n) -> drawLoom());

            syncFailureRow();
            drawLoom();
        }

        private void syncFailureRow() {
            boolean failed = getSkinnable().failedStationProperty().get() != null;
            failureRow.setVisible(failed);
            failureRow.setManaged(failed);
            drawLoom();
        }

        private void drawLoom() {
            double w = loomCanvas.getWidth();
            double h = loomCanvas.getHeight();
            if (w <= 20) return;

            GraphicsContext g = loomCanvas.getGraphicsContext2D();
            g.clearRect(0, 0, w, h);

            HandshakeStation[] stations = HandshakeStation.values();
            int completed = getSkinnable().completedStationsProperty().get();
            HandshakeStation failed = getSkinnable().failedStationProperty().get();
            int failIdx = failed != null ? failed.ordinal() : -1;

            double r = getSkinnable().sealRadiusProperty().get();
            double padX = Math.max(46.0, w * 0.08);
            double span = Math.max(80.0, w - padX * 2.0);
            double stepX = span / (stations.length - 1);
            double cy = 22.0;

            // Draw connecting threads between stations
            for (int i = 0; i < stations.length - 1; i++) {
                double x1 = padX + i * stepX + r + 2;
                double x2 = padX + (i + 1) * stepX - r - 2;
                if (x2 <= x1) continue;

                if (failIdx == i + 1) {
                    // Frayed coral broken thread
                    g.setStroke(Tokens.CORAL);
                    g.setLineWidth(2.2);
                    double mid = (x1 + x2) * 0.5;
                    g.strokeLine(x1, cy, mid - 6, cy - 4);
                    g.strokeLine(mid - 6, cy - 4, mid - 2, cy + 4);
                    g.strokeLine(mid + 4, cy - 3, x2, cy);
                } else if (i < completed) {
                    g.setStroke(Tokens.PEACOCK);
                    g.setLineWidth(2.4);
                    g.strokeLine(x1, cy, x2, cy);
                } else {
                    g.setStroke(Tokens.HAIRLINE);
                    g.setLineWidth(2.0);
                    g.setLineDashes(4, 4);
                    g.strokeLine(x1, cy, x2, cy);
                    g.setLineDashes((double[]) null);
                }
            }

            // Draw stamped seals + station captions
            for (int i = 0; i < stations.length; i++) {
                double cx = padX + i * stepX;
                boolean isDone = i < completed && (failIdx == -1 || i < failIdx);
                boolean isFail = (failIdx == i);
                boolean isActive = (failIdx == -1 && i == completed && completed > 0 && completed < stations.length);

                Color fill;
                Color ring;
                Color glyphColor;

                if (isFail) {
                    fill = Tokens.CORAL_WASH;
                    ring = Tokens.CORAL;
                    glyphColor = Tokens.CORAL_TEXT;
                } else if (isDone) {
                    fill = Tokens.PEACOCK;
                    ring = Tokens.PEACOCK;
                    glyphColor = Color.WHITE;
                } else if (isActive) {
                    fill = Tokens.MARIGOLD_WASH;
                    ring = Tokens.MARIGOLD;
                    glyphColor = Tokens.MARIGOLD_TEXT;
                } else {
                    fill = Tokens.PAPER;
                    ring = Tokens.HAIRLINE;
                    glyphColor = Tokens.SOFT_INK;
                }

                if (isActive) {
                    double pulse = 1.0 + 0.16 * Math.sin(weavePhase);
                    g.setStroke(Color.rgb(255, 178, 36, 0.35));
                    g.setLineWidth(3.0);
                    g.strokeOval(cx - r * pulse - 2, cy - r * pulse - 2, (r * pulse + 2) * 2, (r * pulse + 2) * 2);
                }

                g.setFill(fill);
                g.fillOval(cx - r, cy - r, r * 2, r * 2);
                g.setStroke(ring);
                g.setLineWidth(1.8);
                g.strokeOval(cx - r, cy - r, r * 2, r * 2);

                g.setStroke(glyphColor);
                g.setLineWidth(2.0);
                g.setLineCap(StrokeLineCap.ROUND);
                if (isDone) {
                    g.strokeLine(cx - 4.5, cy + 0.5, cx - 1.2, cy + 4.0);
                    g.strokeLine(cx - 1.2, cy + 4.0, cx + 5.0, cy - 3.5);
                } else if (isFail) {
                    g.strokeLine(cx - 4.0, cy - 4.0, cx + 4.0, cy + 4.0);
                    g.strokeLine(cx - 4.0, cy + 4.0, cx + 4.0, cy - 4.0);
                } else {
                    g.setFill(glyphColor);
                    g.setFont(Fonts.monoBold(11));
                    String num = Integer.toString(i + 1);
                    g.fillText(num, cx - 3.5, cy + 4.0);
                }

                // Station caption below
                String lbl = stations[i].label();
                g.setFont(isDone || isActive ? Fonts.uiSemiBold(11) : Fonts.uiRegular(11));
                g.setFill(isFail ? Tokens.CORAL_TEXT : (isDone || isActive ? Tokens.INK : Tokens.SOFT_INK));
                double textWidth = lbl.length() * 5.6;
                g.fillText(lbl, Math.max(4, Math.min(w - textWidth - 4, cx - textWidth * 0.5)), cy + r + 17);
            }
        }
    }
}
