package com.officevpn.ui.components;

import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.ConnectionState;
import com.officevpn.ui.service.VpnModels.ThroughputSample;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.DoubleProperty;
import javafx.beans.property.IntegerProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.css.PseudoClass;
import javafx.geometry.Pos;
import javafx.scene.AccessibleRole;
import javafx.scene.Node;
import javafx.scene.canvas.Canvas;
import javafx.scene.canvas.GraphicsContext;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.Skin;
import javafx.scene.control.SkinBase;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;
import javafx.util.Duration;

import java.util.List;

/**
 * Dual-band throughput ribbon visualizing the last 60 seconds of tunnel traffic:
 * Catmull-Rom smoothed download (peacock) and upload (marigold) bands, an EKG-style
 * latency heartbeat strip, Fraunces rolling odometer numerals, and interactive hover/keyboard scrubbing.
 */
public final class PulseRibbon extends Control {

    private static final PseudoClass PC_LIVE = PseudoClass.getPseudoClass("live");

    private final ObservableList<ThroughputSample> series = FXCollections.observableArrayList();
    private final DoubleProperty downloadMbps = new SimpleDoubleProperty(0.0);
    private final DoubleProperty uploadMbps = new SimpleDoubleProperty(0.0);
    private final IntegerProperty latencyMs = new SimpleIntegerProperty(18);
    private final BooleanProperty connected = new SimpleBooleanProperty(false);

    public PulseRibbon() {
        getStyleClass().setAll("pulse-ribbon");
        setFocusTraversable(true);
        setAccessibleRole(AccessibleRole.TEXT);
        setMinSize(260, Region.USE_PREF_SIZE);

        connected.addListener((_, _, n) -> pseudoClassStateChanged(PC_LIVE, Boolean.TRUE.equals(n)));
    }

    public void bindService(VpnClientService service) {
        if (service == null) return;
        downloadMbps.bind(service.currentDownloadMbpsProperty());
        uploadMbps.bind(service.currentUploadMbpsProperty());
        latencyMs.bind(service.currentLatencyMsProperty());
        connected.bind(service.connectionStateProperty().isEqualTo(ConnectionState.CONNECTED));

        Runnable copy = () -> series.setAll(service.throughputSeries());
        service.throughputSeries().addListener((ListChangeListener<ThroughputSample>) _ -> copy.run());
        copy.run();
    }

    public static Node createStandaloneDemo(VpnClientService service) {
        PulseRibbon ribbon = new PulseRibbon();
        ribbon.bindService(service);
        return ribbon;
    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new PulseRibbonSkin(this);
    }

    public ObservableList<ThroughputSample> series() { return series; }
    public DoubleProperty downloadMbpsProperty() { return downloadMbps; }
    public DoubleProperty uploadMbpsProperty() { return uploadMbps; }
    public IntegerProperty latencyMsProperty() { return latencyMs; }
    public BooleanProperty connectedProperty() { return connected; }

    /**
     * Vertical rolling odometer digit display using bundled Fraunces numerals.
     */
    private static final class OdometerMetric extends HBox {
        private final Label wholeLabel = new Label("0");
        private final Label dotDecimal = new Label(".0");
        private final Label unitLabel;
        private double displayedValue = 0.0;
        private Timeline rollAnim;
        private final DoubleProperty animatedNumber = new SimpleDoubleProperty(0.0);

        OdometerMetric(String prefix, Color inkColor, String unit) {
            setAlignment(Pos.BASELINE_LEFT);
            setSpacing(2);

            Label arrow = new Label(prefix);
            arrow.setFont(Fonts.uiBold(13));
            arrow.setTextFill(inkColor);

            wholeLabel.setFont(Fonts.displaySemiBold(24));
            wholeLabel.setTextFill(Tokens.INK);
            dotDecimal.setFont(Fonts.displayRegular(16));
            dotDecimal.setTextFill(Tokens.SOFT_INK);

            unitLabel = new Label(" " + unit);
            unitLabel.setFont(Fonts.monoMedium(11));
            unitLabel.setTextFill(Tokens.SOFT_INK);

            StackPane roller = new StackPane(wholeLabel);
            Rectangle clip = new Rectangle(84, 34);
            roller.setClip(clip);

            animatedNumber.addListener((_, _, n) -> updateText(n.doubleValue()));
            getChildren().addAll(arrow, roller, dotDecimal, unitLabel);
        }

        void setTarget(double value) {
            setTarget(value, false);
        }

        void setTarget(double value, boolean immediate) {
            if (!immediate && Math.abs(value - displayedValue) < 0.05) return;
            double delta = value - displayedValue;
            displayedValue = value;
            if (immediate || Motion.isReduceMotion()) {
                animatedNumber.set(value);
                updateText(value);
                wholeLabel.setTranslateY(0);
                return;
            }
            if (rollAnim != null) rollAnim.stop();
            double startY = delta >= 0 ? 7.0 : -7.0;
            wholeLabel.setTranslateY(startY);
            rollAnim = new Timeline(
                    new KeyFrame(Duration.ZERO,
                            new KeyValue(wholeLabel.translateYProperty(), startY),
                            new KeyValue(animatedNumber, animatedNumber.get())),
                    new KeyFrame(Motion.FAST,
                            new KeyValue(wholeLabel.translateYProperty(), 0.0, Motion.spring()),
                            new KeyValue(animatedNumber, value))
            );
            rollAnim.play();
        }

        private void updateText(double v) {
            double clamped = Math.max(0.0, v);
            int whole = (int) clamped;
            int dec = (int) Math.round((clamped - whole) * 10.0);
            if (dec >= 10) {
                whole++;
                dec = 0;
            }
            wholeLabel.setText(Integer.toString(whole));
            dotDecimal.setText("." + dec);
        }
    }

    private static final class PulseRibbonSkin extends SkinBase<PulseRibbon> {

        private final VBox root = new VBox(10);
        private final OdometerMetric downMetric = new OdometerMetric("↓", Tokens.PEACOCK_TEXT, "Mbps");
        private final OdometerMetric upMetric = new OdometerMetric("↑", Tokens.MARIGOLD_TEXT, "Mbps");
        private final Label rttPill = new Label("18 ms RTT");
        private final Label scrubReadout = new Label("60s live ribbon");

        private final StackPane canvasBox = new StackPane();
        private final Canvas chartCanvas = new Canvas(560, 145);
        private int scrubIndex = -1;

        PulseRibbonSkin(PulseRibbon control) {
            super(control);

            Label title = new Label("Pulse Ribbon");
            title.getStyleClass().add("ia-card-title");
            title.setMinWidth(Region.USE_PREF_SIZE);

            rttPill.getStyleClass().addAll("ia-pill", "ia-pill-peacock");
            rttPill.setFont(Fonts.monoMedium(11));
            rttPill.setMinWidth(Region.USE_PREF_SIZE);

            scrubReadout.getStyleClass().add("ia-mono-soft");

            Region sp = new Region();
            HBox.setHgrow(sp, Priority.ALWAYS);

            HBox topBar = new HBox(10, title, scrubReadout, sp, rttPill);
            topBar.setAlignment(Pos.CENTER_LEFT);

            HBox countersRow = new HBox(18, downMetric, upMetric);
            countersRow.setAlignment(Pos.CENTER_LEFT);

            chartCanvas.setManaged(false);
            canvasBox.setMinSize(0, 138);
            canvasBox.setPrefHeight(152);
            canvasBox.setStyle("-fx-background-color: #FBF8F1; -fx-background-radius: 12px; -fx-border-color: #E6DCC6; -fx-border-radius: 12px;");
            canvasBox.getChildren().add(chartCanvas);
            VBox.setVgrow(canvasBox, Priority.ALWAYS);

            root.getChildren().addAll(topBar, countersRow, canvasBox);
            getChildren().add(root);

            control.downloadMbpsProperty().addListener((_, _, n) -> downMetric.setTarget(n.doubleValue()));
            control.uploadMbpsProperty().addListener((_, _, n) -> upMetric.setTarget(n.doubleValue()));
            control.latencyMsProperty().addListener((_, _, n) -> {
                rttPill.setText(n.intValue() + " ms RTT");
                control.setAccessibleText("Pulse Ribbon throughput down " + control.downloadMbpsProperty().get()
                        + " Mbps, up " + control.uploadMbpsProperty().get() + " Mbps, latency " + n.intValue() + " ms");
            });

            control.series().addListener((ListChangeListener<ThroughputSample>) _ -> drawChart());
            canvasBox.widthProperty().addListener((_, _, n) -> {
                chartCanvas.setWidth(Math.max(120, n.doubleValue() - 6));
                chartCanvas.relocate(3, 3);
                drawChart();
            });
            canvasBox.heightProperty().addListener((_, _, n) -> {
                chartCanvas.setHeight(Math.max(96, n.doubleValue() - 6));
                chartCanvas.relocate(3, 3);
                drawChart();
            });

            chartCanvas.setOnMouseMoved(e -> {
                List<ThroughputSample> pts = getSkinnable().series();
                if (pts.size() < 2) return;
                double w = Math.max(1.0, chartCanvas.getWidth() - 24);
                double rel = Math.max(0.0, Math.min(1.0, (e.getX() - 12.0) / w));
                scrubIndex = (int) Math.round(rel * (pts.size() - 1));
                updateScrubReadout(pts);
                drawChart();
            });
            chartCanvas.setOnMouseExited(_ -> {
                scrubIndex = -1;
                scrubReadout.setText("60s live ribbon");
                drawChart();
            });

            control.addEventHandler(KeyEvent.KEY_PRESSED, e -> {
                List<ThroughputSample> pts = getSkinnable().series();
                if (pts.isEmpty()) return;
                if (e.getCode() == KeyCode.LEFT) {
                    scrubIndex = scrubIndex < 0 ? pts.size() - 1 : Math.max(0, scrubIndex - 2);
                    updateScrubReadout(pts);
                    drawChart();
                    e.consume();
                } else if (e.getCode() == KeyCode.RIGHT) {
                    scrubIndex = scrubIndex < 0 ? 0 : Math.min(pts.size() - 1, scrubIndex + 2);
                    updateScrubReadout(pts);
                    drawChart();
                    e.consume();
                }
            });

            downMetric.setTarget(control.downloadMbpsProperty().get(), true);
            upMetric.setTarget(control.uploadMbpsProperty().get(), true);
            rttPill.setText(control.latencyMsProperty().get() + " ms RTT");
            drawChart();
        }

        private void updateScrubReadout(List<ThroughputSample> pts) {
            if (scrubIndex < 0 || scrubIndex >= pts.size()) return;
            ThroughputSample s = pts.get(scrubIndex);
            int secAgo = pts.size() - 1 - scrubIndex;
            scrubReadout.setText(String.format("-%ds • ↓%.1f ↑%.1f Mbps • %dms",
                    secAgo, s.downloadMbps(), s.uploadMbps(), s.latencyMs()));
        }

        private void drawChart() {
            double w = chartCanvas.getWidth();
            double h = chartCanvas.getHeight();
            if (w <= 40 || h <= 40) return;

            GraphicsContext g = chartCanvas.getGraphicsContext2D();
            g.clearRect(0, 0, w, h);

            List<ThroughputSample> pts = getSkinnable().series();
            if (pts.size() < 2) return;

            double padX = 12.0;
            double plotW = w - padX * 2;
            double heartbeatH = 26.0;
            double ribbonTop = 10.0;
            double ribbonBot = h - heartbeatH - 12.0;
            double ribbonH = Math.max(36.0, ribbonBot - ribbonTop);

            // Hairline horizontal reference guide rules
            g.setStroke(Color.rgb(230, 220, 198, 0.7));
            g.setLineWidth(1.0);
            g.strokeLine(padX, ribbonTop + ribbonH * 0.5, padX + plotW, ribbonTop + ribbonH * 0.5);
            g.strokeLine(padX, ribbonBot, padX + plotW, ribbonBot);

            double maxMbps = 60.0;
            for (ThroughputSample s : pts) {
                maxMbps = Math.max(maxMbps, s.downloadMbps() * 1.15);
            }

            int n = pts.size();
            double[] xs = new double[n];
            double[] ysDown = new double[n];
            double[] ysUp = new double[n];
            for (int i = 0; i < n; i++) {
                ThroughputSample s = pts.get(i);
                xs[i] = padX + (i / (double) (n - 1)) * plotW;
                ysDown[i] = ribbonBot - (s.downloadMbps() / maxMbps) * ribbonH;
                ysUp[i] = ribbonBot - (s.uploadMbps() / maxMbps) * ribbonH;
            }

            // Draw Catmull-Rom area fills and crisp top ribbons
            drawCatmullArea(g, xs, ysDown, ribbonBot, Color.rgb(14, 159, 154, 0.16), Tokens.PEACOCK, 2.2);
            drawCatmullArea(g, xs, ysUp, ribbonBot, Color.rgb(255, 178, 36, 0.18), Tokens.MARIGOLD, 1.9);

            // Latency Heartbeat Strip along bottom
            double hbTop = h - heartbeatH;
            double hbBase = h - 7.0;
            g.setStroke(Tokens.LILAC);
            g.setLineWidth(1.4);
            for (int i = 0; i < n; i++) {
                double normLat = Math.min(1.0, Math.max(0.12, pts.get(i).latencyMs() / 60.0));
                double spike = normLat * (heartbeatH - 10.0);
                g.strokeLine(xs[i], hbBase, xs[i], hbBase - spike);
            }
            g.setFill(Tokens.SOFT_INK);
            g.setFont(Fonts.monoRegular(9.5));
            g.fillText("RTT PULSE", padX, hbTop + 9);

            // Interactive Scrubber cursor
            if (scrubIndex >= 0 && scrubIndex < n) {
                double sx = xs[scrubIndex];
                g.setStroke(Tokens.INK);
                g.setLineWidth(1.2);
                g.strokeLine(sx, ribbonTop, sx, hbBase);

                g.setFill(Tokens.PEACOCK);
                g.fillOval(sx - 4, ysDown[scrubIndex] - 4, 8, 8);
                g.setFill(Tokens.MARIGOLD);
                g.fillOval(sx - 4, ysUp[scrubIndex] - 4, 8, 8);

                // Floating paper callout pill
                ThroughputSample s = pts.get(scrubIndex);
                String tag = String.format("↓%.1f  ↑%.1f Mbps  (%dms)", s.downloadMbps(), s.uploadMbps(), s.latencyMs());
                double boxW = Math.min(198, Math.max(145, tag.length() * 6.5));
                double boxX = Math.max(padX, Math.min(w - boxW - padX, sx - boxW * 0.5));
                g.setFill(Tokens.PAPER);
                g.fillRoundRect(boxX, 4, boxW, 20, 8, 8);
                g.setStroke(Tokens.HAIRLINE);
                g.strokeRoundRect(boxX, 4, boxW, 20, 8, 8);
                g.setFill(Tokens.INK);
                g.setFont(Fonts.monoMedium(10.5));
                g.fillText(tag, boxX + 8, 17.5);
            }
        }

        private void drawCatmullArea(GraphicsContext g, double[] xs, double[] ys, double baseY,
                                     Color fillColor, Color strokeColor, double strokeW) {
            int n = xs.length;
            // Filled polygon along Catmull-Rom interpolation
            g.beginPath();
            g.moveTo(xs[0], baseY);
            g.lineTo(xs[0], ys[0]);
            traceCatmullSegments(g, xs, ys);
            g.lineTo(xs[n - 1], baseY);
            g.closePath();
            g.setFill(fillColor);
            g.fill();

            // Crisp top stroke
            g.beginPath();
            g.moveTo(xs[0], ys[0]);
            traceCatmullSegments(g, xs, ys);
            g.setStroke(strokeColor);
            g.setLineWidth(strokeW);
            g.stroke();
        }

        private void traceCatmullSegments(GraphicsContext g, double[] xs, double[] ys) {
            int n = xs.length;
            for (int i = 0; i < n - 1; i++) {
                int i0 = Math.max(0, i - 1);
                int i1 = i;
                int i2 = i + 1;
                int i3 = Math.min(n - 1, i + 2);

                double cp1x = xs[i1] + (xs[i2] - xs[i0]) / 6.0;
                double cp1y = ys[i1] + (ys[i2] - ys[i0]) / 6.0;
                double cp2x = xs[i2] - (xs[i3] - xs[i1]) / 6.0;
                double cp2y = ys[i2] - (ys[i3] - ys[i1]) / 6.0;
                g.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, xs[i2], ys[i2]);
            }
        }
    }
}
