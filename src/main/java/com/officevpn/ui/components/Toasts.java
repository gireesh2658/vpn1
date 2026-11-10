package com.officevpn.ui.components;

import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.animation.FadeTransition;
import javafx.animation.PauseTransition;
import javafx.animation.TranslateTransition;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.util.Duration;
import org.kordamp.ikonli.feather.Feather;

/**
 * Paper-slip Toasts notification stack that anchors cleanly in a window corner,
 * slides in with damped spring choreography, pauses auto-dismiss on hover, and uses
 * strictly light opaque paper surfaces.
 */
public final class Toasts extends VBox {

    public enum Severity {
        INFO(Tokens.LILAC_HEX, Feather.INFO, Tokens.LILAC),
        SUCCESS(Tokens.PEACOCK_HEX, Feather.CHECK_CIRCLE, Tokens.PEACOCK),
        WARNING(Tokens.MARIGOLD_HEX, Feather.ALERT_CIRCLE, Tokens.MARIGOLD),
        ERROR(Tokens.CORAL_HEX, Feather.ALERT_TRIANGLE, Tokens.CORAL);

        private final String accentHex;
        private final Feather glyph;
        private final javafx.scene.paint.Color iconColor;

        Severity(String accentHex, Feather glyph, javafx.scene.paint.Color iconColor) {
            this.accentHex = accentHex;
            this.glyph = glyph;
            this.iconColor = iconColor;
        }
    }

    public Toasts() {
        setSpacing(8);
        setPadding(new Insets(16));
        setAlignment(Pos.BOTTOM_RIGHT);
        setPickOnBounds(false);
        setMaxSize(360, USE_PREF_SIZE);
        StackPane.setAlignment(this, Pos.BOTTOM_RIGHT);
    }

    /**
     * Pushes a paper-slip toast notification with automatic timeout (paused on hover).
     */
    public HBox push(Severity severity, String title, String message) {
        HBox slip = buildSlip(severity, title, message, null);
        getChildren().add(slip);
        while (getChildren().size() > 4) {
            getChildren().remove(0);
        }

        if (!Motion.isReduceMotion()) {
            slip.setTranslateX(32);
            slip.setOpacity(0);
            TranslateTransition slide = new TranslateTransition(Motion.MEDIUM, slip);
            slide.setToX(0);
            slide.setInterpolator(Motion.spring());
            FadeTransition fade = new FadeTransition(Motion.MEDIUM, slip);
            fade.setToValue(1.0);
            slide.play();
            fade.play();
        }

        PauseTransition autoHide = new PauseTransition(Duration.seconds(4.2));
        autoHide.setOnFinished(_ -> dismissSlip(slip));
        slip.hoverProperty().addListener((_, _, hovered) -> {
            if (Boolean.TRUE.equals(hovered)) autoHide.pause();
            else autoHide.play();
        });
        autoHide.play();
        return slip;
    }

    /**
     * Builds a static standalone slip node suitable for ComponentGallery / PreviewExporter inspection.
     */
    public static Node createStandaloneDemo() {
        VBox box = new VBox(10);
        Toasts host = new Toasts();
        box.getChildren().addAll(
                host.buildSlip(Severity.SUCCESS, "Keycard Authenticated", "Tunnel open to Munich Core 01 (AES-256-GCM).", () -> {}),
                host.buildSlip(Severity.INFO, "DNS Guard Active", "Routing *.office.local strictly via 10.8.0.1.", () -> {}),
                host.buildSlip(Severity.WARNING, "Disk Encryption Warning", "Secondary volume D:\\ awaits BitLocker seal.", () -> {})
        );
        return box;
    }

    private HBox buildSlip(Severity severity, String title, String message, Runnable customDismiss) {
        Region stripe = new Region();
        stripe.setMinWidth(4);
        stripe.setPrefWidth(4);
        stripe.setStyle("-fx-background-color: " + severity.accentHex + "; -fx-background-radius: 4px;");

        Label hdr = new Label(title);
        hdr.setFont(Fonts.uiSemiBold(12.5));
        hdr.setTextFill(Tokens.INK);

        Label body = new Label(message);
        body.getStyleClass().add("ia-subtitle");
        body.setWrapText(true);
        body.setMinHeight(Region.USE_PREF_SIZE);

        VBox txt = new VBox(2, hdr, body);
        txt.setMinWidth(220);
        HBox.setHgrow(txt, Priority.ALWAYS);

        Button closeBtn = new Button();
        closeBtn.setGraphic(Icons.soft(Feather.X, 13));
        closeBtn.setPadding(new Insets(3));
        closeBtn.setStyle("-fx-background-color: transparent; -fx-border-color: transparent;");
        closeBtn.setMinWidth(Region.USE_PREF_SIZE);

        HBox slip = new HBox(10, stripe, Icons.of(severity.glyph, 16, severity.iconColor), txt, closeBtn);
        slip.getStyleClass().add("ia-toast-slip");
        slip.setPadding(new Insets(10, 12, 10, 10));
        slip.setAlignment(Pos.CENTER_LEFT);
        slip.setPrefWidth(346);
        slip.setMaxWidth(360);
        slip.setMinHeight(Region.USE_PREF_SIZE);
        slip.setEffect(Tokens.createAmbientShadow());

        closeBtn.setOnAction(_ -> {
            if (customDismiss != null) customDismiss.run();
            else dismissSlip(slip);
        });
        return slip;
    }

    private void dismissSlip(HBox slip) {
        if (!getChildren().contains(slip)) return;
        if (Motion.isReduceMotion()) {
            getChildren().remove(slip);
            return;
        }
        FadeTransition ft = new FadeTransition(Motion.FAST, slip);
        ft.setToValue(0.0);
        ft.setOnFinished(_ -> getChildren().remove(slip));
        ft.play();
    }
}
