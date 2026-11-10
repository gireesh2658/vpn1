package com.officevpn.ui.theme;

import javafx.geometry.Insets;
import javafx.scene.CacheHint;
import javafx.scene.Node;
import javafx.scene.effect.BlurType;
import javafx.scene.effect.DropShadow;
import javafx.scene.image.PixelWriter;
import javafx.scene.image.WritableImage;
import javafx.scene.layout.Background;
import javafx.scene.layout.BackgroundImage;
import javafx.scene.layout.BackgroundPosition;
import javafx.scene.layout.BackgroundRepeat;
import javafx.scene.layout.BackgroundSize;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.paint.Color;

import java.util.SplittableRandom;

/**
 * Canonical design tokens and surface elevation helpers for the "Ivory Atelier" design language.
 * <p>
 * Colors match looked-up tokens in {@code /ui/theme/ivory-atelier.css}. Small-text semantic
 * foregrounds are paired so all readable typography achieves >= 4.5:1 WCAG contrast on light
 * paper, canvas, and sand surfaces.
 */
public final class Tokens {

    // Core surface palette
    public static final String CANVAS_HEX   = "#FBF8F1";
    public static final String PAPER_HEX    = "#FFFFFF";
    public static final String SAND_HEX     = "#F2EBDC";
    public static final String HAIRLINE_HEX = "#E6DCC6";

    // Brand & semantic accents
    public static final String MARIGOLD_HEX = "#FFB224";
    public static final String PEACOCK_HEX  = "#0E9F9A";
    public static final String CORAL_HEX    = "#F4604C";
    public static final String LILAC_HEX    = "#7C6CF0";

    // Typography inks
    public static final String INK_HEX      = "#26233A";
    public static final String SOFT_INK_HEX = "#6A6580";

    // Contrast-verified (>= 4.5:1 on white & canvas) semantic text inks
    public static final String MARIGOLD_TEXT_HEX = "#7A4B00";
    public static final String PEACOCK_TEXT_HEX  = "#096B67";
    public static final String CORAL_TEXT_HEX    = "#BA2A1A";
    public static final String LILAC_TEXT_HEX    = "#4F3CC9";

    public static final Color CANVAS        = Color.web(CANVAS_HEX);
    public static final Color PAPER         = Color.web(PAPER_HEX);
    public static final Color SAND          = Color.web(SAND_HEX);
    public static final Color HAIRLINE      = Color.web(HAIRLINE_HEX);

    public static final Color MARIGOLD      = Color.web(MARIGOLD_HEX);
    public static final Color PEACOCK       = Color.web(PEACOCK_HEX);
    public static final Color CORAL         = Color.web(CORAL_HEX);
    public static final Color LILAC         = Color.web(LILAC_HEX);

    public static final Color INK           = Color.web(INK_HEX);
    public static final Color SOFT_INK      = Color.web(SOFT_INK_HEX);

    public static final Color MARIGOLD_TEXT = Color.web(MARIGOLD_TEXT_HEX);
    public static final Color PEACOCK_TEXT  = Color.web(PEACOCK_TEXT_HEX);
    public static final Color CORAL_TEXT    = Color.web(CORAL_TEXT_HEX);
    public static final Color LILAC_TEXT    = Color.web(LILAC_TEXT_HEX);

    // Soft translucent washes on opaque paper
    public static final Color MARIGOLD_WASH = Color.rgb(255, 178, 36, 0.16);
    public static final Color PEACOCK_WASH  = Color.rgb(14, 159, 154, 0.12);
    public static final Color CORAL_WASH    = Color.rgb(244, 96, 76, 0.12);
    public static final Color LILAC_WASH    = Color.rgb(124, 108, 240, 0.12);

    // Radii & spacing scale
    public static final double RADIUS_SM = 8.0;
    public static final double RADIUS_MD = 14.0;
    public static final double RADIUS_LG = 18.0;
    public static final double RADIUS_PILL = 999.0;

    private static volatile WritableImage cachedPaperGrain;

    private Tokens() {
    }

    /**
     * Generates or returns the singleton 128x128 monochrome warm paper grain tile
     * with strictly <= 4% pixel alpha opacity to enrich opaque paper cards without clutter.
     */
    public static WritableImage getPaperGrainImage() {
        WritableImage existing = cachedPaperGrain;
        if (existing != null) {
            return existing;
        }
        synchronized (Tokens.class) {
            if (cachedPaperGrain == null) {
                int size = 128;
                WritableImage img = new WritableImage(size, size);
                PixelWriter pw = img.getPixelWriter();
                SplittableRandom rng = new SplittableRandom(0x49564F5259L);
                for (int y = 0; y < size; y++) {
                    for (int x = 0; x < size; x++) {
                        int delta = rng.nextInt(100);
                        if (delta < 28) {
                            // Subtle warm ink speckle at 2.3%..3.5% opacity (strictly <= 4%)
                            int alpha = 6 + rng.nextInt(4);
                            int argb = (alpha << 24) | (0x54 << 16) | (0x46 << 8) | 0x36;
                            pw.setArgb(x, y, argb);
                        } else if (delta < 45) {
                            int alpha = 4 + rng.nextInt(4);
                            int argb = (alpha << 24) | (0xE8 << 16) | (0xDE << 8) | 0xC8;
                            pw.setArgb(x, y, argb);
                        } else {
                            pw.setArgb(x, y, 0x00000000);
                        }
                    }
                }
                cachedPaperGrain = img;
            }
            return cachedPaperGrain;
        }
    }

    /**
     * Creates an optional subtle tiled paper-grain {@link Background} (&lt;= 4% alpha).
     */
    public static Background createPaperGrainBackground() {
        BackgroundImage bgImg = new BackgroundImage(
                getPaperGrainImage(),
                BackgroundRepeat.REPEAT,
                BackgroundRepeat.REPEAT,
                BackgroundPosition.DEFAULT,
                BackgroundSize.DEFAULT
        );
        return new Background(bgImg);
    }

    /**
     * Ambient outer warm shadow layer for two-layer elevation.
     */
    public static DropShadow createAmbientShadow() {
        DropShadow ds = new DropShadow();
        ds.setBlurType(BlurType.GAUSSIAN);
        ds.setRadius(18.0);
        ds.setSpread(0.06);
        ds.setOffsetX(0.0);
        ds.setOffsetY(6.0);
        ds.setColor(Color.rgb(64, 52, 34, 0.065));
        return ds;
    }

    /**
     * Crisp close contact shadow layer paired inside nested elevated regions.
     */
    public static DropShadow createContactShadow() {
        DropShadow ds = new DropShadow();
        ds.setBlurType(BlurType.GAUSSIAN);
        ds.setRadius(5.0);
        ds.setSpread(0.12);
        ds.setOffsetX(0.0);
        ds.setOffsetY(1.5);
        ds.setColor(Color.rgb(92, 78, 56, 0.085));
        return ds;
    }

    /**
     * Wraps content in a true two-layer warm-tinted opaque paper card using nested regions
     * because JavaFX CSS natively supports only a single DropShadow per node.
     *
     * @param content        inner node
     * @param applyGrainTile whether to overlay the <= 4% paper grain texture inside the card
     * @return outer elevated card container with {@link CacheHint#SPEED}
     */
    public static StackPane wrapPaperCard(Node content, boolean applyGrainTile) {
        StackPane outer = new StackPane();
        outer.getStyleClass().add("ia-card-shadow-outer");
        outer.setEffect(createAmbientShadow());

        StackPane inner = new StackPane();
        inner.getStyleClass().add("ia-card-paper");
        inner.setEffect(createContactShadow());
        if (applyGrainTile) {
            Region grainLayer = new Region();
            grainLayer.setMouseTransparent(true);
            grainLayer.setBackground(createPaperGrainBackground());
            grainLayer.setMaxSize(Double.MAX_VALUE, Double.MAX_VALUE);
            inner.getChildren().addAll(grainLayer, content);
        } else {
            inner.getChildren().add(content);
        }
        StackPane.setMargin(content, Insets.EMPTY);
        outer.getChildren().add(inner);
        outer.setCache(true);
        outer.setCacheHint(CacheHint.SPEED);
        return outer;
    }

    /**
     * Computes WCAG 2.1 contrast ratio between two opaque colors.
     */
    public static double contrastRatio(Color a, Color b) {
        double l1 = relativeLuminance(a);
        double l2 = relativeLuminance(b);
        double lighter = Math.max(l1, l2);
        double darker = Math.min(l1, l2);
        return (lighter + 0.05) / (darker + 0.05);
    }

    private static double relativeLuminance(Color c) {
        double r = linearize(c.getRed());
        double g = linearize(c.getGreen());
        double b = linearize(c.getBlue());
        return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    }

    private static double linearize(double channel) {
        return channel <= 0.04045 ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4);
    }
}

