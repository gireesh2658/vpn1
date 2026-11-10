package com.officevpn.ui.theme;

import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;

import java.io.InputStream;

/**
 * Typography registry for Ivory Atelier.
 * <p>
 * Loads bundled OFL static TTFs from {@code /fonts/} using {@link Font#loadFont(InputStream, double)}
 * and preserves each font's exact reported family name (such as {@code "Manrope Medium"} and
 * {@code "Manrope SemiBold"}) because JavaFX CSS reduces weights to Regular and Bold only.
 * Falls back cleanly to {@code Segoe UI} if any font fails to load.
 */
public final class Fonts {

    public static final String FALLBACK_FAMILY = "Segoe UI";

    private static volatile boolean initialized = false;

    private static String displayFamily         = FALLBACK_FAMILY;
    private static String displaySemiBoldFamily = FALLBACK_FAMILY;
    private static String displayBoldFamily     = FALLBACK_FAMILY;

    private static String uiFamily              = FALLBACK_FAMILY;
    private static String uiMediumFamily        = FALLBACK_FAMILY;
    private static String uiSemiBoldFamily      = FALLBACK_FAMILY;
    private static String uiBoldFamily          = FALLBACK_FAMILY;

    private static String monoFamily            = "JetBrains Mono";
    private static String monoMediumFamily      = "JetBrains Mono";
    private static String monoBoldFamily        = "JetBrains Mono";

    private Fonts() {
    }

    /**
     * Ensures all bundled static fonts are loaded once onto the JavaFX font registry.
     */
    public static void ensureLoaded() {
        if (initialized) {
            return;
        }
        synchronized (Fonts.class) {
            if (initialized) {
                return;
            }
            displayFamily         = loadStaticFamily("/fonts/Fraunces-Regular.ttf", FALLBACK_FAMILY);
            displaySemiBoldFamily = loadStaticFamily("/fonts/Fraunces-SemiBold.ttf", displayFamily);
            displayBoldFamily     = loadStaticFamily("/fonts/Fraunces-Bold.ttf", displayFamily);

            uiFamily              = loadStaticFamily("/fonts/Manrope-Regular.ttf", FALLBACK_FAMILY);
            uiMediumFamily        = loadStaticFamily("/fonts/Manrope-Medium.ttf", uiFamily);
            uiSemiBoldFamily      = loadStaticFamily("/fonts/Manrope-SemiBold.ttf", uiFamily);
            uiBoldFamily          = loadStaticFamily("/fonts/Manrope-Bold.ttf", uiFamily);

            monoFamily            = loadStaticFamily("/fonts/JetBrainsMono-Regular.ttf", "Consolas");
            monoMediumFamily      = loadStaticFamily("/fonts/JetBrainsMono-Medium.ttf", monoFamily);
            monoBoldFamily        = loadStaticFamily("/fonts/JetBrainsMono-Bold.ttf", monoFamily);

            initialized = true;
        }
    }

    private static String loadStaticFamily(String resourcePath, String fallback) {
        try (InputStream is = Fonts.class.getResourceAsStream(resourcePath)) {
            if (is != null) {
                Font loaded = Font.loadFont(is, 14.0);
                if (loaded != null && loaded.getFamily() != null && !loaded.getFamily().isBlank()) {
                    return loaded.getFamily();
                }
            }
        } catch (Exception ignored) {
            // Fall through cleanly to Segoe UI / Consolas
        }
        return fallback;
    }

    public static String getDisplayFamily() {
        ensureLoaded();
        return displayFamily;
    }

    public static String getDisplaySemiBoldFamily() {
        ensureLoaded();
        return displaySemiBoldFamily;
    }

    public static String getUiFamily() {
        ensureLoaded();
        return uiFamily;
    }

    public static String getUiMediumFamily() {
        ensureLoaded();
        return uiMediumFamily;
    }

    public static String getUiSemiBoldFamily() {
        ensureLoaded();
        return uiSemiBoldFamily;
    }

    public static String getMonoFamily() {
        ensureLoaded();
        return monoFamily;
    }

    public static String getMonoMediumFamily() {
        ensureLoaded();
        return monoMediumFamily;
    }

    public static Font displayRegular(double size) {
        ensureLoaded();
        return Font.font(displayFamily, FontWeight.NORMAL, size);
    }

    public static Font displaySemiBold(double size) {
        ensureLoaded();
        return displaySemiBoldFamily.equals(displayFamily)
                ? Font.font(displayFamily, FontWeight.SEMI_BOLD, size)
                : Font.font(displaySemiBoldFamily, size);
    }

    public static Font displayBold(double size) {
        ensureLoaded();
        return Font.font(displayBoldFamily, FontWeight.BOLD, size);
    }

    public static Font uiRegular(double size) {
        ensureLoaded();
        return Font.font(uiFamily, FontWeight.NORMAL, size);
    }

    public static Font uiMedium(double size) {
        ensureLoaded();
        return uiMediumFamily.equals(uiFamily)
                ? Font.font(uiFamily, FontWeight.MEDIUM, size)
                : Font.font(uiMediumFamily, size);
    }

    public static Font uiSemiBold(double size) {
        ensureLoaded();
        return uiSemiBoldFamily.equals(uiFamily)
                ? Font.font(uiFamily, FontWeight.SEMI_BOLD, size)
                : Font.font(uiSemiBoldFamily, size);
    }

    public static Font uiBold(double size) {
        ensureLoaded();
        return Font.font(uiBoldFamily, FontWeight.BOLD, size);
    }

    public static Font monoRegular(double size) {
        ensureLoaded();
        return Font.font(monoFamily, FontWeight.NORMAL, size);
    }

    public static Font monoMedium(double size) {
        ensureLoaded();
        return monoMediumFamily.equals(monoFamily)
                ? Font.font(monoFamily, FontWeight.MEDIUM, size)
                : Font.font(monoMediumFamily, size);
    }

    public static Font monoBold(double size) {
        ensureLoaded();
        return Font.font(monoBoldFamily, FontWeight.BOLD, size);
    }
}

