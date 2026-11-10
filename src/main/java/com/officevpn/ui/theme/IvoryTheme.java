package com.officevpn.ui.theme;

import atlantafx.base.theme.PrimerLight;
import javafx.application.Application;
import javafx.scene.Scene;

import java.net.URL;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Coordinates AtlantaFX's light base foundation with Ivory Atelier stylesheet tokens and bundled fonts.
 */
public final class IvoryTheme {

    public static final String STYLESHEET_RESOURCE = "/ui/theme/ivory-atelier.css";
    private static final AtomicBoolean UA_APPLIED = new AtomicBoolean(false);

    private IvoryTheme() {
    }

    /**
     * Installs AtlantaFX {@link PrimerLight} as the global user-agent stylesheet and loads bundled OFL fonts.
     */
    public static void installBase() {
        Fonts.ensureLoaded();
        if (UA_APPLIED.compareAndSet(false, true)) {
            Application.setUserAgentStylesheet(new PrimerLight().getUserAgentStylesheet());
        }
    }

    /**
     * Applies Ivory Atelier stylesheet and fonts to a JavaFX {@link Scene}.
     */
    public static void apply(Scene scene) {
        installBase();
        URL url = IvoryTheme.class.getResource(STYLESHEET_RESOURCE);
        if (url != null) {
            String css = url.toExternalForm();
            if (!scene.getStylesheets().contains(css)) {
                scene.getStylesheets().add(css);
            }
        }
    }
}

