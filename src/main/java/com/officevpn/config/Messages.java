package com.officevpn.config;

import javafx.scene.control.Control;
import javafx.scene.control.Tooltip;

import java.text.MessageFormat;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Centralized UI localization and accessible control-labeling helper backed by {@code i18n/messages.properties}.
 */
public final class Messages {

    private static final String BUNDLE_NAME = "i18n.messages";
    private static final ResourceBundle BUNDLE = loadBundle();

    private Messages() {}

    private static ResourceBundle loadBundle() {
        return ResourceBundle.getBundle(BUNDLE_NAME, Locale.ROOT);
    }

    public static String get(String key) {
        if (key == null || key.isBlank()) {
            return "";
        }
        try {
            return BUNDLE.getString(key);
        } catch (MissingResourceException ex) {
            return key;
        }
    }

    public static String format(String key, Object... args) {
        String pattern = get(key);
        if (args == null || args.length == 0) {
            return pattern;
        }
        return MessageFormat.format(pattern, args);
    }

    /**
     * Attaches accessible text and a non-null tooltip consistently onto any JavaFX control.
     */
    public static void configureAccessibleControl(Control control, String accessibleText, String tooltipText) {
        if (control == null) {
            return;
        }
        if (accessibleText != null && !accessibleText.isBlank()) {
            control.setAccessibleText(accessibleText);
        }
        if (tooltipText != null && !tooltipText.isBlank()) {
            control.setTooltip(new Tooltip(tooltipText));
        }
    }
}
