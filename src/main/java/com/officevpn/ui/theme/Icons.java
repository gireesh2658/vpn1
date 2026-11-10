package com.officevpn.ui.theme;

import javafx.scene.paint.Color;
import org.kordamp.ikonli.feather.Feather;
import org.kordamp.ikonli.javafx.FontIcon;

/**
 * Icon factory backed strictly by Ikonli's MIT-licensed Feather icon pack,
 * styled in Ivory Atelier ink and contrast-safe accent tokens.
 */
public final class Icons {

    private Icons() {
    }

    public static FontIcon of(Feather glyph, int size, Color color) {
        FontIcon icon = FontIcon.of(glyph, size, color);
        icon.setFocusTraversable(false);
        return icon;
    }

    public static FontIcon ink(Feather glyph, int size) {
        return of(glyph, size, Tokens.INK);
    }

    public static FontIcon soft(Feather glyph, int size) {
        return of(glyph, size, Tokens.SOFT_INK);
    }

    public static FontIcon peacock(Feather glyph, int size) {
        return of(glyph, size, Tokens.PEACOCK_TEXT);
    }

    public static FontIcon marigold(Feather glyph, int size) {
        return of(glyph, size, Tokens.MARIGOLD_TEXT);
    }

    public static FontIcon coral(Feather glyph, int size) {
        return of(glyph, size, Tokens.CORAL_TEXT);
    }

    public static FontIcon lilac(Feather glyph, int size) {
        return of(glyph, size, Tokens.LILAC_TEXT);
    }
}

