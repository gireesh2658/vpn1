package com.officevpn.gui;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UiSafeTest {

    @Test
    @DisplayName("UiSafe.text strips control characters, directional overrides, and bounds length")
    void testSanitizeText() {
        assertEquals("", UiSafe.text(null, 50));
        String dangerous = "alice\r\n\t\u202Eadmin\u0007";
        assertEquals("alice admin", UiSafe.text(dangerous, 50));
        assertEquals("hello", UiSafe.text("hello world", 5));
    }
}

