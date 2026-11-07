package com.officevpn.gui.client;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

/**
 * Entry point for launching the Office VPN Remote Employee Client Application.
 */
public final class VpnClientApp {

    public static void main(String[] args) {
        // Set cross-platform or system look and feel
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
        }

        SwingUtilities.invokeLater(() -> {
            LoginFrame loginFrame = new LoginFrame();
            loginFrame.setVisible(true);
        });
    }
}

