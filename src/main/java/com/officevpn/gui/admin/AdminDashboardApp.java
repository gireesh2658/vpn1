package com.officevpn.gui.admin;

import com.officevpn.admin.AdminBootstrap;
import com.officevpn.admin.DemoSeeder;
import com.officevpn.db.DatabaseManager;
import com.officevpn.model.UserAccount;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.awt.GraphicsEnvironment;
import java.util.List;

/**
 * Entry point for launching the Headquarters VPN Gateway Central Admin Dashboard.
 */
public final class AdminDashboardApp {

    public static void main(String[] args) {
        if (GraphicsEnvironment.isHeadless()) {
            com.officevpn.server.VpnServer.main(args);
            return;
        }

        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
        }

        DatabaseManager db = new DatabaseManager();

        final List<DemoSeeder.DemoAccount> seededAccounts = DemoSeeder.isDemoEnabled()
                ? DemoSeeder.seed(db)
                : java.util.Collections.emptyList();

        if (!seededAccounts.isEmpty()) {
            System.out.println("========================================================================");
            System.out.println("       DEMO MODE INITIALIZED - EPHEMERAL TEST CREDENTIALS               ");
            System.out.println("========================================================================");
            for (DemoSeeder.DemoAccount acc : seededAccounts) {
                System.out.printf("  Username: %-15s Password: %-18s Dept: %-12s Role: %s%n",
                        acc.username(), acc.password(), acc.department(), acc.role());
            }
            System.out.println("========================================================================");
        }

        SwingUtilities.invokeLater(() -> {
            if (AdminBootstrap.needsBootstrap(db)) {
                AdminBootstrapDialog bootstrapDialog = new AdminBootstrapDialog(null, db);
                bootstrapDialog.setVisible(true);
                if (!bootstrapDialog.isBootstrapped()) {
                    bootstrapDialog.dispose();
                    db.close();
                    return;
                }
            }

            AdminLoginDialog loginDialog = new AdminLoginDialog(null, db);
            loginDialog.setVisible(true);
            UserAccount loggedInAdmin = loginDialog.getAuthenticatedUser();
            if (loggedInAdmin == null) {
                loginDialog.dispose();
                db.close();
                return;
            }

            AdminDashboardFrame adminFrame = new AdminDashboardFrame(db, loggedInAdmin.username());
            adminFrame.displayDemoCredentials(seededAccounts);
            adminFrame.setVisible(true);
        });
    }
}
