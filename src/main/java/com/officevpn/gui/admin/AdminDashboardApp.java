package com.officevpn.gui.admin;

import com.officevpn.admin.AdminBootstrap;
import com.officevpn.admin.DemoSeeder;
import com.officevpn.config.ConfigUtil;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.AuditVerifyResult;
import com.officevpn.model.UserAccount;
import com.officevpn.security.ServerIdentity;
import com.officevpn.server.VpnGatewayServer;
import com.officevpn.server.VpnServer;
import com.officevpn.storage.VaultManager;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.stage.Stage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.GraphicsEnvironment;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Office VPN Headquarters Gateway &amp; Admin Governance Launcher.
 * <p>
 * Automatically delegates to headless console mode ({@link VpnServer}) when running without
 * a graphical display, and otherwise boots the JavaFX Enterprise Governance Suite.
 */
public final class AdminDashboardApp {

    private static final Logger LOGGER = LoggerFactory.getLogger(AdminDashboardApp.class);

    private AdminDashboardApp() {}

    public static void main(String[] args) {
        if (GraphicsEnvironment.isHeadless() || Boolean.getBoolean("java.awt.headless")) {
            VpnServer.main(args);
            return;
        }
        Application.launch(AdminFxApplication.class, args);
    }

    public static final class AdminFxApplication extends Application {

        private DatabaseManager db;
        private VpnGatewayServer gatewayServer;
        private AdminDashboardFrame dashboard;

        @Override
        public void start(Stage primaryStage) {
            Platform.setImplicitExit(false);
            try {
                db = new DatabaseManager();
            } catch (Exception ex) {
                UiSafe.showError(null, "MySQL Initialization Failed",
                        "Unable to initialize MySQL persistence (" + ConfigUtil.getDbUrl() + ").\n\n"
                                + "Ensure MySQL / MariaDB is running and credentials in config.properties are valid.\n\nDetails: "
                                + ex.getMessage());
                Platform.exit();
                return;
            }

            CompletableFuture<AuditVerifyResult> verifyFuture = db.startBackgroundVerify();

            List<DemoSeeder.DemoAccount> seededDemoAccounts = List.of();
            if (DemoSeeder.isDemoEnabled()) {
                seededDemoAccounts = DemoSeeder.seed(db);
                LOGGER.info("Demo mode enabled: seeded {} temporary account(s) for current session.", seededDemoAccounts.size());
            } else if (AdminBootstrap.needsBootstrap(db)) {
                Optional<UserAccount> bootstrapped = AdminBootstrapDialog.showSetupDialog(null, db);
                if (bootstrapped.isEmpty()) {
                    closeQuietly();
                    Platform.exit();
                    return;
                }
            }

            Optional<UserAccount> loggedIn = AdminLoginDialog.showLoginDialog(null, db, seededDemoAccounts);
            if (loggedIn.isEmpty()) {
                closeQuietly();
                Platform.exit();
                return;
            }

            Optional<ServerIdentity> identityOpt = AdminIdentityDialog.resolveIdentity(
                    null, Path.of(ConfigUtil.getServerDataDir()));
            if (identityOpt.isEmpty()) {
                closeQuietly();
                Platform.exit();
                return;
            }

            VaultManager vault = new VaultManager(Path.of(ConfigUtil.getVaultRootDir()));
            gatewayServer = new VpnGatewayServer(db, vault, identityOpt.get());

            int port = ConfigUtil.getPort();
            try {
                gatewayServer.start(port);
            } catch (Exception startEx) {
                UiSafe.showWarning(null, "Gateway Start Warning",
                        "Dashboard launched, but failed to bind gateway on port " + port + ":\n" + startEx.getMessage()
                                + "\n\nYou can start or reconfigure the port from the Configuration tab.");
            }

            Platform.setImplicitExit(true);
            dashboard = new AdminDashboardFrame(primaryStage, db, gatewayServer, loggedIn.get().username(), verifyFuture);
            dashboard.show();
        }

        @Override
        public void stop() {
            if (dashboard != null) {
                dashboard.shutdown();
            } else {
                closeQuietly();
            }
        }

        private void closeQuietly() {
            if (gatewayServer != null) {
                try {
                    gatewayServer.stop();
                } catch (Exception ex) {
                    LOGGER.debug("Ignoring error stopping gateway during shutdown: {}", ex.getMessage());
                }
            }
            if (db != null) {
                try {
                    db.close();
                } catch (Exception ex) {
                    LOGGER.debug("Ignoring error closing database pool during shutdown: {}", ex.getMessage());
                }
            }
        }
    }
}
