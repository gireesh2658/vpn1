package com.officevpn.gui.client;

import com.officevpn.config.Messages;
import com.officevpn.security.TrustedFingerprintStore;
import com.officevpn.ui.AppShell;
import com.officevpn.ui.service.BackendVpnServiceAdapter;
import com.officevpn.ui.theme.IvoryTheme;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * Office VPN Encrypted Client Application Launcher.
 * Separate non-{@link Application} launcher ensures self-contained shaded JAR compatibility on Java 25.
 */
public final class VpnClientApp {

    private VpnClientApp() {}

    public static void main(String[] args) {
        Application.launch(ClientFxApplication.class, args);
    }

    public static final class ClientFxApplication extends Application {
        private BackendVpnServiceAdapter atelierService;

        @Override
        public void start(Stage primaryStage) {
            Platform.setImplicitExit(true);
            if ("atelier".equalsIgnoreCase(System.getProperty("officevpn.ui", ""))) {
                atelierService = new BackendVpnServiceAdapter(
                        new com.officevpn.client.VpnClientEngine(),
                        TrustedFingerprintStore.getDefault(), null, null);
                AppShell shell = new AppShell(atelierService);
                Scene scene = new Scene(shell, 1180, 780);
                IvoryTheme.apply(scene);
                primaryStage.setTitle(Messages.format("app.title.client.atelier", "local"));
                primaryStage.setMinWidth(960);
                primaryStage.setMinHeight(640);
                primaryStage.setScene(scene);
                primaryStage.show();
                return;
            }
            LoginFrame loginFrame = new LoginFrame(primaryStage);
            loginFrame.show();
        }

        @Override
        public void stop() {
            if (atelierService != null) {
                atelierService.close();
            }
        }
    }
}
