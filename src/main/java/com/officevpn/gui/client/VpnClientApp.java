package com.officevpn.gui.client;

import javafx.application.Application;
import javafx.application.Platform;
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
        @Override
        public void start(Stage primaryStage) {
            Platform.setImplicitExit(true);
            LoginFrame loginFrame = new LoginFrame(primaryStage);
            loginFrame.show();
        }
    }
}
