package com.officevpn.ui;

import com.officevpn.ui.components.AuditThread;
import com.officevpn.ui.components.GatewayShelf;
import com.officevpn.ui.components.HandshakeLoom;
import com.officevpn.ui.components.KeycardGate;
import com.officevpn.ui.components.LiveRoster;
import com.officevpn.ui.components.OfficeAtlas;
import com.officevpn.ui.components.PostureSeal;
import com.officevpn.ui.components.PulseRibbon;
import com.officevpn.ui.components.SafetyLatches;
import com.officevpn.ui.components.SignInCard;
import com.officevpn.ui.components.Toasts;
import com.officevpn.ui.components.TrayFlyout;
import com.officevpn.ui.components.WorkModes;
import com.officevpn.ui.service.MockVpnService;
import com.officevpn.ui.service.VpnModels.ConnectionState;
import com.officevpn.ui.service.VpnModels.HandshakeStation;
import com.officevpn.ui.theme.FxPngWriter;
import com.officevpn.ui.theme.IvoryTheme;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Bounds;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.SnapshotParameters;
import javafx.scene.image.WritableImage;
import javafx.scene.layout.StackPane;
import javafx.scene.transform.Transform;
import javafx.stage.Stage;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Automated JavaFX 1x and 2x preview snapshot exporter rendering every Ivory Atelier
 * component (including key states) and every AppShell screen into {@code docs/ui-previews}.
 * <p>
 * Separate non-{@link Application} entrypoint supports direct classpath launch from the shaded JAR.
 */
public final class PreviewExporter {

    private static Path outputDirectory = Path.of("docs/ui-previews");

    private PreviewExporter() {
    }

    public static void main(String[] args) {
        if (args != null && args.length > 0 && args[0] != null && !args[0].isBlank()) {
            outputDirectory = Path.of(args[0]);
        }
        Application.launch(ExporterApp.class, args);
    }

    public static final class ExporterApp extends Application {
        @Override
        public void start(Stage primaryStage) {
            try {
                int exported = exportAll(outputDirectory);
                System.out.println("PreviewExporter completed cleanly: exported " + exported + " PNG files into " + outputDirectory.toAbsolutePath());
            } catch (Throwable t) {
                t.printStackTrace();
                Platform.exit();
                System.exit(1);
                return;
            }
            Platform.exit();
        }
    }

    /**
     * Renders and saves all 1x and 2x component & full-screen PNG snapshots.
     * Must be invoked on the JavaFX Application Thread.
     */
    public static int exportAll(Path outDir) throws IOException {
        IvoryTheme.installBase();
        boolean prevReduce = Motion.isReduceMotion();
        Motion.setReduceMotion(true);
        int count = 0;

        try (MockVpnService disconnected = new MockVpnService(false);
             MockVpnService connected = new MockVpnService(true)) {

            // 1. KeycardGate (Disconnected, Connected, Kill-Switch Blocked)
            KeycardGate gateDisc = new KeycardGate();
            gateDisc.bindService(disconnected);
            count += snapshotNode(gateDisc, 660, 232, outDir, "component-keycard-gate-disconnected");

            KeycardGate gateConn = new KeycardGate();
            gateConn.bindService(connected);
            count += snapshotNode(gateConn, 660, 232, outDir, "component-keycard-gate-connected");

            KeycardGate gateBlocked = new KeycardGate();
            gateBlocked.connectionStateProperty().set(ConnectionState.BLOCKED_BY_KILL_SWITCH);
            gateBlocked.statusCaptionProperty().set("Non-VPN egress sealed after unexpected drop");
            count += snapshotNode(gateBlocked, 660, 232, outDir, "component-keycard-gate-blocked");

            // 2. HandshakeLoom (Complete & Failed)
            HandshakeLoom loomOk = new HandshakeLoom();
            loomOk.bindService(connected);
            count += snapshotNode(loomOk, 680, 152, outDir, "component-handshake-loom-complete");

            HandshakeLoom loomFail = new HandshakeLoom();
            loomFail.completedStationsProperty().set(2);
            loomFail.failedStationProperty().set(HandshakeStation.VERIFY_IDENTITY);
            loomFail.failureReasonProperty().set("Gateway RSA-PSS transcript signature check timed out");
            count += snapshotNode(loomFail, 680, 194, outDir, "component-handshake-loom-failed");

            // 3. OfficeAtlas
            OfficeAtlas atlas = new OfficeAtlas();
            atlas.bindService(connected);
            count += snapshotNode(atlas, 700, 380, outDir, "component-office-atlas");

            // 4. PulseRibbon
            PulseRibbon ribbon = new PulseRibbon();
            ribbon.bindService(connected);
            count += snapshotNode(ribbon, 620, 290, outDir, "component-pulse-ribbon");

            // 5. GatewayShelf & CommandPalette
            GatewayShelf shelf = new GatewayShelf();
            shelf.bindService(connected);
            count += snapshotNode(shelf, 760, 580, outDir, "component-gateway-shelf");

            StackPane palette = GatewayShelf.createCommandPaletteOverlay(connected, s -> {}, () -> {});
            count += snapshotNode(palette, 640, 440, outDir, "component-command-palette");

            // 6. WorkModes
            WorkModes modes = new WorkModes();
            modes.bindService(connected, null);
            count += snapshotNode(modes, 820, 460, outDir, "component-work-modes");

            // 7. SafetyLatches & SplitLanes
            SafetyLatches latches = new SafetyLatches();
            latches.bindService(connected);
            count += snapshotNode(latches, 760, 580, outDir, "component-safety-latches");

            // 8. PostureSeal
            PostureSeal posture = new PostureSeal();
            posture.bindService(connected);
            count += snapshotNode(posture, 560, 420, outDir, "component-posture-seal");

            // 9. LiveRoster & SessionTable
            LiveRoster roster = new LiveRoster();
            roster.bindService(connected, null);
            count += snapshotNode(roster, 940, 535, outDir, "component-live-roster");

            // 10. AuditThread (Normal & Loading Shimmer)
            AuditThread audit = new AuditThread();
            audit.bindService(connected, null);
            count += snapshotNode(audit, 840, 515, outDir, "component-audit-thread");

            AuditThread auditLoading = new AuditThread();
            auditLoading.loadingProperty().set(true);
            count += snapshotNode(auditLoading, 840, 355, outDir, "component-audit-thread-loading");

            // 11. SignInCard (Default & OTP Error Shake state)
            SignInCard signIn = new SignInCard();
            signIn.bindService(disconnected, null);
            count += snapshotNode(signIn, 480, 575, outDir, "component-signin-card");

            SignInCard signInErr = new SignInCard();
            signInErr.bindService(disconnected, null);
            count += snapshotNode(signInErr, 480, 575, outDir, "component-signin-card-error",
                    () -> signInErr.showErrorShake("Authenticator mismatch — try 123456"));

            // 12. Toasts & TrayFlyout
            count += snapshotNode(Toasts.createStandaloneDemo(), 410, 290, outDir, "component-toasts");
            count += snapshotNode(TrayFlyout.createStandaloneDemo(connected), 360, 290, outDir, "component-tray-flyout");

            // 13. All 7 AppShell Screens + compact 960x640 check
            AppShell shell = new AppShell(connected);
            Scene shellScene = new Scene(shell, 1280, 820);
            IvoryTheme.apply(shellScene);
            for (AppShell.Section sec : AppShell.Section.values()) {
                shell.switchTo(sec);
                count += snapshotAttachedRoot(shell, outDir, "screen-" + sec.name().toLowerCase());
            }

            AppShell compactShell = new AppShell(connected);
            Scene compactScene = new Scene(compactShell, 960, 640);
            IvoryTheme.apply(compactScene);
            compactShell.switchTo(AppShell.Section.HOME);
            count += snapshotAttachedRoot(compactShell, outDir, "screen-home-compact-960x640");
        } finally {
            Motion.setReduceMotion(prevReduce);
        }
        return count;
    }

    private static int snapshotAttachedRoot(Parent root, Path outDir, String baseName) throws IOException {
        root.applyCss();
        root.layout();
        Bounds b = root.getLayoutBounds();
        if (b.getWidth() <= 0 || b.getHeight() <= 0) {
            throw new IllegalStateException("Zero-sized layout bounds for preview: " + baseName);
        }

        SnapshotParameters sp1 = new SnapshotParameters();
        sp1.setFill(Tokens.CANVAS);
        WritableImage img1 = root.snapshot(sp1, null);
        FxPngWriter.write(img1, outDir.resolve(baseName + "@1x.png"));

        SnapshotParameters sp2 = new SnapshotParameters();
        sp2.setFill(Tokens.CANVAS);
        sp2.setTransform(Transform.scale(2.0, 2.0));
        WritableImage img2 = root.snapshot(sp2, null);
        FxPngWriter.write(img2, outDir.resolve(baseName + "@2x.png"));
        return 2;
    }

    private static int snapshotNode(Node node, double width, double height, Path outDir, String baseName) throws IOException {
        return snapshotNode(node, width, height, outDir, baseName, null);
    }

    private static int snapshotNode(Node node, double width, double height, Path outDir, String baseName, Runnable afterAttach) throws IOException {
        StackPane frame = new StackPane(node);
        frame.setPadding(new Insets(14));
        frame.setStyle("-fx-background-color: " + Tokens.CANVAS_HEX + ";");
        if (afterAttach != null) {
            return snapshotRoot(frame, width, height, outDir, baseName, afterAttach);
        }
        return snapshotRoot(frame, width, height, outDir, baseName);
    }

    private static int snapshotRoot(Parent root, double width, double height, Path outDir, String baseName) throws IOException {
        return snapshotRoot(root, width, height, outDir, baseName, null);
    }

    private static int snapshotRoot(Parent root, double width, double height, Path outDir, String baseName, Runnable afterAttach) throws IOException {
        Scene scene = new Scene(root, width, height);
        IvoryTheme.apply(scene);
        if (afterAttach != null) {
            root.applyCss();
            root.layout();
            afterAttach.run();
        }
        return snapshotAttachedRoot(root, outDir, baseName);
    }
}
