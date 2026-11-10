package com.officevpn.ui;

import com.officevpn.ui.service.MockVpnService;
import com.officevpn.ui.service.VpnModels;
import com.officevpn.ui.service.VpnModels.ConnectionState;
import com.officevpn.ui.theme.FxPngWriter;
import com.officevpn.ui.theme.Tokens;
import javafx.scene.image.PixelReader;
import javafx.scene.image.WritableImage;
import javafx.scene.paint.Color;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IvoryAtelierThemeAndServiceTest {

    @Test
    void ivoryAtelierColorsMeetWcagContrastMinimum() {
        assertTrue(Tokens.contrastRatio(Tokens.INK, Tokens.CANVAS) >= 4.5, "INK on CANVAS");
        assertTrue(Tokens.contrastRatio(Tokens.INK, Tokens.PAPER) >= 4.5, "INK on PAPER");
        assertTrue(Tokens.contrastRatio(Tokens.INK, Tokens.SAND) >= 4.5, "INK on SAND");
        assertTrue(Tokens.contrastRatio(Tokens.INK, Tokens.MARIGOLD) >= 4.5, "INK on MARIGOLD");
        assertTrue(Tokens.contrastRatio(Tokens.SOFT_INK, Tokens.PAPER) >= 4.5, "SOFT_INK on PAPER");
        assertTrue(Tokens.contrastRatio(Tokens.SOFT_INK, Tokens.CANVAS) >= 4.5, "SOFT_INK on CANVAS");
        assertTrue(Tokens.contrastRatio(Tokens.SOFT_INK, Tokens.SAND) >= 4.5, "SOFT_INK on SAND");
        assertTrue(Tokens.contrastRatio(Tokens.PEACOCK_TEXT, Tokens.PAPER) >= 4.5, "PEACOCK_TEXT on PAPER");
        assertTrue(Tokens.contrastRatio(Tokens.MARIGOLD_TEXT, Tokens.PAPER) >= 4.5, "MARIGOLD_TEXT on PAPER");
        assertTrue(Tokens.contrastRatio(Tokens.CORAL_TEXT, Tokens.PAPER) >= 4.5, "CORAL_TEXT on PAPER");
        assertTrue(Tokens.contrastRatio(Tokens.LILAC_TEXT, Tokens.PAPER) >= 4.5, "LILAC_TEXT on PAPER");
    }

    @Test
    void paperGrainTileRespectsFourPercentOpacityCap() {
        WritableImage grain = Tokens.getPaperGrainImage();
        PixelReader pr = grain.getPixelReader();
        double maxAlpha = 0.0;
        for (int y = 0; y < (int) grain.getHeight(); y++) {
            for (int x = 0; x < (int) grain.getWidth(); x++) {
                maxAlpha = Math.max(maxAlpha, pr.getColor(x, y).getOpacity());
            }
        }
        assertTrue(maxAlpha <= 0.04, "Paper grain opacity must not exceed 4%, got " + maxAlpha);
    }

    @Test
    void pureJavaPngWriterProducesValidPngHeader() throws Exception {
        WritableImage img = new WritableImage(8, 8);
        for (int y = 0; y < 8; y++) {
            for (int x = 0; x < 8; x++) {
                img.getPixelWriter().setColor(x, y, Color.web(Tokens.PEACOCK_HEX));
            }
        }
        byte[] bytes = FxPngWriter.encode(img);
        assertTrue(bytes.length > 40);
        assertEquals((byte) 137, bytes[0]);
        assertEquals((byte) 80, bytes[1]);
        assertEquals((byte) 78, bytes[2]);
        assertEquals((byte) 71, bytes[3]);
    }

    @Test
    void gatewayFuzzySearchScoresSubsequenceMatches() {
        assertTrue(VpnModels.fuzzyScore("Munich Core 01 Munich HQ", "mun1") >= 0);
        assertTrue(VpnModels.fuzzyScore("Koramangala Core Bengaluru R&D", "blr") >= 0);
        assertEquals(-1, VpnModels.fuzzyScore("Midtown Gateway", "zzzz"));
    }

    @Test
    void mockVpnServiceStateMachineAndCsvExportWorkCleanly(@TempDir Path tempDir) throws Exception {
        try (MockVpnService svc = new MockVpnService(false)) {
            assertEquals(ConnectionState.DISCONNECTED, svc.connectionStateProperty().get());
            svc.triggerKillSwitchBlock();
            assertEquals(ConnectionState.BLOCKED_BY_KILL_SWITCH, svc.connectionStateProperty().get());
            svc.clearKillSwitchBlock();
            assertEquals(ConnectionState.DISCONNECTED, svc.connectionStateProperty().get());

            svc.toggleFavoriteGateway("gw-nyc-1");
            assertTrue(svc.gateways().stream().anyMatch(g -> g.id().equals("gw-nyc-1") && g.favorite()));

            svc.moveSplitApp("app-zoom", true);
            assertTrue(svc.splitApps().stream().anyMatch(a -> a.appId().equals("app-zoom") && a.throughTunnel()));

            svc.remediatePostureCheck("posture-disk");
            assertTrue(svc.postureChecks().stream().allMatch(p -> p.passed()));

            var badAuth = svc.authenticate("a.mehta", "Password123!", "000000").get(3, TimeUnit.SECONDS);
            assertFalse(badAuth.success());
            var okAuth = svc.authenticate("a.mehta", "Password123!", "123456").get(3, TimeUnit.SECONDS);
            assertTrue(okAuth.success());

            int beforeRoster = svc.activeRoster().size();
            svc.revokeSession("sess-102");
            assertEquals(beforeRoster - 1, svc.activeRoster().size());

            Path csv = tempDir.resolve("audit.csv");
            assertTrue(svc.exportAuditCsv(csv));
            assertTrue(Files.readString(csv).contains("Keycard"));
        }
    }
}
