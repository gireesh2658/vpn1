package com.officevpn;

import com.officevpn.admin.AuditService;
import com.officevpn.admin.DeviceManager;
import com.officevpn.client.VpnClientEngine;
import com.officevpn.db.DatabaseManager;
import com.officevpn.model.AuditVerifyResult;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.security.AuditKeyStore;
import com.officevpn.security.ServerIdentity;
import com.officevpn.security.TotpUtil;
import com.officevpn.security.TrustedFingerprintStore;
import com.officevpn.server.VpnGatewayServer;
import com.officevpn.storage.VaultManager;
import com.officevpn.ui.service.BackendVpnServiceAdapter;
import com.officevpn.ui.service.VpnModels.ConnectionState;
import com.officevpn.util.HardwareUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VpnEndToEndWorkflowTest {

    private static String newH2MySqlUrl(String prefix) {
        return "jdbc:h2:mem:" + prefix + "_" + UUID.randomUUID().toString().replace("-", "")
                + ";MODE=MySQL;DATABASE_TO_LOWER=TRUE;CASE_INSENSITIVE_IDENTIFIERS=TRUE;DB_CLOSE_DELAY=-1";
    }

    @Test
    @DisplayName("Full VPN lifecycle: TOFU handshake, MFA auth, vault transfer, broadcast, password change, reconnect, and audit verification")
    void testEndToEndClientServerWorkflow(@TempDir Path tempDir) throws Exception {
        Path dbKeyDir = tempDir.resolve("keys");
        Path vaultDir = tempDir.resolve("vaults");
        Path pinFile = tempDir.resolve("known_gateways.properties");

        String alicePw = "Alice#VpnPass2026!";
        String bobPw1 = "Bob#InitialPass2026!";
        String bobPw2 = "Bob#RotatedPass2026!";

        try (DatabaseManager db = new DatabaseManager(newH2MySqlUrl("e2e_wire"), new AuditKeyStore(dbKeyDir))) {
            VaultManager vault = new VaultManager(vaultDir);
            ServerIdentity identity = ServerIdentity.createEphemeral();

            db.createUser("alice_fin", alicePw.toCharArray(), Department.FINANCE, Role.EMPLOYEE, "admin_hq");
            String aliceTotpSecret = TotpUtil.generateSecret();
            db.saveTotpSecret("alice_fin", aliceTotpSecret);

            db.createUser("bob_it", bobPw1.toCharArray(), Department.IT, Role.EMPLOYEE, "admin_hq");

            try (VpnGatewayServer server = new VpnGatewayServer(db, vault, identity)) {
                server.start(0);
                int port = server.getBoundPort();
                assertTrue(port > 0, "Gateway must bind an active ephemeral port");

                TrustedFingerprintStore pinStore = new TrustedFingerprintStore(pinFile);
                List<String> aliceReceivedBroadcasts = new CopyOnWriteArrayList<>();
                List<String> bobReceivedBroadcasts = new CopyOnWriteArrayList<>();
                CountDownLatch aliceBroadcastLatch = new CountDownLatch(2);
                CountDownLatch bobBroadcastLatch = new CountDownLatch(1);

                // 1. Wrong TOTP rejected over real ECDH + RSASSA-PSS wire, valid TOTP succeeds
                try (VpnClientEngine alice = new VpnClientEngine()) {
                    alice.addClientEventListener(new VpnClientEngine.ClientEventListener() {
                        @Override
                        public void onChatMessage(String senderUser, String senderDept, String senderVip, String message) {
                            aliceReceivedBroadcasts.add(senderUser + ":" + message);
                            aliceBroadcastLatch.countDown();
                        }

                        @Override
                        public void onPacketSniffed(com.officevpn.protocol.VpnPacket packet, String direction) {}

                        @Override
                        public void onConnectionStateChanged(String newState) {}
                    });

                    alice.connectAndHandshake("127.0.0.1", port, null, pinStore, false);
                    assertFalse(alice.login("alice_fin", alicePw, "000000"),
                            "Invalid 6-digit TOTP must be rejected over wire");
                    alice.disconnect();

                    alice.connectAndHandshake("127.0.0.1", port, null, pinStore, false);
                    String code = TotpUtil.generateCurrentCode(aliceTotpSecret);
                    assertTrue(alice.login("alice_fin", alicePw, code),
                            "Valid password + TOTP must authenticate");
                    assertTrue(alice.isAuthenticated());
                    assertNotNull(alice.getAssignedVirtualIp());
                    assertTrue(alice.getAssignedVirtualIp().startsWith("10."));
                    assertTrue(pinStore.getPinnedFingerprint("127.0.0.1", port).isPresent(),
                            "TOFU server fingerprint must be pinned after verified handshake");

                    // 2. Encrypted tunnel ping and departmental vault upload/list/download
                    assertTrue(alice.ping(), "Encrypted PING/PONG probe must succeed");

                    byte[] secretDoc = "Q4 Treasury Reconciliation Report".getBytes(StandardCharsets.UTF_8);
                    alice.uploadFile(Department.FINANCE, "q4-treasury.txt", secretDoc);
                    List<String> finFiles = alice.listDepartmentFiles(Department.FINANCE);
                    assertTrue(finFiles.contains("q4-treasury.txt"));
                    byte[] downloaded = alice.downloadFile(Department.FINANCE, "q4-treasury.txt");
                    assertArrayEquals(secretDoc, downloaded);

                    assertThrows(SecurityException.class, () -> alice.listDepartmentFiles(Department.IT),
                            "Cross-department vault access must fail for EMPLOYEE role");

                    // 3. Connect Bob in parallel to verify encrypted chat + admin notice broadcast + password rotation
                    try (VpnClientEngine bob = new VpnClientEngine()) {
                        bob.addClientEventListener(new VpnClientEngine.ClientEventListener() {
                            @Override
                            public void onChatMessage(String senderUser, String senderDept, String senderVip, String message) {
                                bobReceivedBroadcasts.add(senderUser + ":" + message);
                                bobBroadcastLatch.countDown();
                            }

                            @Override
                            public void onPacketSniffed(com.officevpn.protocol.VpnPacket packet, String direction) {}

                            @Override
                            public void onConnectionStateChanged(String newState) {}
                        });

                        bob.connectAndHandshake("127.0.0.1", port, null, pinStore, false);
                        assertTrue(bob.login("bob_it", bobPw1));

                        alice.sendChatMessage("Finance report uploaded");
                        server.broadcastSystemMessage("Scheduled maintenance window at 22:00 UTC", "admin_hq");
                        assertTrue(aliceBroadcastLatch.await(5, TimeUnit.SECONDS),
                                "Finance client must receive own department message and HQ broadcast");
                        assertTrue(bobBroadcastLatch.await(5, TimeUnit.SECONDS),
                                "IT client must receive HQ broadcast notice");
                        assertTrue(aliceReceivedBroadcasts.stream().anyMatch(m -> m.contains("Finance report uploaded")));
                        assertTrue(aliceReceivedBroadcasts.stream().anyMatch(m -> m.contains("Scheduled maintenance")));
                        assertTrue(bobReceivedBroadcasts.stream().anyMatch(m -> m.contains("Scheduled maintenance")));
                        assertFalse(bobReceivedBroadcasts.stream().anyMatch(m -> m.contains("Finance report uploaded")),
                                "Cross-department chat isolation must block FINANCE messages from reaching IT clients");

                        // 4. Encrypted self-service Change Password + Reconnect
                        assertThrows(SecurityException.class,
                                () -> bob.changePassword("WrongCurrent#123!".toCharArray(), bobPw2.toCharArray()));
                        bob.changePassword(bobPw1.toCharArray(), bobPw2.toCharArray());
                        bob.disconnect();
                        assertFalse(bob.isConnected());

                        bob.connectAndHandshake("127.0.0.1", port, null, pinStore, false);
                        assertFalse(bob.login("bob_it", bobPw1),
                                "Old password must no longer authenticate after password change");
                        bob.disconnect();

                        bob.connectAndHandshake("127.0.0.1", port, null, pinStore, false);
                        assertTrue(bob.login("bob_it", bobPw2),
                                "New password must authenticate on reconnect");

                        // 5. Hardware device revocation blocks next login until re-trusted
                        bob.disconnect();
                        DeviceManager dm = new DeviceManager(db);
                        assertTrue(dm.revokeDevice("bob_it", HardwareUtil.getAuthenticHardwareFingerprint()));
                        bob.connectAndHandshake("127.0.0.1", port, null, pinStore, false);
                        assertFalse(bob.login("bob_it", bobPw2),
                                "Revoked hardware device must be blocked");
                        bob.disconnect();

                        assertTrue(dm.trustDevice("bob_it", HardwareUtil.getAuthenticHardwareFingerprint()));
                        bob.connectAndHandshake("127.0.0.1", port, null, pinStore, false);
                        assertTrue(bob.login("bob_it", bobPw2),
                                "Re-trusted hardware device must authenticate again");
                        bob.disconnect();
                    }
                    alice.disconnect();
                }

                // 6. Verify tamper-evident audit chain covers full session lifecycle
                AuditVerifyResult verify = db.verifyAuditChain();
                assertEquals(AuditVerifyResult.AuditStatus.OK, verify.status());
                AuditService audit = new AuditService(db);
                List<DatabaseManager.AuditLogEntry> events = audit.getRecentAudit(50);
                assertTrue(events.stream().anyMatch(e -> "AUTH_SUCCESS".equals(e.eventType())));
                assertTrue(events.stream().anyMatch(e -> "USER_PASSWORD_CHANGED".equals(e.eventType())));
                assertTrue(events.stream().anyMatch(e -> "DEVICE_ACCESS_BLOCKED".equals(e.eventType())));
            }
        }
    }

    @Test
    @DisplayName("Ivory Atelier BackendVpnServiceAdapter binds live gateway, authenticates, syncs roster/audit, exports CSV, and revokes sessions")
    void testBackendAdapterLiveWorkflow(@TempDir Path tempDir) throws Exception {
        Path dbKeyDir = tempDir.resolve("keys");
        Path vaultDir = tempDir.resolve("vaults");
        Path pinFile = tempDir.resolve("known_gateways.properties");
        Path csvExport = tempDir.resolve("atelier-audit.csv");

        String userPw = "Charlie#Atelier2026!";

        try (DatabaseManager db = new DatabaseManager(newH2MySqlUrl("e2e_adapter"), new AuditKeyStore(dbKeyDir))) {
            VaultManager vault = new VaultManager(vaultDir);
            ServerIdentity identity = ServerIdentity.createEphemeral();
            db.createUser("charlie_hr", userPw.toCharArray(), Department.HR, Role.EMPLOYEE, "admin_hq");

            try (VpnGatewayServer server = new VpnGatewayServer(db, vault, identity)) {
                server.start(0);
                try (VpnClientEngine engine = new VpnClientEngine();
                     BackendVpnServiceAdapter adapter = new BackendVpnServiceAdapter(
                             engine, new TrustedFingerprintStore(pinFile), db, server)) {

                    var badAuth = adapter.authenticate("charlie_hr", "Wrong#Pass2026!", "").get(5, TimeUnit.SECONDS);
                    assertFalse(badAuth.success());

                    var okAuth = adapter.authenticate("charlie_hr", userPw, "").get(5, TimeUnit.SECONDS);
                    assertTrue(okAuth.success(), okAuth.message());
                    assertTrue(engine.isAuthenticated());

                    // Wait briefly for async adapter snapshot + roster + audit updates to settle
                    long deadline = System.currentTimeMillis() + 3000;
                    while (System.currentTimeMillis() < deadline
                            && (adapter.connectionStateProperty().get() != ConnectionState.CONNECTED
                            || adapter.activeRoster().isEmpty()
                            || adapter.auditEvents().isEmpty())) {
                        Thread.sleep(25);
                    }

                    assertEquals(ConnectionState.CONNECTED, adapter.connectionStateProperty().get());
                    assertEquals("charlie_hr", adapter.currentIdentityProperty().get().username());
                    assertFalse(adapter.activeRoster().isEmpty(), "Live roster must contain charlie_hr session");
                    assertTrue(adapter.exportAuditCsv(csvExport));
                    assertTrue(Files.readString(csvExport).contains("AUTH_SUCCESS"));

                    String sessionId = adapter.activeRoster().get(0).sessionId();
                    adapter.revokeSession(sessionId);

                    deadline = System.currentTimeMillis() + 3000;
                    while (System.currentTimeMillis() < deadline && !server.getActiveSessions().isEmpty()) {
                        Thread.sleep(25);
                    }
                    assertTrue(server.getActiveSessions().isEmpty(), "Revoking session via adapter must close gateway session");

                    adapter.disconnect();
                    deadline = System.currentTimeMillis() + 2000;
                    while (System.currentTimeMillis() < deadline && engine.isConnected()) {
                        Thread.sleep(25);
                    }
                    assertFalse(engine.isConnected());
                }
            }
        }
    }
}
