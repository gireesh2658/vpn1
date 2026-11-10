package com.officevpn.db;

import com.officevpn.admin.AlertManager;
import com.officevpn.admin.AuditService;
import com.officevpn.model.AuditVerifyResult;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;
import com.officevpn.security.AuditKeyStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.sql.Connection;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MySqlSchemaAndPoolTest {

    private static String newH2MySqlUrl(String name) {
        return "jdbc:h2:mem:" + name + "_" + UUID.randomUUID().toString().replace("-", "")
                + ";MODE=MySQL;DATABASE_TO_LOWER=TRUE;CASE_INSENSITIVE_IDENTIFIERS=TRUE;DB_CLOSE_DELAY=-1";
    }

    @Test
    @DisplayName("Rejects legacy SQLite file paths and requires mysql or h2 JDBC URL")
    void testRejectsUnsupportedDatabaseUrl() {
        assertThrows(IllegalArgumentException.class, () -> new DatabaseManager("office_vpn.db"));
        assertThrows(IllegalArgumentException.class, () -> new DatabaseManager("jdbc:sqlite:office_vpn.db"));
    }

    @Test
    @DisplayName("HikariCP pool, MySQL DDL, case-insensitive lookup, AuditService search, and upserts work end-to-end")
    void testPoolSchemaAuditSearchAndUpserts(@TempDir Path tempDir) throws Exception {
        try (DatabaseManager db = new DatabaseManager(newH2MySqlUrl("pool_e2e"), new AuditKeyStore(tempDir))) {
            assertTrue(db.getPoolMaxSize() >= 2);
            try (Connection c = db.openConnection()) {
                assertTrue(c.isValid(2));
            }

            UserAccount hq = db.createUser("admin_hq", "HQ#Pass2026!Master".toCharArray(),
                    Department.HEADQUARTERS, Role.ADMIN, "BOOTSTRAP");
            assertNotNull(hq);

            // Case-insensitive lookup and password reset
            UserAccount mixedCase = db.getUserByUsername("ADMIN_HQ");
            assertNotNull(mixedCase);
            assertEquals("admin_hq", mixedCase.username());

            UserAccount emp = db.createUser("alice_fin", "Finance#SafePass2026!".toCharArray(),
                    Department.FINANCE, Role.EMPLOYEE, "admin_hq");
            assertNotNull(emp);
            assertTrue(db.changeRole("ALICE_FIN", Role.AUDITOR, "admin_hq"));
            assertTrue(db.changeDepartment("ALICE_FIN", Department.IT, "admin_hq"));
            assertEquals(Department.IT, db.getUserByUsername("alice_fin").department());

            // Session upsert + close
            db.insertSession("sess-1", "alice_fin", "10.8.0.2", "IT", "AUDITOR", "127.0.0.1");
            db.insertSession("sess-1", "alice_fin", "10.8.0.3", "IT", "AUDITOR", "127.0.0.2");
            assertEquals(1, db.listActiveSessions().size());
            assertEquals("10.8.0.3", db.listActiveSessions().get(0).virtualIp());
            db.closeSession("sess-1", "LOGOUT");
            assertTrue(db.listActiveSessions().isEmpty());

            // Site-to-site peer upsert
            db.saveSiteToSitePeer("branch-ny", "198.51.100.1", "10.8.0.0/24", "10.9.0.0/24", "hash1", "ONLINE", 100L);
            db.saveSiteToSitePeer("branch-ny", "198.51.100.2", "10.8.0.0/24", "10.9.0.0/24", "hash2", "DEGRADED", 200L);
            assertEquals("198.51.100.2", db.getSiteToSitePeer("branch-ny").peerGatewayIp());
            assertEquals("DEGRADED", db.getSiteToSitePeer("branch-ny").status());

            // Alerts + Bandwidth + Metrics
            AlertManager alerts = new AlertManager(db);
            alerts.createAlert(AlertManager.AlertType.CONFIG_CHANGED, AlertManager.AlertSeverity.WARNING, "admin_hq", "Test alert");
            assertFalse(alerts.getAllAlerts().isEmpty());
            db.logBandwidthConsumption("alice_fin", 4096L, 0L);
            assertEquals(4096L, db.sumBandwidthToday(0L));
            assertEquals(1, db.getTopUsersByBandwidth(5).size());

            // AuditService uses pooled connection and case-insensitive filter
            AuditService auditService = new AuditService(db, alerts);
            List<DatabaseManager.AuditLogEntry> found = auditService.searchAudit("ALICE_FIN", null, null, null);
            assertFalse(found.isEmpty());
            assertTrue(auditService.verifyAuditChain());

            AuditVerifyResult verifyResult = db.verifyAuditChain();
            assertEquals(AuditVerifyResult.AuditStatus.OK, verifyResult.status());
            assertTrue(verifyResult.rowsChecked() >= 4);
        }
    }
}
