package com.officevpn.security;

import com.officevpn.admin.LegacyDemoCredentials;
import com.officevpn.admin.PasswordPolicy;
import com.officevpn.db.DatabaseManager;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthAndMfaSecurityTest {

    private static String newH2MySqlUrl(String prefix) {
        return "jdbc:h2:mem:" + prefix + "_" + UUID.randomUUID().toString().replace("-", "")
                + ";MODE=MySQL;DATABASE_TO_LOWER=TRUE;CASE_INSENSITIVE_IDENTIFIERS=TRUE;DB_CLOSE_DELAY=-1";
    }

    @Test
    @DisplayName("H1 Fix: Atomic authentication verifies both password and TOTP together")
    void testAtomicAuthenticationWithTotp(@TempDir Path tempDir) throws Exception {
        String dbUrl = newH2MySqlUrl("auth_mfa");
        try (DatabaseManager db = new DatabaseManager(dbUrl, new AuditKeyStore(tempDir))) {
            String username = "testuser_" + UUID.randomUUID().toString().substring(0, 8);
            char[] password = "Secure#Password2026!".toCharArray();

            UserAccount created = db.createUser(username, password, Department.IT, Role.EMPLOYEE, "ADMIN");
            assertNotNull(created);

            // Case 1: Before TOTP is enabled, valid password authenticates
            UserAccount auth1 = db.authenticateUser(username, password, "127.0.0.1");
            assertNotNull(auth1);

            // Enable TOTP for user
            String totpSecret = TotpUtil.generateSecret();
            db.saveTotpSecret(username, totpSecret);
            assertTrue(db.isTotpEnabled(username));

            // Case 2: Wrong TOTP code -> rejected atomically
            UserAccount authWrongTotp = db.authenticateUser(username, password, "000000", "127.0.0.1");
            assertNull(authWrongTotp, "Authentication must fail when TOTP code is invalid");

            // Case 3: Missing TOTP code when TOTP is required -> rejected atomically
            UserAccount authMissingTotp = db.authenticateUser(username, password, null, "127.0.0.1");
            assertNull(authMissingTotp, "Authentication must fail when TOTP code is omitted");

            // Case 4: Correct password and valid TOTP code -> succeeds atomically
            String validTotp = TotpUtil.generateCurrentCode(totpSecret);
            UserAccount authSuccess = db.authenticateUser(username, password, validTotp, "127.0.0.1");
            assertNotNull(authSuccess, "Authentication must succeed with valid credentials and valid TOTP");
        }
    }

    @Test
    @DisplayName("H1 Fix: Failed TOTP codes increment failure counter and trigger lockout without bypass")
    void testTotpFailuresTriggerLockout(@TempDir Path tempDir) throws Exception {
        String dbUrl = newH2MySqlUrl("lockout");
        try (DatabaseManager db = new DatabaseManager(dbUrl, new AuditKeyStore(tempDir))) {
            String username = "lockout_user";
            char[] password = "Secure#Password2026!".toCharArray();

            db.createUser(username, password, Department.FINANCE, Role.EMPLOYEE, "ADMIN");
            String totpSecret = TotpUtil.generateSecret();
            db.saveTotpSecret(username, totpSecret);

            // Five consecutive failed TOTP attempts from same IP
            for (int i = 0; i < 5; i++) {
                UserAccount attempt = db.authenticateUser(username, password, "999999", "192.168.1.50");
                assertNull(attempt);
            }

            // 6th attempt with CORRECT TOTP code must still be blocked by active lockout
            String validTotp = TotpUtil.generateCurrentCode(totpSecret);
            UserAccount lockedAttempt = db.authenticateUser(username, password, validTotp, "192.168.1.50");
            assertNull(lockedAttempt, "Account must be locked out after consecutive failed TOTP attempts");
        }
    }

    @Test
    @DisplayName("TOTP Replay Defense: Reusing the same TOTP window code is rejected")
    void testTotpStepReplayRejection(@TempDir Path tempDir) throws Exception {
        String dbUrl = newH2MySqlUrl("totp_replay");
        try (DatabaseManager db = new DatabaseManager(dbUrl, new AuditKeyStore(tempDir))) {
            String username = "replay_user";
            char[] password = "Secure#Password2026!".toCharArray();

            db.createUser(username, password, Department.HR, Role.EMPLOYEE, "ADMIN");
            String totpSecret = TotpUtil.generateSecret();
            db.saveTotpSecret(username, totpSecret);

            String validCode = TotpUtil.generateCurrentCode(totpSecret);

            // First use of current code succeeds
            boolean firstUse = db.verifyAndConsumeTotpCode(username, validCode);
            assertTrue(firstUse, "First use of valid TOTP code must succeed");

            // Replay attempt with same code within same window must be rejected
            boolean replayAttempt = db.verifyAndConsumeTotpCode(username, validCode);
            assertFalse(replayAttempt, "Replaying the same TOTP code in the same window must be rejected");
        }
    }

    @Test
    @DisplayName("H2 Fix: Hardware device trust cap and fail-closed enforcement")
    void testHardwareDeviceTrustCap(@TempDir Path tempDir) throws Exception {
        String dbUrl = newH2MySqlUrl("devices");
        try (DatabaseManager db = new DatabaseManager(dbUrl, new AuditKeyStore(tempDir))) {
            String username = "device_user";
            char[] password = "Secure#Password2026!".toCharArray();

            db.createUser(username, password, Department.IT, Role.EMPLOYEE, "ADMIN");

            // Auto-enroll first 3 devices (default device.maxPerUser = 3)
            assertTrue(db.isDeviceTrusted(username, "HW-FINGERPRINT-DEV-1"));
            assertTrue(db.isDeviceTrusted(username, "HW-FINGERPRINT-DEV-2"));
            assertTrue(db.isDeviceTrusted(username, "HW-FINGERPRINT-DEV-3"));

            // 4th device exceeds device cap and must be rejected (fail-closed)
            assertFalse(db.isDeviceTrusted(username, "HW-FINGERPRINT-DEV-4"), "4th device must exceed max devices cap");

            // Revoked device check
            db.setDeviceTrust(username, "HW-FINGERPRINT-DEV-1", false);
            assertFalse(db.isDeviceTrusted(username, "HW-FINGERPRINT-DEV-1"), "Revoked device must not be trusted");
        }
    }

    @Test
    @DisplayName("Password Policy: Rejects burned legacy default credentials")
    void testLegacyDemoCredentialsRejected() {
        assertThrows(IllegalArgumentException.class, () ->
                PasswordPolicy.validatePassword("Admin@123", "admin")
        );
        assertThrows(IllegalArgumentException.class, () ->
                PasswordPolicy.validatePassword("Admin@2026!HQ", "user")
        );

        assertTrue(LegacyDemoCredentials.isLegacyPassword("Admin@123"));
        assertTrue(LegacyDemoCredentials.isLegacyPassword("Admin@2026!HQ"));
        assertFalse(LegacyDemoCredentials.isLegacyPassword("TrulyUnpredictablePassphrase2026#$"));
    }

    @Test
    @DisplayName("MFA QR Generator: Produces valid finder patterns and version bounds for otpauth URIs")
    void testQrCodeGenerationForTotpUri() {
        String uri = "otpauth://totp/OfficeVPN:alice_fin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=OfficeVPN";
        boolean[][] matrix = com.officevpn.security.QrCodeUtil.encode(uri);
        int size = matrix.length;
        assertTrue(size >= 37 && size <= 57, "Unexpected QR module dimension: " + size);
        // Verify top-left, top-right, bottom-left 7x7 finder corners and (size-8, 8) dark module
        assertTrue(matrix[0][0] && matrix[0][6] && matrix[6][0] && matrix[6][6] && matrix[3][3]);
        assertTrue(matrix[0][size - 1] && matrix[0][size - 7] && matrix[3][size - 4]);
        assertTrue(matrix[size - 1][0] && matrix[size - 7][0] && matrix[size - 4][3]);
        assertTrue(matrix[size - 8][8]);
        assertThrows(IllegalArgumentException.class, () -> com.officevpn.security.QrCodeUtil.encode("x".repeat(300)));
    }
}
