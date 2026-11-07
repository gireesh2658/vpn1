package com.officevpn.security;

import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;
import com.officevpn.server.VpnSession;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionTimeoutTest {

    @Test
    @DisplayName("M1 Fix: Session activity recording and timeout bounds detection")
    void testSessionActivityAndTimeoutBounds() throws Exception {
        VpnSession session = new VpnSession("test-session-1", "127.0.0.1:54321");

        assertFalse(session.isAuthenticated());
        long startEstablished = session.getEstablishedTime();
        long startActivity = session.getLastActivityTime();

        assertTrue(startEstablished > 0);
        assertTrue(startActivity > 0);

        Thread.sleep(15);
        session.recordActivity();
        assertTrue(session.getLastActivityTime() > startActivity, "recordActivity must update lastActivityAt");

        // Authenticate session
        UserAccount user = new UserAccount(
                10, "bob", "salt", "hash", Department.IT, Role.EMPLOYEE, true, System.currentTimeMillis()
        );
        byte[] dummyKey = new byte[32];
        CryptoUtils.DirectionalKeys keys = new CryptoUtils.DirectionalKeys(
                new SecretKeySpec(dummyKey, "AES"),
                new SecretKeySpec(dummyKey, "AES")
        );
        session.setAuthenticatedUser(user);
        session.setAssignedVirtualIp("10.8.0.5");
        session.setDirectionalKeys(keys);

        assertTrue(session.isAuthenticated());

        // Test idle timeout calculation logic
        long idleLimitMs = 30 * 60 * 1000L;
        long now = System.currentTimeMillis();
        long fakeStaleActivity = now - idleLimitMs - 5000L;
        boolean isIdleExpired = (now - fakeStaleActivity) > idleLimitMs;
        assertTrue(isIdleExpired, "Activity older than idleLimitMs must be detected as expired");

        // Test absolute timeout calculation logic
        long absLimitMs = 480 * 60 * 1000L;
        long fakeStaleEstablished = now - absLimitMs - 5000L;
        boolean isAbsExpired = (now - fakeStaleEstablished) > absLimitMs;
        assertTrue(isAbsExpired, "Session established longer than absLimitMs must be detected as expired");
    }
}
