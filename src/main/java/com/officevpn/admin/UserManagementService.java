package com.officevpn.admin;

import com.officevpn.db.DatabaseManager;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;
import com.officevpn.security.CryptoUtils;
import com.officevpn.server.SessionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Enterprise User Management and Lifecycle Service.
 * Coordinates user onboarding, offboarding, password resets, and RBAC governance.
 */
public final class UserManagementService {

    private static final Logger LOGGER = LoggerFactory.getLogger(UserManagementService.class);
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-z][a-z0-9_.]{2,29}$");

    private final DatabaseManager databaseManager;
    private final SessionManager sessionManager;
    private final DeviceManager deviceManager;

    public UserManagementService(DatabaseManager databaseManager) {
        this(databaseManager, null, new DeviceManager(databaseManager));
    }

    public UserManagementService(DatabaseManager databaseManager, SessionManager sessionManager, DeviceManager deviceManager) {
        this.databaseManager = Objects.requireNonNull(databaseManager, "DatabaseManager cannot be null");
        this.sessionManager = sessionManager;
        this.deviceManager = deviceManager != null ? deviceManager : new DeviceManager(databaseManager);
    }

    /**
     * Enforces that the initiating actor possesses administrative privileges.
     *
     * @param adminUsername initiating administrator identity
     * @throws SecurityException if actor is not an active ADMIN
     */
    public void requireAdmin(String adminUsername) {
        if (adminUsername == null || adminUsername.isBlank()) {
            throw new SecurityException("Access Denied: Unspecified administrator identity");
        }
        UserAccount actor = databaseManager.getUserByUsername(adminUsername.trim());
        if (actor == null || !actor.isActive() || actor.role() != Role.ADMIN) {
            databaseManager.logAuditEvent("RBAC_DENIED", adminUsername.trim(), "UNKNOWN",
                    "Administrative action denied: caller lacks ADMIN privileges", "admin", "local");
            LOGGER.warn("RBAC_DENIED: User '{}' attempted admin action without ADMIN role", adminUsername);
            throw new SecurityException("Access Denied: Administrative privileges required");
        }
    }

    /**
     * Validates password policy: at least 8 chars, containing uppercase, lowercase, digit, and special symbol.
     */
    public static void validatePasswordPolicy(String password) {
        if (password == null || password.length() < 12 || password.length() > 128) {
            throw new IllegalArgumentException("Password must be between 12 and 128 characters in length");
        }
        boolean hasUpper = false;
        boolean hasLower = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;

        for (char c : password.toCharArray()) {
            if (Character.isUpperCase(c)) hasUpper = true;
            else if (Character.isLowerCase(c)) hasLower = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else hasSpecial = true;
        }

        if (!hasUpper || !hasLower || !hasDigit || !hasSpecial) {
            throw new IllegalArgumentException("Password must contain uppercase, lowercase, numeric, and special characters");
        }
    }

    /**
     * Onboards a new user with PBKDF2 credential derivation and audit trail registration.
     */
    public UserAccount onboardUser(String adminUsername, String newUsername, String password, Department department, Role role) {
        requireAdmin(adminUsername);
        Objects.requireNonNull(newUsername, "Username cannot be null");
        Objects.requireNonNull(password, "Password cannot be null");
        Department dept = department != null ? department : Department.IT;
        Role userRole = role != null ? role : Role.EMPLOYEE;

        String cleanUsername = newUsername.trim().toLowerCase(Locale.ROOT);
        if (!USERNAME_PATTERN.matcher(cleanUsername).matches()) {
            throw new IllegalArgumentException("Invalid username format. Must match regex ^[a-z][a-z0-9_.]{2,29}$");
        }

        validatePasswordPolicy(password);

        if (databaseManager.getUserByUsername(cleanUsername) != null) {
            throw new IllegalArgumentException("Username already exists: " + cleanUsername);
        }

        char[] pwChars = password.toCharArray();
        try {
            String hash = CryptoUtils.hashPasswordModular(pwChars);
            String salt = CryptoUtils.parseStoredHash(hash).saltB64();
            if (salt == null || salt.isBlank()) {
                salt = CryptoUtils.generateSalt();
            }

            // Direct insert with active status
            UserAccount account = databaseManager.createUser(cleanUsername, pwChars, dept, userRole, adminUsername);
            if (account == null) {
                // In case createUser failed due to constraints, ensure insertion
                throw new IllegalStateException("Failed to insert user record for: " + cleanUsername);
            }

            databaseManager.logAuditEvent("USER_ONBOARDED", cleanUsername, dept.name(),
                    "User onboarded by " + adminUsername + " with role " + userRole.name(), adminUsername, "local");
            LOGGER.info("Successfully onboarded user '{}' in department '{}' with role '{}'", cleanUsername, dept, userRole);

            return account;
        } finally {
            java.util.Arrays.fill(pwChars, '\0');
        }
    }

    /**
     * Offboards an existing user: deactivates account, revokes all sessions and trusted devices.
     */
    public void offboardUser(String adminUsername, String targetUsername) {
        requireAdmin(adminUsername);
        Objects.requireNonNull(targetUsername, "Target username cannot be null");
        String cleanTarget = targetUsername.trim().toLowerCase(Locale.ROOT);

        UserAccount user = databaseManager.getUserByUsername(cleanTarget);
        if (user == null) {
            throw new IllegalArgumentException("Target user does not exist: " + cleanTarget);
        }

        // 1. Deactivate in DB
        databaseManager.setUserActiveStatus(cleanTarget, false, adminUsername);

        // 2. Revoke all active sessions
        if (sessionManager != null) {
            sessionManager.revokeAllSessions(cleanTarget);
        }

        // 3. Revoke all registered devices
        if (deviceManager != null) {
            deviceManager.revokeAllDevices(cleanTarget);
        }

        // 4. Audit logging
        databaseManager.logAuditEvent("USER_OFFBOARDED", cleanTarget, user.department().name(),
                "User offboarded by " + adminUsername + "; sessions and devices terminated", adminUsername, "local");
        databaseManager.logAuditEvent("SESSION_REVOKED", cleanTarget, user.department().name(),
                "All sessions revoked due to user offboarding", adminUsername, "local");
        LOGGER.warn("User '{}' offboarded by admin '{}'", cleanTarget, adminUsername);
    }

    /**
     * Re-enables a disabled user account.
     */
    public void enableUser(String adminUsername, String targetUsername) {
        requireAdmin(adminUsername);
        Objects.requireNonNull(targetUsername, "Target username cannot be null");
        String cleanTarget = targetUsername.trim();

        databaseManager.setUserActiveStatus(cleanTarget, true, adminUsername);
        databaseManager.logAuditEvent("USER_ENABLED", cleanTarget, "UNKNOWN",
                "User account re-enabled by " + adminUsername, adminUsername, "local");
        LOGGER.info("User '{}' re-enabled by admin '{}'", cleanTarget, adminUsername);
    }

    /**
     * Disables a user account and terminates existing active sessions.
     */
    public void disableUser(String adminUsername, String targetUsername) {
        requireAdmin(adminUsername);
        Objects.requireNonNull(targetUsername, "Target username cannot be null");
        String cleanTarget = targetUsername.trim();

        databaseManager.setUserActiveStatus(cleanTarget, false, adminUsername);
        if (sessionManager != null) {
            sessionManager.revokeAllSessions(cleanTarget);
        }
        databaseManager.logAuditEvent("USER_DISABLED", cleanTarget, "UNKNOWN",
                "User account disabled by " + adminUsername, adminUsername, "local");
        LOGGER.info("User '{}' disabled by admin '{}'", cleanTarget, adminUsername);
    }

    /**
     * Resets a user's password, invalidates active sessions, and records the administrative action.
     */
    public void resetPassword(String adminUsername, String targetUsername, String newPassword) {
        requireAdmin(adminUsername);
        Objects.requireNonNull(targetUsername, "Target username cannot be null");
        Objects.requireNonNull(newPassword, "New password cannot be null");
        String cleanTarget = targetUsername.trim();

        validatePasswordPolicy(newPassword);

        char[] pwChars = newPassword.toCharArray();
        try {
            String hash = CryptoUtils.hashPasswordModular(pwChars);
            String salt = CryptoUtils.parseStoredHash(hash).saltB64();
            if (salt == null || salt.isBlank()) {
                salt = CryptoUtils.generateSalt();
            }

            boolean updated = databaseManager.updatePasswordDirect(cleanTarget, salt, hash, adminUsername);
            if (!updated) {
                throw new IllegalArgumentException("User not found: " + cleanTarget);
            }

            if (sessionManager != null) {
                sessionManager.revokeAllSessions(cleanTarget);
            }

            LOGGER.info("Password reset successfully for user '{}' by '{}'", cleanTarget, adminUsername);
        } finally {
            java.util.Arrays.fill(pwChars, '\0');
        }
    }

    /**
     * Returns all user accounts associated with a department.
     */
    public List<UserAccount> listUsersByDepartment(Department department) {
        if (department == null) {
            return List.of();
        } else {
            return databaseManager.listAllUsers().stream()
                    .filter(u -> u.department() == department)
                    .toList();
        }
    }

    /**
     * Returns all disabled user accounts.
     */
    public List<UserAccount> listDisabledUsers() {
        return databaseManager.listAllUsers().stream()
                .filter(u -> !u.isActive())
                .toList();
    }

    /**
     * Searches users matching username, department, or role.
     */
    public List<UserAccount> searchUsers(String query) {
        if (query == null || query.isBlank()) {
            return databaseManager.listAllUsers();
        } else {
            String cleanQ = query.trim().toLowerCase(Locale.ROOT);
            return databaseManager.listAllUsers().stream()
                    .filter(u -> u.username().toLowerCase(Locale.ROOT).contains(cleanQ)
                            || u.department().name().toLowerCase(Locale.ROOT).contains(cleanQ)
                            || u.role().name().toLowerCase(Locale.ROOT).contains(cleanQ))
                    .toList();
        }
    }

    public DatabaseManager getDatabaseManager() {
        return databaseManager;
    }

    public SessionManager getSessionManager() {
        return sessionManager;
    }

    public DeviceManager getDeviceManager() {
        return deviceManager;
    }
}
