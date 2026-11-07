package com.officevpn.admin;

import com.officevpn.db.DatabaseManager;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;

import java.util.Arrays;
import java.util.Objects;

/**
 * Handles initial first-run system bootstrapping.
 * Allows establishing the primary Headquarters Administrator account only when no active
 * administrator exists.
 */
public final class AdminBootstrap {

    private static final Object BOOTSTRAP_LOCK = new Object();

    private AdminBootstrap() {}

    /**
     * Checks if the system requires first-run bootstrapping.
     *
     * @param db database manager instance
     * @return true if no active user exists with Role ADMIN and Department HEADQUARTERS
     */
    public static boolean needsBootstrap(DatabaseManager db) {
        Objects.requireNonNull(db, "DatabaseManager cannot be null");
        for (UserAccount user : db.listAllUsers()) {
            if (user.active() && user.role() == Role.ADMIN && user.department() == Department.HEADQUARTERS) {
                return false;
            }
        }
        return true;
    }

    /**
     * Atomically creates the initial Headquarters Administrator account.
     *
     * @param db database manager instance
     * @param username admin username
     * @param password admin password char array (wiped after use)
     * @param confirmPassword confirmation password char array (wiped after use)
     * @return created UserAccount record
     */
    public static UserAccount createInitialAdmin(DatabaseManager db, String username,
                                                char[] password, char[] confirmPassword) {
        Objects.requireNonNull(db, "DatabaseManager cannot be null");
        Objects.requireNonNull(username, "Username cannot be null");
        Objects.requireNonNull(password, "Password cannot be null");
        Objects.requireNonNull(confirmPassword, "Confirm password cannot be null");

        try {
            if (password.length != confirmPassword.length) {
                throw new IllegalArgumentException("Passwords do not match");
            }
            int diff = 0;
            for (int i = 0; i < password.length; i++) {
                diff |= (password[i] ^ confirmPassword[i]);
            }
            if (diff != 0) {
                throw new IllegalArgumentException("Passwords do not match");
            }

            UsernamePolicy.validateUsername(username);
            PasswordPolicy.validatePassword(password, username);

            synchronized (BOOTSTRAP_LOCK) {
                if (!needsBootstrap(db)) {
                    throw new IllegalStateException("Initial administrator is already configured");
                }

                db.createUser(username, password, Department.HEADQUARTERS, Role.ADMIN, "BOOTSTRAP");
                UserAccount created = db.getUserByUsername(username);
                if (created == null) {
                    throw new IllegalStateException("Failed to retrieve created initial administrator");
                }
                return created;
            }
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmPassword, '\0');
        }
    }
}

