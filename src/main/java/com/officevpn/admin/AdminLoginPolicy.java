package com.officevpn.admin;

import com.officevpn.db.DatabaseManager;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;

import java.util.Objects;

/**
 * Access policy rules governing administrative authentication and dashboard access.
 * <p>
 * An account must meet all of the following requirements:
 * <ul>
 *   <li>The account must exist and credentials must be valid.</li>
 *   <li>The account must be active (is_active = 1).</li>
 *   <li>The account's role must be {@link Role#ADMIN}.</li>
 *   <li>The account's department must be {@link Department#HEADQUARTERS}.</li>
 * </ul>
 */
public final class AdminLoginPolicy {

    private AdminLoginPolicy() {}

    /**
     * Checks if a user account is permitted to log in as an administrator.
     *
     * @param account candidate user account
     * @return true if account is active, role is ADMIN, and department is HEADQUARTERS
     */
    public static boolean canLoginAsAdmin(UserAccount account) {
        if (account == null) {
            return false;
        }
        return account.active() && account.role() == Role.ADMIN && account.department() == Department.HEADQUARTERS;
    }

    /**
     * Authenticates an administrator against the database.
     *
     * @param db DatabaseManager instance
     * @param username username candidate
     * @param password password candidate char array (wiped after use)
     * @param ipAddress IP address for audit logging
     * @return UserAccount if authenticated and authorized as HQ ADMIN; null otherwise
     */
    public static UserAccount authenticateAdmin(DatabaseManager db, String username, char[] password, String ipAddress) {
        Objects.requireNonNull(db, "DatabaseManager cannot be null");
        if (username == null || password == null) {
            return null;
        }

        UserAccount account = db.authenticateUser(username, password, ipAddress);
        if (account == null) {
            return null;
        }

        if (!canLoginAsAdmin(account)) {
            db.logAuditEvent("ADMIN_LOGIN_REJECTED", username, account.department().name(),
                    "Admin dashboard access denied: must be active HEADQUARTERS ADMIN", ipAddress);
            return null;
        }

        return account;
    }


}

