package com.officevpn.model;

/**
 * Organizational departments within the office network.
 * <p>
 * Enforces strict <b>Deny-by-Default Role-Based Access Control (RBAC)</b>.
 * Cross-departmental file access is forbidden unless the actor is an {@link Role#ADMIN}
 * operating from {@link #HEADQUARTERS}.
 */
public enum Department {
    FINANCE,
    HR,
    IT,
    HEADQUARTERS;

    /**
     * Strict Deny-by-Default authorization check.
     *
     * @param role        User's assigned role (ADMIN, EMPLOYEE, AUDITOR)
     * @param userDept    User's assigned department
     * @param targetVault Target department vault being accessed
     * @return {@code true} if access is explicitly permitted; {@code false} otherwise
     */
    public static boolean canAccessVault(Role role, Department userDept, Department targetVault) {
        // Strict Deny-by-Default: any null or unassigned attribute results in DENIED
        if (role == null || userDept == null || targetVault == null) {
            return false;
        }

        // HeadQuarters Admin has global governance access across all department vaults
        if (role == Role.ADMIN && userDept == HEADQUARTERS) {
            return true;
        }

        // Employees and Auditors are strictly confined to their own departmental vault
        if (userDept == targetVault) {
            return true;
        }

        // All other cross-department access requests are DENIED
        return false;
    }

    /**
     * Instance convenience method to evaluate access where {@code this} represents the user's department.
     *
     * @param role        User's assigned role
     * @param targetVault Target department vault being accessed
     * @return {@code true} if access is permitted; {@code false} otherwise
     */
    public boolean canAccessVault(Role role, Department targetVault) {
        return canAccessVault(role, this, targetVault);
    }
}

