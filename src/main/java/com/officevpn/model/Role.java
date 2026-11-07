package com.officevpn.model;

/**
 * Access control roles within the Office VPN system.
 * <p>
 * Enforces principle of least privilege:
 * <ul>
 *   <li>{@link #ADMIN}: System administrator with cross-vault governance if assigned to HEADQUARTERS.</li>
 *   <li>{@link #EMPLOYEE}: Standard departmental personnel restricted strictly to their assigned vault.</li>
 *   <li>{@link #AUDITOR}: Compliance reader restricted strictly to departmental records within their assigned vault.</li>
 * </ul>
 */
public enum Role {
    ADMIN,
    EMPLOYEE,
    AUDITOR
}

