package com.officevpn.model;

import java.util.Objects;

/**
 * Domain entity representing an authenticated user account in the Office VPN system.
 *
 * @param id           Unique database row identifier
 * @param username     Unique username identifier
 * @param passwordSalt Base64 encoded 16-byte cryptographic salt
 * @param passwordHash Base64 encoded PBKDF2 derived password hash
 * @param department   User's assigned department
 * @param role         User's assigned access role
 * @param active       Account activation status (inactive accounts are rejected upon login)
 * @param createdAt    Account creation timestamp in milliseconds
 */
public record UserAccount(
        int id,
        String username,
        String passwordSalt,
        String passwordHash,
        Department department,
        Role role,
        boolean active,
        long createdAt
) {
    public UserAccount {
        Objects.requireNonNull(username, "Username cannot be null");
        Objects.requireNonNull(department, "Department cannot be null");
        Objects.requireNonNull(role, "Role cannot be null");
    }

    public boolean isActive() {
        return active;
    }

    /**
     * Security-hardened string representation that redacts sensitive cryptographic salt and hash.
     * Prevents unintentional credential leakage in logs or crash traces.
     */
    @Override
    public String toString() {
        return "UserAccount{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", department=" + department +
                ", role=" + role +
                ", active=" + active +
                ", createdAt=" + createdAt +
                ", passwordSalt='[PROTECTED]'" +
                ", passwordHash='[PROTECTED]'" +
                '}';
    }
}

