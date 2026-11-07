package com.officevpn.security;

/**
 * Functional interface for password hashing.
 * <p>
 * Enables unit testing of concurrent operations, call counting,
 * and simulated hashing delays without holding monitors or coupling tests to real PBKDF2 compute time.
 */
@FunctionalInterface
public interface PasswordHasher {
    /**
     * Hashes a raw password into a secure string representation.
     *
     * @param password Raw plaintext password characters
     * @return Formatted hash string (e.g. modular PBKDF2 format)
     */
    String hash(char[] password);
}

