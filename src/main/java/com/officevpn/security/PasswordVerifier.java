package com.officevpn.security;

/**
 * Functional interface for password hash verification.
 * <p>
 * Enables unit testing of concurrent authentication, call counting,
 * and simulated verification delays without coupling tests to real PBKDF2 compute time.
 */
@FunctionalInterface
public interface PasswordVerifier {
    /**
     * Verifies a raw password against the stored password hash representation.
     *
     * @param password    Raw password characters
     * @param storedHash  Stored hash string (either new modular format or legacy hash)
     * @param legacySalt  Legacy salt string if storedHash is legacy, or null/empty if modular
     * @return true if password matches, false otherwise
     */
    boolean verify(char[] password, String storedHash, String legacySalt);
}

