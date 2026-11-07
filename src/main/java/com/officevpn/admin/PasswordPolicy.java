package com.officevpn.admin;

import java.util.Locale;

/**
 * Enforces password complexity and safety rules.
 * <p>
 * Rules:
 * <ul>
 *   <li>Length must be between 12 and 128 characters inclusive.</li>
 *   <li>Must not equal or contain the associated username (case-insensitive).</li>
 *   <li>Must not match any known public legacy demonstration passwords.</li>
 * </ul>
 */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 128;

    private PasswordPolicy() {}

    /**
     * Validates a password represented as a char array.
     */
    public static void validatePassword(char[] password, String username) {
        if (password == null || password.length < MIN_LENGTH || password.length > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be between " + MIN_LENGTH + " and " + MAX_LENGTH + " characters in length"
            );
        }

        String pwString = new String(password);
        try {
            validatePassword(pwString, username);
        } finally {
            // Note: Caller remains responsible for wiping password char[]
        }
    }

    /**
     * Validates a password represented as a String.
     */
    public static void validatePassword(String password, String username) {
        if (password == null || password.length() < MIN_LENGTH || password.length() > MAX_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be between " + MIN_LENGTH + " and " + MAX_LENGTH + " characters in length"
            );
        }

        if (username != null && !username.trim().isEmpty()) {
            String cleanUsername = username.trim().toLowerCase(Locale.ROOT);
            String lowerPw = password.toLowerCase(Locale.ROOT);
            if (lowerPw.contains(cleanUsername)) {
                throw new IllegalArgumentException("Password must not contain or match the username");
            }
        }

        if (LegacyDemoCredentials.isLegacyPassword(password)) {
            throw new IllegalArgumentException("Password matches a known insecure legacy default password");
        }
    }
}

