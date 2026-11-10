package com.officevpn.admin;

import java.security.SecureRandom;
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

    private static final String GENERATED_ALPHABET =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

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

    /**
     * Generates a cryptographically random password meeting length and policy constraints.
     */
    public static String generateStrongPassword(int length) {
        int effectiveLength = Math.max(MIN_LENGTH, Math.min(length, MAX_LENGTH));
        String upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        String lower = "abcdefghijkmnopqrstuvwxyz";
        String digits = "23456789";
        String symbols = "!@#$%^&*";
        for (int attempt = 0; attempt < 16; attempt++) {
            char[] chars = new char[effectiveLength];
            chars[0] = upper.charAt(SECURE_RANDOM.nextInt(upper.length()));
            chars[1] = lower.charAt(SECURE_RANDOM.nextInt(lower.length()));
            chars[2] = digits.charAt(SECURE_RANDOM.nextInt(digits.length()));
            chars[3] = symbols.charAt(SECURE_RANDOM.nextInt(symbols.length()));
            for (int i = 4; i < effectiveLength; i++) {
                chars[i] = GENERATED_ALPHABET.charAt(SECURE_RANDOM.nextInt(GENERATED_ALPHABET.length()));
            }
            for (int i = effectiveLength - 1; i > 0; i--) {
                int j = SECURE_RANDOM.nextInt(i + 1);
                char tmp = chars[i];
                chars[i] = chars[j];
                chars[j] = tmp;
            }
            String candidate = new String(chars);
            if (!LegacyDemoCredentials.isLegacyPassword(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("Unable to generate policy-compliant password");
    }
}

