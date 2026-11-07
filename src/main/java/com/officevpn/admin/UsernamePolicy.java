package com.officevpn.admin;

import java.util.regex.Pattern;

/**
 * Enforces username validation rules across the Office VPN platform.
 * Usernames must be 3 to 32 characters consisting only of alphanumeric characters,
 * underscores, dots, and hyphens.
 */
public final class UsernamePolicy {

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]{3,32}$");

    private UsernamePolicy() {}

    /**
     * Validates whether the given username adheres to policy.
     *
     * @param username username to validate
     * @throws IllegalArgumentException if username does not meet policy
     */
    public static void validateUsername(String username) {
        if (!isValidUsername(username)) {
            throw new IllegalArgumentException(
                    "Invalid username: must be 3-32 characters (alphanumeric, underscore, dot, hyphen)"
            );
        }
    }

    /**
     * Checks if the username format is valid.
     */
    public static boolean isValidUsername(String username) {
        return username != null && USERNAME_PATTERN.matcher(username).matches();
    }

    /**
     * Convenient alias for {@link #isValidUsername(String)}.
     */
    public static boolean isValid(String username) {
        return isValidUsername(username);
    }
}

