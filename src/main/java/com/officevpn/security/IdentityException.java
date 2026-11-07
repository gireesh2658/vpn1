package com.officevpn.security;

/**
 * Thrown when server cryptographic identity cannot be loaded, decrypted, or verified.
 */
public class IdentityException extends Exception {
    private static final long serialVersionUID = 1L;

    public IdentityException(String message) {
        super(message);
    }

    public IdentityException(String message, Throwable cause) {
        super(message, cause);
    }
}

