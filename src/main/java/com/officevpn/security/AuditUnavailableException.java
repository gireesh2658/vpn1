package com.officevpn.security;

/**
 * Exception thrown when audit logging is unavailable or failed,
 * enforcing fail-closed security semantics for critical operations.
 */
public class AuditUnavailableException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public AuditUnavailableException(String message) {
        super(message);
    }

    public AuditUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}

