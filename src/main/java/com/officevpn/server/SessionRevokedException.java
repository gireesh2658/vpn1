package com.officevpn.server;

/**
 * Exception thrown when an operation is attempted on a session that has been revoked.
 */
public class SessionRevokedException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public SessionRevokedException(String message) {
        super(message);
    }

    public SessionRevokedException(String message, Throwable cause) {
        super(message, cause);
    }
}

