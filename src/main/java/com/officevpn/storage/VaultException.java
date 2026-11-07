package com.officevpn.storage;

/**
 * Exception thrown for vault security policy, format, bounds, or quota violations.
 */
public class VaultException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String errorCode;

    public VaultException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public VaultException(String errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}

