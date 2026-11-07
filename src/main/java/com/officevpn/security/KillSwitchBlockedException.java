package com.officevpn.security;

import java.io.IOException;

/**
 * Exception thrown when outbound network transmission is blocked by the application-level Kill Switch
 * due to an unexpected VPN tunnel disruption.
 */
public class KillSwitchBlockedException extends IOException {

    private static final long serialVersionUID = 1L;

    public KillSwitchBlockedException(String message) {
        super(message);
    }

    public KillSwitchBlockedException(String message, Throwable cause) {
        super(message, cause);
    }
}
