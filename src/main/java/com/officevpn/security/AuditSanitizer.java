package com.officevpn.security;

import java.util.regex.Pattern;

/**
 * Sanitizes input strings before embedding into audit log records to prevent
 * audit injection, log corruption, and unbounded field growth.
 */
public final class AuditSanitizer {

    private static final Pattern EVENT_TYPE_PATTERN = Pattern.compile("^[A-Z0-9_]{1,32}$");

    private AuditSanitizer() {}

    /**
     * Sanitizes strings intended for log outputs, completely replacing
     * CR (\r), LF (\n), tabs (\t), and all ASCII control characters (< 32, 127) with spaces
     * to prevent log injection and terminal/GUI corruption.
     *
     * @param input  Raw input string
     * @param maxLen Maximum permitted length
     * @return Cleaned single-line string
     */
    public static String sanitizeLog(String input, int maxLen) {
        if (input == null) {
            return "";
        }
        if (maxLen <= 0) {
            return "";
        }
        int limit = Math.min(input.length(), maxLen);
        StringBuilder sb = new StringBuilder(limit);
        for (int i = 0; i < limit; i++) {
            char c = input.charAt(i);
            if (c == '\r' || c == '\n' || c == '\t' || c < 32 || c == 127) {
                sb.append(' ');
            } else {
                sb.append(c);
            }
        }
        if (input.length() > maxLen) {
            sb.append('~');
        }
        return sb.toString();
    }

    /**
     * Sanitizes general string fields with control character replacement and truncation.
     * Over-long values are truncated with a trailing '~'.
     */
    public static String sanitize(String input, int maxLen) {
        return sanitizeField(input, maxLen);
    }

    public static String sanitizeField(String input, int maxLen) {
        if (input == null) {
            return "";
        }
        if (maxLen <= 0) {
            return "";
        }

        boolean truncated = input.length() > maxLen;
        int limit = truncated ? maxLen - 1 : input.length();

        StringBuilder sb = new StringBuilder(maxLen);
        for (int i = 0; i < limit; i++) {
            char c = input.charAt(i);
            if (c < 32 || c == 127) {
                sb.append('?');
            } else {
                sb.append(c);
            }
        }
        if (truncated) {
            sb.append('~');
        }
        return sb.toString();
    }

    /**
     * Validates event_type against ^[A-Z0-9_]{1,32}$; returns INVALID_EVENT if non-compliant.
     */
    public static String sanitizeEventType(String eventType) {
        if (eventType == null) {
            return "INVALID_EVENT";
        }
        String trimmed = eventType.trim();
        if (EVENT_TYPE_PATTERN.matcher(trimmed).matches()) {
            return trimmed;
        }
        return "INVALID_EVENT";
    }

    /**
     * Validates and sanitizes remote_ip as an IP literal or "local", otherwise "invalid".
     * Strips leading "/" and trailing ":port" if present.
     */
    public static String sanitizeRemoteIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return "invalid";
        }
        String clean = ip.trim();
        if (clean.startsWith("/")) {
            clean = clean.substring(1).trim();
        }
        // Handle IPv6 bracketed address with port, e.g. [::1]:51234
        if (clean.startsWith("[") && clean.contains("]")) {
            clean = clean.substring(1, clean.indexOf(']'));
        } else if (clean.indexOf(':') == clean.lastIndexOf(':') && clean.contains(":")) {
            // Single colon: IPv4:port
            clean = clean.substring(0, clean.indexOf(':')).trim();
        }

        if ("local".equalsIgnoreCase(clean)) {
            return "local";
        }

        if (isValidIpLiteral(clean)) {
            return clean;
        }
        return "invalid";
    }

    public static boolean isValidIpLiteral(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        // IPv4 check
        String[] parts = ip.split("\\.", -1);
        if (parts.length == 4) {
            for (String p : parts) {
                if (p.isEmpty() || p.length() > 3) return false;
                for (int i = 0; i < p.length(); i++) {
                    if (!Character.isDigit(p.charAt(i))) return false;
                }
                int val;
                try {
                    val = Integer.parseInt(p);
                } catch (NumberFormatException e) {
                    return false;
                }
                if (val < 0 || val > 255) return false;
                if (p.length() > 1 && p.startsWith("0")) return false; // no leading zeroes
            }
            return true;
        }
        // IPv6 check
        if (ip.contains(":")) {
            String[] v6Parts = ip.split(":", -1);
            if (v6Parts.length >= 3 && v6Parts.length <= 8) {
                for (String p : v6Parts) {
                    if (p.length() > 4) return false;
                    for (int i = 0; i < p.length(); i++) {
                        char c = p.charAt(i);
                        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                            return false;
                        }
                    }
                }
                return true;
            }
        }
        return false;
    }
}
