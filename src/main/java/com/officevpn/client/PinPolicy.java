package com.officevpn.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Objects;

/**
 * Pure non-Swing policy engine for evaluating Gateway Public Key Fingerprints and pinning decisions.
 */
public final class PinPolicy {

    private PinPolicy() {}

    /**
     * Normalizes a fingerprint string by stripping whitespace and colons and converting to lowercase.
     */
    public static String normalize(String fp) {
        if (fp == null) return "";
        return fp.replaceAll("[\\s:]+", "").toLowerCase(Locale.ROOT);
    }

    /**
     * Constant-time comparison of two strings.
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(aBytes, bBytes);
    }

    /**
     * Decides the fingerprint pinning outcome based on stored pin, user-typed fingerprint,
     * actual server fingerprint, and user replacement confirmation flag.
     *
     * @param storedPin         Previously recorded pin for host:port (null or empty if first use)
     * @param typedFingerprint  Optional fingerprint typed in by the user (null or empty if blank)
     * @param actualFingerprint Actual SHA-256 fingerprint presented by the gateway during handshake
     * @param confirmReplace    Whether user explicitly confirmed replacement of an existing pin
     * @return PinDecision outcome enum
     */
    public static PinDecision decide(String storedPin, String typedFingerprint, String actualFingerprint, boolean confirmReplace) {
        Objects.requireNonNull(actualFingerprint, "actualFingerprint cannot be null");
        String normActual = normalize(actualFingerprint);
        if (normActual.isEmpty()) {
            throw new IllegalArgumentException("actualFingerprint cannot be blank");
        }

        String normStored = (storedPin != null && !storedPin.trim().isEmpty()) ? normalize(storedPin) : null;
        String normTyped = (typedFingerprint != null && !typedFingerprint.trim().isEmpty()) ? normalize(typedFingerprint) : null;

        // A typed fingerprint that differs from actual server fingerprint is ALWAYS a failure
        if (normTyped != null && !constantTimeEquals(normTyped, normActual)) {
            if (normStored != null && !constantTimeEquals(normStored, normActual)) {
                return PinDecision.PIN_MISMATCH_HARD_FAIL;
            }
            return PinDecision.FIRST_USE_TYPED_MISMATCH_FAIL;
        }

        if (normStored == null) {
            // First use (no prior pin recorded)
            if (normTyped == null) {
                return PinDecision.FIRST_USE_NEEDS_CONFIRMATION;
            }
            return PinDecision.FIRST_USE_TYPED_MATCH;
        }

        // Prior pin exists
        if (constantTimeEquals(normStored, normActual)) {
            return PinDecision.PIN_MATCH;
        }

        // Pinned fingerprint does NOT match actual gateway identity
        if (normTyped != null && constantTimeEquals(normTyped, normActual) && confirmReplace) {
            return PinDecision.PIN_REPLACED;
        }

        return PinDecision.PIN_MISMATCH_HARD_FAIL;
    }
}
