package com.officevpn.client;

/**
 * Outcome decisions for VPN Gateway Public Key Fingerprint verification.
 */
public enum PinDecision {
    /** First time connecting to host:port, no stored pin, fingerprint field left blank */
    FIRST_USE_NEEDS_CONFIRMATION,

    /** First time connecting, typed fingerprint matches actual server fingerprint */
    FIRST_USE_TYPED_MATCH,

    /** First time connecting, typed fingerprint does NOT match actual server fingerprint */
    FIRST_USE_TYPED_MISMATCH_FAIL,

    /** Previously enrolled host:port, actual server fingerprint matches stored pin */
    PIN_MATCH,

    /** Previously enrolled host:port, actual server fingerprint does NOT match stored pin (MITM/Rogue) */
    PIN_MISMATCH_HARD_FAIL,

    /** Previously enrolled host:port, replacement confirmed with matching typed fingerprint */
    PIN_REPLACED
}

