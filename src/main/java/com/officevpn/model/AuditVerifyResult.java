package com.officevpn.model;

/**
 * Result of audit hash chain integrity verification.
 */
public record AuditVerifyResult(
        AuditStatus status,
        long rowsChecked,
        long firstBadSeq,
        String message
) {
    public long checkedRows() {
        return rowsChecked;
    }

    public long brokenSeq() {
        return firstBadSeq;
    }

    public String details() {
        return message;
    }

    public enum AuditStatus {
        OK,
        HASH_MISMATCH,
        PREV_MISMATCH,
        SEQ_GAP,
        TRUNCATED,
        KEY_MISSING,
        SCHEMA_ERROR
    }
}
