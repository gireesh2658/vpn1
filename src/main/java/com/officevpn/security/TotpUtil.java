package com.officevpn.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * RFC 6238 Time-Based One-Time Password (TOTP) utility.
 * - Algorithm: HMAC-SHA1
 * - Time Step: 30 seconds
 * - Code Digits: 6 digits
 * - Clock Drift Tolerance: ±1 step (allows 30s forward/backward drift)
 * - Base32 secret encoding / decoding
 */
public final class TotpUtil {

    private static final String HMAC_ALGO = "HmacSHA1";
    private static final int TIME_STEP_SECONDS = 30;
    private static final int DIGITS = 6;
    private static final int MODULUS = 1_000_000;
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private TotpUtil() {}

    /**
     * Generates a new random Base32 encoded TOTP secret (160-bit / 20 bytes).
     *
     * @return Base32 string secret
     */
    public static String generateSecret() {
        byte[] bytes = new byte[20];
        SECURE_RANDOM.nextBytes(bytes);
        try {
            return encodeBase32(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Generates the current 6-digit TOTP code for the given Base32 secret.
     *
     * @param base32Secret Base32 encoded secret key
     * @return 6-digit zero-padded OTP code
     */
    public static String generateCurrentCode(String base32Secret) {
        long currentWindow = System.currentTimeMillis() / 1000L / TIME_STEP_SECONDS;
        return generateCodeForWindow(base32Secret, currentWindow);
    }

    /**
     * Generates 6-digit TOTP code for a specific time window.
     *
     * @param base32Secret Base32 encoded secret key
     * @param window       time step index
     * @return 6-digit OTP code
     */
    public static String generateCodeForWindow(String base32Secret, long window) {
        Objects.requireNonNull(base32Secret, "Secret cannot be null");
        byte[] keyBytes = decodeBase32(base32Secret);
        try {
            byte[] data = ByteBuffer.allocate(8).putLong(window).array();
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(keyBytes, HMAC_ALGO));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int otp = binary % MODULUS;
            return String.format("%0" + DIGITS + "d", otp);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to calculate HMAC-SHA1 for TOTP", e);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /**
     * Verifies a 6-digit TOTP code with ±1 window tolerance using constant-time comparison.
     *
     * @param base32Secret Base32 encoded secret key
     * @param code         user-submitted code
     * @return true if valid within tolerance window
     */
    public static boolean verifyCode(String base32Secret, String code) {
        return verifyCodeWithReplayCheck(base32Secret, code, -1L) >= 0;
    }

    /**
     * Verifies a 6-digit TOTP code against a secret key and rejects already-used time steps.
     * Uses constant-time comparison via MessageDigest.isEqual to prevent timing attacks.
     *
     * @param base32Secret   Base32 encoded secret key
     * @param code           6-digit OTP code submitted by user
     * @param lastUsedWindow Last recorded time step window successfully used by this user (or -1 if none)
     * @return Positive time step window if valid and strictly greater than lastUsedWindow; -1 if invalid or replayed
     */
    public static long verifyCodeWithReplayCheck(String base32Secret, String code, long lastUsedWindow) {
        if (base32Secret == null || code == null || code.trim().length() != DIGITS) {
            return -1L;
        }
        String cleanCode = code.trim();
        long currentWindow = System.currentTimeMillis() / 1000L / TIME_STEP_SECONDS;

        for (long w = currentWindow - 1; w <= currentWindow + 1; w++) {
            if (w <= lastUsedWindow) {
                continue; // Reject replayed time step
            }
            String expected = generateCodeForWindow(base32Secret, w);
            if (constantTimeEquals(cleanCode, expected)) {
                return w;
            }
        }
        return -1L;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return java.security.MessageDigest.isEqual(
                a.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                b.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
    }

    /**
     * Encodes raw bytes to RFC 4648 Base32 string.
     */
    public static String encodeBase32(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                int index = (buffer >> bitsLeft) & 0x1F;
                sb.append(BASE32_ALPHABET.charAt(index));
            }
        }
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            sb.append(BASE32_ALPHABET.charAt(index));
        }
        return sb.toString();
    }

    /**
     * Decodes RFC 4648 Base32 string to raw bytes.
     */
    public static byte[] decodeBase32(String base32) {
        if (base32 == null) {
            return new byte[0];
        }
        String clean = base32.trim().toUpperCase().replaceAll("[^A-Z2-7]", "");
        ByteBuffer out = ByteBuffer.allocate((clean.length() * 5) / 8 + 1);
        int buffer = 0;
        int bitsLeft = 0;
        for (int i = 0; i < clean.length(); i++) {
            char c = clean.charAt(i);
            int val = BASE32_ALPHABET.indexOf(c);
            if (val < 0) {
                continue;
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                out.put((byte) ((buffer >> bitsLeft) & 0xFF));
            }
        }
        out.flip();
        byte[] result = new byte[out.remaining()];
        out.get(result);
        return result;
    }
}
