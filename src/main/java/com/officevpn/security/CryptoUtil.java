package com.officevpn.security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * High-level cryptographic facade delegating to {@link CryptoUtils} and standard JCA algorithms.
 * Provides simplified utilities for AES-256-GCM and PBKDF2 password operations.
 */
public final class CryptoUtil {

    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int AES_KEY_SIZE_BITS = 256;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CryptoUtil() {}

    /**
     * Generates a random 256-bit AES symmetric key.
     *
     * @return 256-bit AES {@link SecretKey}
     */
    public static SecretKey generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE_BITS, SECURE_RANDOM);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("AES algorithm unavailable in JVM", e);
        }
    }

    /**
     * Encrypts plaintext bytes using AES-256-GCM with the specified initialization vector.
     *
     * @param plaintext data bytes to encrypt
     * @param key       AES secret key
     * @param iv        12-byte initialization vector
     * @return encrypted ciphertext with 128-bit authentication tag appended
     */
    public static byte[] encryptAESGCM(byte[] plaintext, SecretKey key, byte[] iv) {
        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(key, "SecretKey cannot be null");
        Objects.requireNonNull(iv, "IV cannot be null");
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("AES-GCM encryption failed", e);
        }
    }

    /**
     * Decrypts ciphertext bytes using AES-256-GCM with the specified initialization vector.
     *
     * @param ciphertext encrypted data bytes
     * @param key        AES secret key
     * @param iv         12-byte initialization vector
     * @return original decrypted plaintext bytes
     */
    public static byte[] decryptAESGCM(byte[] ciphertext, SecretKey key, byte[] iv) {
        Objects.requireNonNull(ciphertext, "Ciphertext cannot be null");
        Objects.requireNonNull(key, "SecretKey cannot be null");
        Objects.requireNonNull(iv, "IV cannot be null");
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("AES-GCM decryption failed", e);
        }
    }

    /**
     * Generates a cryptographically secure random Base64 salt.
     *
     * @return Base64-encoded salt string
     */
    public static String generateSalt() {
        return CryptoUtils.generateSalt();
    }

    /**
     * Hashes a raw password using PBKDF2WithHmacSHA256 and the provided Base64 salt.
     *
     * @param password   user password char array
     * @param saltBase64 Base64-encoded salt
     * @return Base64-encoded password hash
     */
    public static String hashPassword(char[] password, String saltBase64) {
        return CryptoUtils.hashPassword(password, saltBase64);
    }

    /**
     * Constant-time verification of a password against a salt and stored hash.
     *
     * @param password           user password char array
     * @param saltBase64         Base64-encoded salt
     * @param expectedHashBase64 Base64-encoded expected hash
     * @return true if password matches, false otherwise
     */
    public static boolean verifyPassword(char[] password, String saltBase64, String expectedHashBase64) {
        return CryptoUtils.verifyPassword(password, saltBase64, expectedHashBase64);
    }
}
