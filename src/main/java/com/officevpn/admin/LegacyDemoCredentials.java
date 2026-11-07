package com.officevpn.admin;

import java.util.Collections;
import java.util.Set;

/**
 * Registry of breached and burned legacy demonstration passwords.
 * <p>
 * <b>SECURITY NOTE:</b> Plaintext passwords have been replaced with cryptographic
 * SHA-256 digests to ensure zero sensitive credentials exist in the codebase.
 */
public final class LegacyDemoCredentials {

    private static final Set<String> BURNED_PASSWORD_HASHES = Set.of(
            "e86f78a8a3caf0b60d8e74e5942aa6d86dc150cd3c03338aef25b7d2d7e3acc7", // Admin
            "798a72f3acf7e9689841b4acccd8242e7fa25fb63f87ec87ff02568432a52c35", // Gireesh
            "ca35068eabfd1dc3ba09cbe6255036fb1e69e3e0b1e95a52f1494638bc759071", // Emp
            "3d5e9ac865d0e0ec9a56fa0f8739772b001269721c5776eb4dfe25c1eab1919f", // Alice
            "ec78f6af326ce2ef33a213a09945bfe0872126874258ae7a8be4f2e7888aa4fa", // Bob
            "add2a3bedcb093b9a0bdc7031889186844ef3000abd2f294d7987bfddae3615a", // Charlie
            "ac71321b2d698816e659eeb8e1d34e9ba1d2c184a2bdb9175d57773ca6e14925", // Admin HQ
            "97dc20d3df3d637824f3bae4a272ae45bb8b8ea28abad825fd884419a55dbf0e", // Finance Alice
            "d350d152e11bff4548d86d6cc8e70ee2c7f76b0dcf4ddbafde0df6f415b0f478", // HR Bob
            "6e9ac5d60331a53aa228a654983ce9da471c203b27edf824dfad71436ebc5dc7", // IT Charlie
            "ad9783a9116f22bf5798af41dba26499dedb7224aa8699eab538f5a3e9db37e5"  // Audit David
    );

    private LegacyDemoCredentials() {}

    public static Set<String> getBurnedPasswordHashes() {
        return Collections.unmodifiableSet(BURNED_PASSWORD_HASHES);
    }

    /**
     * Checks if a candidate password matches any known burned legacy password hash.
     *
     * @param password Candidate password
     * @return true if password matches a burned credential hash
     */
    public static boolean isLegacyPassword(String password) {
        if (password == null || password.isBlank()) {
            return false;
        }
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(password.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String hex = java.util.HexFormat.of().formatHex(digest);
            return BURNED_PASSWORD_HASHES.contains(hex);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
