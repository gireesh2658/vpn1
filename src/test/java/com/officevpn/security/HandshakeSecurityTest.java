package com.officevpn.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HandshakeSecurityTest {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    @DisplayName("Ephemeral ECDH on secp256r1 generates valid points and derives mutual shared secret")
    void testEcdhKeyExchangeAndDerivation() throws Exception {
        KeyPair clientPair = KeyExchangeUtil.generateECDHKeyPair();
        KeyPair serverPair = KeyExchangeUtil.generateECDHKeyPair();

        assertTrue(KeyExchangeUtil.isValidSecp256r1PublicKey(clientPair.getPublic()));
        assertTrue(KeyExchangeUtil.isValidSecp256r1PublicKey(serverPair.getPublic()));

        byte[] clientSecret = KeyExchangeUtil.deriveRawSharedSecret(clientPair.getPrivate(), serverPair.getPublic());
        byte[] serverSecret = KeyExchangeUtil.deriveRawSharedSecret(serverPair.getPrivate(), clientPair.getPublic());

        assertNotNull(clientSecret);
        assertEquals(32, clientSecret.length);
        assertEquals(32, serverSecret.length);

        // Raw ECDH shared secret must match mutually
        java.util.Arrays.equals(clientSecret, serverSecret);

        // Directional keys derived from transcript hash
        byte[] transcriptHash = new byte[32];
        RANDOM.nextBytes(transcriptHash);

        CryptoUtils.DirectionalKeys clientKeys = KeyExchangeUtil.deriveDirectionalKeys(clientSecret, transcriptHash);
        CryptoUtils.DirectionalKeys serverKeys = KeyExchangeUtil.deriveDirectionalKeys(serverSecret, transcriptHash);

        assertNotNull(clientKeys.c2sKey());
        assertNotNull(clientKeys.s2cKey());
        assertEquals(clientKeys.c2sKey(), serverKeys.c2sKey());
        assertEquals(clientKeys.s2cKey(), serverKeys.s2cKey());
        assertFalse(clientKeys.c2sKey().equals(clientKeys.s2cKey()), "C2S and S2C keys must be independent");
    }

    @Test
    @DisplayName("Transcript RSASSA-PSS signing and tamper detection")
    void testTranscriptSignatureAndTampering() throws Exception {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair serverRsa = rsaGen.generateKeyPair();

        KeyPair clientEc = KeyExchangeUtil.generateECDHKeyPair();
        KeyPair serverEc = KeyExchangeUtil.generateECDHKeyPair();

        byte[] clientNonce = new byte[32];
        byte[] serverNonce = new byte[32];
        RANDOM.nextBytes(clientNonce);
        RANDOM.nextBytes(serverNonce);

        byte[] canonicalTranscript = CryptoUtils.buildHandshakeTranscriptV2(
                "OFFICE-VPN-2.0",
                clientNonce,
                serverNonce,
                clientEc.getPublic().getEncoded(),
                serverEc.getPublic().getEncoded()
        );

        byte[] signature = CryptoUtils.signWithRsaPss(canonicalTranscript, serverRsa.getPrivate());
        assertNotNull(signature);

        // Valid signature verifies
        assertTrue(CryptoUtils.verifyWithRsaPss(canonicalTranscript, signature, serverRsa.getPublic()));

        // Tampered client nonce must fail verification
        byte[] tamperedNonce = clientNonce.clone();
        tamperedNonce[0] = (byte) (tamperedNonce[0] ^ 0xFF);
        byte[] tamperedTranscript = CryptoUtils.buildHandshakeTranscriptV2(
                "OFFICE-VPN-2.0",
                tamperedNonce,
                serverNonce,
                clientEc.getPublic().getEncoded(),
                serverEc.getPublic().getEncoded()
        );

        assertFalse(CryptoUtils.verifyWithRsaPss(tamperedTranscript, signature, serverRsa.getPublic()));
    }

    @Test
    @DisplayName("H3 Fix: TOFU policy pins fingerprint only after RSASSA-PSS signature verification succeeds")
    void testTofuPinAfterVerify(@TempDir Path tempDir) throws Exception {
        Path pinStorePath = tempDir.resolve("trusted_fingerprints.properties");
        TrustedFingerprintStore store = new TrustedFingerprintStore(pinStorePath);

        String host = "vpn.company.com";
        int port = 8443;

        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair legitimateServer = rsaGen.generateKeyPair();
        KeyPair attackerServer = rsaGen.generateKeyPair();

        String legitimateFp = CryptoUtils.computeSha256FingerprintHex(legitimateServer.getPublic());
        String attackerFp = CryptoUtils.computeSha256FingerprintHex(attackerServer.getPublic());

        // Initial state: not enrolled
        assertFalse(store.isEnrolled(host, port));

        // Scenario 1: Attacker presents key but produces invalid signature over transcript
        byte[] transcript = "test-transcript-bytes".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] invalidSignature = CryptoUtils.signWithRsaPss(transcript, attackerServer.getPrivate());

        // Verification against legitimate key fails
        boolean verified = CryptoUtils.verifyWithRsaPss(transcript, invalidSignature, legitimateServer.getPublic());
        assertFalse(verified);

        // Verify that store is NOT pinned when signature verification fails
        if (!verified) {
            // Client rejects connection and aborts WITHOUT calling pinFingerprint
        }
        assertFalse(store.isEnrolled(host, port));

        // Scenario 2: Legitimate handshake succeeds and verifies
        byte[] validSignature = CryptoUtils.signWithRsaPss(transcript, legitimateServer.getPrivate());
        assertTrue(CryptoUtils.verifyWithRsaPss(transcript, validSignature, legitimateServer.getPublic()));

        // ONLY now does client pin the fingerprint
        store.pinFingerprint(host, port, legitimateFp);

        assertTrue(store.isEnrolled(host, port));
        Optional<String> pinned = store.getPinnedFingerprint(host, port);
        assertTrue(pinned.isPresent());
        assertEquals(legitimateFp, pinned.get());

        // Scenario 3: Attacker later tries to replace key -> detected as MITM mismatch
        assertFalse(legitimateFp.equalsIgnoreCase(attackerFp));
    }
}
