package com.officevpn.security;

import com.officevpn.protocol.PacketType;
import com.officevpn.protocol.VpnPacket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoSecurityTest {

    private SecretKey generateAes256Key() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }

    @Test
    @DisplayName("Bidirectional AES-256-GCM encryption and decryption preserves payload and verifies directional AAD")
    void testBidirectionalAeadEncryption() throws Exception {
        SecretKey c2sKey = generateAes256Key();
        SecretKey s2cKey = generateAes256Key();

        byte[] clientPayload = "Client to Server Tunnel Data".getBytes(StandardCharsets.UTF_8);
        Map<String, String> c2sMeta = new LinkedHashMap<>();
        c2sMeta.put("seqNum", "101");

        VpnPacket clientPacket = CryptoUtils.createEncryptedPacket(
                PacketType.FILE_UPLOAD,
                "10.8.0.2",
                "alice",
                "IT",
                c2sMeta,
                clientPayload,
                c2sKey,
                CryptoUtils.DIRECTION_C2S
        );

        byte[] decryptedClientPayload = CryptoUtils.decryptPacket(clientPacket, c2sKey, CryptoUtils.DIRECTION_C2S);
        assertArrayEquals(clientPayload, decryptedClientPayload);

        // Direction byte tampering check: decrypting with DIRECTION_S2C must fail
        assertThrows(SecurityException.class, () ->
                CryptoUtils.decryptPacket(clientPacket, c2sKey, CryptoUtils.DIRECTION_S2C)
        );

        // Key mismatch check: decrypting with wrong directional key must fail
        assertThrows(SecurityException.class, () ->
                CryptoUtils.decryptPacket(clientPacket, s2cKey, CryptoUtils.DIRECTION_C2S)
        );
    }

    @Test
    @DisplayName("H4 Chat Fix: Server chat broadcast roundtrip encrypts with s2cKey and client decrypts cleanly")
    void testChatBroadcastRoundtrip() throws Exception {
        SecretKey s2cKey = generateAes256Key();
        String chatMsg = "Intranet announcement: all systems operational";
        byte[] chatPayload = chatMsg.getBytes(StandardCharsets.UTF_8);

        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("senderUser", "admin");
        meta.put("senderDept", "HEADQUARTERS");
        meta.put("senderVip", "10.8.0.1");
        meta.put("seqNum", "42");

        VpnPacket chatPacket = CryptoUtils.createEncryptedPacket(
                PacketType.CHAT_MESSAGE,
                "10.8.0.1",
                "admin",
                "HEADQUARTERS",
                meta,
                chatPayload,
                s2cKey,
                CryptoUtils.DIRECTION_S2C
        );

        assertNotNull(chatPacket);
        assertEquals(PacketType.CHAT_MESSAGE, chatPacket.getType());

        // Client decrypts with s2cKey and DIRECTION_S2C
        byte[] decrypted = CryptoUtils.decryptPacket(chatPacket, s2cKey, CryptoUtils.DIRECTION_S2C);
        assertEquals(chatMsg, new String(decrypted, StandardCharsets.UTF_8));

        // Tampering with sender department in packet header must invalidate GCM AAD
        VpnPacket tamperedPacket = new VpnPacket(
                chatPacket.getType(),
                chatPacket.getSenderVirtualIp(),
                chatPacket.getSenderUsername(),
                "ROGUE_DEPT",
                chatPacket.getTimestamp(),
                chatPacket.getIv(),
                chatPacket.getEncryptedPayload(),
                null,
                chatPacket.getMetadata()
        );

        assertThrows(SecurityException.class, () ->
                CryptoUtils.decryptPacket(tamperedPacket, s2cKey, CryptoUtils.DIRECTION_S2C)
        );
    }

    @Test
    @DisplayName("Anti-Replay Window: Rejects duplicate, non-positive, and stale sequence numbers")
    void testAntiReplayWindow() {
        SequenceReplayWindow window = new SequenceReplayWindow(64);

        // Positive initial packet accepted
        assertTrue(window.checkAndRecord(100));

        // Newer packets within window accepted
        assertTrue(window.checkAndRecord(105));
        assertTrue(window.checkAndRecord(102));

        // Duplicate sequence numbers must be rejected
        assertThrows(SecurityException.class, () -> window.checkAndRecord(100));
        assertThrows(SecurityException.class, () -> window.checkAndRecord(105));
        assertThrows(SecurityException.class, () -> window.checkAndRecord(102));

        // Non-positive sequence numbers must be rejected
        assertThrows(SecurityException.class, () -> window.checkAndRecord(0));
        assertThrows(SecurityException.class, () -> window.checkAndRecord(-1));

        // Advance window significantly
        assertTrue(window.checkAndRecord(200));

        // Packets outside window (diff >= 64, e.g. 200 - 100 = 100) must be rejected
        assertThrows(SecurityException.class, () -> window.checkAndRecord(100));
    }

    @Test
    @DisplayName("RSA Key Size: Rejects weak RSA keys under 2048 bits and accepts 2048-bit keys")
    void testRsaKeySizeEnforcement() throws Exception {
        // 2048-bit RSA key must be accepted
        KeyPairGenerator kpg2048 = KeyPairGenerator.getInstance("RSA");
        kpg2048.initialize(2048);
        KeyPair kp2048 = kpg2048.generateKeyPair();
        String b64Valid = Base64.getEncoder().encodeToString(kp2048.getPublic().getEncoded());
        PublicKey pub2048 = CryptoUtils.base64ToPublicKey(b64Valid);
        assertNotNull(pub2048);

        // 1024-bit RSA key must be rejected
        KeyPairGenerator kpg1024 = KeyPairGenerator.getInstance("RSA");
        kpg1024.initialize(1024);
        KeyPair kp1024 = kpg1024.generateKeyPair();
        String b64Weak = Base64.getEncoder().encodeToString(kp1024.getPublic().getEncoded());
        assertThrows(SecurityException.class, () -> CryptoUtils.base64ToPublicKey(b64Weak));
    }

    @Test
    @DisplayName("Strict hex decoding and SHA-256 fingerprinting")
    void testHexFormatAndFingerprint() throws Exception {
        byte[] expected = new byte[]{(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF};
        byte[] parsed = HexFormat.of().parseHex("deadbeef");
        assertArrayEquals(expected, parsed);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        PublicKey pubKey = kpg.generateKeyPair().getPublic();

        String fp = CryptoUtils.computeSha256FingerprintHex(pubKey);
        assertNotNull(fp);
        assertEquals(64, fp.length());
        assertTrue(fp.matches("^[0-9a-f]{64}$"));

        String hash = CryptoUtils.sha256Hex("test");
        assertEquals(64, hash.length());
        assertFalse(hash.isBlank());
    }
}
