package com.officevpn.protocol;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Custom hardened binary packet format for the Office VPN Wire Protocol.
 * <p>
 * Does NOT implement {@link java.io.Serializable} and rejects Java native object deserialization
 * to eliminate deserialization vulnerabilities (e.g., gadget-chain RCE exploits).
 * Enforces strict length-prefixed framing and defensive memory allocation limits.
 * <p>
 * <i>Stage 1.5 Security Audit Enhancements:</i>
 * Deterministic canonical Header AAD serialization with length prefixes and lexicographical metadata sorting,
 * eliminating delimiter collisions, injection vulnerabilities, and parsing ambiguity.
 */
public final class VpnPacket {

    /**
     * Parsing limit boundaries for wire protocol packets.
     */
    public record Limits(
            int maxPayload,
            int maxString,
            int maxMetadataEntries,
            int maxMetadataBytes,
            int maxIv
    ) {}

    /** Defensive limits enforced on unauthenticated connections during handshake and auth */
    public static final Limits PRE_AUTH = new Limits(
            64 * 1024,      // 64 KB max payload
            512,            // 512 bytes max string
            16,             // 16 max metadata entries
            16 * 1024,      // 16 KB cumulative metadata bytes
            32              // 32 bytes max IV
    );

    /** Standard limits enforced on authenticated tunnel sessions */
    public static final Limits POST_AUTH = new Limits(
            16 * 1024 * 1024, // 16 MB max payload
            8192,             // 8192 bytes max string
            64,               // 64 max metadata entries
            1024 * 1024,      // 1 MB cumulative metadata bytes
            32                // 32 bytes max IV
    );

    /** Maximum encrypted payload size: 16 MB to prevent memory exhaustion attacks */
    public static final int MAX_PAYLOAD_SIZE = POST_AUTH.maxPayload();

    /** Maximum metadata map entries */
    public static final int MAX_METADATA_ENTRIES = POST_AUTH.maxMetadataEntries();

    /** Maximum length for string headers in bytes */
    public static final int MAX_STRING_LENGTH = POST_AUTH.maxString();

    /** Maximum initialization vector length (Standard AES-GCM IV is 12 bytes) */
    public static final int MAX_IV_LENGTH = POST_AUTH.maxIv();

    private PacketType type;
    private String senderVirtualIp;
    private String senderUsername;
    private String department;
    private long timestamp;
    private byte[] iv;
    private byte[] encryptedPayload;
    private String payloadHmacHex;
    private Map<String, String> metadata;

    /**
     * Default constructor for packet construction.
     */
    public VpnPacket() {
        this.metadata = new LinkedHashMap<>();
    }

    /**
     * Primary constructor for a fully populated VpnPacket.
     *
     * @param type             Packet classification type
     * @param senderVirtualIp  Virtual IP within the VPN subnet (e.g., 10.8.0.x)
     * @param senderUsername   Authenticated user identity
     * @param department       User's department (e.g., Finance, HR, IT, HeadQuarters)
     * @param timestamp        Epoch timestamp in milliseconds
     * @param iv               12-byte AES-GCM initialization vector
     * @param encryptedPayload AES-256-GCM ciphertext + 128-bit authentication tag
     * @param payloadHmacHex   Keyed HMAC-SHA256 hex string over headerAad + iv + ciphertext
     * @param metadata         Optional metadata map (filenames, headers, etc.)
     */
    public VpnPacket(PacketType type,
                     String senderVirtualIp,
                     String senderUsername,
                     String department,
                     long timestamp,
                     byte[] iv,
                     byte[] encryptedPayload,
                     String payloadHmacHex,
                     Map<String, String> metadata) {
        this.type = type;
        this.senderVirtualIp = senderVirtualIp;
        this.senderUsername = senderUsername;
        this.department = department;
        this.timestamp = timestamp;
        this.iv = (iv != null) ? iv.clone() : new byte[0];
        this.encryptedPayload = (encryptedPayload != null) ? encryptedPayload.clone() : new byte[0];
        this.payloadHmacHex = (payloadHmacHex != null) ? payloadHmacHex : "";
        this.metadata = (metadata != null) ? new LinkedHashMap<>(metadata) : new LinkedHashMap<>();
    }

    /**
     * Computes deterministic, canonical UTF-8 bytes for Additional Authenticated Data (AAD).
     * <p>
     * <b>Stage 1.5 Canonical Framing:</b>
     * Serializes {@code type.name()}, {@code senderVirtualIp}, {@code senderUsername},
     * {@code department}, and {@code timestamp}, followed by {@code metadata} entries sorted
     * lexicographically by key using a {@link TreeMap}.
     * Every individual string field is explicitly 4-byte length-prefixed in binary, completely
     * eliminating delimiter collisions, injection vulnerabilities, and field-bleeding ambiguity.
     *
     * @return Deterministic byte representation of canonical packet header and metadata AAD
     */
    public byte[] getHeaderAadBytes() {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            // 1. Packet Type
            writeAadString(dos, (type != null) ? type.name() : "UNKNOWN");

            // 2. Sender Virtual IP
            writeAadString(dos, (senderVirtualIp != null) ? senderVirtualIp : "");

            // 3. Sender Username
            writeAadString(dos, (senderUsername != null) ? senderUsername : "");

            // 4. Department
            writeAadString(dos, (department != null) ? department : "");

            // 5. Timestamp (8 bytes)
            dos.writeLong(timestamp);

            // 6. Metadata entries sorted lexicographically by key
            if (metadata == null || metadata.isEmpty()) {
                dos.writeInt(0);
            } else {
                TreeMap<String, String> sortedMeta = new TreeMap<>(metadata);
                dos.writeInt(sortedMeta.size());
                for (Map.Entry<String, String> entry : sortedMeta.entrySet()) {
                    writeAadString(dos, entry.getKey() != null ? entry.getKey() : "");
                    writeAadString(dos, entry.getValue() != null ? entry.getValue() : "");
                }
            }

            dos.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize canonical Header AAD bytes", e);
        }
    }

    private static void writeAadString(DataOutputStream dos, String str) throws IOException {
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        dos.writeInt(bytes.length);
        if (bytes.length > 0) {
            dos.write(bytes);
        }
    }

    /**
     * Serializes this packet to an output stream using safe length-prefixed binary framing.
     *
     * @param out Target DataOutputStream
     * @throws IOException If serialization fails or size constraints are exceeded
     */
    public void writeToStream(DataOutputStream out) throws IOException {
        Objects.requireNonNull(out, "Output stream cannot be null");

        // 1. Packet Type
        String typeName = (type != null) ? type.name() : "";
        writeSafeString(out, typeName);

        // 2. Sender Virtual IP
        writeSafeString(out, senderVirtualIp != null ? senderVirtualIp : "");

        // 3. Sender Username
        writeSafeString(out, senderUsername != null ? senderUsername : "");

        // 4. Department
        writeSafeString(out, department != null ? department : "");

        // 5. Timestamp
        out.writeLong(timestamp);

        // 6. IV
        byte[] safeIv = (iv != null) ? iv : new byte[0];
        if (safeIv.length > MAX_IV_LENGTH) {
            throw new IOException("IV length exceeds maximum bound of " + MAX_IV_LENGTH + " bytes: " + safeIv.length);
        }
        out.writeInt(safeIv.length);
        if (safeIv.length > 0) {
            out.write(safeIv);
        }

        // 7. Encrypted Payload (Ciphertext + Tag)
        byte[] safePayload = (encryptedPayload != null) ? encryptedPayload : new byte[0];
        if (safePayload.length > MAX_PAYLOAD_SIZE) {
            throw new IOException("Encrypted payload exceeds maximum bound of 16 MB: " + safePayload.length);
        }
        out.writeInt(safePayload.length);
        if (safePayload.length > 0) {
            out.write(safePayload);
        }

        // 8. Keyed HMAC-SHA256 Hex
        writeSafeString(out, payloadHmacHex != null ? payloadHmacHex : "");

        // 9. Metadata map
        int metaCount = (metadata != null) ? metadata.size() : 0;
        if (metaCount > MAX_METADATA_ENTRIES) {
            throw new IOException("Metadata size exceeds maximum bound of " + MAX_METADATA_ENTRIES + " entries: " + metaCount);
        }
        out.writeInt(metaCount);
        if (metaCount > 0) {
            for (Map.Entry<String, String> entry : metadata.entrySet()) {
                writeSafeString(out, entry.getKey() != null ? entry.getKey() : "");
                writeSafeString(out, entry.getValue() != null ? entry.getValue() : "");
            }
        }
    }

    /**
     * Reads and parses a VpnPacket from an input stream with POST_AUTH bounds.
     *
     * @param in Source DataInputStream
     * @return Deserialized VpnPacket instance
     * @throws IOException If parsing fails or malicious bounds are detected
     */
    public static VpnPacket readFromStream(DataInputStream in) throws IOException {
        return readFromStream(in, POST_AUTH);
    }

    /**
     * Reads and parses a VpnPacket from an input stream with explicit limit boundaries.
     * Validates every remote length before reading or allocating, and streams large payloads
     * in bounded 64 KB chunks to defend against memory exhaustion attacks.
     *
     * @param in     Source DataInputStream
     * @param limits Boundary limits to enforce
     * @return Deserialized VpnPacket instance
     * @throws IOException If parsing fails or boundaries are violated
     */
    public static VpnPacket readFromStream(DataInputStream in, Limits limits) throws IOException {
        Objects.requireNonNull(in, "Input stream cannot be null");
        Objects.requireNonNull(limits, "Limits cannot be null");

        // 1. Packet Type
        String typeName = readSafeString(in, limits.maxString());
        if (typeName == null || typeName.trim().isEmpty()) {
            throw new IOException("Malformed wire packet: missing or empty PacketType");
        }
        PacketType parsedType;
        try {
            parsedType = PacketType.valueOf(typeName);
        } catch (IllegalArgumentException e) {
            throw new IOException("Invalid or unrecognized PacketType: " + typeName, e);
        }

        // 2. Sender Virtual IP
        String parsedIp = readSafeString(in, limits.maxString());

        // 3. Sender Username
        String parsedUser = readSafeString(in, limits.maxString());

        // 4. Department
        String parsedDept = readSafeString(in, limits.maxString());

        // 5. Timestamp
        long parsedTimestamp = in.readLong();

        // 6. IV
        int ivLength = in.readInt();
        if (ivLength < 0 || ivLength > limits.maxIv()) {
            throw new IOException("Defensive bounds violation: IV length is " + ivLength + " (max: " + limits.maxIv() + ")");
        }
        byte[] parsedIv = new byte[ivLength];
        if (ivLength > 0) {
            in.readFully(parsedIv);
        }

        // 7. Encrypted Payload (Validated BEFORE reading payload bytes)
        int payloadLength = in.readInt();
        if (payloadLength < 0 || payloadLength > limits.maxPayload()) {
            throw new IOException("Defensive bounds violation: Payload length is " + payloadLength + " (max: " + limits.maxPayload() + ")");
        }
        byte[] parsedPayload;
        if (payloadLength == 0) {
            parsedPayload = new byte[0];
        } else if (payloadLength <= 64 * 1024) {
            parsedPayload = new byte[payloadLength];
            in.readFully(parsedPayload);
        } else {
            // Read in bounded chunks of at most 64 KB into a growing stream
            ByteArrayOutputStream payloadBaos = new ByteArrayOutputStream(64 * 1024);
            byte[] chunk = new byte[64 * 1024];
            int remaining = payloadLength;
            while (remaining > 0) {
                int toRead = Math.min(remaining, chunk.length);
                in.readFully(chunk, 0, toRead);
                payloadBaos.write(chunk, 0, toRead);
                remaining -= toRead;
            }
            parsedPayload = payloadBaos.toByteArray();
        }

        // 8. HMAC Hex
        String parsedHmac = readSafeString(in, limits.maxString());

        // 9. Metadata map
        int metaCount = in.readInt();
        if (metaCount < 0 || metaCount > limits.maxMetadataEntries()) {
            throw new IOException("Defensive bounds violation: Metadata entry count is " + metaCount + " (max: " + limits.maxMetadataEntries() + ")");
        }
        int totalMetadataBytes = 0;
        Map<String, String> parsedMeta = new LinkedHashMap<>(metaCount);
        for (int i = 0; i < metaCount; i++) {
            String k = readSafeString(in, limits.maxString());
            String v = readSafeString(in, limits.maxString());
            if (k == null || v == null) {
                throw new IOException("Malformed wire packet: metadata key/value cannot be null");
            }
            int entryBytes = k.getBytes(StandardCharsets.UTF_8).length + v.getBytes(StandardCharsets.UTF_8).length;
            totalMetadataBytes += entryBytes;
            if (totalMetadataBytes > limits.maxMetadataBytes()) {
                throw new IOException("Defensive bounds violation: Cumulative metadata byte size is " + totalMetadataBytes + " (max: " + limits.maxMetadataBytes() + ")");
            }
            parsedMeta.put(k, v);
        }

        return new VpnPacket(
                parsedType,
                parsedIp,
                parsedUser,
                parsedDept,
                parsedTimestamp,
                parsedIv,
                parsedPayload,
                parsedHmac,
                parsedMeta
        );
    }

    /**
     * Serializes this packet to an in-memory binary wire byte array.
     * Test seam for packet framing and limits verification.
     *
     * @return Raw binary representation
     * @throws IOException If serialization fails
     */
    public byte[] toWireBytes() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DataOutputStream dos = new DataOutputStream(baos)) {
            writeToStream(dos);
            dos.flush();
            return baos.toByteArray();
        }
    }

    /**
     * Parses a VpnPacket from an in-memory binary wire byte array using explicit limits.
     * Enforces strict integrity check that rejects unexpected trailing bytes.
     *
     * @param rawBytes Binary wire bytes
     * @param limits   Parsing limits
     * @return Deserialized VpnPacket instance
     * @throws IOException If parsing fails or trailing bytes are detected
     */
    public static VpnPacket fromWireBytes(byte[] rawBytes, Limits limits) throws IOException {
        Objects.requireNonNull(rawBytes, "Raw bytes cannot be null");
        ByteArrayInputStream bais = new ByteArrayInputStream(rawBytes);
        try (DataInputStream dis = new DataInputStream(bais)) {
            VpnPacket packet = readFromStream(dis, limits);
            if (bais.available() > 0) {
                throw new IOException("Malformed wire packet: unexpected trailing bytes detected (" + bais.available() + " bytes remaining)");
            }
            return packet;
        }
    }

    /**
     * Parses a VpnPacket from an in-memory binary wire byte array using POST_AUTH limits.
     *
     * @param rawBytes Binary wire bytes
     * @return Deserialized VpnPacket instance
     * @throws IOException If parsing fails or trailing bytes are detected
     */
    public static VpnPacket fromWireBytes(byte[] rawBytes) throws IOException {
        return fromWireBytes(rawBytes, POST_AUTH);
    }



    // Helper write/read routines for length-prefixed UTF-8 strings
    private static void writeSafeString(DataOutputStream out, String str) throws IOException {
        if (str == null) {
            out.writeInt(-1);
            return;
        }
        byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_STRING_LENGTH) {
            throw new IOException("String byte length exceeds maximum allowed bound of " + MAX_STRING_LENGTH);
        }
        out.writeInt(bytes.length);
        if (bytes.length > 0) {
            out.write(bytes);
        }
    }

    private static String readSafeString(DataInputStream in, int maxString) throws IOException {
        int length = in.readInt();
        if (length == -1) {
            return null;
        }
        if (length < 0 || length > maxString) {
            throw new IOException("Defensive bounds violation: String byte length is " + length + " (max: " + maxString + ")");
        }
        if (length == 0) {
            return "";
        }
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    // Getters and Setters

    public PacketType getType() {
        return type;
    }

    public String getSenderVirtualIp() {
        return senderVirtualIp;
    }

    public String getSenderUsername() {
        return senderUsername;
    }

    public String getDepartment() {
        return department;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public byte[] getIv() {
        return (iv != null) ? iv.clone() : new byte[0];
    }

    public byte[] getEncryptedPayload() {
        return (encryptedPayload != null) ? encryptedPayload.clone() : new byte[0];
    }

    public String getPayloadHmacHex() {
        return payloadHmacHex;
    }

    public Map<String, String> getMetadata() {
        return Collections.unmodifiableMap(metadata);
    }

    public void putMetadata(String key, String value) {
        if (this.metadata == null) {
            this.metadata = new LinkedHashMap<>();
        }
        this.metadata.put(key, value);
    }

    /**
     * Retrieves the sequence number from packet metadata if present.
     *
     * @return Sequence number &gt; 0, or -1 if not set
     */
    public long getSequenceNumber() {
        if (metadata != null && metadata.containsKey("seqNum")) {
            try {
                return Long.parseLong(metadata.get("seqNum"));
            } catch (NumberFormatException ignored) {
            }
        }
        return -1L;
    }


    /**
     * Checks if packet metadata contains a sequence number.
     *
     * @return True if seqNum is present
     */
    public boolean hasSequenceNumber() {
        return metadata != null && metadata.containsKey("seqNum");
    }

    @Override
    public String toString() {
        return "VpnPacket{" +
                "type=" + type +
                ", senderVirtualIp='" + senderVirtualIp + '\'' +
                ", senderUsername='" + senderUsername + '\'' +
                ", department='" + department + '\'' +
                ", timestamp=" + timestamp +
                ", ivLen=" + (iv != null ? iv.length : 0) +
                ", payloadLen=" + (encryptedPayload != null ? encryptedPayload.length : 0) +
                ", payloadHmacHex='" + payloadHmacHex + '\'' +
                ", metadataSize=" + (metadata != null ? metadata.size() : 0) +
                '}';
    }
}
