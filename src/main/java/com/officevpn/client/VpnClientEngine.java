package com.officevpn.client;

import com.officevpn.config.ConfigUtil;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.protocol.PacketType;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.security.CryptoUtils;
import com.officevpn.security.KeyExchangeUtil;
import com.officevpn.security.KillSwitchBlockedException;
import com.officevpn.security.KillSwitchManager;
import com.officevpn.security.SequenceReplayWindow;
import com.officevpn.security.TrustedFingerprintStore;
import com.officevpn.tunnel.TunnelManager;
import com.officevpn.network.DnsLeakProtection;
import com.officevpn.util.HardwareUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Remote Employee VPN Client Engine.
 * <p>
 * Manages:
 * <ul>
 *   <li>3-Step cryptographic handshake &amp; strict MITM public key pinning validation.</li>
 *   <li>Encrypted PBKDF2 authentication with the Headquarters Gateway.</li>
 *   <li>Synchronous departmental vault operations (List, Download, Upload) correlated via reqId.</li>
 *   <li>Real-time asynchronous encrypted intranet chat communication.</li>
 * </ul>
 */
public final class VpnClientEngine implements AutoCloseable {

    private static final Logger LOGGER = LoggerFactory.getLogger(VpnClientEngine.class);

    /**
     * Configuration options for client operational and transfer deadlines.
     */
    public static final class Options {
        private final long opTimeoutMs;
        private final long transferTimeoutMs;
        private final int connectTimeoutMs;

        public Options() {
            this(15_000L, 30_000L, 10_000);
        }

        public Options(long opTimeoutMs, long transferTimeoutMs, int connectTimeoutMs) {
            this.opTimeoutMs = opTimeoutMs;
            this.transferTimeoutMs = transferTimeoutMs;
            this.connectTimeoutMs = connectTimeoutMs;
        }

        public long getOpTimeoutMs() {
            return opTimeoutMs;
        }

        public long getTransferTimeoutMs() {
            return transferTimeoutMs;
        }

        public int getConnectTimeoutMs() {
            return connectTimeoutMs;
        }

        public Options withOpTimeoutMs(long opTimeoutMs) {
            return new Options(opTimeoutMs, this.transferTimeoutMs, this.connectTimeoutMs);
        }

        public Options withTransferTimeoutMs(long transferTimeoutMs) {
            return new Options(this.opTimeoutMs, transferTimeoutMs, this.connectTimeoutMs);
        }


    }

    /**
     * Verified inbound packet and its decrypted plaintext payload.
     */
    public record VerifiedPacket(VpnPacket packet, byte[] plainPayload) {}

    private record PendingRequest(long reqId, PacketType expectedType, CompletableFuture<VerifiedPacket> future) {}

    /**
     * Listener callback interface for client-side events (chat messages, packet sniffer, disconnects).
     */
    public interface ClientEventListener {
        void onChatMessage(String senderUser, String senderDept, String senderVip, String message);
        void onPacketSniffed(VpnPacket packet, String direction);
        void onConnectionStateChanged(String state);
    }

    private final Options options;

    private Socket socket;
    private DataInputStream in;
    private DataOutputStream out;

    private PublicKey serverPublicKey;
    private CryptoUtils.DirectionalKeys directionalKeys;

    private String username;
    private String assignedVirtualIp = "0.0.0.0";
    private Department department;
    private Role role;

    private final List<ClientEventListener> listeners = new CopyOnWriteArrayList<>();

    private Thread receiverThread;
    private ScheduledExecutorService keepAliveScheduler;

    private final AtomicBoolean connected = new AtomicBoolean(false);
    private final AtomicBoolean authenticated = new AtomicBoolean(false);

    // Client-to-server outbound sequence generator
    private final AtomicLong clientSendSeq = new AtomicLong(1);

    // Server-to-client inbound sequence replay window
    private final SequenceReplayWindow clientInboundSeqWindow = new SequenceReplayWindow(128);

    // Request-response correlation
    private final AtomicReference<PendingRequest> pendingRequest = new AtomicReference<>(null);
    private final AtomicLong reqIdSeq = new AtomicLong(1);

    // Lock architecture: explicit locks, zero monitor methods
    private final ReentrantLock opLock = new ReentrantLock();
    private final ReentrantLock outLock = new ReentrantLock();
    private final ReentrantLock keepAliveLock = new ReentrantLock();

    // Diagnostics / Reliability counters
    private final AtomicLong forgedDropped = new AtomicLong(0);
    private final AtomicLong staleResponsesDropped = new AtomicLong(0);

    // Advanced Network Core Managers
    private final KillSwitchManager killSwitchManager = new KillSwitchManager();
    private final TunnelManager tunnelManager = new TunnelManager();
    private final DnsLeakProtection dnsLeakProtection = new DnsLeakProtection();
    private final AutoReconnectManager autoReconnectManager = new AutoReconnectManager();

    public VpnClientEngine() {
        this(new Options());
    }

    public VpnClientEngine(Options options) {
        this.options = Objects.requireNonNull(options, "Options cannot be null");
    }



    public long getNextClientSendSeq() {
        return clientSendSeq.getAndIncrement();
    }

    public SequenceReplayWindow getInboundSeqWindow() {
        return clientInboundSeqWindow;
    }

    public ReentrantLock getOpLock() {
        return opLock;
    }

    // Test seam
    long getForgedDropped() {
        return forgedDropped.get();
    }

    // Test seam
    long getStaleResponsesDropped() {
        return staleResponsesDropped.get();
    }

    /**
     * Connects to the Headquarters VPN Gateway and executes the 3-step cryptographic handshake.
     * Strictly verifies the server's public key against the expected pinned SHA-256 fingerprint.
     *
     * @param host                         Server hostname or IP
     * @param port                         Server port
     * @param expectedServerFingerprintHex Pinned 64-character SHA-256 hex fingerprint
     * @throws IOException       If connection fails
     * @throws SecurityException If MITM or key pinning mismatch occurs
     */
    public void connectAndHandshake(String host, int port, String expectedServerFingerprintHex) throws IOException {
        connectAndHandshake(host, port, expectedServerFingerprintHex, null);
    }

    /**
     * Connects to the Headquarters VPN Gateway with optional {@link TrustedFingerprintStore} validation.
     *
     * @param host                         Server hostname or IP
     * @param port                         Server port
     * @param expectedServerFingerprintHex Pinned 64-character SHA-256 hex fingerprint (optional if store used)
     * @param store                        Optional fingerprint store for TOFU enrollment and change detection
     * @throws IOException       If connection fails
     * @throws SecurityException If MITM or key pinning mismatch occurs
     */
    public void connectAndHandshake(String host, int port, String expectedServerFingerprintHex, TrustedFingerprintStore store) throws IOException {
        connectAndHandshake(host, port, expectedServerFingerprintHex, store, false);
    }

    /**
     * Connects to the Headquarters VPN Gateway with explicit pin replacement confirmation.
     *
     * @param host             Server hostname or IP
     * @param port             Server port
     * @param typedFingerprint User-typed 64-character SHA-256 hex fingerprint (or null/blank)
     * @param store            Fingerprint store for persistent pins (null uses default store)
     * @param confirmReplace   Whether to confirm pin replacement if server public key changed
     * @throws IOException       If connection fails
     * @throws SecurityException If MITM or key pinning mismatch occurs
     */
    public void connectAndHandshake(String host, int port, String typedFingerprint, TrustedFingerprintStore store, boolean confirmReplace) throws IOException {
        opLock.lock();
        try {
            Objects.requireNonNull(host, "Host cannot be null");

            this.socket = new Socket();
            this.socket.setTcpNoDelay(true);
            this.socket.connect(new InetSocketAddress(host, port), options.getConnectTimeoutMs());
            this.socket.setSoTimeout(30_000);
            this.in = new DataInputStream(socket.getInputStream());
            this.out = new DataOutputStream(socket.getOutputStream());

            notifyState("Connecting to VPN Gateway at " + host + ":" + port + "...");

            // Step 1: Generate ephemeral ECDH keypair and 32-byte client nonce
            KeyPair clientEcPair = KeyExchangeUtil.generateECDHKeyPair();
            byte[] clientRandom = new byte[32];
            new SecureRandom().nextBytes(clientRandom);

            Map<String, String> initMeta = new LinkedHashMap<>();
            initMeta.put("protocolVersion", "OFFICE-VPN-2.0");
            initMeta.put("clientRandom", Base64.getEncoder().encodeToString(clientRandom));
            initMeta.put("clientEcPub", KeyExchangeUtil.ecPublicKeyToBase64(clientEcPair.getPublic()));

            VpnPacket initPacket = new VpnPacket(
                    PacketType.HANDSHAKE_INIT,
                    "0.0.0.0",
                    "CLIENT_INIT",
                    "UNKNOWN",
                    System.currentTimeMillis(),
                    null,
                    null,
                    null,
                    initMeta
            );
            sendRawPacket(initPacket);

            // Step 2: Receive HANDSHAKE_CHALLENGE and strictly verify Public Key Pinning & Transcript Signature
            VpnPacket challengePacket = VpnPacket.readFromStream(in, VpnPacket.PRE_AUTH);
            notifyPacketSniffed(challengePacket, "INCOMING");

            if (challengePacket.getType() != PacketType.HANDSHAKE_CHALLENGE) {
                throw new SecurityException("Expected HANDSHAKE_CHALLENGE, got: " + challengePacket.getType());
            }

            String serverPubKeyB64 = challengePacket.getMetadata().get("serverPublicKey");
            String serverEcPubB64 = challengePacket.getMetadata().get("serverEcPub");
            String serverRandomB64 = challengePacket.getMetadata().get("serverRandom");
            String signatureB64 = challengePacket.getMetadata().get("transcriptSignature");
            String protocolVer = challengePacket.getMetadata().get("protocolVersion");

            if (serverPubKeyB64 == null || serverEcPubB64 == null || serverRandomB64 == null
                    || signatureB64 == null || !"OFFICE-VPN-2.0".equals(protocolVer)) {
                throw new SecurityException("Malformed HANDSHAKE_CHALLENGE parameters or protocol version mismatch");
            }

            this.serverPublicKey = CryptoUtils.base64ToPublicKey(serverPubKeyB64);
            byte[] serverRandom = Base64.getDecoder().decode(serverRandomB64);
            byte[] serverSignature = Base64.getDecoder().decode(signatureB64);

            String actualFingerprint = CryptoUtils.computeSha256FingerprintHex(serverPublicKey);

            // Strict MITM Protection and Key Pinning evaluated through PinPolicy
            TrustedFingerprintStore effectiveStore = (store != null) ? store : TrustedFingerprintStore.getDefault();
            String storedPin = effectiveStore.getPinnedFingerprint(host, port).orElse(null);

            PinDecision decision = PinPolicy.decide(storedPin, typedFingerprint, actualFingerprint, confirmReplace);

            switch (decision) {
                case PIN_MATCH -> {
                    // Established pin matches observed server key
                }
                case FIRST_USE_TYPED_MATCH, PIN_REPLACED, FIRST_USE_NEEDS_CONFIRMATION -> {
                    // Verified and pinned AFTER successful signature verification
                }
                case FIRST_USE_TYPED_MISMATCH_FAIL -> {
                    disconnect();
                    throw new SecurityException(String.format(
                            "MITM Alert: Typed fingerprint does not match server public key!\nExpected Typed: %s\nActual Server:  %s",
                            typedFingerprint, actualFingerprint
                    ));
                }
                case PIN_MISMATCH_HARD_FAIL -> {
                    disconnect();
                    throw new SecurityException(String.format(
                            "GATEWAY IDENTITY CHANGED - possible attack!\nPinned: %s\nActual: %s",
                            storedPin, actualFingerprint
                    ));
                }
            }

            notifyState("Server public key verified against pinned fingerprint (" + actualFingerprint.substring(0, 16) + "...)");

            // Reconstruct canonical transcript and verify server signature BEFORE using ephemeral key
            PublicKey serverEcPub = KeyExchangeUtil.base64ToEcPublicKey(serverEcPubB64);
            byte[] transcript = CryptoUtils.buildHandshakeTranscriptV2(
                    "OFFICE-VPN-2.0",
                    clientRandom,
                    serverRandom,
                    clientEcPair.getPublic().getEncoded(),
                    serverEcPub.getEncoded()
            );

            boolean sigValid = CryptoUtils.verifyWithRsaPss(transcript, serverSignature, serverPublicKey);
            if (!sigValid) {
                disconnect();
                throw new SecurityException("MITM Alert: Server RSASSA-PSS transcript signature verification failed!");
            }

            // ONLY AFTER SIGNATURE IS VERIFIED: pin fingerprint for first use or confirmed replacement
            if (decision == PinDecision.FIRST_USE_TYPED_MATCH
                    || decision == PinDecision.PIN_REPLACED
                    || decision == PinDecision.FIRST_USE_NEEDS_CONFIRMATION) {
                effectiveStore.pinFingerprint(host, port, actualFingerprint);
            }

            // Derive ECDH raw shared secret and directional keys with transcript hash as HKDF salt
            byte[] rawSharedSecret = KeyExchangeUtil.deriveRawSharedSecret(clientEcPair.getPrivate(), serverEcPub);
            byte[] transcriptHash;
            try {
                transcriptHash = MessageDigest.getInstance("SHA-256").digest(transcript);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 unavailable", e);
            }
            this.directionalKeys = KeyExchangeUtil.deriveDirectionalKeys(rawSharedSecret, transcriptHash);
            Arrays.fill(rawSharedSecret, (byte) 0);

            // Step 3: Send client confirmation encrypted with c2sKey and direction DIRECTION_C2S
            Map<String, String> confirmSendMeta = new LinkedHashMap<>();
            confirmSendMeta.put("protocolVersion", "OFFICE-VPN-2.0");
            confirmSendMeta.put("status", "CONFIRMED");
            confirmSendMeta.put("seqNum", String.valueOf(getNextClientSendSeq()));

            VpnPacket sessionKeyPacket = CryptoUtils.createEncryptedPacket(
                    PacketType.HANDSHAKE_SESSION_KEY,
                    "0.0.0.0",
                    "CLIENT_INIT",
                    "UNKNOWN",
                    confirmSendMeta,
                    new byte[0],
                    directionalKeys.c2sKey(),
                    CryptoUtils.DIRECTION_C2S
            );
            sendRawPacket(sessionKeyPacket);

            // Step 4: Receive encrypted server confirmation and decrypt with s2cKey
            VpnPacket confirmPacket = VpnPacket.readFromStream(in, VpnPacket.PRE_AUTH);
            notifyPacketSniffed(confirmPacket, "INCOMING");

            if (confirmPacket.getType() != PacketType.HANDSHAKE_SESSION_KEY) {
                throw new SecurityException("Expected HANDSHAKE_SESSION_KEY confirmation, got: " + confirmPacket.getType());
            }

            CryptoUtils.decryptPacket(confirmPacket, directionalKeys.s2cKey(), CryptoUtils.DIRECTION_S2C);

            this.connected.set(true);
            this.socket.setSoTimeout(0); // Clear timeout for persistent listener thread

            // Start background receiver thread
            this.receiverThread = new Thread(this::receiveLoop, "vpn-client-receiver");
            this.receiverThread.setDaemon(true);
            this.receiverThread.start();

            notifyState("Cryptographic handshake completed: Dual-Layer Tunnel Established (OFFICE-VPN-2.0 PFS ECDH).");
        } finally {
            opLock.unlock();
        }
    }

    public CryptoUtils.DirectionalKeys getDirectionalKeys() {
        return directionalKeys;
    }

    private VpnPacket encryptClientPacket(PacketType type, Map<String, String> meta, byte[] payload) {
        if (directionalKeys == null) {
            throw new IllegalStateException("Directional session keys not established");
        }
        return CryptoUtils.createEncryptedPacket(
                type,
                assignedVirtualIp,
                username != null ? username : "CLIENT_INIT",
                department != null ? department.name() : "UNKNOWN",
                meta,
                payload,
                directionalKeys.c2sKey(),
                CryptoUtils.DIRECTION_C2S
        );
    }

    private byte[] decryptServerPacket(VpnPacket packet) {
        if (directionalKeys == null) {
            throw new IllegalStateException("Directional session keys not established");
        }
        return CryptoUtils.decryptPacket(packet, directionalKeys.s2cKey(), CryptoUtils.DIRECTION_S2C);
    }

    /**
     * Authenticates the employee credentials over the encrypted tunnel.
     *
     * @param username Raw username
     * @param password Raw plaintext password
     * @return True if authentication succeeds and Virtual IP is leased; false otherwise
     * @throws IOException If network transmission fails
     */
    public boolean login(String username, String password) throws IOException {
        return login(username, password, null);
    }

    /**
     * Authenticates the employee credentials with optional TOTP two-factor code over the encrypted tunnel.
     *
     * @param username Raw username
     * @param password Raw plaintext password
     * @param totpCode Optional 6-digit TOTP code (or null)
     * @return True if authentication succeeds and Virtual IP is leased; false otherwise
     * @throws IOException If network transmission fails
     */
    public boolean login(String username, String password, String totpCode) throws IOException {
        opLock.lock();
        try {
            if (!isConnected()) {
                throw new IllegalStateException("Client is not connected. Call connectAndHandshake first.");
            }

            byte[] authPayload = null;
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                try (DataOutputStream dos = new DataOutputStream(baos)) {
                    dos.writeUTF(username);
                    dos.writeUTF(password);
                    dos.flush();
                }
                authPayload = baos.toByteArray();

                long reqId = reqIdSeq.getAndIncrement();
                Map<String, String> authMeta = new LinkedHashMap<>();
                authMeta.put("reqId", String.valueOf(reqId));
                authMeta.put("seqNum", String.valueOf(getNextClientSendSeq()));
                authMeta.put("deviceName", HardwareUtil.getAuthenticDeviceName());
                authMeta.put("deviceFp", HardwareUtil.getAuthenticHardwareFingerprint());
                if (totpCode != null && !totpCode.isBlank()) {
                    authMeta.put("totpCode", totpCode.trim());
                }

                VpnPacket authReq = encryptClientPacket(
                        PacketType.AUTH_REQUEST,
                        authMeta,
                        authPayload
                );

                VerifiedPacket verified = sendAndAwait(authReq, reqId, PacketType.AUTH_RESPONSE, options.getOpTimeoutMs());
                VpnPacket response = verified.packet();
                byte[] payload = verified.plainPayload();
                try {
                    String status = response.getMetadata() != null ? response.getMetadata().get("status") : null;

                    if ("SUCCESS".equals(status)) {
                        String canonicalUsername = response.getMetadata().get("username");
                        this.username = (canonicalUsername != null && !canonicalUsername.isEmpty())
                                ? canonicalUsername
                                : username;
                        this.assignedVirtualIp = response.getMetadata().get("virtualIp");
                        this.department = Department.valueOf(response.getMetadata().get("department"));
                        this.role = Role.valueOf(response.getMetadata().get("role"));
                        this.authenticated.set(true);
                        killSwitchManager.onTunnelConnected();
                        dnsLeakProtection.setTunnelActive(true);
                        autoReconnectManager.recordSuccess();
                        autoReconnectManager.setPreservedVirtualIp(assignedVirtualIp);
                        startKeepAlive();
                        notifyState("Authenticated as " + this.username + " (" + department + " " + role + ") | Virtual IP: " + assignedVirtualIp);
                        return true;
                    } else {
                        String reason = response.getMetadata() != null ? response.getMetadata().get("reason") : "Unknown";
                        notifyState("Authentication DENIED: " + reason);
                        return false;
                    }
                } finally {
                    if (payload != null) {
                        Arrays.fill(payload, (byte) 0);
                    }
                }
            } finally {
                if (authPayload != null) {
                    Arrays.fill(authPayload, (byte) 0);
                }
            }
        } finally {
            opLock.unlock();
        }
    }

    /**
     * Lists files available in the target department vault.
     *
     * @param targetVault Department vault to browse
     * @return List of file names
     * @throws IOException       If network transmission fails
     * @throws SecurityException If access is denied by RBAC
     */
    public List<String> listDepartmentFiles(Department targetVault) throws IOException {
        opLock.lock();
        try {
            ensureAuthenticated();
            Objects.requireNonNull(targetVault, "Target vault cannot be null");

            long reqId = reqIdSeq.getAndIncrement();
            Map<String, String> meta = new LinkedHashMap<>();
            meta.put("targetVault", targetVault.name());
            meta.put("reqId", String.valueOf(reqId));
            meta.put("seqNum", String.valueOf(getNextClientSendSeq()));

            VpnPacket req = encryptClientPacket(
                    PacketType.FILE_LIST_REQ,
                    meta,
                    new byte[0]
            );

            VerifiedPacket res = sendAndAwait(req, reqId, PacketType.FILE_LIST_RES, options.getOpTimeoutMs());
            checkErrorResponse(res);

            byte[] payload = res.plainPayload();
            String listStr = payload != null ? new String(payload, StandardCharsets.UTF_8) : "";

            List<String> files = new ArrayList<>();
            if (!listStr.trim().isEmpty()) {
                for (String f : listStr.split("\n")) {
                    if (!f.trim().isEmpty()) {
                        files.add(f.trim());
                    }
                }
            }
            return files;
        } finally {
            opLock.unlock();
        }
    }

    /**
     * Downloads a file from the target department vault.
     *
     * @param targetVault Department vault
     * @param fileName   Target filename
     * @return Downloaded file content bytes
     * @throws IOException       If network transmission fails
     * @throws SecurityException If access is denied by RBAC or file is invalid
     */
    public byte[] downloadFile(Department targetVault, String fileName) throws IOException {
        opLock.lock();
        try {
            ensureAuthenticated();
            Objects.requireNonNull(targetVault, "Target vault cannot be null");
            Objects.requireNonNull(fileName, "Filename cannot be null");

            long reqId = reqIdSeq.getAndIncrement();
            Map<String, String> meta = new LinkedHashMap<>();
            meta.put("targetVault", targetVault.name());
            meta.put("fileName", fileName);
            meta.put("reqId", String.valueOf(reqId));
            meta.put("seqNum", String.valueOf(getNextClientSendSeq()));

            VpnPacket req = encryptClientPacket(
                    PacketType.FILE_DOWNLOAD_REQ,
                    meta,
                    new byte[0]
            );

            VerifiedPacket res = sendAndAwait(req, reqId, PacketType.FILE_DOWNLOAD_RES, options.getTransferTimeoutMs());
            checkErrorResponse(res);

            return res.plainPayload() != null ? res.plainPayload() : new byte[0];
        } finally {
            opLock.unlock();
        }
    }

    /**
     * Uploads a file into the target department vault.
     *
     * @param targetVault Department vault
     * @param fileName   Target filename
     * @param content    File content bytes
     * @throws IOException       If network transmission fails
     * @throws SecurityException If access is denied by RBAC (e.g. Auditor read-only or cross-dept)
     */
    public void uploadFile(Department targetVault, String fileName, byte[] content) throws IOException {
        opLock.lock();
        try {
            ensureAuthenticated();
            Objects.requireNonNull(targetVault, "Target vault cannot be null");
            Objects.requireNonNull(fileName, "Filename cannot be null");
            Objects.requireNonNull(content, "File content cannot be null");

            long reqId = reqIdSeq.getAndIncrement();
            Map<String, String> meta = new LinkedHashMap<>();
            meta.put("targetVault", targetVault.name());
            meta.put("fileName", fileName);
            meta.put("reqId", String.valueOf(reqId));
            meta.put("seqNum", String.valueOf(getNextClientSendSeq()));

            VpnPacket req = encryptClientPacket(
                    PacketType.FILE_UPLOAD,
                    meta,
                    content
            );

            VerifiedPacket res = sendAndAwait(req, reqId, PacketType.FILE_UPLOAD, options.getTransferTimeoutMs());
            checkErrorResponse(res);
        } finally {
            opLock.unlock();
        }
    }

    /**
     * Broadcasts an intranet chat message to connected office peers.
     *
     * @param message Text message to broadcast
     * @throws IOException If transmission fails
     */
    public void sendChatMessage(String message) throws IOException {
        ensureAuthenticated();
        Objects.requireNonNull(message, "Message cannot be null");

        byte[] payload = message.getBytes(StandardCharsets.UTF_8);
        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("seqNum", String.valueOf(getNextClientSendSeq()));

        VpnPacket req = encryptClientPacket(
                PacketType.CHAT_MESSAGE,
                meta,
                payload
        );
        sendRawPacket(req);
    }

    /**
     * Sends an encrypted ping packet to verify tunnel responsiveness and sequence freshness.
     *
     * @return True if gateway returns verified PONG successfully
     * @throws IOException If transmission fails
     */
    public boolean ping() throws IOException {
        opLock.lock();
        try {
            ensureAuthenticated();
            long reqId = reqIdSeq.getAndIncrement();
            Map<String, String> meta = new LinkedHashMap<>();
            meta.put("reqId", String.valueOf(reqId));
            meta.put("seqNum", String.valueOf(getNextClientSendSeq()));

            VpnPacket req = encryptClientPacket(
                    PacketType.PING,
                    meta,
                    new byte[0]
            );

            try {
                VerifiedPacket res = sendAndAwait(req, reqId, PacketType.PING, 10_000);
                return res != null && res.packet().getType() == PacketType.PING && "PONG".equals(res.packet().getMetadata().get("status"));
            } catch (IOException e) {
                return false;
            }
        } finally {
            opLock.unlock();
        }
    }

    /**
     * Executes a non-blocking keepalive ping tick, skipping immediately if another operation is in flight.
     *
     * @return True if ping succeeded, false if skipped or failed
     */
    public boolean performKeepAliveTick() {
        if (!isConnected() || !isAuthenticated()) {
            return false;
        }
        if (!opLock.tryLock()) {
            return false; // Skip tick if op is in flight
        }
        try {
            long reqId = reqIdSeq.getAndIncrement();
            Map<String, String> meta = new LinkedHashMap<>();
            meta.put("reqId", String.valueOf(reqId));
            meta.put("seqNum", String.valueOf(getNextClientSendSeq()));

            VpnPacket req = encryptClientPacket(
                    PacketType.PING,
                    meta,
                    new byte[0]
            );

            VerifiedPacket res = sendAndAwait(req, reqId, PacketType.PING, 10_000);
            return res != null && res.packet().getType() == PacketType.PING && "PONG".equals(res.packet().getMetadata().get("status"));
        } catch (Exception ex) {
            LOGGER.debug("Keepalive ping tick failed: {}", ex.getMessage());
            return false;
        } finally {
            opLock.unlock();
        }
    }

    private void receiveLoop() {
        while (isConnected() && socket != null && !socket.isClosed()) {
            try {
                VpnPacket packet = VpnPacket.readFromStream(in, isAuthenticated() ? VpnPacket.POST_AUTH : VpnPacket.PRE_AUTH);
                notifyPacketSniffed(packet, "INCOMING");

                // 1. Decrypt packet FIRST before sequence replay window check
                byte[] plainPayload = null;
                if (isAuthenticated()) {
                    if (directionalKeys == null || packet.getEncryptedPayload() == null || packet.getEncryptedPayload().length == 0) {
                        forgedDropped.incrementAndGet();
                        continue;
                    }
                    try {
                        plainPayload = decryptServerPacket(packet);
                    } catch (Exception e) {
                        forgedDropped.incrementAndGet();
                        continue;
                    }
                } else if (directionalKeys != null && packet.getEncryptedPayload() != null && packet.getEncryptedPayload().length > 0) {
                    try {
                        plainPayload = decryptServerPacket(packet);
                    } catch (Exception e) {
                        forgedDropped.incrementAndGet();
                        continue;
                    }
                }

                // 2. Sliding sequence-number replay window check AFTER successful decryption
                if (packet.hasSequenceNumber()) {
                    try {
                        clientInboundSeqWindow.checkAndRecord(packet.getSequenceNumber());
                    } catch (SecurityException se) {
                        forgedDropped.incrementAndGet();
                        continue;
                    }
                } else if (isAuthenticated()) {
                    forgedDropped.incrementAndGet();
                    continue;
                }

                // 3. Dispatch
                if (packet.getType() == PacketType.DISCONNECT) {
                    if (isAuthenticated()) {
                        String reason = (packet.getMetadata() != null) ? packet.getMetadata().get("reason") : null;
                        if (reason == null || reason.isBlank()) {
                            reason = "Gateway requested disconnection";
                        }
                        notifyState("Tunnel disconnected: " + reason);
                        disconnect();
                        break;
                    } else {
                        forgedDropped.incrementAndGet();
                        continue;
                    }
                } else if (packet.getType() == PacketType.CHAT_MESSAGE) {
                    String msg = plainPayload != null ? new String(plainPayload, StandardCharsets.UTF_8) : "";
                    String sender = packet.getMetadata() != null ? packet.getMetadata().getOrDefault("senderUser", packet.getSenderUsername()) : packet.getSenderUsername();
                    String dept = packet.getMetadata() != null ? packet.getMetadata().getOrDefault("senderDept", packet.getDepartment()) : packet.getDepartment();
                    String vip = packet.getMetadata() != null ? packet.getMetadata().getOrDefault("senderVip", packet.getSenderVirtualIp()) : packet.getSenderVirtualIp();

                    for (ClientEventListener l : listeners) {
                        l.onChatMessage(sender, dept, vip, msg);
                    }
                } else {
                    // Match against pending request by reqId and expected type
                    long respReqId = -1;
                    if (packet.getMetadata() != null && packet.getMetadata().containsKey("reqId")) {
                        try {
                            respReqId = Long.parseLong(packet.getMetadata().get("reqId"));
                        } catch (NumberFormatException nfe) {
                            LOGGER.debug("Ignoring malformed reqId metadata '{}'", packet.getMetadata().get("reqId"));
                        }
                    }

                    PendingRequest pending = pendingRequest.get();
                    if (pending != null && respReqId >= 0 && respReqId == pending.reqId()) {
                        if (packet.getType() == pending.expectedType() || packet.getType() == PacketType.ERROR) {
                            if (pendingRequest.compareAndSet(pending, null)) {
                                pending.future().complete(new VerifiedPacket(packet, plainPayload));
                            }
                        } else {
                            staleResponsesDropped.incrementAndGet();
                        }
                    } else {
                        staleResponsesDropped.incrementAndGet();
                    }
                }
            } catch (IOException e) {
                if (isConnected()) {
                    String safeReason = (e instanceof java.io.EOFException)
                            ? "Gateway closed connection (EOF)"
                            : (e.getMessage() != null && !e.getMessage().isBlank()) ? e.getMessage() : e.getClass().getSimpleName();
                    notifyState("Connection lost: " + safeReason);
                    killSwitchManager.onTunnelDisconnectedUnexpectedly();
                    dnsLeakProtection.setTunnelActive(false);
                    if (autoReconnectManager.shouldReconnect()) {
                        autoReconnectManager.recordFailure();
                    }
                    disconnect();
                }
                break;
            } catch (Throwable t) {
                notifyState("Error processing incoming packet: " + t.getMessage());
            }
        }
    }

    private VerifiedPacket sendAndAwait(VpnPacket reqPacket, long reqId, PacketType expectedType, long timeoutMs) throws IOException {
        CompletableFuture<VerifiedPacket> future = new CompletableFuture<>();
        PendingRequest pending = new PendingRequest(reqId, expectedType, future);
        pendingRequest.set(pending);

        try {
            sendRawPacket(reqPacket);
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException te) {
            pendingRequest.compareAndSet(pending, null);
            throw new IOException("Tunnel operation timed out after " + timeoutMs + "ms waiting for Gateway response", te);
        } catch (ExecutionException ee) {
            Throwable cause = ee.getCause();
            if (cause instanceof IOException ioe) {
                throw ioe;
            }
            if (cause instanceof SecurityException se) {
                throw se;
            }
            throw new IOException(cause != null ? cause.getMessage() : "Unknown execution failure", cause);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            pendingRequest.compareAndSet(pending, null);
            throw new IOException("Operation interrupted", ie);
        }
    }

    private void checkErrorResponse(VerifiedPacket verified) {
        if (verified != null && verified.packet().getType() == PacketType.ERROR) {
            String code = null;
            if (verified.packet().getMetadata() != null) {
                code = verified.packet().getMetadata().get("code");
                if (code == null) {
                    code = verified.packet().getMetadata().get("errorCode");
                }
            }
            String error = verified.packet().getMetadata() != null ? verified.packet().getMetadata().get("error") : null;
            String msg = (code != null ? "[" + code + "] " : "") + (error != null ? error : "Unspecified gateway error");
            throw new SecurityException("Gateway Error: " + msg);
        }
    }

    private void sendRawPacket(VpnPacket packet) throws IOException {
        outLock.lock();
        try {
            if (packet != null && packet.getType() != PacketType.HANDSHAKE_INIT && packet.getType() != PacketType.HANDSHAKE_SESSION_KEY) {
                String dest = (socket != null && socket.getInetAddress() != null)
                        ? socket.getInetAddress().getHostAddress() : ConfigUtil.getClientDefaultHost();
                if (!killSwitchManager.isTrafficAllowed(dest)) {
                    throw new KillSwitchBlockedException("Outbound transmission blocked by active Kill Switch to " + dest);
                }
            }

            if (socket != null && !socket.isClosed() && out != null) {
                packet.writeToStream(out);
                out.flush();
                notifyPacketSniffed(packet, "OUTGOING");
            }
        } finally {
            outLock.unlock();
        }
    }

    private void startKeepAlive() {
        stopKeepAlive();
        keepAliveLock.lock();
        try {
            keepAliveScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "vpn-client-keepalive");
                t.setDaemon(true);
                return t;
            });
            keepAliveScheduler.scheduleWithFixedDelay(this::performKeepAliveTick, 25, 25, TimeUnit.SECONDS);
        } finally {
            keepAliveLock.unlock();
        }
    }

    private void stopKeepAlive() {
        keepAliveLock.lock();
        try {
            if (keepAliveScheduler != null && !keepAliveScheduler.isShutdown()) {
                keepAliveScheduler.shutdownNow();
                keepAliveScheduler = null;
            }
        } finally {
            keepAliveLock.unlock();
        }
    }

    private void ensureAuthenticated() {
        if (!isConnected() || !isAuthenticated()) {
            throw new IllegalStateException("Client must be authenticated before executing tunnel operations");
        }
    }

    public void disconnect() {
        if (!connected.getAndSet(false) && !authenticated.getAndSet(false)) {
            return;
        }
        authenticated.set(false);
        stopKeepAlive();

        // Complete any pending request exceptionally - NEVER block on opLock
        PendingRequest pending = pendingRequest.getAndSet(null);
        if (pending != null) {
            pending.future().completeExceptionally(new IOException("Connection closed"));
        }

        try {
            if (directionalKeys != null && socket != null && !socket.isClosed() && out != null) {
                Map<String, String> discMeta = new LinkedHashMap<>();
                discMeta.put("seqNum", String.valueOf(getNextClientSendSeq()));

                VpnPacket disconnectPacket = encryptClientPacket(
                        PacketType.DISCONNECT,
                        discMeta,
                        new byte[0]
                );
                sendRawPacket(disconnectPacket);
            }
        } catch (Exception ex) {
            LOGGER.debug("Ignoring disconnect packet notification error: {}", ex.getMessage());
        }

        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException ex) {
            LOGGER.debug("Ignoring socket close failure on disconnect: {}", ex.getMessage());
        }

        if (receiverThread != null && receiverThread.isAlive()) {
            receiverThread.interrupt();
        }

        killSwitchManager.onCleanDisconnect();
        dnsLeakProtection.setTunnelActive(false);
        autoReconnectManager.reset();

        notifyState("Disconnected from VPN Gateway.");
    }

    public void addClientEventListener(ClientEventListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    public void removeClientEventListener(ClientEventListener listener) {
        if (listener != null) {
            listeners.remove(listener);
        }
    }

    private void notifyState(String state) {
        for (ClientEventListener l : listeners) {
            l.onConnectionStateChanged(state);
        }
    }

    private void notifyPacketSniffed(VpnPacket packet, String direction) {
        for (ClientEventListener l : listeners) {
            l.onPacketSniffed(packet, direction);
        }
    }

    public boolean isConnected() {
        return connected.get();
    }

    public boolean isAuthenticated() {
        return authenticated.get();
    }

    public String getUsername() {
        return username;
    }

    public String getAssignedVirtualIp() {
        return assignedVirtualIp;
    }

    public Department getDepartment() {
        return department;
    }

    public Role getRole() {
        return role;
    }

    public Socket getSocket() {
        return socket;
    }



    public KillSwitchManager getKillSwitchManager() {
        return killSwitchManager;
    }

    public TunnelManager getTunnelManager() {
        return tunnelManager;
    }

    public DnsLeakProtection getDnsLeakProtection() {
        return dnsLeakProtection;
    }

    public AutoReconnectManager getAutoReconnectManager() {
        return autoReconnectManager;
    }

    public void setAutoReconnect(boolean enabled) {
        autoReconnectManager.setEnabled(enabled);
    }

    public String getDnsStatus() {
        return dnsLeakProtection.getDnsStatus();
    }

    public String getServerFingerprint() {
        if (serverPublicKey == null) {
            return null;
        }
        return CryptoUtils.computeSha256FingerprintHex(serverPublicKey);
    }

    @Override
    public void close() {
        disconnect();
    }
}
