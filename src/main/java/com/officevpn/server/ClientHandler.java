package com.officevpn.server;

import com.officevpn.model.Department;
import com.officevpn.model.UserAccount;
import com.officevpn.protocol.PacketType;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.security.AuditSanitizer;
import com.officevpn.security.AuditUnavailableException;
import com.officevpn.security.CryptoUtils;
import com.officevpn.security.KeyExchangeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletionException;
import java.util.function.LongSupplier;

/**
 * Multithreaded client connection handler managing handshake, authentication,
 * and encrypted command dispatch for a connected VPN tunnel.
 */
public final class ClientHandler implements Runnable, SessionHandle {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientHandler.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static final int HANDSHAKE_PENDING = 0;
    public static final int HANDSHAKE_AUTHENTICATED = 1;
    public static final int HANDSHAKE_TIMED_OUT = 2;

    private static final int MAX_PRE_AUTH_PACKETS = 4;

    private final Socket socket;
    private final VpnGatewayServer server;
    private final VpnSession session;
    private final ConnectionGuard.Permit permit;

    private final java.util.concurrent.atomic.AtomicInteger handshakeState = new java.util.concurrent.atomic.AtomicInteger(HANDSHAKE_PENDING);
    private java.util.concurrent.ScheduledFuture<?> deadlineTask;
    private int preAuthPacketsReceived = 0;

    private DataInputStream in;
    private DataOutputStream out;
    private volatile boolean running = true;

    private final BlockingQueue<VpnPacket> outboundBroadcastQueue;
    private Thread writerThread;
    private volatile long writeStartTime = 0L;
    private WriteGate writeGate;
    private long lastUserRefreshMs = 0L;
    private LongSupplier clock = System::currentTimeMillis;

    public ClientHandler(Socket socket, VpnGatewayServer server) {
        this(socket, server, null);
    }

    public ClientHandler(Socket socket, VpnGatewayServer server, ConnectionGuard.Permit permit) {
        this.socket = Objects.requireNonNull(socket, "Socket cannot be null");
        this.server = Objects.requireNonNull(server, "Server cannot be null");
        this.permit = permit;
        String sessionId = UUID.randomUUID().toString();
        this.session = new VpnSession(sessionId, socket.getRemoteSocketAddress().toString());
        this.outboundBroadcastQueue = new ArrayBlockingQueue<>(server.getServerLimits().getOutboundQueueCapacity());
    }

    public java.util.concurrent.atomic.AtomicInteger getHandshakeState() {
        return handshakeState;
    }

    public String getRemoteHost() {
        if (socket != null && socket.getRemoteSocketAddress() instanceof InetSocketAddress addr) {
            InetAddress inet = addr.getAddress();
            if (inet != null) {
                return inet.getHostAddress();
            }
        }
        return "UNKNOWN";
    }

    public void setDeadlineTask(java.util.concurrent.ScheduledFuture<?> deadlineTask) {
        this.deadlineTask = deadlineTask;
    }

    private void checkPreAuthPacketBudget() throws IOException {
        if (++preAuthPacketsReceived > MAX_PRE_AUTH_PACKETS) {
            try {
                socket.close();
            } catch (IOException closeEx) {
                LOGGER.debug("Ignoring socket close failure on pre-auth budget exceedance: {}", closeEx.getMessage());
            }
            throw new SecurityException("Pre-authentication packet budget exceeded (max 4 packets)");
        }
    }

    @Override
    public void run() {
        server.registerHandler(this);
        try {
            // Handshake timeout from ServerLimits
            socket.setSoTimeout(server.getServerLimits().getPreAuthReadTimeoutMillis());
            this.in = new DataInputStream(socket.getInputStream());
            this.out = new DataOutputStream(socket.getOutputStream());

            server.log("Client connected from " + session.getClientSocketAddress() + " [Session " + session.getSessionId() + "]");

            // -----------------------------------------------------------------
            // PHASE A: 3-STEP AUTHENTICATED CRYPTOGRAPHIC HANDSHAKE
            // -----------------------------------------------------------------
            performHandshake();

            // -----------------------------------------------------------------
            // PHASE B: ENCRYPTED EMPLOYEE AUTHENTICATION
            // -----------------------------------------------------------------
            if (!performAuthentication()) {
                return; // Disconnect on failed auth
            }

            // Authentication succeeded: extend timeout to 180 seconds (client sends keepalive every 25s)
            socket.setSoTimeout(180_000);

            // -----------------------------------------------------------------
            // PHASE C: ENCRYPTED TUNNEL COMMAND LOOP
            // -----------------------------------------------------------------
            runTunnelCommandLoop();

        } catch (EOFException | SocketException e) {
            // Normal client disconnect
        } catch (SocketTimeoutException e) {
            server.log("Session timed out: " + session.getClientSocketAddress());
        } catch (Throwable t) {
            server.log("Error in client handler [" + session.getClientSocketAddress() + "]: " + t.getMessage());
        } finally {
            if (deadlineTask != null) {
                deadlineTask.cancel(false);
            }
            server.unregisterHandler(this);
            if (permit != null) {
                permit.release();
            }
            cleanup();
        }
    }

    private void performHandshake() throws IOException {
        // Step 1: Read HANDSHAKE_INIT (allowing pre-auth packets like PING within budget)
        VpnPacket initPacket = null;
        while (true) {
            checkPreAuthPacketBudget();
            VpnPacket packet = VpnPacket.readFromStream(in, VpnPacket.PRE_AUTH);
            server.notifyPacketSniffed(packet, "INCOMING");

            if (packet.getType() == PacketType.HANDSHAKE_INIT) {
                initPacket = packet;
                break;
            } else if (packet.getType() == PacketType.PING) {
                VpnPacket pong = new VpnPacket(
                        PacketType.PING,
                        VirtualIpPool.GATEWAY_SERVER_IP,
                        "GATEWAY_SERVER",
                        Department.HEADQUARTERS.name(),
                        System.currentTimeMillis(),
                        null,
                        null,
                        null,
                        Map.of("status", "PONG")
                );
                sendPacketDirect(pong);
            }
        }

        String clientRandomB64 = initPacket.getMetadata().get("clientRandom");
        String clientEcPubB64 = initPacket.getMetadata().get("clientEcPub");
        String protocolVer = initPacket.getMetadata().get("protocolVersion");

        if (clientRandomB64 == null || clientEcPubB64 == null || !"OFFICE-VPN-2.0".equals(protocolVer)) {
            throw new SecurityException("Invalid HANDSHAKE_INIT parameters (protocol mismatch, missing nonce, or missing ephemeral EC key)");
        }
        byte[] clientRandom = Base64.getDecoder().decode(clientRandomB64);
        PublicKey clientEcPub = KeyExchangeUtil.base64ToEcPublicKey(clientEcPubB64);

        // Step 2: Generate server ephemeral EC keypair and nonce, then compute shared secret and transcript
        KeyPair serverEcPair = KeyExchangeUtil.generateECDHKeyPair();
        byte[] serverRandom = new byte[32];
        SECURE_RANDOM.nextBytes(serverRandom);

        byte[] rawSharedSecret = KeyExchangeUtil.deriveRawSharedSecret(serverEcPair.getPrivate(), clientEcPub);
        byte[] transcript = CryptoUtils.buildHandshakeTranscriptV2(
                "OFFICE-VPN-2.0",
                clientRandom,
                serverRandom,
                clientEcPub.getEncoded(),
                serverEcPair.getPublic().getEncoded()
        );
        byte[] transcriptHash;
        try {
            transcriptHash = MessageDigest.getInstance("SHA-256").digest(transcript);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 computation failed", e);
        }

        // Server signs transcript with RSASSA-PSS using its static RSA identity key
        byte[] transcriptSignature = CryptoUtils.signWithRsaPss(transcript, server.getServerKeyPair().getPrivate());

        // Derive directional keys using transcript hash as HKDF salt
        CryptoUtils.DirectionalKeys dirKeys = KeyExchangeUtil.deriveDirectionalKeys(rawSharedSecret, transcriptHash);
        Arrays.fill(rawSharedSecret, (byte) 0);
        session.setDirectionalKeys(dirKeys);

        Map<String, String> challengeMeta = new LinkedHashMap<>();
        challengeMeta.put("protocolVersion", "OFFICE-VPN-2.0");
        challengeMeta.put("serverPublicKey", CryptoUtils.publicKeyToBase64(server.getServerKeyPair().getPublic()));
        challengeMeta.put("serverEcPub", KeyExchangeUtil.ecPublicKeyToBase64(serverEcPair.getPublic()));
        challengeMeta.put("serverRandom", Base64.getEncoder().encodeToString(serverRandom));
        challengeMeta.put("transcriptSignature", Base64.getEncoder().encodeToString(transcriptSignature));

        VpnPacket challengePacket = new VpnPacket(
                PacketType.HANDSHAKE_CHALLENGE,
                VirtualIpPool.GATEWAY_SERVER_IP,
                "GATEWAY_SERVER",
                Department.HEADQUARTERS.name(),
                System.currentTimeMillis(),
                null,
                null,
                null,
                challengeMeta
        );
        sendPacketDirect(challengePacket);

        // Step 3: Read client HANDSHAKE_SESSION_KEY encrypted confirmation
        VpnPacket sessionKeyPacket = null;
        while (true) {
            checkPreAuthPacketBudget();
            VpnPacket packet = VpnPacket.readFromStream(in, VpnPacket.PRE_AUTH);
            if (packet != null) {
                server.recordPostHandshakeInitPacket();
            }
            server.notifyPacketSniffed(packet, "INCOMING");

            if (packet.getType() == PacketType.HANDSHAKE_SESSION_KEY) {
                sessionKeyPacket = packet;
                break;
            } else if (packet.getType() == PacketType.PING) {
                VpnPacket pong = new VpnPacket(
                        PacketType.PING,
                        VirtualIpPool.GATEWAY_SERVER_IP,
                        "GATEWAY_SERVER",
                        Department.HEADQUARTERS.name(),
                        System.currentTimeMillis(),
                        null,
                        null,
                        null,
                        Map.of("status", "PONG")
                );
                sendPacketDirect(pong);
            }
        }

        // Decrypt client confirmation with c2sKey and direction DIRECTION_C2S
        CryptoUtils.decryptPacket(sessionKeyPacket, dirKeys.c2sKey(), CryptoUtils.DIRECTION_C2S);

        // Step 4: Send server confirmation encrypted with s2cKey and direction DIRECTION_S2C
        Map<String, String> confirmMeta = new LinkedHashMap<>();
        confirmMeta.put("status", "ESTABLISHED");
        confirmMeta.put("seqNum", String.valueOf(session.getNextServerSendSeq()));

        VpnPacket confirmPacket = CryptoUtils.createEncryptedPacket(
                PacketType.HANDSHAKE_SESSION_KEY,
                VirtualIpPool.GATEWAY_SERVER_IP,
                "GATEWAY_SERVER",
                Department.HEADQUARTERS.name(),
                confirmMeta,
                new byte[0],
                dirKeys.s2cKey(),
                CryptoUtils.DIRECTION_S2C
        );
        sendPacketDirect(confirmPacket);

        server.log("Handshake OFFICE-VPN-2.0 (PFS ECDH-secp256r1) completed successfully with " + session.getClientSocketAddress());
    }

    private VpnPacket encryptServerPacket(PacketType type, Map<String, String> meta, byte[] payload) {
        if (session.getDirectionalKeys() == null) {
            throw new IllegalStateException("Directional session keys not initialized");
        }
        return CryptoUtils.createEncryptedPacket(
                type,
                VirtualIpPool.GATEWAY_SERVER_IP,
                "GATEWAY_SERVER",
                Department.HEADQUARTERS.name(),
                meta,
                payload,
                session.getDirectionalKeys().s2cKey(),
                CryptoUtils.DIRECTION_S2C
        );
    }

    private byte[] decryptClientPacket(VpnPacket packet) {
        if (session.getDirectionalKeys() == null) {
            throw new IllegalStateException("Directional session keys not initialized");
        }
        return CryptoUtils.decryptPacket(packet, session.getDirectionalKeys().c2sKey(), CryptoUtils.DIRECTION_C2S);
    }

    private boolean performAuthentication() throws IOException {
        VpnPacket authReq = null;
        while (true) {
            checkPreAuthPacketBudget();
            VpnPacket packet = VpnPacket.readFromStream(in, VpnPacket.PRE_AUTH);
            if (packet != null) {
                server.recordPostHandshakeInitPacket();
            }
            server.notifyPacketSniffed(packet, "INCOMING");

            if (packet.getType() == PacketType.AUTH_REQUEST) {
                authReq = packet;
                break;
            } else if (packet.getType() == PacketType.PING) {
                VpnPacket pong = new VpnPacket(
                        PacketType.PING,
                        VirtualIpPool.GATEWAY_SERVER_IP,
                        "GATEWAY_SERVER",
                        Department.HEADQUARTERS.name(),
                        System.currentTimeMillis(),
                        null,
                        null,
                        null,
                        Map.of("status", "PONG")
                );
                sendPacketDirect(pong);
            }
        }

        byte[] authPayload = decryptClientPacket(authReq);
        session.validateAndRecordPacket(authReq);

        String reqIdStr = authReq.getMetadata() != null ? authReq.getMetadata().get("reqId") : null;

        UserAccount user;
        String username = "UNKNOWN";
        try {
            char[] pwChars = null;
            try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(authPayload))) {
                username = dis.readUTF();
                String rawPassword = dis.readUTF();
                pwChars = rawPassword.toCharArray();
            }

            Map<String, String> meta = authReq.getMetadata();
            String totpCode = (meta != null) ? meta.get("totpCode") : null;

            try {
                user = server.getDatabaseManager().authenticateUser(
                        username,
                        pwChars,
                        totpCode,
                        getRemoteHost()
                );
            } finally {
                if (pwChars != null) {
                    Arrays.fill(pwChars, '\0');
                }
            }
        } finally {
            Arrays.fill(authPayload, (byte) 0);
        }

        if (user == null) {
            // Send encrypted denial
            Map<String, String> deniedMeta = new LinkedHashMap<>();
            deniedMeta.put("status", "DENIED");
            deniedMeta.put("reason", "Authentication failed: invalid credentials, MFA failure, or account disabled");
            if (reqIdStr != null && !reqIdStr.isBlank()) {
                deniedMeta.put("reqId", reqIdStr.trim());
            }
            deniedMeta.put("seqNum", String.valueOf(session.getNextServerSendSeq()));

            VpnPacket deniedPacket = encryptServerPacket(
                    PacketType.AUTH_RESPONSE,
                    deniedMeta,
                    new byte[0]
            );
            sendPacketDirect(deniedPacket);
            String safeUser = AuditSanitizer.sanitizeLog(username, 64);
            server.log("Authentication DENIED for user '" + safeUser + "' from " + session.getClientSocketAddress());
            return false;
        }

        // Extract authentic client device telemetry with strict sanitization
        Map<String, String> meta = authReq.getMetadata();
        String rawDeviceName = (meta != null && meta.containsKey("deviceName") && !meta.get("deviceName").isBlank())
                ? meta.get("deviceName")
                : (getRemoteHost() + " (" + System.getProperty("os.name") + ")");
        String clientDeviceName = AuditSanitizer.sanitizeLog(rawDeviceName, 128);

        String rawDeviceFp = (meta != null && meta.containsKey("deviceFp") && !meta.get("deviceFp").isBlank())
                ? meta.get("deviceFp")
                : ("HW-" + CryptoUtils.sha256Hex(user.username() + ":" + getRemoteHost()).substring(0, 16).toUpperCase(java.util.Locale.ROOT));
        String clientDeviceFp = AuditSanitizer.sanitizeLog(rawDeviceFp, 128);

        // Enforce Zero-Trust Hardware Authorization
        if (!server.getDatabaseManager().isDeviceTrusted(user.username(), clientDeviceFp)) {
            Map<String, String> deniedMeta = new LinkedHashMap<>();
            deniedMeta.put("status", "DENIED");
            deniedMeta.put("reason", "Authentication failed: invalid credentials or account disabled");
            if (reqIdStr != null && !reqIdStr.isBlank()) {
                deniedMeta.put("reqId", reqIdStr.trim());
            }
            deniedMeta.put("seqNum", String.valueOf(session.getNextServerSendSeq()));

            VpnPacket deniedPacket = encryptServerPacket(
                    PacketType.AUTH_RESPONSE,
                    deniedMeta,
                    new byte[0]
            );
            sendPacketDirect(deniedPacket);
            server.log("Authentication BLOCKED: Device '" + clientDeviceFp + "' is untrusted or revoked for user '" + user.username() + "' from " + session.getClientSocketAddress());
            server.getDatabaseManager().logAuditEvent(
                    "DEVICE_ACCESS_BLOCKED",
                    user.username(),
                    user.department().name(),
                    "Connection blocked: hardware device '" + clientDeviceFp + "' is untrusted or revoked",
                    getRemoteHost()
            );
            return false;
        }

        // Successfully authenticated: transition state and cancel deadline timer
        if (!handshakeState.compareAndSet(HANDSHAKE_PENDING, HANDSHAKE_AUTHENTICATED)) {
            return false;
        }
        if (deadlineTask != null) {
            deadlineTask.cancel(false);
        }
        if (permit != null) {
            permit.markAuthenticated();
        }

        // Atomic session binding via VpnGatewayServer
        VpnGatewayServer.BindResult bindResult = server.bindSession(user, this);
        String virtualIp = bindResult.virtualIp();
        session.setAuthenticatedUser(user);
        session.setAssignedVirtualIp(virtualIp);

        if (bindResult.supersededHandle() != null && bindResult.supersededHandle() != this) {
            server.log("Superseding existing session for user '" + user.username() + "' - terminating previous tunnel.");
            bindResult.supersededHandle().terminate("Superseded by new session login");
        }

        this.writerThread = new Thread(this::runWriterLoop, "vpn-writer-" + session.getSessionId());
        this.writerThread.setDaemon(true);
        this.writerThread.start();

        // Register or update authentic client hardware device in database
        server.getDatabaseManager().registerDevice(user.username(), clientDeviceFp, clientDeviceName);

        server.getDatabaseManager().insertSession(session.getSessionId(), user.username(), virtualIp, user.department().name(), user.role().name(), getRemoteHost());
        server.getDatabaseManager().logConnectionEvent(user.username(), virtualIp, getRemoteHost(), "CONNECT", "Encrypted VPN tunnel established");

        server.getDatabaseManager().logAuditEvent(
                "TUNNEL_ESTABLISHED",
                user.username(),
                user.department().name(),
                "Encrypted VPN tunnel established. Assigned Virtual IP: " + virtualIp,
                getRemoteHost()
        );

        // Send encrypted success confirmation
        Map<String, String> successMeta = new LinkedHashMap<>();
        successMeta.put("status", "SUCCESS");
        successMeta.put("virtualIp", virtualIp);
        successMeta.put("username", user.username()); // DB canonical casing
        successMeta.put("department", user.department().name());
        successMeta.put("role", user.role().name());
        if (reqIdStr != null && !reqIdStr.isBlank()) {
            successMeta.put("reqId", reqIdStr.trim());
        }
        successMeta.put("seqNum", String.valueOf(session.getNextServerSendSeq()));

        VpnPacket successPacket = encryptServerPacket(
                PacketType.AUTH_RESPONSE,
                successMeta,
                new byte[0]
        );
        sendPacketDirect(successPacket);

        server.log("Tunnel ESTABLISHED: " + user.username() + " (" + user.department() + " " + user.role() + ") -> Virtual IP " + virtualIp);
        server.notifySessionUpdated();
        return true;
    }

    private void runTunnelCommandLoop() throws IOException {
        while (running && !socket.isClosed()) {
            VpnPacket packet = VpnPacket.readFromStream(in, VpnPacket.POST_AUTH);
            server.notifyPacketSniffed(packet, "INCOMING");

            if (packet == null || packet.getType() == null) {
                throw new IOException("Malformed packet received");
            }

            // 1. Structural check complete (type and framing verified)
            // 2. Authenticate & Decrypt FIRST with zero state mutation
            byte[] plainPayload = decryptClientPacket(packet);

            // 3. ONLY THEN validate replay window and clock skew
            session.validateAndRecordPacket(packet);
            if (packet.getType() != PacketType.PING) {
                session.recordActivity();
            }

            String reqIdStr = packet.getMetadata() != null ? packet.getMetadata().get("reqId") : null;
            long reqId = parseBoundedLong(reqIdStr, -1L);

            // Strict Anti-Spoofing Identity Verification:
            // Client packet headers must strictly match the server's authoritative session binding
            UserAccount user = session.getAuthenticatedUser();
            String assignedVip = session.getAssignedVirtualIp();

            if (!user.username().equalsIgnoreCase(packet.getSenderUsername()) ||
                    !Objects.equals(packet.getSenderVirtualIp(), assignedVip)) {
                server.getDatabaseManager().logAuditEvent(
                        "SECURITY_ALERT",
                        user.username(),
                        user.department().name(),
                        String.format("Identity Spoofing Detected! Declared user='%s', vip='%s' vs Bound user='%s', vip='%s'",
                                packet.getSenderUsername(), packet.getSenderVirtualIp(), user.username(), assignedVip),
                        getRemoteHost()
                );
                throw new SecurityException("Identity Spoofing Violation: packet header credentials do not match authenticated tunnel session");
            }

            // Defense in depth: refresh UserAccount from DB every 5s before executing command
            long now = clock.getAsLong();
            if (now - lastUserRefreshMs >= 5000L) {
                UserAccount fresh = server.getDatabaseManager().getUserByUsername(user.username());
                if (fresh == null || !fresh.active()) {
                    server.getDatabaseManager().logAuditEvent(
                            "SESSION_REVOKED",
                            user.username(),
                            user.department().name(),
                            "Session revoked due to account deactivation or deletion",
                            "SYSTEM",
                            getRemoteHost()
                    );
                    sendEncryptedErrorCode("E_REVOKED", "Session revoked: account inactive or deleted", reqId);
                    terminateSession("Account inactive or deleted");
                    return;
                }
                if (fresh.role() != user.role() || fresh.department() != user.department()) {
                    session.setAuthenticatedUser(fresh);
                    user = fresh;
                    server.notifySessionUpdated();
                }
                lastUserRefreshMs = now;
            }

            try {
                switch (packet.getType()) {
                    case FILE_LIST_REQ -> handleFileList(packet, reqId);
                    case FILE_DOWNLOAD_REQ -> handleFileDownload(packet, reqId);
                    case FILE_UPLOAD -> handleFileUpload(packet, plainPayload, reqId);
                    case CHAT_MESSAGE -> handleChatMessage(plainPayload);
                    case CHANGE_PASSWORD -> handleChangePassword(plainPayload, reqId);
                    case PING -> handlePing(reqId);
                    case DISCONNECT -> {
                        running = false;
                        server.log("Client initiated disconnect: " + user.username());
                        return;
                    }
                    default -> sendEncryptedErrorCode("E_BAD_REQUEST", "Unsupported packet command: " + packet.getType(), reqId);
                }
            } catch (Throwable t) {
                translateAndSendError(t, reqId);
            }
        }
    }

    private void handleFileList(VpnPacket request, long reqId) throws IOException {
        UserAccount user = session.getAuthenticatedUser();
        String targetVaultStr = request.getMetadata().get("targetVault");
        Department targetVault = (targetVaultStr != null) ? Department.valueOf(targetVaultStr) : user.department();

        List<String> files = server.getVaultManager().listFiles(user, targetVault, server.getDatabaseManager(), getRemoteHost());
        String fileListJoined = String.join("\n", files);
        byte[] payload = fileListJoined.getBytes(StandardCharsets.UTF_8);

        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("targetVault", targetVault.name());
        meta.put("fileCount", String.valueOf(files.size()));
        if (reqId >= 0) {
            meta.put("reqId", String.valueOf(reqId));
        }
        meta.put("seqNum", String.valueOf(session.getNextServerSendSeq()));

        VpnPacket response = encryptServerPacket(
                PacketType.FILE_LIST_RES,
                meta,
                payload
        );
        sendPacketDirect(response);
    }

    private void handleFileDownload(VpnPacket request, long reqId) throws IOException {
        UserAccount user = session.getAuthenticatedUser();
        String targetVaultStr = request.getMetadata().get("targetVault");
        Department targetVault = (targetVaultStr != null) ? Department.valueOf(targetVaultStr) : user.department();
        String fileName = request.getMetadata().get("fileName");

        byte[] fileBytes = server.getVaultManager().readFile(user, targetVault, fileName, server.getDatabaseManager(), getRemoteHost());

        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("targetVault", targetVault.name());
        meta.put("fileName", fileName);
        meta.put("fileSize", String.valueOf(fileBytes.length));
        if (reqId >= 0) {
            meta.put("reqId", String.valueOf(reqId));
        }
        meta.put("seqNum", String.valueOf(session.getNextServerSendSeq()));

        VpnPacket response = encryptServerPacket(
                PacketType.FILE_DOWNLOAD_RES,
                meta,
                fileBytes
        );
        sendPacketDirect(response);
    }

    private void handleFileUpload(VpnPacket request, byte[] fileData, long reqId) throws IOException {
        String fileSizeStr = request.getMetadata().get("fileSize");
        long declaredSize = parseBoundedLong(fileSizeStr, -1);
        if (declaredSize > com.officevpn.storage.VaultManager.MAX_FILE_SIZE || (fileData != null && fileData.length > com.officevpn.storage.VaultManager.MAX_FILE_SIZE)) {
            translateAndSendError(new com.officevpn.storage.VaultException("E_TOO_LARGE", "Request payload exceeds allowable limits"), reqId);
            return;
        }

        UserAccount user = session.getAuthenticatedUser();
        String targetVaultStr = request.getMetadata().get("targetVault");
        Department targetVault = (targetVaultStr != null) ? Department.valueOf(targetVaultStr) : user.department();
        String fileName = request.getMetadata().get("fileName");

        server.getVaultManager().writeFile(user, targetVault, fileName, fileData, server.getDatabaseManager(), getRemoteHost());

        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("targetVault", targetVault.name());
        meta.put("fileName", fileName);
        meta.put("status", "OK");
        if (reqId >= 0) {
            meta.put("reqId", String.valueOf(reqId));
        }
        meta.put("seqNum", String.valueOf(session.getNextServerSendSeq()));

        VpnPacket ack = encryptServerPacket(
                PacketType.FILE_UPLOAD,
                meta,
                new byte[0]
        );
        sendPacketDirect(ack);
    }

    private void handleChatMessage(byte[] messageBytes) {
        if (messageBytes != null && messageBytes.length > 2048) {
            try {
                sendEncryptedErrorCode("E_TOO_LARGE", "Request payload exceeds allowable limits", -1L);
            } catch (Exception ex) {
                LOGGER.debug("Failed to deliver E_TOO_LARGE notification for oversized message: {}", ex.getMessage());
            }
            return;
        }

        UserAccount user = session.getAuthenticatedUser();
        String rawMessage = (messageBytes != null) ? new String(messageBytes, StandardCharsets.UTF_8) : "";
        String message = AuditSanitizer.sanitizeLog(rawMessage, 512);

        server.log("[CHAT] [" + user.department() + "] " + user.username() + ": " + message);
        server.broadcastChatMessage(user.username(), user.department().name(), session.getAssignedVirtualIp(), message);
    }

    private void handleChangePassword(byte[] payloadBytes, long reqId) throws IOException {
        UserAccount user = session.getAuthenticatedUser();
        if (payloadBytes == null || payloadBytes.length == 0 || payloadBytes.length > 4096) {
            sendEncryptedErrorCode("E_BAD_REQUEST", "Invalid password update payload", reqId);
            return;
        }
        char[] currentPw = null;
        char[] newPw = null;
        try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(payloadBytes))) {
            currentPw = dis.readUTF().toCharArray();
            newPw = dis.readUTF().toCharArray();
            boolean changed = server.getDatabaseManager().changeOwnPassword(
                    user.username(), currentPw, newPw, getRemoteHost());
            if (!changed) {
                sendEncryptedErrorCode("E_AUTH_FAILED", "Current password verification failed", reqId);
                return;
            }
            Map<String, String> meta = new LinkedHashMap<>();
            meta.put("status", "OK");
            if (reqId >= 0) {
                meta.put("reqId", String.valueOf(reqId));
            }
            meta.put("seqNum", String.valueOf(session.getNextServerSendSeq()));
            VpnPacket ack = encryptServerPacket(PacketType.CHANGE_PASSWORD, meta, new byte[0]);
            sendPacketDirect(ack);
        } catch (IllegalArgumentException ex) {
            sendEncryptedErrorCode("E_VALIDATION", ex.getMessage(), reqId);
        } finally {
            if (currentPw != null) Arrays.fill(currentPw, '\0');
            if (newPw != null) Arrays.fill(newPw, '\0');
            Arrays.fill(payloadBytes, (byte) 0);
        }
    }

    private void handlePing(long reqId) throws IOException {
        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("status", "PONG");
        if (reqId >= 0) {
            meta.put("reqId", String.valueOf(reqId));
        }
        meta.put("seqNum", String.valueOf(session.getNextServerSendSeq()));

        VpnPacket pong = encryptServerPacket(
                PacketType.PING,
                meta,
                new byte[0]
        );
        sendPacketDirect(pong);
    }

    private void translateAndSendError(Throwable t, long reqId) {
        Throwable eff = t;
        while (eff != null && eff.getCause() != null && eff.getCause() != eff
                && (eff.getClass() == RuntimeException.class || eff.getClass() == CompletionException.class)) {
            eff = eff.getCause();
        }
        String code;
        String genericMsg;
        if (eff instanceof com.officevpn.storage.VaultException ve) {
            code = ve.getErrorCode();
            genericMsg = switch (code) {
                case "E_TOO_LARGE" -> "Request payload exceeds allowable limits";
                case "E_QUOTA" -> "Resource quota exceeded";
                case "E_NOT_FOUND" -> "The requested resource was not found";
                case "E_REVOKED" -> "Session has been revoked";
                case "E_BAD_REQUEST" -> "Bad request: invalid input or parameter format";
                case "E_DENIED" -> "Access denied: insufficient permissions or security policy violation";
                case "E_UNAVAILABLE" -> "Service temporarily unavailable";
                default -> "Internal gateway error occurred while processing request";
            };
        } else if (eff instanceof SessionRevokedException) {
            code = "E_REVOKED";
            genericMsg = "Session has been revoked";
        } else if (eff instanceof AuditUnavailableException) {
            code = "E_UNAVAILABLE";
            genericMsg = "Service temporarily unavailable";
        } else if (eff instanceof java.nio.file.NoSuchFileException || eff instanceof java.io.FileNotFoundException) {
            code = "E_NOT_FOUND";
            genericMsg = "The requested resource was not found";
        } else if (eff instanceof SecurityException) {
            code = "E_DENIED";
            genericMsg = "Access denied: insufficient permissions or security policy violation";
        } else if (eff instanceof IllegalArgumentException) {
            code = "E_BAD_REQUEST";
            genericMsg = "Bad request: invalid input or parameter format";
        } else {
            code = "E_INTERNAL";
            genericMsg = "Internal gateway error occurred while processing request";
        }

        server.log(String.format("[SESSION %s] Error mapped to %s: %s (internal: %s)",
                session.getSessionId(), code, genericMsg, t != null ? t.getMessage() : "null"));
        try {
            sendEncryptedErrorCode(code, genericMsg, reqId);
        } catch (Exception e) {
            server.log("Failed to send error response to " + session.getClientSocketAddress() + ": " + e.getMessage());
        }
    }

    private void sendEncryptedErrorCode(String code, String errorMessage, long reqId) throws IOException {
        if (session.getDirectionalKeys() != null && socket != null && !socket.isClosed()) {
            Map<String, String> meta = new LinkedHashMap<>();
            meta.put("status", "ERROR");
            meta.put("code", code != null ? code : "E_INTERNAL");
            meta.put("error", errorMessage != null ? errorMessage : "Unspecified error");
            if (reqId >= 0) {
                meta.put("reqId", String.valueOf(reqId));
            }
            meta.put("seqNum", String.valueOf(session.getNextServerSendSeq()));

            VpnPacket errPacket = encryptServerPacket(
                    PacketType.ERROR,
                    meta,
                    new byte[0]
            );
            sendPacketDirect(errPacket);
        }
    }

    public void enqueueBroadcast(VpnPacket packet) {
        if (!outboundBroadcastQueue.offer(packet)) {
            server.log("Client " + session.getClientSocketAddress() + " slow consumer: outbound broadcast queue overflow - disconnecting");
            if (server.getDatabaseManager() != null) {
                UserAccount u = session.getAuthenticatedUser();
                server.getDatabaseManager().logAuditEvent(
                        "SLOW_CONSUMER",
                        u != null ? u.username() : "UNKNOWN",
                        u != null ? u.department().name() : "UNKNOWN",
                        "Outbound broadcast queue overflow (slow consumer)",
                        "SYSTEM",
                        getRemoteHost()
                );
            }
            terminateSession("Outbound broadcast queue overflow (slow consumer)");
        }
    }

    private void runWriterLoop() {
        while (running && socket != null && !socket.isClosed()) {
            try {
                VpnPacket packet = outboundBroadcastQueue.take();
                writeStartTime = (clock != null) ? clock.getAsLong() : System.currentTimeMillis();
                try {
                    if (writeGate != null) {
                        writeGate.beforeWrite();
                    }
                    sendPacketDirect(packet);
                } finally {
                    writeStartTime = 0L;
                }
            } catch (InterruptedException e) {
                break;
            } catch (Exception e) {
                terminateSession("Outbound writer error: " + e.getMessage());
                break;
            }
        }
    }

    private static long parseBoundedLong(String str, long defaultVal) {
        if (str == null || str.isBlank() || str.length() > 19) {
            return defaultVal;
        }
        try {
            return Long.parseLong(str.trim());
        } catch (NumberFormatException ignored) {
            return defaultVal;
        }
    }

    public long getWriteStartTime() {
        return writeStartTime;
    }

    // Test seam
    void setWriteGate(WriteGate writeGate) {
        this.writeGate = writeGate;
    }

    // Test seam
    void setClock(LongSupplier clock) {
        this.clock = (clock != null) ? clock : System::currentTimeMillis;
    }

    @Override
    public String id() {
        return session.getSessionId();
    }

    @Override
    public void terminate(String reason) {
        terminateSession(reason);
    }

    /**
     * Thread-safely dispatches an encrypted packet to the client socket.
     *
     * @param packet Packet to transmit
     * @throws IOException If write fails
     */
    public synchronized void sendPacketDirect(VpnPacket packet) throws IOException {
        if (server != null && server.getBandwidthManager() != null && session != null && session.getAuthenticatedUser() != null) {
            int payloadLen = (packet.getEncryptedPayload() != null) ? packet.getEncryptedPayload().length : 64;
            boolean ok = server.getBandwidthManager().tryConsume(session.getAuthenticatedUser().username(), session.getAuthenticatedUser().department(), payloadLen);
            if (!ok) {
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        if (socket != null && !socket.isClosed() && out != null) {
            packet.writeToStream(out);
            out.flush();
            server.notifyPacketSniffed(packet, "OUTGOING");
        }
    }

    public void terminateSession() {
        terminateSession("Administrative session revocation");
    }

    public void terminateSession(String reason) {
        this.running = false;
        try {
            if (session.isAuthenticated() && session.getDirectionalKeys() != null && socket != null && !socket.isClosed() && out != null) {
                Map<String, String> meta = new LinkedHashMap<>();
                meta.put("reason", reason != null ? reason : "Session terminated by Administrator");
                meta.put("seqNum", String.valueOf(session.getNextServerSendSeq()));

                VpnPacket disc = encryptServerPacket(
                        PacketType.DISCONNECT,
                        meta,
                        new byte[0]
                );
                sendPacketDirect(disc);
            }
        } catch (Exception ignored) {
        }

        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException ignored) {
        }
    }

    private void cleanup() {
        this.running = false;
        if (session.getAuthenticatedUser() != null) {
            String uname = session.getAuthenticatedUser().username();
            server.unregisterAuthenticatedClient(uname, this);
            server.getDatabaseManager().closeSession(session.getSessionId(), "TUNNEL_CLOSED");
            server.getDatabaseManager().logConnectionEvent(uname, session.getAssignedVirtualIp(), getRemoteHost(), "DISCONNECT", "VPN tunnel session terminated");
            server.getDatabaseManager().logAuditEvent(
                    "TUNNEL_TERMINATED",
                    uname,
                    session.getAuthenticatedUser().department().name(),
                    "VPN tunnel session terminated. Virtual IP: " + session.getAssignedVirtualIp(),
                    getRemoteHost()
            );
            // Only release virtual IP if this user no longer has an active client handler
            if (server.getActiveClient(uname) == null && session.getAssignedVirtualIp() != null) {
                server.getVirtualIpPool().releaseIp(session.getAssignedVirtualIp());
            }
        } else if (session.getAssignedVirtualIp() != null) {
            server.getVirtualIpPool().releaseIp(session.getAssignedVirtualIp());
        }

        server.notifySessionUpdated();

        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException ignored) {
        }
        server.log("Session closed for " + session.getClientSocketAddress());
    }

    public boolean isRunning() {
        return running;
    }

    public Socket getSocket() {
        return socket;
    }

    public VpnSession getSession() {
        return session;
    }
}

