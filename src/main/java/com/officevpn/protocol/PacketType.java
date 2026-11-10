package com.officevpn.protocol;

/**
 * High-level control and data packet types for the Office VPN Wire Protocol.
 * <p>
 * Standardizes communication phases: handshake, mutual authentication,
 * encrypted file transfer, secure intra-office chat, keep-alive, and termination.
 */
public enum PacketType {
    HANDSHAKE_INIT,
    HANDSHAKE_CHALLENGE,
    HANDSHAKE_SESSION_KEY,
    AUTH_REQUEST,
    AUTH_RESPONSE,
    FILE_LIST_REQ,
    FILE_LIST_RES,
    FILE_UPLOAD,
    FILE_DOWNLOAD_REQ,
    FILE_DOWNLOAD_RES,
    CHAT_MESSAGE,
    CHANGE_PASSWORD,
    PING,
    DISCONNECT,
    ERROR
}

