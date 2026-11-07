package com.officevpn.server;

import com.officevpn.protocol.VpnPacket;

/**
 * Event listener interface for monitoring live VPN Gateway Server operations.
 * <p>
 * Decouples the backend multithreaded network engine from the test harnesses and
 * future GUI management dashboards (Stage 4).
 */
public interface ServerEventListener {

    /**
     * Emitted when a server-level lifecycle or diagnostic event occurs.
     *
     * @param message Log message text
     */
    void onServerLog(String message);

    /**
     * Emitted on every encrypted packet received or dispatched across any tunnel.
     * Enables live raw packet inspection without compromising plaintext payload security.
     *
     * @param rawPacket Encrypted VpnPacket
     * @param direction "INCOMING" (Client -> Server) or "OUTGOING" (Server -> Client)
     */
    void onPacketSniffed(VpnPacket rawPacket, String direction);

    /**
     * Emitted when client connection states change (handshake, authenticated, disconnected).
     */
    void onSessionUpdated();

    /**
     * Emitted when an encrypted intranet chat message is broadcast to office peers.
     *
     * @param senderUser Acting sender username
     * @param senderDept Sender's department
     * @param senderVip  Sender's assigned virtual IP (10.8.0.x)
     * @param message    Intranet chat text
     */
    void onChatBroadcast(String senderUser, String senderDept, String senderVip, String message);
}

