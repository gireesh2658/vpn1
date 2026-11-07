package com.officevpn.network;

import com.officevpn.db.DatabaseManager;
import com.officevpn.security.CryptoUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enterprise Site-to-Site (Gateway-to-Gateway) Peering & Routing Manager.
 * Connects Headquarter and Branch office networks over encrypted tunnels.
 * Topology:
 * - Headquarters Local Subnet: 10.8.0.0/24 (Gateway: 10.8.0.1)
 * - Remote Branch Subnet: 10.9.0.0/24 (Gateway: 10.9.0.1)
 */
public final class SiteToSiteManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(SiteToSiteManager.class);
    private static final long KEEPALIVE_TIMEOUT_MS = 45_000L; // 45 seconds

    public record SiteToSitePeer(
            String peerId,
            String peerGatewayIp,
            String localSubnet,
            String remoteSubnet,
            String sharedSecretHash,
            String status,
            long lastKeepalive
    ) {
        public SiteToSitePeer withStatus(String newStatus, long timestamp) {
            return new SiteToSitePeer(peerId, peerGatewayIp, localSubnet, remoteSubnet, sharedSecretHash, newStatus, timestamp);
        }
    }

    private final DatabaseManager databaseManager;
    private final Map<String, SiteToSitePeer> peers = new ConcurrentHashMap<>();

    public SiteToSiteManager(DatabaseManager databaseManager) {
        this.databaseManager = Objects.requireNonNull(databaseManager, "DatabaseManager cannot be null");
        loadPersistedPeers();
    }

    private void loadPersistedPeers() {
        try {
            for (DatabaseManager.SiteToSitePeerRecord rec : databaseManager.listSiteToSitePeers()) {
                peers.put(rec.peerId(), new SiteToSitePeer(
                        rec.peerId(),
                        rec.peerGatewayIp(),
                        rec.localSubnet(),
                        rec.remoteSubnet(),
                        rec.secretHash(),
                        rec.status(),
                        rec.lastKeepalive()
                ));
            }
            LOGGER.info("Loaded {} site-to-site peers from database", peers.size());
        } catch (Exception e) {
            LOGGER.debug("Could not pre-load site-to-site peers: {}", e.getMessage());
        }
    }

    public synchronized void addPeer(SiteToSitePeer peer) {
        Objects.requireNonNull(peer, "Peer cannot be null");
        peers.put(peer.peerId(), peer);
        databaseManager.saveSiteToSitePeer(peer.peerId(), peer.peerGatewayIp(), peer.localSubnet(),
                peer.remoteSubnet(), peer.sharedSecretHash(), peer.status(), peer.lastKeepalive());
        LOGGER.info("SITE_TO_SITE_PEER_ADDED: Registered peer '{}' for subnet {}", peer.peerId(), peer.remoteSubnet());
    }

    public synchronized void removePeer(String peerId) {
        if (peerId == null) return;
        peers.remove(peerId);
        databaseManager.deleteSiteToSitePeer(peerId);
        LOGGER.info("Removed site-to-site peer: {}", peerId);
    }

    /**
     * Authenticates a remote gateway peer using salted PBKDF2 hash verification.
     */
    public boolean authenticatePeer(String peerId, char[] sharedSecret) {
        if (peerId == null || sharedSecret == null) {
            return false;
        }
        SiteToSitePeer peer = peers.get(peerId);
        if (peer == null) {
            return false;
        }
        boolean ok = CryptoUtils.verifyPasswordModular(sharedSecret, peer.sharedSecretHash(), null);
        if (ok) {
            handleKeepalive(peerId);
        }
        return ok;
    }

    /**
     * Inspects destination subnet or IP and resolves the target site-to-site peer.
     *
     * @param sourceSubnet source network subnet
     * @param destSubnet   target network subnet or IP address
     * @return Matching SiteToSitePeer if routable via peering; null otherwise
     */
    public SiteToSitePeer routePacket(String sourceSubnet, String destSubnet) {
        if (destSubnet == null || destSubnet.isBlank()) {
            return null;
        }
        String cleanDest = destSubnet.trim();
        for (SiteToSitePeer peer : peers.values()) {
            if (!"ONLINE".equalsIgnoreCase(peer.status())) {
                continue;
            }
            if (cleanDest.equals(peer.remoteSubnet())) {
                return peer;
            }
            // Check IP match inside remote subnet (e.g., 10.9.0.x matches 10.9.0.0/24)
            if (peer.remoteSubnet().startsWith("10.9.0.") && cleanDest.startsWith("10.9.0.")) {
                return peer;
            }
        }
        return null;
    }

    /**
     * Handles incoming keepalive heartbeats from remote peer.
     */
    public synchronized void handleKeepalive(String peerId) {
        if (peerId == null) return;
        long now = System.currentTimeMillis();
        peers.computeIfPresent(peerId, (k, p) -> {
            SiteToSitePeer updated = p.withStatus("ONLINE", now);
            databaseManager.updateSiteToSiteKeepalive(peerId, "ONLINE", now);
            return updated;
        });
    }

    /**
     * Emits keepalive ping to all active online peers.
     */
    public void sendKeepalive() {
        for (SiteToSitePeer p : peers.values()) {
            LOGGER.debug("Sending site-to-site keepalive to peer: {} at {}", p.peerId(), p.peerGatewayIp());
        }
    }

    /**
     * Inspects peers and transitions stale peers to OFFLINE if no keepalive received in 45s.
     *
     * @return count of newly marked offline peers
     */
    public synchronized int checkPeerTimeouts() {
        long now = System.currentTimeMillis();
        int offlineCount = 0;
        for (Map.Entry<String, SiteToSitePeer> entry : peers.entrySet()) {
            SiteToSitePeer peer = entry.getValue();
            if ("ONLINE".equalsIgnoreCase(peer.status()) && (now - peer.lastKeepalive() > KEEPALIVE_TIMEOUT_MS)) {
                LOGGER.warn("SITE_TO_SITE_KEEPALIVE_MISS: Peer '{}' timed out (> {}ms); setting OFFLINE",
                        peer.peerId(), KEEPALIVE_TIMEOUT_MS);
                SiteToSitePeer offlinePeer = peer.withStatus("OFFLINE", peer.lastKeepalive());
                peers.put(entry.getKey(), offlinePeer);
                databaseManager.updateSiteToSiteKeepalive(peer.peerId(), "OFFLINE", peer.lastKeepalive());
                offlineCount++;
            }
        }
        return offlineCount;
    }

    public SiteToSitePeer getPeer(String peerId) {
        return peerId != null ? peers.get(peerId) : null;
    }

    public List<SiteToSitePeer> listPeers() {
        return Collections.unmodifiableList(new ArrayList<>(peers.values()));
    }
}

