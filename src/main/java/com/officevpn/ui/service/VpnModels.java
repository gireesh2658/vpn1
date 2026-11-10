package com.officevpn.ui.service;

import java.util.List;
import java.util.Locale;

/**
 * Immutable UI view models decoupling the Ivory Atelier presentation layer from VPN daemon / crypto internals.
 */
public final class VpnModels {

    private VpnModels() {
    }

    /**
     * Toolkit-independent fuzzy subsequence matcher scoring higher for consecutive and prefix hits.
     */
    public static int fuzzyScore(String candidate, String query) {
        if (query == null || query.isBlank()) return 100;
        if (candidate == null || candidate.isBlank()) return -1;
        String hay = candidate.toLowerCase(Locale.ROOT);
        String needle = query.trim().toLowerCase(Locale.ROOT);
        int hi = 0;
        int score = 0;
        int lastMatch = -2;
        for (int ni = 0; ni < needle.length(); ni++) {
            char c = needle.charAt(ni);
            if (Character.isWhitespace(c)) continue;
            int found = hay.indexOf(c, hi);
            if (found < 0) return -1;
            score += (found == lastMatch + 1) ? 14 : 5;
            if (found == 0) score += 8;
            lastMatch = found;
            hi = found + 1;
        }
        return score;
    }

    public enum ConnectionState {
        DISCONNECTED("Disconnected", "Ready to authenticate with corporate keycard"),
        CONNECTING("Connecting", "Opening TLS/TCP channel to edge gateway"),
        HANDSHAKING("Handshaking", "Verifying ECDH P-256 & RSASSA-PSS identity"),
        CONNECTED("Connected", "Encrypted corporate tunnel open"),
        RECONNECTING("Reconnecting", "Restoring tunnel after network transition"),
        BLOCKED_BY_KILL_SWITCH("Kill Switch Active", "All non-tunnel egress blocked until re-armed");

        private final String title;
        private final String defaultCaption;

        ConnectionState(String title, String defaultCaption) {
            this.title = title;
            this.defaultCaption = defaultCaption;
        }

        public String title() {
            return title;
        }

        public String defaultCaption() {
            return defaultCaption;
        }
    }

    public enum HandshakeStation {
        REACH_GATEWAY("Reach gateway"),
        EXCHANGE_KEYS("Exchange keys"),
        VERIFY_IDENTITY("Verify identity"),
        CHECK_POSTURE("Check posture"),
        TUNNEL_OPEN("Tunnel open");

        private final String label;

        HandshakeStation(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public record GatewayNode(
            String id,
            String branch,
            String city,
            String countryCode,
            String hostname,
            int port,
            int latencyMs,
            int loadPercent,
            boolean favorite,
            boolean online,
            String fingerprintShort
    ) {
        public GatewayNode withFavorite(boolean fav) {
            return new GatewayNode(id, branch, city, countryCode, hostname, port, latencyMs, loadPercent, fav, online, fingerprintShort);
        }

        public GatewayNode withTelemetry(int newLatency, int newLoad) {
            return new GatewayNode(id, branch, city, countryCode, hostname, port, newLatency, newLoad, favorite, online, fingerprintShort);
        }
    }

    public record ThroughputSample(
            long timestampMs,
            double downloadMbps,
            double uploadMbps,
            int latencyMs
    ) {}

    public enum OfficeBranch {
        HQ("HQ — Munich Core"),
        BLR("BLR — Bengaluru R&D"),
        NYC("NYC — Midtown Studio");

        private final String displayName;

        OfficeBranch(String displayName) {
            this.displayName = displayName;
        }

        public String displayName() {
            return displayName;
        }
    }

    public record OfficeResource(
            String id,
            OfficeBranch branch,
            String roomName,
            String department,
            String hosts,
            String ports,
            boolean unlocked,
            double xNorm,
            double yNorm,
            double wNorm,
            double hNorm
    ) {
        public OfficeResource withUnlocked(boolean value) {
            return new OfficeResource(id, branch, roomName, department, hosts, ports, value, xNorm, yNorm, wNorm, hNorm);
        }
    }

    public enum TunnelProfileType {
        FULL_TUNNEL("Full Tunnel"),
        OFFICE_ONLY("Office Only"),
        SPLIT("Split"),
        GUEST_SAFE("Guest-Safe");

        private final String label;

        TunnelProfileType(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public record WorkModeProfile(
            String id,
            String name,
            TunnelProfileType profileType,
            String subtitle,
            String launchUrl,
            String dnsPolicy,
            boolean pinned,
            long lastUsedEpochMs,
            String accentRole
    ) {
        public WorkModeProfile withPinned(boolean value) {
            return new WorkModeProfile(id, name, profileType, subtitle, launchUrl, dnsPolicy, value, lastUsedEpochMs, accentRole);
        }

        public WorkModeProfile withLastUsed(long ts) {
            return new WorkModeProfile(id, name, profileType, subtitle, launchUrl, dnsPolicy, pinned, ts, accentRole);
        }

        public WorkModeProfile withEdited(String newSubtitle, String newLaunchUrl, String newDnsPolicy) {
            return new WorkModeProfile(id, name, profileType, newSubtitle, newLaunchUrl, newDnsPolicy, pinned, lastUsedEpochMs, accentRole);
        }
    }

    public record SplitAppItem(
            String appId,
            String displayName,
            String processHint,
            boolean throughTunnel
    ) {
        public SplitAppItem withThroughTunnel(boolean value) {
            return new SplitAppItem(appId, displayName, processHint, value);
        }
    }

    public record PostureCheck(
            String id,
            String title,
            boolean passed,
            String observedDetail,
            String remediationTip
    ) {
        public PostureCheck withPassed(boolean value, String newDetail) {
            return new PostureCheck(id, title, value, newDetail, remediationTip);
        }
    }

    public record EmployeeSessionItem(
            String sessionId,
            String username,
            String initials,
            String department,
            String virtualIp,
            String gatewayLabel,
            String deviceOs,
            boolean posturePassed,
            String postureBadge,
            long connectedAtMs,
            String accentRole
    ) {}

    public enum AuditCategory {
        SIGN_IN("Sign-in"),
        POLICY_CHANGE("Policy"),
        REVOKE("Revoke"),
        FAILED_ATTEMPT("Blocked");

        private final String label;

        AuditCategory(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public record AuditEventItem(
            long id,
            String dayGroup,
            String timeText,
            AuditCategory category,
            String actor,
            String headline,
            String detail,
            String remoteIp
    ) {}

    public record InviteKeyState(
            String setupKey,
            long expiresAtMs,
            int remainingUses,
            String issuedBy
    ) {}

    public record AuthResult(
            boolean success,
            boolean requiresOtp,
            String message
    ) {}

    public record EmployeeIdentity(
            String username,
            String displayName,
            String initials,
            String role,
            String department,
            String badgeId,
            List<String> allowedDepartments
    ) {}
}
