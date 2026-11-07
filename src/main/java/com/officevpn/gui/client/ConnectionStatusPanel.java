package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.protocol.VpnPacket;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Tunnel Diagnostics and Encrypted Traffic Status Panel for the Employee Client GUI.
 * <p>
 * Displays cryptographic session parameters, assigned virtual IP lease, packet counters,
 * and live encrypted packet sniffer traces (with zero plaintext payload leakage).
 */
public final class ConnectionStatusPanel extends JPanel implements VpnClientEngine.ClientEventListener {

    private static final long serialVersionUID = 1L;

    private final transient VpnClientEngine clientEngine;
    private final JLabel statusLabel = new JLabel("CONNECTED (ENCRYPTED TUNNEL)");
    private final JLabel vipLabel = new JLabel("10.8.0.x");
    private final JLabel userLabel = new JLabel("-");
    private final JLabel deptLabel = new JLabel("-");
    private final JLabel txCounterLabel = new JLabel("0 packets");
    private final JLabel rxCounterLabel = new JLabel("0 packets");
    private final JTextArea snifferArea = new JTextArea();

    private final AtomicLong txCount = new AtomicLong(0);
    private final AtomicLong rxCount = new AtomicLong(0);
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");

    public ConnectionStatusPanel(VpnClientEngine clientEngine) {
        this.clientEngine = clientEngine;
        this.clientEngine.addClientEventListener(this);

        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top parameters grid
        JPanel infoPanel = new JPanel(new GridBagLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder("Cryptographic Tunnel Status"));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 8, 4, 8);
        gbc.anchor = GridBagConstraints.WEST;

        // Row 0
        gbc.gridx = 0; gbc.gridy = 0;
        infoPanel.add(new JLabel("Tunnel State:"), gbc);
        gbc.gridx = 1;
        statusLabel.setForeground(new Color(0, 128, 0));
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD));
        infoPanel.add(statusLabel, gbc);

        gbc.gridx = 2;
        infoPanel.add(new JLabel("Virtual IP Lease:"), gbc);
        gbc.gridx = 3;
        vipLabel.setFont(vipLabel.getFont().deriveFont(Font.BOLD));
        infoPanel.add(vipLabel, gbc);

        // Row 1
        gbc.gridx = 0; gbc.gridy = 1;
        infoPanel.add(new JLabel("Authenticated User:"), gbc);
        gbc.gridx = 1;
        infoPanel.add(userLabel, gbc);

        gbc.gridx = 2;
        infoPanel.add(new JLabel("Department / Role:"), gbc);
        gbc.gridx = 3;
        infoPanel.add(deptLabel, gbc);

        // Row 2
        gbc.gridx = 0; gbc.gridy = 2;
        infoPanel.add(new JLabel("Cryptographic Suite:"), gbc);
        gbc.gridx = 1;
        JLabel cipherLabel = new JLabel("AES-256-GCM + HKDF-SHA256 + RSA-2048 OAEP/PSS");
        cipherLabel.setForeground(new Color(40, 80, 160));
        infoPanel.add(cipherLabel, gbc);

        gbc.gridx = 2;
        infoPanel.add(new JLabel("Packets (Tx / Rx):"), gbc);
        gbc.gridx = 3;
        JPanel pktPanel = new JPanel();
        pktPanel.add(txCounterLabel);
        pktPanel.add(new JLabel(" / "));
        pktPanel.add(rxCounterLabel);
        infoPanel.add(pktPanel, gbc);

        add(infoPanel, BorderLayout.NORTH);

        // Bottom: Live Encrypted Traffic Inspector
        JPanel tracePanel = new JPanel(new BorderLayout(5, 5));
        tracePanel.setBorder(BorderFactory.createTitledBorder("Encrypted Application-Packet Sniffer (Raw Wire Frame Inspector)"));

        snifferArea.setEditable(false);
        snifferArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        snifferArea.setBackground(new Color(245, 245, 250));
        com.officevpn.gui.UiSafe.disableHtml(snifferArea);
        tracePanel.add(new JScrollPane(snifferArea), BorderLayout.CENTER);

        add(tracePanel, BorderLayout.CENTER);

        updateLabels();
    }

    public void updateLabels() {
        if (clientEngine.isAuthenticated()) {
            userLabel.setText(clientEngine.getUsername());
            vipLabel.setText(clientEngine.getAssignedVirtualIp());
            deptLabel.setText(clientEngine.getDepartment() + " (" + clientEngine.getRole() + ")");
            statusLabel.setText("CONNECTED [10.8.0.x Subnet]");
            statusLabel.setForeground(new Color(0, 140, 0));
        } else if (clientEngine.isConnected()) {
            statusLabel.setText("HANDSHAKE COMPLETE (AWAITING AUTH)");
            statusLabel.setForeground(Color.BLUE);
        } else {
            statusLabel.setText("DISCONNECTED");
            statusLabel.setForeground(Color.RED);
        }
    }

    @Override
    public void onChatMessage(String senderUser, String senderDept, String senderVip, String message) {
        // Chat events handled primarily in ChatPanel
    }

    @Override
    public void onPacketSniffed(VpnPacket packet, String direction) {
        if ("OUTGOING".equalsIgnoreCase(direction)) {
            txCount.incrementAndGet();
        } else {
            rxCount.incrementAndGet();
        }

        SwingUtilities.invokeLater(() -> {
            txCounterLabel.setText(txCount.get() + " tx");
            rxCounterLabel.setText(rxCount.get() + " rx");

            String timeStr = timeFormat.format(new Date(packet.getTimestamp()));
            String hmacSnippet = (packet.getPayloadHmacHex() != null && packet.getPayloadHmacHex().length() >= 16)
                    ? packet.getPayloadHmacHex().substring(0, 16) + "..."
                    : "NONE";
            int payloadLen = (packet.getEncryptedPayload() != null) ? packet.getEncryptedPayload().length : 0;
            long seq = packet.getSequenceNumber();
            String seqStr = (seq > 0) ? " seq=#" + seq : "";

            String line = String.format("[%s] [%-8s] Type=%-18s VIP=%-10s User=%-12s Bytes=%-5d HMAC=%s%s%n",
                    timeStr, direction, packet.getType(), packet.getSenderVirtualIp(),
                    packet.getSenderUsername(), payloadLen, hmacSnippet, seqStr);

            snifferArea.append(line);
            if (snifferArea.getLineCount() > 200) {
                try {
                    int end = snifferArea.getLineEndOffset(10);
                    snifferArea.replaceRange("", 0, end);
                } catch (Exception ignored) {
                }
            }
            snifferArea.setCaretPosition(snifferArea.getDocument().getLength());
        });
    }

    @Override
    public void onConnectionStateChanged(String state) {
        SwingUtilities.invokeLater(() -> {
            updateLabels();
            snifferArea.append("[" + timeFormat.format(new Date()) + "] [STATE] " + state + "\n");
        });
    }
}


