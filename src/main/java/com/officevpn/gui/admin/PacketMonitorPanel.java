package com.officevpn.gui.admin;

import com.officevpn.gui.UiSafe;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.server.ServerEventListener;
import com.officevpn.server.VpnGatewayServer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Encrypted Application-Packet Monitor Panel for the Headquarters Admin Dashboard.
 * <p>
 * <b>Security Invariant:</b> Clearly labeled as an application-level encrypted wire inspector.
 * Provides real-time visibility into encrypted packet metadata, transmission directions,
 * and keyed HMAC-SHA256 tags without exposing decrypted plaintext, passwords, or master keys.
 * Hardened with EDT protection, event coalescing (max 200/tick), and HTML disablement.
 */
public final class PacketMonitorPanel extends JPanel implements ServerEventListener {

    private static final long serialVersionUID = 1L;

    public static final int MAX_DRAIN_PER_TICK = 200;
    public static final int MAX_ROWS = 500;

    private final DefaultTableModel tableModel;
    private final JTable packetTable;
    private final JLabel counterLabel = new JLabel("Total Inspected: 0 packets");
    private final JButton clearButton = new JButton("Clear Monitor");
    private final AtomicLong packetCount = new AtomicLong(0);
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss.SSS");

    private final transient Queue<Object[]> packetQueue = new ConcurrentLinkedQueue<>();
    private final javax.swing.Timer drainTimer;

    public PacketMonitorPanel() {
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Header Notice
        JPanel headerPanel = new JPanel(new BorderLayout(5, 5));
        JLabel noticeLabel = new JLabel("Encrypted Application-Packet Monitor (Zero Plaintext Leakage) - Wire Frame Inspector");
        UiSafe.disableHtml(noticeLabel);
        headerPanel.add(noticeLabel, BorderLayout.CENTER);
        add(headerPanel, BorderLayout.NORTH);

        // Center Table
        String[] columnNames = {
                "Timestamp", "Direction", "Packet Type", "Sender VIP", "Sender User",
                "Dept", "Payload (B)", "Keyed HMAC-SHA256", "Seq #"
        };

        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        packetTable = new JTable(tableModel);
        UiSafe.configureSafeTable(packetTable);
        packetTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        packetTable.setFont(new Font("Monospaced", Font.PLAIN, 11));
        packetTable.setRowHeight(22);

        // Custom renderer for Direction column (colored tags), wrapped for UI safety
        DefaultTableCellRenderer dirRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                           boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if ("INCOMING".equals(value)) {
                    c.setForeground(new Color(0, 120, 215));
                } else if ("OUTGOING".equals(value)) {
                    c.setForeground(new Color(0, 150, 50));
                } else {
                    c.setForeground(Color.BLACK);
                }
                return c;
            }
        };
        packetTable.getColumnModel().getColumn(1).setCellRenderer(UiSafe.wrap(dirRenderer));

        packetTable.getColumnModel().getColumn(0).setPreferredWidth(95);
        packetTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        packetTable.getColumnModel().getColumn(2).setPreferredWidth(140);
        packetTable.getColumnModel().getColumn(3).setPreferredWidth(85);
        packetTable.getColumnModel().getColumn(4).setPreferredWidth(100);
        packetTable.getColumnModel().getColumn(5).setPreferredWidth(80);
        packetTable.getColumnModel().getColumn(6).setPreferredWidth(75);
        packetTable.getColumnModel().getColumn(7).setPreferredWidth(160);
        packetTable.getColumnModel().getColumn(8).setPreferredWidth(55);

        add(new JScrollPane(packetTable), BorderLayout.CENTER);

        // Bottom Controls
        JPanel bottomBar = new JPanel(new BorderLayout());
        UiSafe.disableHtml(counterLabel);
        bottomBar.add(counterLabel, BorderLayout.WEST);

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        clearButton.addActionListener(e -> {
            tableModel.setRowCount(0);
            packetQueue.clear();
            packetCount.set(0);
            counterLabel.setText("Total Inspected: 0 packets");
        });
        btnPanel.add(clearButton);
        bottomBar.add(btnPanel, BorderLayout.EAST);

        add(bottomBar, BorderLayout.SOUTH);

        // EDT Coalescing Drain Timer (every 250ms)
        this.drainTimer = new javax.swing.Timer(250, e -> drainPacketQueue(MAX_DRAIN_PER_TICK));
        this.drainTimer.start();
    }

    public int drainPacketQueue(int maxDrain) {
        int drained = 0;
        while (drained < maxDrain && !packetQueue.isEmpty()) {
            Object[] row = packetQueue.poll();
            if (row != null) {
                tableModel.addRow(row);
                drained++;
            }
        }
        if (tableModel.getRowCount() > MAX_ROWS) {
            int excess = tableModel.getRowCount() - MAX_ROWS;
            for (int i = 0; i < excess; i++) {
                tableModel.removeRow(0);
            }
        }
        int lastRow = tableModel.getRowCount() - 1;
        if (lastRow >= 0 && !packetTable.isEditing()) {
            packetTable.scrollRectToVisible(packetTable.getCellRect(lastRow, 0, true));
        }
        return drained;
    }

    // Test seam
    public Queue<Object[]> getPacketQueue() {
        return packetQueue;
    }

    // Test seam
    public JTable getPacketTable() {
        return packetTable;
    }

    public void bindToServer(VpnGatewayServer server) {
        if (server != null) {
            server.addServerEventListener(this);
        }
    }

    public void unbindFromServer(VpnGatewayServer server) {
        if (server != null) {
            server.removeServerEventListener(this);
        }
    }

    @Override
    public void onPacketSniffed(VpnPacket packet, String direction) {
        if (packet == null) return;
        long count = packetCount.incrementAndGet();
        SwingUtilities.invokeLater(() -> counterLabel.setText("Total Inspected: " + count + " packets"));

        String timeStr = timeFormat.format(new Date(packet.getTimestamp()));
        String hmacSnippet = (packet.getPayloadHmacHex() != null && packet.getPayloadHmacHex().length() >= 16)
                ? packet.getPayloadHmacHex().substring(0, 16) + "..."
                : "-";
        int payloadLen = (packet.getEncryptedPayload() != null) ? packet.getEncryptedPayload().length : 0;
        long seq = packet.getSequenceNumber();
        String seqStr = (seq > 0) ? String.valueOf(seq) : "-";

        Object[] rowData = new Object[]{
                UiSafe.text(timeStr, 32),
                UiSafe.text(direction, 16),
                UiSafe.text(packet.getType() != null ? packet.getType().name() : "UNKNOWN", 32),
                UiSafe.text(packet.getSenderVirtualIp(), 20),
                UiSafe.text(packet.getSenderUsername(), 32),
                UiSafe.text(packet.getDepartment(), 32),
                payloadLen,
                UiSafe.text(hmacSnippet, 32),
                UiSafe.text(seqStr, 20)
        };
        packetQueue.offer(rowData);
    }

    @Override
    public void onServerLog(String message) {
    }

    @Override
    public void onSessionUpdated() {
    }

    @Override
    public void onChatBroadcast(String senderUser, String senderDept, String senderVip, String message) {
    }
}

