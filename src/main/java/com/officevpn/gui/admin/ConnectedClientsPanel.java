package com.officevpn.gui.admin;

import com.officevpn.gui.UiSafe;
import com.officevpn.model.UserAccount;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.server.ServerEventListener;
import com.officevpn.server.VirtualIpPool;
import com.officevpn.server.VpnGatewayServer;
import com.officevpn.server.VpnSession;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

/**
 * Active Connected Client Sessions Panel for the Headquarters Admin Dashboard.
 * <p>
 * Displays live employee tunnels leased in the 10.8.0.x intranet subnet.
 * Provides administrative session revocation and global system broadcast capabilities.
 */
public final class ConnectedClientsPanel extends JPanel implements ServerEventListener {

    private static final long serialVersionUID = 1L;

    private transient VpnGatewayServer server;
    private final DefaultTableModel tableModel;
    private final JTable clientTable;
    private final JButton revokeButton = new JButton("Revoke Selected Session");
    private final JButton broadcastButton = new JButton("Broadcast System Announcement");
    private final JButton refreshButton = new JButton("Refresh Tunnels");
    private final JLabel statusLabel = new JLabel("Active Tunnels: 0");

    private final SimpleDateFormat timeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public ConnectedClientsPanel() {
        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Center Table
        String[] columnNames = {
                "Username", "Department", "Role", "Virtual IP",
                "Remote Address", "Connected At", "Last Activity"
        };

        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        clientTable = new JTable(tableModel);
        clientTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        clientTable.setFont(new Font("SansSerif", Font.PLAIN, 12));
        clientTable.setRowHeight(24);
        com.officevpn.gui.UiSafe.configureSafeTable(clientTable);

        DefaultTableCellRenderer vipRenderer = new DefaultTableCellRenderer();
        clientTable.getColumnModel().getColumn(3).setCellRenderer(UiSafe.wrap(vipRenderer));

        add(new JScrollPane(clientTable), BorderLayout.CENTER);

        // Bottom Controls
        JPanel bottomPanel = new JPanel(new BorderLayout(10, 5));

        statusLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        bottomPanel.add(statusLabel, BorderLayout.WEST);

        JPanel buttonBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));

        revokeButton.setFont(new Font("SansSerif", Font.BOLD, 12));
        revokeButton.setForeground(new Color(180, 25, 25));
        revokeButton.setBackground(new Color(254, 240, 240));
        revokeButton.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 35, 35), 1),
                BorderFactory.createEmptyBorder(5, 12, 5, 12)
        ));
        revokeButton.setFocusPainted(false);
        revokeButton.addActionListener(e -> revokeSelectedSession());

        broadcastButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        broadcastButton.addActionListener(e -> sendSystemAnnouncement());

        refreshButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        refreshButton.addActionListener(e -> refreshSessions());

        buttonBar.add(broadcastButton);
        buttonBar.add(revokeButton);
        buttonBar.add(refreshButton);
        bottomPanel.add(buttonBar, BorderLayout.EAST);

        add(bottomPanel, BorderLayout.SOUTH);
    }


    public void bindToServer(VpnGatewayServer server) {
        this.server = server;
        if (server != null) {
            server.addServerEventListener(this);
            refreshSessions();
        }
    }

    public void unbindFromServer(VpnGatewayServer server) {
        if (server != null) {
            server.removeServerEventListener(this);
        }
        this.server = null;
    }

    public void refreshSessions() {
        if (server == null) {
            tableModel.setRowCount(0);
            statusLabel.setText("Server not running");
            return;
        }

        new SwingWorker<Map<String, VpnSession>, Void>() {
            @Override
            protected Map<String, VpnSession> doInBackground() {
                return server.getActiveSessions();
            }

            @Override
            protected void done() {
                try {
                    Map<String, VpnSession> sessions = get();
                    tableModel.setRowCount(0);

                    for (Map.Entry<String, VpnSession> entry : sessions.entrySet()) {
                        VpnSession s = entry.getValue();
                        UserAccount user = s.getAuthenticatedUser();
                        String dept = (user != null) ? user.department().name() : "-";
                        String role = (user != null) ? user.role().name() : "-";

                        tableModel.addRow(new Object[]{
                                entry.getKey(),
                                dept,
                                role,
                                s.getAssignedVirtualIp() != null ? s.getAssignedVirtualIp() : "-",
                                s.getClientSocketAddress(),
                                timeFormat.format(new Date(s.getConnectedAt())),
                                timeFormat.format(new Date(s.getLastActivityAt()))
                        });
                    }

                    statusLabel.setText("Active Tunnels: " + sessions.size() + " (" + VirtualIpPool.GATEWAY_SERVER_IP + " Gateway)");
                } catch (Exception ex) {
                    statusLabel.setText("Failed to query active sessions: " + ex.getMessage());
                }
            }
        }.execute();
    }

    private void revokeSelectedSession() {
        int selectedRow = clientTable.getSelectedRow();
        if (selectedRow < 0) {
            UiSafe.showMessageDialog(this, "Please select an active tunnel session to revoke.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String username = (String) tableModel.getValueAt(selectedRow, 0);
        String vip = (String) tableModel.getValueAt(selectedRow, 3);

        int confirm = UiSafe.showConfirmDialog(this,
                "Are you sure you want to forcefully revoke and terminate the VPN tunnel for user '" + username + "' (VIP: " + vip + ")?",
                "Confirm Session Revocation",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (confirm != JOptionPane.YES_OPTION) {
            return;
        }

        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() {
                return server.disconnectUser(username, "ADMIN");
            }

            @Override
            protected void done() {
                try {
                    boolean result = get();
                    if (result) {
                        UiSafe.showMessageDialog(ConnectedClientsPanel.this,
                                "Tunnel session for user '" + username + "' was successfully revoked.\nVirtual IP " + vip + " returned to pool.",
                                "Session Revoked",
                                JOptionPane.INFORMATION_MESSAGE);
                        refreshSessions();
                    } else {
                        UiSafe.showMessageDialog(ConnectedClientsPanel.this,
                                "User '" + username + "' is no longer connected.",
                                "Revocation Notice",
                                JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (Exception ex) {
                    UiSafe.showMessageDialog(ConnectedClientsPanel.this,
                            "Failed to revoke session: " + ex.getMessage(),
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void sendSystemAnnouncement() {
        if (server == null || !server.isRunning()) {
            UiSafe.showMessageDialog(this, "Gateway Server is not running.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String message = UiSafe.showInputDialog(this,
                "Enter system announcement message to broadcast to all connected employee tunnels:",
                "Broadcast System Message",
                JOptionPane.QUESTION_MESSAGE);

        if (message != null && !message.trim().isEmpty()) {
            server.broadcastSystemMessage(message.trim(), "ADMIN");
            UiSafe.showMessageDialog(this, "System announcement broadcast dispatched.", "Dispatched", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    @Override
    public void onSessionUpdated() {
        SwingUtilities.invokeLater(this::refreshSessions);
    }

    @Override
    public void onServerLog(String message) {
    }

    @Override
    public void onPacketSniffed(VpnPacket rawPacket, String direction) {
    }

    @Override
    public void onChatBroadcast(String senderUser, String senderDept, String senderVip, String message) {
    }
}

