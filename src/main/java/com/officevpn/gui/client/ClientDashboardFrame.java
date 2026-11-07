package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.gui.UiSafe;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * Main Employee Client Dashboard Frame.
 * <p>
 * Displayed only after successful cryptographic handshake and PBKDF2
 * authentication
 * confirmation from the Headquarters Gateway Server.
 */
public final class ClientDashboardFrame extends JFrame implements VpnClientEngine.ClientEventListener {

    private static final long serialVersionUID = 1L;

    private final transient VpnClientEngine clientEngine;
    private final JLabel headerStatusLabel = new JLabel();
    private final JButton disconnectButton = new JButton("Disconnect Tunnel");

    public ClientDashboardFrame(VpnClientEngine clientEngine) {
        super("Office VPN Client - Secure Employee Gateway [10.8.0.x Subnet]");
        this.clientEngine = clientEngine;
        this.clientEngine.addClientEventListener(this);

        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setSize(920, 680);
        setLocationRelativeTo(null);

        // Header Panel
        JPanel headerPanel = new JPanel(new BorderLayout(15, 5));
        headerPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY),
                BorderFactory.createEmptyBorder(12, 16, 12, 16)
        ));
        headerPanel.setBackground(new Color(245, 248, 252));

        JPanel userDetailsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 0));
        userDetailsPanel.setOpaque(false);

        JLabel logoLabel = new JLabel("OFFICE VPN");
        logoLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        logoLabel.setForeground(new Color(25, 75, 150));
        userDetailsPanel.add(logoLabel);

        updateHeaderStatus();
        headerStatusLabel.setFont(new Font("SansSerif", Font.PLAIN, 13));
        userDetailsPanel.add(headerStatusLabel);

        headerPanel.add(userDetailsPanel, BorderLayout.CENTER);

        disconnectButton.setFont(new Font("SansSerif", Font.BOLD, 12));
        disconnectButton.setForeground(new Color(180, 25, 25));
        disconnectButton.setBackground(new Color(254, 240, 240));
        disconnectButton.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 35, 35), 2),
                BorderFactory.createEmptyBorder(5, 14, 5, 14)
        ));
        disconnectButton.setFocusPainted(false);
        disconnectButton.setOpaque(true);
        disconnectButton.addActionListener(e -> confirmAndDisconnect());
        headerPanel.add(disconnectButton, BorderLayout.EAST);

        getContentPane().add(headerPanel, BorderLayout.NORTH);

        // Center: Tabbed Panes
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(new Font("SansSerif", Font.PLAIN, 13));

        FileVaultPanel fileVaultPanel = new FileVaultPanel(clientEngine);
        ChatPanel chatPanel = new ChatPanel(clientEngine);
        ConnectionStatusPanel statusPanel = new ConnectionStatusPanel(clientEngine);
        MyDevicesPanel devicesPanel = new MyDevicesPanel(clientEngine);

        tabbedPane.addTab("Department File Vault", fileVaultPanel);
        tabbedPane.addTab("Office Intranet Chat", chatPanel);
        tabbedPane.addTab("Tunnel Diagnostics & Wire Inspector", statusPanel);
        tabbedPane.addTab("My Registered Devices", devicesPanel);

        getContentPane().add(tabbedPane, BorderLayout.CENTER);

        // Window Close Listener
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                confirmAndDisconnect();
            }
        });
    }

    private void updateHeaderStatus() {
        if (clientEngine.isAuthenticated()) {
            headerStatusLabel.setText(String.format("User: %s  |  Dept: %s  |  VIP: %s  [CONNECTED]  |  DNS: 10.8.0.1 (Protected)  |  Mode: SPLIT  |  KillSwitch: ARMED",
                    clientEngine.getUsername(),
                    clientEngine.getDepartment(),
                    clientEngine.getAssignedVirtualIp()));
        } else {
            headerStatusLabel.setText("Status: NOT AUTHENTICATED");
        }
    }

    @Override
    public void onChatMessage(String senderUser, String senderDept, String senderVip, String message) {
    }

    @Override
    public void onPacketSniffed(com.officevpn.protocol.VpnPacket packet, String direction) {
    }

    @Override
    public void onConnectionStateChanged(String state) {
        SwingUtilities.invokeLater(() -> {
            if (clientEngine.isConnected() && clientEngine.isAuthenticated()) {
                updateHeaderStatus();
            } else {
                headerStatusLabel.setText(String.format("User: %s  |  Dept: %s  |  [DISCONNECTED: %s]",
                        clientEngine.getUsername() != null ? clientEngine.getUsername() : "-",
                        clientEngine.getDepartment() != null ? clientEngine.getDepartment() : "-",
                        state));
                headerStatusLabel.setForeground(Color.RED);
                disconnectButton.setText("Back to Login");
                disconnectButton.setForeground(new Color(15, 23, 42));
                disconnectButton.setBackground(new Color(245, 245, 245));
                disconnectButton.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(new Color(100, 116, 139), 2),
                        BorderFactory.createEmptyBorder(5, 14, 5, 14)
                ));
                disconnectButton.setEnabled(true);
            }
        });
    }

    private void confirmAndDisconnect() {
        if (!clientEngine.isConnected()) {
            clientEngine.removeClientEventListener(this);
            dispose();
            new LoginFrame().setVisible(true);
            return;
        }

        int choice = UiSafe.showConfirmDialog(this,
                "Are you sure you want to terminate this encrypted VPN tunnel session?",
                "Confirm Disconnect",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);

        if (choice == JOptionPane.YES_OPTION) {
            disconnectButton.setEnabled(false);
            clientEngine.removeClientEventListener(this);
            new Thread(() -> {
                clientEngine.disconnect();
                SwingUtilities.invokeLater(() -> {
                    dispose();
                    new LoginFrame().setVisible(true);
                });
            }, "vpn-client-disconnect-worker").start();
        }
    }

    public static void main(String[] args) {
        VpnClientApp.main(args);
    }
}

