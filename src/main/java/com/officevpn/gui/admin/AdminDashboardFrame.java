package com.officevpn.gui.admin;

import com.officevpn.admin.AlertManager;
import com.officevpn.admin.ConfigManager;
import com.officevpn.admin.DeviceManager;
import com.officevpn.admin.MetricsCollector;
import com.officevpn.admin.ServerManager;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import com.officevpn.security.AuditKeyStore;
import com.officevpn.security.IdentityException;
import com.officevpn.security.ServerIdentity;
import com.officevpn.server.ServerEventListener;
import com.officevpn.server.VirtualIpPool;
import com.officevpn.server.VpnGatewayServer;
import com.officevpn.storage.VaultManager;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import java.nio.file.Path;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.List;

/**
 * Headquarters Central VPN Gateway Management &amp; Administration Dashboard.
 * <p>
 * Coordinates:
 * <ul>
 *   <li>Server lifecycle controls (Start/Stop listening socket on TCP port).</li>
 *   <li>Public Key Fingerprint extraction for out-of-band client provisioning.</li>
 *   <li>Active tunnel management, Virtual IP leases (10.8.0.x), and session revocation.</li>
 *   <li>User account governance and immutable security audit logs.</li>
 *   <li>Live encrypted application-packet monitoring and server diagnostic logs.</li>
 * </ul>
 */
public final class AdminDashboardFrame extends JFrame {

    private static final long serialVersionUID = 1L;

    private final transient DatabaseManager databaseManager;
    private final transient VaultManager vaultManager;
    private transient VpnGatewayServer gatewayServer;

    private final JTextField portField = new JTextField("8443", 5);
    private final JButton startButton = new JButton("Start Gateway Server");
    private final JButton stopButton = new JButton("Stop Gateway Server");
    private final JLabel serverStatusLabel = new JLabel("SERVER STOPPED");
    private final JLabel auditStatusLabel = new JLabel("Audit: Verifying...");
    private final JLabel identityModeLabel = new JLabel("Identity: [Server Not Started]");
    private final JLabel fingerprintLabel = new JLabel("Fingerprint: [Server Not Started]");
    private final JButton copyFpButton = new JButton("Copy Fingerprint");
    private final JLabel networkStatusLabel = new JLabel("Tunnel: SPLIT | Kill Switch: ARMED | DNS: 10.8.0.1 | Site-to-Site: 10.9.0.0/24 (ONLINE) | Transport: TCP 8443 (TLS/PFS)");

    private final ConnectedClientsPanel clientsPanel = new ConnectedClientsPanel();
    private final UserManagementPanel userPanel;
    private final AuditLogPanel auditPanel;
    private final ServerLogPanel logPanel = new ServerLogPanel();
    private final PacketMonitorPanel packetPanel = new PacketMonitorPanel();
    private final transient MetricsCollector metricsCollector;
    private final OverviewPanel overviewPanel;
    private final ConfigPanel configPanel;

    public AdminDashboardFrame() {
        this(new DatabaseManager(), "admin_hq");
    }

    public AdminDashboardFrame(DatabaseManager databaseManager, String actor) {
        super("Headquarters VPN Gateway Server - Central Admin Dashboard (" + actor + ")");

        this.databaseManager = java.util.Objects.requireNonNull(databaseManager, "DatabaseManager cannot be null");
        this.vaultManager = new VaultManager();

        this.userPanel = new UserManagementPanel(databaseManager, actor);
        this.auditPanel = new AuditLogPanel(databaseManager);

        this.metricsCollector = new MetricsCollector(databaseManager, null, gatewayServer);
        this.overviewPanel = new OverviewPanel(metricsCollector);
        AlertManager alertManager = new AlertManager(databaseManager);
        AlertsPanel alertsPanel = new AlertsPanel(alertManager);
        DeviceManager deviceManager = new DeviceManager(databaseManager);
        DevicesPanel devicesPanel = new DevicesPanel(deviceManager, databaseManager);
        ConfigManager configManager = new ConfigManager(databaseManager, alertManager);
        this.configPanel = new ConfigPanel(configManager, null, actor);

        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setSize(1050, 750);
        setLocationRelativeTo(null);

        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        // Top Server Control Panel
        JPanel controlPanel = createServerControlPanel();
        mainPanel.add(controlPanel, BorderLayout.NORTH);

        // Center Tabbed Pane
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.setFont(new Font("SansSerif", Font.PLAIN, 13));
        tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);

        tabbedPane.addTab("System Overview", overviewPanel);
        tabbedPane.addTab("Active Tunnels & Leases", clientsPanel);
        tabbedPane.addTab("User Accounts & RBAC", userPanel);
        tabbedPane.addTab("Hardware Devices & Trust", devicesPanel);
        tabbedPane.addTab("Security Alerts & Incidents", alertsPanel);
        tabbedPane.addTab("System Configuration", configPanel);
        tabbedPane.addTab("Security Audit Log", auditPanel);
        tabbedPane.addTab("Live Server Logs", logPanel);
        tabbedPane.addTab("Encrypted Packet Monitor", packetPanel);

        mainPanel.add(tabbedPane, BorderLayout.CENTER);

        getContentPane().add(mainPanel);

        this.userPanel.setSessionRevoker((username, reason, adminActor) -> {
            if (gatewayServer != null) {
                gatewayServer.disconnectUser(username, reason, adminActor);
            }
        });

        this.databaseManager.startBackgroundVerify().thenAccept(res -> {
            SwingUtilities.invokeLater(() -> {
                logPanel.onServerLog("[AUDIT STARTUP] Chain status: " + res.status() + " (" + res.rowsChecked() + " rows) - " + res.details());
                if (res.status() == com.officevpn.model.AuditVerifyResult.AuditStatus.OK) {
                    auditStatusLabel.setText("Audit: OK (" + res.rowsChecked() + " rows)");
                    auditStatusLabel.setForeground(new Color(0, 130, 0));
                } else if (res.status() == com.officevpn.model.AuditVerifyResult.AuditStatus.KEY_MISSING) {
                    auditStatusLabel.setText("Audit: UNVERIFIABLE (Key Missing)");
                    auditStatusLabel.setForeground(Color.RED);
                } else {
                    auditStatusLabel.setText("Audit: BROKEN (" + res.status() + ")");
                    auditStatusLabel.setForeground(Color.RED);
                }
            });
        });

        // Window Closing Listener
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                confirmAndShutdown();
            }
        });
    }

    private JPanel createServerControlPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 8));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Gateway Server Controls"),
                BorderFactory.createEmptyBorder(6, 10, 6, 10)
        ));
        panel.setBackground(new Color(245, 248, 252));

        // Left controls (Port, Start, Stop)
        JPanel leftControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        leftControls.setOpaque(false);

        leftControls.add(new JLabel("Listening Port:"));
        leftControls.add(portField);

        startButton.setBackground(new Color(235, 250, 238));
        startButton.setForeground(new Color(0, 115, 40));
        startButton.setFont(new Font("SansSerif", Font.BOLD, 12));
        startButton.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0, 140, 50), 2),
                BorderFactory.createEmptyBorder(5, 14, 5, 14)
        ));
        startButton.setFocusPainted(false);
        startButton.setOpaque(true);
        startButton.addActionListener(e -> startServer());
        leftControls.add(startButton);

        stopButton.setBackground(new Color(245, 245, 245));
        stopButton.setForeground(Color.GRAY);
        stopButton.setFont(new Font("SansSerif", Font.BOLD, 12));
        stopButton.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 200, 200), 2),
                BorderFactory.createEmptyBorder(5, 14, 5, 14)
        ));
        stopButton.setFocusPainted(false);
        stopButton.setOpaque(true);
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopServer());
        leftControls.add(stopButton);

        panel.add(leftControls, BorderLayout.WEST);

        // Right status and fingerprint
        JPanel rightStatus = new JPanel(new GridBagLayout());
        rightStatus.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(2, 6, 2, 6);

        gbc.gridx = 0; gbc.gridy = 0;
        serverStatusLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        serverStatusLabel.setForeground(Color.RED);
        rightStatus.add(serverStatusLabel, gbc);

        gbc.gridx = 0; gbc.gridy = 1;
        auditStatusLabel.setFont(new Font("SansSerif", Font.BOLD, 11));
        auditStatusLabel.setForeground(Color.DARK_GRAY);
        rightStatus.add(auditStatusLabel, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        identityModeLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        identityModeLabel.setForeground(Color.DARK_GRAY);
        UiSafe.disableHtml(identityModeLabel);
        rightStatus.add(identityModeLabel, gbc);

        gbc.gridx = 0; gbc.gridy = 3;
        JPanel fpPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        fpPanel.setOpaque(false);
        fingerprintLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
        fpPanel.add(fingerprintLabel);

        copyFpButton.setFont(new Font("SansSerif", Font.PLAIN, 11));
        copyFpButton.setEnabled(false);
        copyFpButton.addActionListener(e -> copyFingerprintToClipboard());
        fpPanel.add(copyFpButton);

        rightStatus.add(fpPanel, gbc);

        gbc.gridx = 0; gbc.gridy = 4;
        networkStatusLabel.setFont(new Font("SansSerif", Font.BOLD, 10));
        networkStatusLabel.setForeground(new Color(0, 100, 160));
        rightStatus.add(networkStatusLabel, gbc);

        panel.add(rightStatus, BorderLayout.EAST);
        return panel;
    }

    private void startServer() {
        int port;
        try {
            port = Integer.parseInt(portField.getText().trim());
            if (port < 1 || port > 65535) throw new NumberFormatException();
        } catch (NumberFormatException e) {
            UiSafe.showMessageDialog(this, "Please enter a valid port between 1 and 65535.", "Port Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        startButton.setEnabled(false);
        startButton.setForeground(Color.GRAY);
        startButton.setBackground(new Color(245, 245, 245));
        startButton.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 200, 200), 2),
                BorderFactory.createEmptyBorder(5, 14, 5, 14)
        ));
        portField.setEnabled(false);

        new SwingWorker<VpnGatewayServer, Void>() {
            @Override
            protected VpnGatewayServer doInBackground() throws Exception {
                Path dataDir = AuditKeyStore.resolveDefaultDataDir();
                Path identityFile = dataDir.resolve(ServerIdentity.IDENTITY_FILE_NAME);
                ServerIdentity identity;

                String envPass = System.getenv("OFFICEVPN_KEYSTORE_PASS");
                if (envPass == null) {
                    envPass = System.getProperty("officevpn.keystore.pass");
                }

                if (envPass != null && !envPass.isBlank()) {
                    identity = ServerIdentity.loadOrCreate(dataDir, envPass.toCharArray(), true);
                } else if (Boolean.getBoolean("officevpn.demo")) {
                    identity = ServerIdentity.createEphemeral();
                } else {
                    if (java.awt.GraphicsEnvironment.isHeadless()) {
                        throw new IdentityException("Headless server startup requires OFFICEVPN_KEYSTORE_PASS environment variable or -Dofficevpn.demo=true");
                    }
                    final char[][] passRef = new char[1][];
                    SwingUtilities.invokeAndWait(() -> {
                        passRef[0] = AdminIdentityDialog.prompt(AdminDashboardFrame.this, identityFile);
                    });
                    if (passRef[0] == null) {
                        throw new IdentityException("Server startup cancelled: Passphrase entry aborted.");
                    }
                    identity = ServerIdentity.loadOrCreate(dataDir, passRef[0], true);
                }

                VpnGatewayServer server = new VpnGatewayServer(databaseManager, vaultManager, identity);
                server.start(port);
                return server;
            }

            @Override
            protected void done() {
                try {
                    gatewayServer = get();
                    stopButton.setEnabled(true);
                    stopButton.setForeground(new Color(180, 25, 25));
                    stopButton.setBackground(new Color(254, 240, 240));
                    stopButton.setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createLineBorder(new Color(200, 35, 35), 2),
                            BorderFactory.createEmptyBorder(5, 14, 5, 14)
                    ));

                    startButton.setEnabled(false);
                    startButton.setForeground(Color.GRAY);
                    startButton.setBackground(new Color(245, 245, 245));
                    startButton.setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createLineBorder(new Color(200, 200, 200), 2),
                            BorderFactory.createEmptyBorder(5, 14, 5, 14)
                    ));

                    serverStatusLabel.setText("RUNNING on Port " + gatewayServer.getBoundPort() + " (Gateway IP: " + VirtualIpPool.GATEWAY_SERVER_IP + ")");
                    serverStatusLabel.setForeground(new Color(0, 140, 0));

                    ServerIdentity id = gatewayServer.getServerIdentity();
                    String modeText = id.isEphemeral() ? "EPHEMERAL" : "persistent: " + id.path().toAbsolutePath();
                    identityModeLabel.setText("Identity Mode: " + modeText);

                    String fp = gatewayServer.getServerPublicKeyFingerprintHex();
                    fingerprintLabel.setText("Fingerprint: " + fp.substring(0, 24) + "...");
                    fingerprintLabel.setToolTipText("Full SHA-256 Fingerprint: " + fp);
                    copyFpButton.setEnabled(true);

                    // Bind panels to live server events
                    clientsPanel.bindToServer(gatewayServer);
                    logPanel.bindToServer(gatewayServer);
                    packetPanel.bindToServer(gatewayServer);
                    metricsCollector.setGatewayServer(gatewayServer);
                    overviewPanel.refreshMetrics();
                    configPanel.bindServer(new ServerManager(gatewayServer));

                    // Add session listener to update audit tab
                    gatewayServer.addServerEventListener(new ServerEventListener() {
                        @Override
                        public void onServerLog(String message) {}
                        @Override
                        public void onPacketSniffed(com.officevpn.protocol.VpnPacket rawPacket, String direction) {}
                        @Override
                        public void onSessionUpdated() {
                            auditPanel.loadAuditLogs();
                        }
                        @Override
                        public void onChatBroadcast(String senderUser, String senderDept, String senderVip, String message) {}
                    });

                } catch (Exception ex) {
                    startButton.setEnabled(true);
                    startButton.setForeground(new Color(0, 115, 40));
                    startButton.setBackground(new Color(235, 250, 238));
                    startButton.setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createLineBorder(new Color(0, 140, 50), 2),
                            BorderFactory.createEmptyBorder(5, 14, 5, 14)
                    ));
                    stopButton.setEnabled(false);
                    stopButton.setForeground(Color.GRAY);
                    stopButton.setBackground(new Color(245, 245, 245));
                    stopButton.setBorder(BorderFactory.createCompoundBorder(
                            BorderFactory.createLineBorder(new Color(200, 200, 200), 2),
                            BorderFactory.createEmptyBorder(5, 14, 5, 14)
                    ));
                    portField.setEnabled(true);
                    UiSafe.showMessageDialog(AdminDashboardFrame.this,
                            "Failed to start Gateway Server on port " + port + ":\n" + ex.getMessage(),
                            "Server Bind Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void stopServer() {
        if (gatewayServer == null) return;

        stopButton.setEnabled(false);
        stopButton.setForeground(Color.GRAY);
        stopButton.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(180, 180, 180), 2),
                BorderFactory.createEmptyBorder(5, 14, 5, 14)
        ));

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() {
                clientsPanel.unbindFromServer(gatewayServer);
                logPanel.unbindFromServer(gatewayServer);
                packetPanel.unbindFromServer(gatewayServer);
                metricsCollector.setGatewayServer(null);
                overviewPanel.refreshMetrics();
                configPanel.bindServer(null);

                gatewayServer.stop();
                gatewayServer = null;
                return null;
            }

            @Override
            protected void done() {
                startButton.setEnabled(true);
                startButton.setForeground(new Color(0, 115, 40));
                startButton.setBackground(new Color(235, 250, 238));
                startButton.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(new Color(0, 140, 50), 2),
                        BorderFactory.createEmptyBorder(5, 14, 5, 14)
                ));
                stopButton.setEnabled(false);
                stopButton.setForeground(Color.GRAY);
                stopButton.setBackground(new Color(245, 245, 245));
                stopButton.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createLineBorder(new Color(200, 200, 200), 2),
                        BorderFactory.createEmptyBorder(5, 14, 5, 14)
                ));
                portField.setEnabled(true);
                copyFpButton.setEnabled(false);
                serverStatusLabel.setText("SERVER STOPPED");
                serverStatusLabel.setForeground(Color.RED);
                identityModeLabel.setText("Identity: [Server Stopped]");
                fingerprintLabel.setText("Fingerprint: [Server Stopped]");
                clientsPanel.refreshSessions();
                auditPanel.loadAuditLogs();
            }
        }.execute();
    }

    private void copyFingerprintToClipboard() {
        if (gatewayServer != null) {
            String fp = gatewayServer.getServerPublicKeyFingerprintHex();
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(fp), null);
            UiSafe.showMessageDialog(this,
                    "Headquarters Server Public Key SHA-256 Fingerprint copied to clipboard:\n\n" + fp +
                            "\n\nProvide this 64-character hex string to remote employees for out-of-band MITM key pinning.",
                    "Fingerprint Copied",
                    JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void confirmAndShutdown() {
        if (gatewayServer != null && gatewayServer.isRunning()) {
            int option = UiSafe.showConfirmDialog(this,
                    "The Headquarters VPN Gateway is currently running with active clients.\n" +
                            "Do you want to stop the server and terminate all tunnels?",
                    "Confirm Gateway Shutdown",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);

            if (option != JOptionPane.YES_OPTION) {
                return;
            }
            gatewayServer.stop();
        }

        databaseManager.close();
        dispose();
    }

    public void displayDemoCredentials(List<com.officevpn.admin.DemoSeeder.DemoAccount> accounts) {
        if (accounts == null || accounts.isEmpty()) {
            return;
        }
        logPanel.onServerLog("=== EPHEMERAL DEMO CREDENTIALS INITIALIZED ===");
        for (com.officevpn.admin.DemoSeeder.DemoAccount acc : accounts) {
            logPanel.onServerLog(String.format("Demo Account: %-15s | Password: %-18s | Dept: %-12s | Role: %s",
                    acc.username(), acc.password(), acc.department(), acc.role()));
        }
        logPanel.onServerLog("===============================================");
    }

    public static void main(String[] args) {
        AdminDashboardApp.main(args);
    }
}


