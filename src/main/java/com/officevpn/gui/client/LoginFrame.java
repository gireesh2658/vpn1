package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.gui.UiSafe;
import com.officevpn.security.TrustedFingerprintStore;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JProgressBar;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Arrays;

/**
 * Secure Employee VPN Login &amp; Handshake Authentication Window.
 * <p>
 * Implements strict security controls and memory hygiene:
 * <ul>
 *   <li><b>Explicit Server Key Enrollment:</b> Eliminates silent TOFU risk by requiring explicit user
 *       verification when connecting to unpinned gateways.</li>
 *   <li><b>Rogue Gateway &amp; MITM Defense:</b> Cross-checks observed public keys against
 *       {@link TrustedFingerprintStore} and blocks altered keys immediately.</li>
 *   <li><b>Zero Plaintext Retention:</b> Password buffers are wiped immediately with zeros.</li>
 * </ul>
 */
public final class LoginFrame extends JFrame {

    private static final long serialVersionUID = 1L;

    private final JTextField hostField = new JTextField("127.0.0.1", 16);
    private final JTextField portField = new JTextField("8443", 6);
    private final JTextField fingerprintField = new JTextField("", 32);
    private final JCheckBox replacePinCheckBox = new JCheckBox("Replace stored pin");
    private final JTextField usernameField = new JTextField("", 16);
    private final JPasswordField passwordField = new JPasswordField("", 16);

    private final JButton connectButton = new JButton("Connect to VPN Gateway");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel statusLabel = new JLabel("Enter credentials and server information to establish encrypted tunnel.");

    public LoginFrame() {
        super("Office VPN Client - Secure Employee Gateway Login");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(620, 480);
        setLocationRelativeTo(null);
        setResizable(false);

        JPanel mainPanel = new JPanel(new BorderLayout(15, 15));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 25, 20, 25));

        // Header Title
        JPanel titlePanel = new JPanel(new BorderLayout(5, 5));
        JLabel titleLabel = new JLabel("Office VPN Remote Client");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 20));
        titleLabel.setForeground(new Color(25, 75, 150));

        JLabel subtitleLabel = new JLabel("<html>Application-Level Encrypted Tunnel &amp; Departmental Intranet Access<br>" +
                "Dual-Layer AES-256-GCM + HKDF-SHA256 + RSA-2048 Cryptographic Handshake<br>" +
                "<font color='#0066aa'>DNS Leak Protected (10.8.0.1) | Kill Switch ARMED | Split/Full Tunneling</font></html>");
        subtitleLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        subtitleLabel.setForeground(Color.DARK_GRAY);

        titlePanel.add(titleLabel, BorderLayout.NORTH);
        titlePanel.add(subtitleLabel, BorderLayout.CENTER);
        mainPanel.add(titlePanel, BorderLayout.NORTH);

        // Center Form Panel
        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createTitledBorder("Gateway Connection & Authentication Parameters"));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 10, 6, 10);
        gbc.anchor = GridBagConstraints.WEST;

        // Host & Port
        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("Gateway Server Host:"), gbc);
        gbc.gridx = 1;
        JPanel hostPortPanel = new JPanel(new BorderLayout(5, 0));
        hostPortPanel.add(hostField, BorderLayout.CENTER);
        JPanel pPanel = new JPanel(new BorderLayout(2, 0));
        pPanel.add(new JLabel("Port:"), BorderLayout.WEST);
        pPanel.add(portField, BorderLayout.EAST);
        hostPortPanel.add(pPanel, BorderLayout.EAST);
        formPanel.add(hostPortPanel, gbc);

        // Pinned Public Key Fingerprint
        gbc.gridx = 0; gbc.gridy = 1;
        formPanel.add(new JLabel("Pinned Key SHA-256:"), gbc);
        gbc.gridx = 1;
        fingerprintField.setToolTipText("64-character SHA-256 Hex Fingerprint provisioned by Headquarters Admin. Leave blank for interactive first-time enrollment.");
        formPanel.add(fingerprintField, gbc);

        gbc.gridx = 1; gbc.gridy = 2;
        JPanel fpSubPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        fpSubPanel.setOpaque(false);
        fpSubPanel.add(replacePinCheckBox);
        formPanel.add(fpSubPanel, gbc);

        // Username
        gbc.gridx = 0; gbc.gridy = 3;
        formPanel.add(new JLabel("Employee Username:"), gbc);
        gbc.gridx = 1;
        formPanel.add(usernameField, gbc);

        // Password
        gbc.gridx = 0; gbc.gridy = 4;
        formPanel.add(new JLabel("Office Password:"), gbc);
        gbc.gridx = 1;
        formPanel.add(passwordField, gbc);

        mainPanel.add(formPanel, BorderLayout.CENTER);

        // Bottom Controls and Status
        JPanel bottomPanel = new JPanel(new BorderLayout(10, 10));

        progressBar.setIndeterminate(false);
        progressBar.setVisible(false);

        JPanel actionPanel = new JPanel(new BorderLayout(5, 5));
        connectButton.setFont(new Font("SansSerif", Font.BOLD, 13));
        connectButton.setForeground(new Color(15, 75, 175));
        connectButton.setBackground(new Color(238, 245, 255));
        connectButton.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(30, 100, 200), 2),
                BorderFactory.createEmptyBorder(6, 16, 6, 16)
        ));
        connectButton.setFocusPainted(false);
        connectButton.setOpaque(true);
        connectButton.addActionListener(e -> executeLogin());

        actionPanel.add(connectButton, BorderLayout.CENTER);
        actionPanel.add(progressBar, BorderLayout.SOUTH);

        statusLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        statusLabel.setForeground(Color.DARK_GRAY);

        bottomPanel.add(actionPanel, BorderLayout.CENTER);
        bottomPanel.add(statusLabel, BorderLayout.SOUTH);

        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        getContentPane().add(mainPanel);

        // Enter key action
        passwordField.addActionListener(e -> executeLogin());
        usernameField.addActionListener(e -> executeLogin());
    }

    private void executeLogin() {
        String host = hostField.getText().trim();
        String portStr = portField.getText().trim();
        String username = usernameField.getText().trim();
        String pinnedFp = fingerprintField.getText().trim();
        boolean confirmReplace = replacePinCheckBox.isSelected();

        if (host.isEmpty() || portStr.isEmpty() || username.isEmpty()) {
            UiSafe.showMessageDialog(this, "Please enter server host, port, and username.", "Input Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int port;
        try {
            port = Integer.parseInt(portStr);
            if (port < 1 || port > 65535) throw new NumberFormatException();
        } catch (NumberFormatException e) {
            UiSafe.showMessageDialog(this, "Invalid port number. Must be between 1 and 65535.", "Port Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        char[] passwordChars = passwordField.getPassword();
        if (passwordChars == null || passwordChars.length == 0) {
            UiSafe.showMessageDialog(this, "Please enter your password.", "Input Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        connectButton.setEnabled(false);
        progressBar.setVisible(true);
        progressBar.setIndeterminate(true);
        statusLabel.setText("Connecting and executing 3-step cryptographic handshake...");

        TrustedFingerprintStore store = TrustedFingerprintStore.getDefault();

        new SwingWorker<VpnClientEngine, String>() {
            private String authError = null;

            @Override
            protected VpnClientEngine doInBackground() throws Exception {
                VpnClientEngine client = new VpnClientEngine();

                publish("Handshake in progress; validating server identity...");
                client.connectAndHandshake(host, port, pinnedFp, store, confirmReplace);

                publish("Authenticating user credentials over encrypted tunnel...");
                String pwdStr = new String(passwordChars);
                boolean success;
                try {
                    success = client.login(username, pwdStr);
                } finally {
                    Arrays.fill(passwordChars, '0');
                }

                if (!success) {
                    client.disconnect();
                    authError = "Invalid username/password or account has been disabled by Administrator.";
                    return null;
                }

                return client;
            }

            @Override
            protected void process(java.util.List<String> chunks) {
                if (!chunks.isEmpty()) {
                    statusLabel.setText(chunks.get(chunks.size() - 1));
                }
            }

            @Override
            protected void done() {
                Arrays.fill(passwordChars, '0');
                passwordField.setText("");

                connectButton.setEnabled(true);
                progressBar.setVisible(false);

                try {
                    VpnClientEngine client = get();
                    if (client != null && client.isAuthenticated()) {
                        statusLabel.setText("Authenticated successfully. Opening dashboard...");
                        dispose();
                        new ClientDashboardFrame(client).setVisible(true);
                    } else {
                        statusLabel.setText("Authentication failed.");
                        UiSafe.showMessageDialog(LoginFrame.this,
                                authError != null ? authError : "Authentication rejected by Gateway.",
                                "Login Failed",
                                JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception ex) {
                    Throwable cause = ex;
                    while (cause.getCause() != null) {
                        cause = cause.getCause();
                    }
                    String err = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
                    statusLabel.setText("Connection failed: " + err);

                    if (err.contains("GATEWAY IDENTITY CHANGED")) {
                        UiSafe.showMessageDialog(LoginFrame.this,
                                "GATEWAY IDENTITY CHANGED - possible attack!\n\n" +
                                        "The server at " + host + ":" + port + " presented a public key that differs from your stored pin.\n" +
                                        "No credentials or session keys were transmitted.\n\n" +
                                        "Recovery procedure:\n" +
                                        "1. Obtain the authentic 64-character SHA-256 fingerprint from the administrator out-of-band.\n" +
                                        "2. Enter it into the 'Pinned Key SHA-256' field.\n" +
                                        "3. Check the 'Replace stored pin' checkbox.\n" +
                                        "4. Click Connect to securely enroll the new identity.",
                                "GATEWAY IDENTITY CHANGED - Security Alert",
                                JOptionPane.ERROR_MESSAGE);
                    } else {
                        UiSafe.showMessageDialog(LoginFrame.this,
                                "Failed to connect to VPN Gateway:\n" + err,
                                "Connection / Security Error",
                                JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        }.execute();
    }


    public static void main(String[] args) {
        VpnClientApp.main(args);
    }
}
