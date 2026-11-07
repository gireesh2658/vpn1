package com.officevpn.gui.admin;

import com.officevpn.admin.AdminLoginPolicy;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.UserAccount;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.Arrays;
import java.util.Objects;

/**
 * Authentication modal dialog requiring valid Headquarters Administrator credentials
 * before granting access to the Admin Dashboard.
 */
public final class AdminLoginDialog extends JDialog {

    private static final long serialVersionUID = 1L;

    private static final int MAX_FAILED_ATTEMPTS = 5;

    private final transient DatabaseManager databaseManager;
    private final JTextField usernameField = new JTextField(20);
    private final JPasswordField passwordField = new JPasswordField(20);

    private int failedAttempts = 0;
    private transient UserAccount authenticatedUser = null;

    public AdminLoginDialog(JFrame parent, DatabaseManager databaseManager) {
        super(parent, "Headquarters Admin Authentication", true);
        this.databaseManager = Objects.requireNonNull(databaseManager, "DatabaseManager cannot be null");

        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        setResizable(false);

        JPanel content = new JPanel(new BorderLayout(12, 12));
        content.setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));

        // Header
        JPanel headerPanel = new JPanel(new BorderLayout(4, 4));
        JLabel titleLabel = new JLabel("Administrator Login");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        titleLabel.setForeground(new Color(25, 75, 150));

        JLabel infoLabel = new JLabel("<html>Central Gateway Dashboard access is restricted to authorized<br>" +
                "Headquarters Administrators. Enter your credentials to proceed.</html>");
        infoLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        infoLabel.setForeground(Color.DARK_GRAY);

        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(infoLabel, BorderLayout.CENTER);
        content.add(headerPanel, BorderLayout.NORTH);

        // Form
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1;
        formPanel.add(usernameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1;
        formPanel.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1;
        formPanel.add(passwordField, gbc);

        content.add(formPanel, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        JButton loginButton = new JButton("Authenticate");
        loginButton.setFont(new Font("SansSerif", Font.BOLD, 12));
        loginButton.addActionListener(e -> attemptLogin());
        getRootPane().setDefaultButton(loginButton);

        JButton cancelButton = new JButton("Cancel");
        cancelButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        cancelButton.addActionListener(e -> dispose());

        buttonPanel.add(cancelButton);
        buttonPanel.add(loginButton);
        content.add(buttonPanel, BorderLayout.SOUTH);

        getContentPane().add(content);
        pack();
        setLocationRelativeTo(parent);
    }

    private void attemptLogin() {
        String username = usernameField.getText().trim();
        char[] pw = passwordField.getPassword();

        try {
            UserAccount account = AdminLoginPolicy.authenticateAdmin(databaseManager, username, pw, "local");
            if (account != null) {
                this.authenticatedUser = account;
                dispose();
            } else {
                failedAttempts++;
                int remaining = MAX_FAILED_ATTEMPTS - failedAttempts;
                if (remaining <= 0) {
                    UiSafe.showMessageDialog(this,
                            "Maximum login attempts exceeded. Application terminating.",
                            "Access Denied",
                            JOptionPane.ERROR_MESSAGE);
                    dispose();
                    return;
                } else {
                    UiSafe.showMessageDialog(this,
                            "Authentication failed. " + remaining + " attempt(s) remaining.",
                            "Invalid Credentials",
                            JOptionPane.WARNING_MESSAGE);
                }
            }
        } finally {
            Arrays.fill(pw, '\0');
            passwordField.setText("");
        }
    }

    public UserAccount getAuthenticatedUser() {
        return authenticatedUser;
    }
}


