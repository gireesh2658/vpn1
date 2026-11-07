package com.officevpn.gui.admin;

import com.officevpn.admin.AdminBootstrap;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;

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
 * First-run bootstrap modal dialog for provisioning the initial Headquarters Administrator.
 */
public final class AdminBootstrapDialog extends JDialog {

    private static final long serialVersionUID = 1L;

    private final transient DatabaseManager databaseManager;
    private final JTextField usernameField = new JTextField("admin_hq", 20);
    private final JPasswordField passwordField = new JPasswordField(20);
    private final JPasswordField confirmPasswordField = new JPasswordField(20);

    private boolean bootstrapped = false;

    public AdminBootstrapDialog(JFrame parent, DatabaseManager databaseManager) {
        super(parent, "Initial System Bootstrap - Create Headquarters Administrator", true);
        this.databaseManager = Objects.requireNonNull(databaseManager, "DatabaseManager cannot be null");

        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        setResizable(false);

        JPanel content = new JPanel(new BorderLayout(12, 12));
        content.setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));

        // Header
        JPanel headerPanel = new JPanel(new BorderLayout(4, 4));
        JLabel titleLabel = new JLabel("First-Run Administrator Setup");
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 16));
        titleLabel.setForeground(new Color(25, 75, 150));

        JLabel infoLabel = new JLabel("<html>No active Headquarters Administrator exists. Configure the primary<br>" +
                "administrator account to initialize the VPN Gateway. Password must be 12-128 characters.</html>");
        infoLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        infoLabel.setForeground(Color.DARK_GRAY);

        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(infoLabel, BorderLayout.CENTER);
        content.add(headerPanel, BorderLayout.NORTH);

        // Form Fields
        JPanel formPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(6, 6, 6, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("Admin Username:"), gbc);
        gbc.gridx = 1;
        formPanel.add(usernameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1;
        formPanel.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1;
        formPanel.add(passwordField, gbc);

        gbc.gridx = 0; gbc.gridy = 2;
        formPanel.add(new JLabel("Confirm Password:"), gbc);
        gbc.gridx = 1;
        formPanel.add(confirmPasswordField, gbc);

        content.add(formPanel, BorderLayout.CENTER);

        // Buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        JButton createButton = new JButton("Create Administrator");
        createButton.setFont(new Font("SansSerif", Font.BOLD, 12));
        createButton.addActionListener(e -> attemptBootstrap());

        JButton cancelButton = new JButton("Exit");
        cancelButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        cancelButton.addActionListener(e -> dispose());

        buttonPanel.add(cancelButton);
        buttonPanel.add(createButton);
        content.add(buttonPanel, BorderLayout.SOUTH);

        getContentPane().add(content);
        pack();
        setLocationRelativeTo(parent);
    }

    private void attemptBootstrap() {
        String username = usernameField.getText().trim();
        char[] pw = passwordField.getPassword();
        char[] confirm = confirmPasswordField.getPassword();

        try {
            AdminBootstrap.createInitialAdmin(databaseManager, username, pw, confirm);
            this.bootstrapped = true;
            UiSafe.showMessageDialog(this,
                    "Headquarters Administrator '" + username + "' created successfully.",
                    "Bootstrap Complete",
                    JOptionPane.INFORMATION_MESSAGE);
            dispose();
        } catch (Exception ex) {
            UiSafe.showMessageDialog(this,
                    "Bootstrap failed: " + ex.getMessage(),
                    "Validation Error",
                    JOptionPane.ERROR_MESSAGE);
        } finally {
            Arrays.fill(pw, '\0');
            Arrays.fill(confirm, '\0');
            passwordField.setText("");
            confirmPasswordField.setText("");
        }
    }

    public boolean isBootstrapped() {
        return bootstrapped;
    }

}


