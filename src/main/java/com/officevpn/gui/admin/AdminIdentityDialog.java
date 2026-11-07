package com.officevpn.gui.admin;

import com.officevpn.gui.UiSafe;
import com.officevpn.security.ServerIdentity;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Modal dialog for obtaining the Server Identity keystore passphrase from the administrator.
 * Prompts twice on initial creation; prompts once when unlocking an existing keystore.
 */
public final class AdminIdentityDialog extends JDialog {
    private static final long serialVersionUID = 1L;

    private final JPasswordField passwordField = new JPasswordField(20);
    private final JPasswordField confirmPasswordField = new JPasswordField(20);
    private final boolean isCreation;
    private char[] resultingPassphrase = null;

    public AdminIdentityDialog(JFrame parent, Path identityFile) {
        super(parent, "Server Identity Keystore Passphrase", true);
        this.isCreation = !Files.exists(identityFile);

        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setResizable(false);
        setLayout(new BorderLayout(10, 10));

        JPanel headerPanel = new JPanel(new BorderLayout(5, 5));
        headerPanel.setBorder(BorderFactory.createEmptyBorder(12, 12, 0, 12));
        JLabel titleLabel = new JLabel(isCreation ? "Initialize Server Identity Keystore" : "Unlock Server Identity Keystore");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14f));
        JLabel descLabel = new JLabel(isCreation
                ? "Enter a strong passphrase (minimum 12 characters) to encrypt server_identity.key:"
                : "Enter passphrase to decrypt persistent server identity (" + identityFile.getFileName() + "):");
        UiSafe.disableHtml(titleLabel);
        UiSafe.disableHtml(descLabel);
        headerPanel.add(titleLabel, BorderLayout.NORTH);
        headerPanel.add(descLabel, BorderLayout.CENTER);
        add(headerPanel, BorderLayout.NORTH);

        JPanel formPanel = new JPanel(new GridBagLayout());
        formPanel.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0;
        formPanel.add(new JLabel("Passphrase:"), gbc);
        gbc.gridx = 1;
        formPanel.add(passwordField, gbc);

        if (isCreation) {
            gbc.gridx = 0; gbc.gridy = 1;
            formPanel.add(new JLabel("Confirm Passphrase:"), gbc);
            gbc.gridx = 1;
            formPanel.add(confirmPasswordField, gbc);
        }
        add(formPanel, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        JButton okButton = new JButton(isCreation ? "Create Identity" : "Unlock");
        JButton cancelButton = new JButton("Cancel");

        okButton.addActionListener(e -> onOk());
        cancelButton.addActionListener(e -> dispose());
        passwordField.addActionListener(e -> onOk());
        if (isCreation) {
            confirmPasswordField.addActionListener(e -> onOk());
        }

        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        add(buttonPanel, BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(parent);
    }

    private void onOk() {
        char[] pw = passwordField.getPassword();
        if (isCreation) {
            char[] confirm = confirmPasswordField.getPassword();
            if (pw.length < ServerIdentity.MIN_PASSPHRASE_LENGTH) {
                UiSafe.showMessageDialog(this,
                        "Passphrase must be at least " + ServerIdentity.MIN_PASSPHRASE_LENGTH + " characters.",
                        "Validation Error",
                        JOptionPane.ERROR_MESSAGE);
                Arrays.fill(pw, '\0');
                Arrays.fill(confirm, '\0');
                return;
            }
            if (!Arrays.equals(pw, confirm)) {
                UiSafe.showMessageDialog(this,
                        "Passphrases do not match.",
                        "Validation Error",
                        JOptionPane.ERROR_MESSAGE);
                Arrays.fill(pw, '\0');
                Arrays.fill(confirm, '\0');
                return;
            }
            Arrays.fill(confirm, '\0');
        } else {
            if (pw.length == 0) {
                UiSafe.showMessageDialog(this,
                        "Please enter the keystore passphrase.",
                        "Input Error",
                        JOptionPane.WARNING_MESSAGE);
                return;
            }
        }

        this.resultingPassphrase = pw;
        dispose();
    }

    public char[] getPassphrase() {
        return resultingPassphrase;
    }

    public static char[] prompt(JFrame parent, Path identityFile) {
        AdminIdentityDialog dialog = new AdminIdentityDialog(parent, identityFile);
        dialog.setVisible(true);
        return dialog.getPassphrase();
    }
}

