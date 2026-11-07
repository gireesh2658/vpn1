package com.officevpn.gui.admin;

import com.officevpn.admin.DeviceManager;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Headquarters Admin Dashboard Device Hardware Registry &amp; Trust Management Panel.
 * <p>
 * Enforces Zero-Trust hardware policing: displays genuine client hardware fingerprints,
 * authentic operating systems, and allows one-click un-revocation / approval or revocation.
 */
public final class DevicesPanel extends JPanel {

    private static final long serialVersionUID = 1L;
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault());

    private final transient DeviceManager deviceManager;
    private final transient DatabaseManager databaseManager;
    private final JTextField userFilterField = new JTextField(16);
    private final JLabel statusLabel = new JLabel("Showing all registered devices");
    private final DefaultTableModel tableModel;
    private final JTable deviceTable;

    public DevicesPanel(DeviceManager deviceManager, DatabaseManager databaseManager) {
        super(new BorderLayout(8, 8));
        this.deviceManager = deviceManager;
        this.databaseManager = databaseManager;
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Two-row structured top toolbar deck
        JPanel topDeck = new JPanel(new GridLayout(2, 1, 4, 6));
        topDeck.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Hardware Device Trust Governance"),
                BorderFactory.createEmptyBorder(4, 6, 6, 6)
        ));

        // Row 1: Search & Filter Controls
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        JLabel filterLabel = new JLabel("Filter by Username:");
        filterLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        filterRow.add(filterLabel);
        filterRow.add(userFilterField);

        JButton searchBtn = new JButton("Search User Devices");
        searchBtn.setFont(new Font("SansSerif", Font.PLAIN, 12));
        searchBtn.addActionListener(e -> loadDevices(userFilterField.getText().trim()));
        filterRow.add(searchBtn);

        JButton showAllBtn = new JButton("Show All Devices");
        showAllBtn.setFont(new Font("SansSerif", Font.PLAIN, 12));
        showAllBtn.addActionListener(e -> {
            userFilterField.setText("");
            loadDevices("");
        });
        filterRow.add(showAllBtn);
        topDeck.add(filterRow);

        // Row 2: Trust & Revocation Actions
        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));

        JButton unrevokeBtn = new JButton("Un-Revoke / Approve Device");
        unrevokeBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        unrevokeBtn.setBackground(new Color(235, 250, 238));
        unrevokeBtn.setForeground(new Color(0, 115, 40));
        unrevokeBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0, 140, 50), 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));
        unrevokeBtn.setFocusPainted(false);
        unrevokeBtn.addActionListener(e -> confirmAndUnrevokeDevice());
        actionRow.add(unrevokeBtn);

        JButton revokeBtn = new JButton("Revoke Device");
        revokeBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        revokeBtn.setBackground(new Color(254, 240, 240));
        revokeBtn.setForeground(new Color(180, 25, 25));
        revokeBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 35, 35), 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));
        revokeBtn.setFocusPainted(false);
        revokeBtn.addActionListener(e -> confirmAndRevokeDevice());
        actionRow.add(revokeBtn);

        JButton revokeAllBtn = new JButton("Revoke All Devices for User");
        revokeAllBtn.setFont(new Font("SansSerif", Font.PLAIN, 12));
        revokeAllBtn.setForeground(new Color(180, 25, 25));
        revokeAllBtn.addActionListener(e -> confirmAndRevokeAll());
        actionRow.add(revokeAllBtn);

        JButton deleteBtn = new JButton("Delete Device Record");
        deleteBtn.setFont(new Font("SansSerif", Font.PLAIN, 12));
        deleteBtn.setForeground(new Color(100, 20, 20));
        deleteBtn.addActionListener(e -> confirmAndDeleteDevice());
        actionRow.add(deleteBtn);

        JButton preauthBtn = new JButton("+ Pre-Authorize Device");
        preauthBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        preauthBtn.setForeground(new Color(15, 75, 160));
        preauthBtn.setBackground(new Color(238, 245, 255));
        preauthBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(30, 100, 200), 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));
        preauthBtn.setFocusPainted(false);
        preauthBtn.setToolTipText("Pre-authorize and enroll a hardware device in advance for any user account");
        preauthBtn.addActionListener(e -> showPreauthorizeDialog());
        actionRow.add(preauthBtn);

        topDeck.add(actionRow);
        add(topDeck, BorderLayout.NORTH);

        // Center Table
        String[] columns = {"ID", "Username", "Device Fingerprint", "Device Name", "First Seen", "Last Seen", "Status"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        deviceTable = new JTable(tableModel);
        deviceTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        deviceTable.setRowHeight(24);
        deviceTable.setFont(new Font("SansSerif", Font.PLAIN, 12));
        UiSafe.configureSafeTable(deviceTable);

        // Status column renderer: bold green for TRUSTED, bold red for REVOKED
        DefaultTableCellRenderer statusRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                           boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if ("TRUSTED".equals(value)) {
                    c.setForeground(new Color(0, 140, 0));
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else if ("REVOKED".equals(value)) {
                    c.setForeground(Color.RED);
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                }
                return c;
            }
        };
        deviceTable.getColumnModel().getColumn(6).setCellRenderer(UiSafe.wrap(statusRenderer));

        add(new JScrollPane(deviceTable), BorderLayout.CENTER);

        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        statusLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        bottomPanel.add(statusLabel);
        add(bottomPanel, BorderLayout.SOUTH);

        loadDevices("");
    }

    public void loadDevices(String usernameFilter) {
        SwingWorker<List<DatabaseManager.UserDeviceRecord>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<DatabaseManager.UserDeviceRecord> doInBackground() {
                if (usernameFilter != null && !usernameFilter.isBlank()) {
                    return databaseManager.listDevicesForUser(usernameFilter.trim());
                }
                return databaseManager.listAllDevices();
            }

            @Override
            protected void done() {
                try {
                    List<DatabaseManager.UserDeviceRecord> records = get();
                    tableModel.setRowCount(0);
                    for (DatabaseManager.UserDeviceRecord r : records) {
                        tableModel.addRow(new Object[]{
                                r.id(),
                                r.username(),
                                r.deviceFingerprint(),
                                r.deviceName(),
                                TIME_FORMAT.format(Instant.ofEpochMilli(r.firstSeenAt())),
                                TIME_FORMAT.format(Instant.ofEpochMilli(r.lastSeenAt())),
                                r.isTrusted() ? "TRUSTED" : "REVOKED"
                        });
                    }
                    if (records.isEmpty()) {
                        if (usernameFilter != null && !usernameFilter.isBlank()) {
                            statusLabel.setText("No hardware devices registered yet for '" + usernameFilter.trim() + "'. (Auto-enrolls on client login, or click '+ Pre-Authorize Device').");
                            statusLabel.setForeground(new Color(180, 80, 0));
                        } else {
                            statusLabel.setText("No registered hardware devices in the system.");
                            statusLabel.setForeground(Color.DARK_GRAY);
                        }
                    } else {
                        statusLabel.setText("Registered Hardware Devices: " + records.size() +
                                ((usernameFilter != null && !usernameFilter.isBlank()) ? " for '" + usernameFilter.trim() + "'" : " (All Users)"));
                        statusLabel.setForeground(new Color(0, 115, 40));
                    }
                } catch (Exception ignored) {}
            }
        };
        worker.execute();
    }

    private void confirmAndRevokeDevice() {
        int row = deviceTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Select a device to revoke.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String username = String.valueOf(tableModel.getValueAt(row, 1));
        String fp = String.valueOf(tableModel.getValueAt(row, 2));

        int confirm = UiSafe.showConfirmDialog(this,
                "Revoke trust for hardware device?\n\nFingerprint: " + fp + "\nUser: " + username +
                "\n\nThis will prevent this physical device from connecting to the VPN gateway.",
                "Confirm Device Revocation", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            deviceManager.revokeDevice(username, fp);
            loadDevices(userFilterField.getText().trim());
            UiSafe.showMessageDialog(this, "Device '" + fp + "' for user '" + username + "' is now REVOKED.",
                    "Device Revoked", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void confirmAndUnrevokeDevice() {
        int row = deviceTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Select a device row to un-revoke and approve.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String username = String.valueOf(tableModel.getValueAt(row, 1));
        String fp = String.valueOf(tableModel.getValueAt(row, 2));
        String devName = String.valueOf(tableModel.getValueAt(row, 3));

        int confirm = UiSafe.showConfirmDialog(this,
                "Un-Revoke and approve hardware device?\n\n" +
                "Username: " + username + "\n" +
                "Device Name: " + devName + "\n" +
                "Fingerprint: " + fp + "\n\n" +
                "Allow this hardware device to connect to the VPN gateway?",
                "Confirm Device Approval", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            deviceManager.trustDevice(username, fp);
            loadDevices(userFilterField.getText().trim());
            UiSafe.showMessageDialog(this,
                    "Device '" + fp + "' for user '" + username + "' is now APPROVED and TRUSTED.",
                    "Device Approved", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void confirmAndRevokeAll() {
        String username = userFilterField.getText().trim();
        int row = deviceTable.getSelectedRow();
        if (username.isBlank() && row >= 0) {
            username = String.valueOf(tableModel.getValueAt(row, 1));
        }

        if (username.isBlank()) {
            UiSafe.showMessageDialog(this, "Please enter or select a username to revoke all devices.", "Missing Username", JOptionPane.WARNING_MESSAGE);
            return;
        }

        int confirm = UiSafe.showConfirmDialog(this,
                "Are you sure you want to revoke ALL trusted devices for user '" + username + "'?",
                "Confirm Bulk Device Revocation", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            int revoked = deviceManager.revokeAllDevices(username);
            UiSafe.showMessageDialog(this, "Revoked " + revoked + " devices for user " + username, "Devices Revoked", JOptionPane.INFORMATION_MESSAGE);
            loadDevices(username);
        }
    }

    private void confirmAndDeleteDevice() {
        int row = deviceTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Select a device record to delete.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String username = String.valueOf(tableModel.getValueAt(row, 1));
        String fp = String.valueOf(tableModel.getValueAt(row, 2));

        String prompt = "Delete hardware device record?\n\nUser: " + username + "\nFingerprint: " + fp
                + "\n\nNote: If this device reconnects, it will be registered afresh.";
        int confirm = UiSafe.showConfirmDialog(this, prompt, "Confirm Delete Device",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            deviceManager.deleteDevice(username, fp);
            loadDevices(userFilterField.getText().trim());
            UiSafe.showMessageDialog(this, "Device record deleted.", "Deleted", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    public void showPreauthorizeDialog() {
        String defaultUser = userFilterField.getText().trim();
        int row = deviceTable.getSelectedRow();
        if (defaultUser.isBlank() && row >= 0) {
            defaultUser = String.valueOf(tableModel.getValueAt(row, 1));
        }

        JTextField userField = new JTextField(defaultUser, 18);
        JTextField fpField = new JTextField(com.officevpn.util.HardwareUtil.getAuthenticHardwareFingerprint(), 22);
        JTextField nameField = new JTextField(com.officevpn.util.HardwareUtil.getAuthenticDeviceName(), 22);

        JPanel panel = new JPanel(new java.awt.GridBagLayout());
        java.awt.GridBagConstraints gbc = new java.awt.GridBagConstraints();
        gbc.insets = new java.awt.Insets(4, 4, 4, 4);
        gbc.fill = java.awt.GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; panel.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1; panel.add(userField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; panel.add(new JLabel("Hardware Fingerprint:"), gbc);
        gbc.gridx = 1; panel.add(fpField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; panel.add(new JLabel("Device Name / OS:"), gbc);
        gbc.gridx = 1; panel.add(nameField, gbc);

        int result = UiSafe.showConfirmDialog(this, panel, "Pre-Authorize Employee Hardware Device",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) {
            return;
        }

        String targetUser = userField.getText().trim();
        String targetFp = fpField.getText().trim();
        String targetName = nameField.getText().trim();

        if (targetUser.isBlank() || targetFp.isBlank()) {
            UiSafe.showMessageDialog(this, "Username and Device Fingerprint are required.", "Validation Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        boolean ok = deviceManager.registerAndTrustDevice(targetUser, targetFp, targetName);
        if (ok) {
            userFilterField.setText(targetUser);
            loadDevices(targetUser);
            UiSafe.showMessageDialog(this,
                    "Hardware device successfully pre-authorized and enrolled for '" + targetUser + "'!\n\n" +
                    "Fingerprint: " + targetFp + "\nDevice: " + targetName + "\nStatus: TRUSTED",
                    "Device Enrolled", JOptionPane.INFORMATION_MESSAGE);
        } else {
            UiSafe.showMessageDialog(this, "Failed to enroll device. Check if user exists.", "Enrollment Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
