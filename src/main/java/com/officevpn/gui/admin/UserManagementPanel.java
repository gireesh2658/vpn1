package com.officevpn.gui.admin;

import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;
import com.officevpn.server.SessionRevoker;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
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
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * User Account &amp; RBAC Management Panel for the Headquarters Admin Dashboard.
 * <p>
 * <b>Security Invariant:</b> Displays user identities, departmental bindings, and active statuses.
 * NEVER renders password hashes, salts, or PBKDF2 derived keys.
 */
public final class UserManagementPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private transient DatabaseManager databaseManager;
    private final String actor;
    private transient SessionRevoker sessionRevoker;
    private final DefaultTableModel tableModel;
    private final JTable userTable;

    private final JButton createUserButton = new JButton("Create User");
    private final JButton resetPasswordButton = new JButton("Reset Password");
    private final JButton changeRoleButton = new JButton("Change Role");
    private final JButton changeDeptButton = new JButton("Change Department");
    private final JButton unrevokeButton = new JButton("Enable / Un-Revoke User");
    private final JButton disableUserButton = new JButton("Disable User");
    private final JButton clearLockoutsButton = new JButton("Clear Lockouts");
    private final JButton deleteUserButton = new JButton("Delete User");
    private final JButton offboardUserButton = new JButton("Offboard User");
    private final JButton refreshButton = new JButton("Refresh");

    private final JLabel totalLabel = new JLabel("Registered Accounts: 0");
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public UserManagementPanel(DatabaseManager databaseManager) {
        this(databaseManager, "SYSTEM", (u, r, a) -> {});
    }

    public UserManagementPanel(DatabaseManager databaseManager, String actor) {
        this(databaseManager, actor, (u, r, a) -> {});
    }

    public UserManagementPanel(DatabaseManager databaseManager, String actor, SessionRevoker sessionRevoker) {
        this.databaseManager = databaseManager;
        this.actor = (actor == null || actor.isBlank()) ? "SYSTEM" : actor.trim();
        this.sessionRevoker = (sessionRevoker != null) ? sessionRevoker : (u, r, a) -> {};

        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Center Table
        String[] columnNames = {
                "User ID", "Username", "Department", "Role", "Account Status", "Created Timestamp"
        };

        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        userTable = new JTable(tableModel);
        userTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        userTable.setFont(new Font("SansSerif", Font.PLAIN, 12));
        userTable.setRowHeight(24);

        // Custom status renderer (Green for ACTIVE, Red for DISABLED), wrapped for UI safety
        DefaultTableCellRenderer statusRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                           boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if ("ACTIVE".equals(value)) {
                    c.setForeground(new Color(0, 140, 0));
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else if ("DISABLED".equals(value)) {
                    c.setForeground(Color.RED);
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                }
                return c;
            }
        };
        com.officevpn.gui.UiSafe.configureSafeTable(userTable);
        userTable.getColumnModel().getColumn(4).setCellRenderer(com.officevpn.gui.UiSafe.wrap(statusRenderer));

        add(new JScrollPane(userTable), BorderLayout.CENTER);

        // Bottom Controls Deck
        JPanel bottomPanel = new JPanel(new BorderLayout(8, 8));
        bottomPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("User Governance & Access Controls"),
                BorderFactory.createEmptyBorder(6, 8, 8, 8)
        ));

        totalLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        bottomPanel.add(totalLabel, BorderLayout.NORTH);

        JPanel buttonDeck = new JPanel();
        buttonDeck.setLayout(new javax.swing.BoxLayout(buttonDeck, javax.swing.BoxLayout.Y_AXIS));

        // Deck Row 1: Account Maintenance
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        createUserButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        createUserButton.setForeground(new Color(15, 23, 42));
        createUserButton.setToolTipText("Provision a new employee user account with department and RBAC role");
        createUserButton.addActionListener(e -> showCreateUserDialog());

        resetPasswordButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        resetPasswordButton.setForeground(new Color(15, 23, 42));
        resetPasswordButton.setToolTipText("Reset password for selected user and invalidate active sessions");
        resetPasswordButton.addActionListener(e -> showResetPasswordDialog());

        changeRoleButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        changeRoleButton.setForeground(new Color(15, 23, 42));
        changeRoleButton.setToolTipText("Modify RBAC role (ADMIN, EMPLOYEE, AUDITOR)");
        changeRoleButton.addActionListener(e -> showChangeRoleDialog());

        changeDeptButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        changeDeptButton.setForeground(new Color(15, 23, 42));
        changeDeptButton.setToolTipText("Reassign department boundary (HEADQUARTERS, IT, HR, FINANCE)");
        changeDeptButton.addActionListener(e -> showChangeDepartmentDialog());

        refreshButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        refreshButton.setForeground(new Color(15, 23, 42));
        refreshButton.setToolTipText("Reload user accounts from database");
        refreshButton.addActionListener(e -> loadUsers());

        row1.add(createUserButton);
        row1.add(resetPasswordButton);
        row1.add(changeRoleButton);
        row1.add(changeDeptButton);
        row1.add(refreshButton);

        // Deck Row 2: Lifecycle & Security Access
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));

        unrevokeButton.setFont(new Font("SansSerif", Font.BOLD, 12));
        unrevokeButton.setForeground(new Color(0, 115, 40));
        unrevokeButton.setBackground(new Color(235, 250, 238));
        unrevokeButton.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0, 140, 50), 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));
        unrevokeButton.setFocusPainted(false);
        unrevokeButton.setToolTipText("Re-activate user, clear authentication lockouts, and re-authorize registered devices");
        unrevokeButton.addActionListener(e -> unrevokeSelectedUser());

        disableUserButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        disableUserButton.setForeground(new Color(160, 80, 0));
        disableUserButton.setToolTipText("Temporarily suspend user account without deleting records");
        disableUserButton.addActionListener(e -> disableSelectedUser());

        clearLockoutsButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        clearLockoutsButton.setForeground(new Color(15, 75, 160));
        clearLockoutsButton.setToolTipText("Clear failed authentication attempt lockout counter");
        clearLockoutsButton.addActionListener(e -> clearSelectedUserLockouts());

        offboardUserButton.setFont(new Font("SansSerif", Font.BOLD, 12));
        offboardUserButton.setForeground(new Color(180, 25, 25));
        offboardUserButton.setBackground(new Color(254, 240, 240));
        offboardUserButton.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 35, 35), 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));
        offboardUserButton.setFocusPainted(false);
        offboardUserButton.setToolTipText("Completely offboard employee: deactivate account, terminate sessions, revoke all devices");
        offboardUserButton.addActionListener(e -> offboardSelectedUser());

        deleteUserButton.setFont(new Font("SansSerif", Font.PLAIN, 12));
        deleteUserButton.setForeground(new Color(100, 20, 20));
        deleteUserButton.setToolTipText("Soft-delete user account from active registry");
        deleteUserButton.addActionListener(e -> deleteSelectedUser());

        row2.add(unrevokeButton);
        row2.add(disableUserButton);
        row2.add(clearLockoutsButton);
        row2.add(offboardUserButton);
        row2.add(deleteUserButton);

        buttonDeck.add(row1);
        buttonDeck.add(row2);
        bottomPanel.add(buttonDeck, BorderLayout.CENTER);

        add(bottomPanel, BorderLayout.SOUTH);

        loadUsers();
    }

    public void setDatabaseManager(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
        loadUsers();
    }

    public void setSessionRevoker(SessionRevoker sessionRevoker) {
        this.sessionRevoker = (sessionRevoker != null) ? sessionRevoker : (u, r, a) -> {};
    }

    public void loadUsers() {
        if (databaseManager == null) return;

        new SwingWorker<List<UserAccount>, Void>() {
            @Override
            protected List<UserAccount> doInBackground() {
                return databaseManager.listAllUsers();
            }

            @Override
            protected void done() {
                try {
                    List<UserAccount> users = get();
                    tableModel.setRowCount(0);
                    int activeCount = 0;
                    int disabledCount = 0;
                    for (UserAccount u : users) {
                        if (u.active()) activeCount++; else disabledCount++;
                        tableModel.addRow(new Object[]{
                                u.id(),
                                u.username(),
                                u.department().name(),
                                u.role().name(),
                                u.active() ? "ACTIVE" : "DISABLED",
                                timeFormat.format(new Date(u.createdAt()))
                        });
                    }
                    totalLabel.setText("Registered Accounts: " + users.size() + " (" + activeCount + " ACTIVE, " + disabledCount + " DISABLED)");
                } catch (Exception ex) {
                    totalLabel.setText("Error querying users: " + getRootCause(ex).getMessage());
                }
            }
        }.execute();
    }

    private String getSelectedUsername() {
        int row = userTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Please select an account row first.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return null;
        }
        return (String) tableModel.getValueAt(row, 1);
    }

    private void showCreateUserDialog() {
        JTextField usernameField = new JTextField(16);
        JPasswordField passwordField = new JPasswordField(16);
        JPasswordField confirmField = new JPasswordField(16);
        JComboBox<Department> deptCombo = new JComboBox<>(Department.values());
        JComboBox<Role> roleCombo = new JComboBox<>(Role.values());

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; panel.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1; panel.add(usernameField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; panel.add(new JLabel("Department:"), gbc);
        gbc.gridx = 1; panel.add(deptCombo, gbc);

        gbc.gridx = 0; gbc.gridy = 2; panel.add(new JLabel("Role:"), gbc);
        gbc.gridx = 1; panel.add(roleCombo, gbc);

        gbc.gridx = 0; gbc.gridy = 3; panel.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1; panel.add(passwordField, gbc);

        gbc.gridx = 0; gbc.gridy = 4; panel.add(new JLabel("Confirm Password:"), gbc);
        gbc.gridx = 1; panel.add(confirmField, gbc);

        int result = UiSafe.showConfirmDialog(this, panel, "Create New User Account", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) {
            return;
        }

        String username = usernameField.getText().trim();
        char[] pw = passwordField.getPassword();
        char[] confirm = confirmField.getPassword();
        Department dept = (Department) deptCombo.getSelectedItem();
        Role role = (Role) roleCombo.getSelectedItem();

        if (!Arrays.equals(pw, confirm)) {
            Arrays.fill(pw, '\0');
            Arrays.fill(confirm, '\0');
            UiSafe.showMessageDialog(this, "Passwords do not match.", "Validation Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        new SwingWorker<UserAccount, Void>() {
            @Override
            protected UserAccount doInBackground() {
                try {
                    return databaseManager.createUser(username, pw, dept, role, actor);
                } finally {
                    Arrays.fill(pw, '\0');
                    Arrays.fill(confirm, '\0');
                }
            }

            @Override
            protected void done() {
                try {
                    get();
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "User '" + username + "' created successfully.",
                            "User Created",
                            JOptionPane.INFORMATION_MESSAGE);
                    loadUsers();
                } catch (Exception ex) {
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "Failed to create user: " + getRootCause(ex).getMessage(),
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void showResetPasswordDialog() {
        String username = getSelectedUsername();
        if (username == null) return;

        JPasswordField passwordField = new JPasswordField(16);
        JPasswordField confirmField = new JPasswordField(16);

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridy = 0; panel.add(new JLabel("New Password:"), gbc);
        gbc.gridx = 1; panel.add(passwordField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; panel.add(new JLabel("Confirm New Password:"), gbc);
        gbc.gridx = 1; panel.add(confirmField, gbc);

        int result = UiSafe.showConfirmDialog(this, panel, "Reset Password for '" + username + "'", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;

        char[] pw = passwordField.getPassword();
        char[] confirm = confirmField.getPassword();

        if (!Arrays.equals(pw, confirm)) {
            Arrays.fill(pw, '\0');
            Arrays.fill(confirm, '\0');
            UiSafe.showMessageDialog(this, "Passwords do not match.", "Validation Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() {
                try {
                    return databaseManager.resetPassword(username, pw, actor);
                } finally {
                    Arrays.fill(pw, '\0');
                    Arrays.fill(confirm, '\0');
                }
            }

            @Override
            protected void done() {
                try {
                    boolean success = get();
                    if (success) {
                        sessionRevoker.revoke(username, "Password reset by admin", actor);
                        UiSafe.showMessageDialog(UserManagementPanel.this,
                                "Password for '" + username + "' reset successfully.",
                                "Password Reset",
                                JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        UiSafe.showMessageDialog(UserManagementPanel.this,
                                "Failed to reset password for '" + username + "'.",
                                "Reset Failed",
                                JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception ex) {
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "Failed to reset password: " + getRootCause(ex).getMessage(),
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void showChangeRoleDialog() {
        int row = userTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Please select an account row first.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String username = (String) tableModel.getValueAt(row, 1);
        Role currentRole = Role.valueOf((String) tableModel.getValueAt(row, 3));

        JComboBox<Role> roleCombo = new JComboBox<>(Role.values());
        roleCombo.setSelectedItem(currentRole);

        int result = UiSafe.showConfirmDialog(this, roleCombo, "Select New Role for '" + username + "'", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;

        Role newRole = (Role) roleCombo.getSelectedItem();
        if (newRole == currentRole) return;

        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() {
                return databaseManager.changeRole(username, newRole, actor);
            }

            @Override
            protected void done() {
                try {
                    get();
                    sessionRevoker.revoke(username, "Role changed to " + newRole + " by admin", actor);
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "Role for '" + username + "' updated to " + newRole + ".",
                            "Role Updated",
                            JOptionPane.INFORMATION_MESSAGE);
                    loadUsers();
                } catch (Exception ex) {
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "Role change denied: " + getRootCause(ex).getMessage(),
                            "Action Denied",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void showChangeDepartmentDialog() {
        int row = userTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Please select an account row first.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String username = (String) tableModel.getValueAt(row, 1);
        Department currentDept = Department.valueOf((String) tableModel.getValueAt(row, 2));

        JComboBox<Department> deptCombo = new JComboBox<>(Department.values());
        deptCombo.setSelectedItem(currentDept);

        int result = UiSafe.showConfirmDialog(this, deptCombo, "Select New Department for '" + username + "'", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (result != JOptionPane.OK_OPTION) return;

        Department newDept = (Department) deptCombo.getSelectedItem();
        if (newDept == currentDept) return;

        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() {
                return databaseManager.changeDepartment(username, newDept, actor);
            }

            @Override
            protected void done() {
                try {
                    get();
                    sessionRevoker.revoke(username, "Department changed to " + newDept + " by admin", actor);
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "Department for '" + username + "' updated to " + newDept + ".",
                            "Department Updated",
                            JOptionPane.INFORMATION_MESSAGE);
                    loadUsers();
                } catch (Exception ex) {
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "Department change denied: " + getRootCause(ex).getMessage(),
                            "Action Denied",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void unrevokeSelectedUser() {
        int row = userTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Please select an account row to un-revoke/re-activate.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String username = (String) tableModel.getValueAt(row, 1);
        String currentStatus = (String) tableModel.getValueAt(row, 4);

        String message = "DISABLED".equals(currentStatus)
                ? "Re-activate and Un-Revoke user account '" + username + "'?\n\n" +
                  "• Re-enables account login privileges (sets status to ACTIVE)\n" +
                  "• Clears authentication lockout counters\n" +
                  "• Re-authorizes registered hardware devices to connect\n\n" +
                  "Proceed with un-revocation?"
                : "User '" + username + "' is currently ACTIVE.\n\n" +
                  "Do you want to re-trust all hardware devices and clear lockouts for this user?";

        int confirm = UiSafe.showConfirmDialog(this, message, "Confirm Un-Revoke Account",
                JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() {
                databaseManager.setUserActiveStatus(username, true, actor);
                databaseManager.unlockAccount(username, actor);
                databaseManager.trustAllDevicesForUser(username);
                databaseManager.logAuditEvent("USER_UNREVOKED", username, "UNKNOWN",
                        "User account and devices un-revoked and re-activated by " + actor, actor, "local");
                return true;
            }

            @Override
            protected void done() {
                try {
                    get();
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "User '" + username + "' has been re-activated and un-revoked successfully.",
                            "Account Un-Revoked",
                            JOptionPane.INFORMATION_MESSAGE);
                    loadUsers();
                } catch (Exception ex) {
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "Failed to un-revoke user: " + getRootCause(ex).getMessage(),
                            "Action Denied",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void disableSelectedUser() {
        int row = userTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Please select an account row to disable.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String username = (String) tableModel.getValueAt(row, 1);
        String currentStatus = (String) tableModel.getValueAt(row, 4);
        if ("DISABLED".equals(currentStatus)) {
            UiSafe.showMessageDialog(this, "User '" + username + "' is already DISABLED.", "Already Disabled", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int confirm = UiSafe.showConfirmDialog(this,
                "Disable user account '" + username + "'?\nActive VPN tunnels for this user will be terminated.",
                "Confirm Disable Account",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) return;

        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() {
                databaseManager.setUserActiveStatus(username, false, actor);
                sessionRevoker.revoke(username, "Account disabled by admin", actor);
                databaseManager.logAuditEvent("USER_DISABLED", username, "UNKNOWN",
                        "User account disabled by " + actor, actor, "local");
                return true;
            }

            @Override
            protected void done() {
                try {
                    get();
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "User '" + username + "' status updated to DISABLED.",
                            "Status Updated",
                            JOptionPane.INFORMATION_MESSAGE);
                    loadUsers();
                } catch (Exception ex) {
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "Status change denied: " + getRootCause(ex).getMessage(),
                            "Action Denied",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void clearSelectedUserLockouts() {
        int row = userTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Please select an account row to clear lockouts.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String username = (String) tableModel.getValueAt(row, 1);
        int confirm = UiSafe.showConfirmDialog(
                this,
                "Clear all active authentication lockouts for user '" + username + "'?",
                "Confirm Clear Lockouts",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
        );
        if (confirm != JOptionPane.YES_OPTION) return;

        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() {
                return databaseManager.unlockAccount(username, actor);
            }

            @Override
            protected void done() {
                try {
                    boolean success = get();
                    if (success) {
                        UiSafe.showMessageDialog(UserManagementPanel.this,
                                "Lockouts cleared successfully for '" + username + "'.",
                                "Lockouts Cleared",
                                JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        UiSafe.showMessageDialog(UserManagementPanel.this,
                                "Failed to clear lockouts for '" + username + "'.",
                                "Action Failed",
                                JOptionPane.ERROR_MESSAGE);
                    }
                } catch (Exception ex) {
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "Error clearing lockouts: " + getRootCause(ex).getMessage(),
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void offboardSelectedUser() {
        int row = userTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Please select an account row to offboard.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String username = (String) tableModel.getValueAt(row, 1);

        int confirm = UiSafe.showConfirmDialog(this,
                "Are you sure you want to completely OFFBOARD user '" + username + "'?\n" +
                "This will deactivate the account, revoke all active VPN sessions, and revoke all trusted devices.",
                "Confirm User Offboarding",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (confirm != JOptionPane.YES_OPTION) return;

        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() {
                databaseManager.setUserActiveStatus(username, false, actor);
                databaseManager.revokeAllDevicesForUser(username);
                databaseManager.logAuditEvent("USER_OFFBOARDED", username, "UNKNOWN", "Offboarded by " + actor, actor, "local");
                return true;
            }

            @Override
            protected void done() {
                try {
                    get();
                    sessionRevoker.revoke(username, "Offboarded by admin", actor);
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "User '" + username + "' has been successfully offboarded. Sessions and devices revoked.",
                            "Offboarding Complete",
                            JOptionPane.INFORMATION_MESSAGE);
                    loadUsers();
                } catch (Exception ex) {
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "Offboarding error: " + getRootCause(ex).getMessage(),
                            "Action Failed",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void deleteSelectedUser() {
        int row = userTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Please select an account row to delete.", "Selection Required", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String username = (String) tableModel.getValueAt(row, 1);

        int confirm = UiSafe.showConfirmDialog(this,
                "Are you sure you want to delete / deactivate user '" + username + "'?",
                "Confirm User Deletion",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);

        if (confirm != JOptionPane.YES_OPTION) return;

        new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() {
                return databaseManager.deleteUser(username, actor);
            }

            @Override
            protected void done() {
                try {
                    get();
                    sessionRevoker.revoke(username, "Account deleted by admin", actor);
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "User '" + username + "' has been soft-deleted (deactivated).",
                            "User Deleted",
                            JOptionPane.INFORMATION_MESSAGE);
                    loadUsers();
                } catch (Exception ex) {
                    UiSafe.showMessageDialog(UserManagementPanel.this,
                            "Deletion denied: " + getRootCause(ex).getMessage(),
                            "Action Denied",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }


    private static Throwable getRootCause(Throwable throwable) {
        Throwable cause = throwable;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause;
    }
}

