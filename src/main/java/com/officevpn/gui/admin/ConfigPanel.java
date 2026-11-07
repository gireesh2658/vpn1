package com.officevpn.gui.admin;

import com.officevpn.admin.ConfigManager;
import com.officevpn.admin.ServerManager;
import com.officevpn.gui.UiSafe;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.Map;

/**
 * Headquarters Admin Dashboard System Configuration &amp; Server Control Panel.
 */
public final class ConfigPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final transient ConfigManager configManager;
    private transient ServerManager serverManager;
    private final String adminUsername;

    private final JLabel serverStatusLabel = new JLabel("Status: -");
    private final JButton startBtn = new JButton("Start Server");
    private final JButton stopBtn = new JButton("Stop Server");
    private final JButton restartBtn = new JButton("Restart Server");

    private final DefaultTableModel tableModel;
    private final JTable configTable;

    public ConfigPanel(ConfigManager configManager, ServerManager serverManager, String adminUsername) {
        super(new BorderLayout(10, 10));
        this.configManager = configManager;
        this.serverManager = serverManager;
        this.adminUsername = adminUsername != null ? adminUsername : "admin_hq";
        setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // North: Server Control Card
        JPanel serverCard = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 8));
        serverCard.setBorder(BorderFactory.createTitledBorder("Gateway Server Controls"));
        serverStatusLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        serverCard.add(serverStatusLabel);

        startBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        startBtn.setForeground(new Color(0, 115, 40));
        startBtn.setBackground(new Color(235, 250, 238));
        startBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0, 140, 50), 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));
        startBtn.addActionListener(e -> startServer());

        stopBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        stopBtn.setForeground(new Color(180, 25, 25));
        stopBtn.setBackground(new Color(254, 240, 240));
        stopBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(200, 35, 35), 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));
        stopBtn.addActionListener(e -> stopServer());

        restartBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        restartBtn.setForeground(new Color(15, 75, 160));
        restartBtn.setBackground(new Color(238, 245, 255));
        restartBtn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(30, 100, 200), 1),
                BorderFactory.createEmptyBorder(4, 10, 4, 10)
        ));
        restartBtn.addActionListener(e -> restartServer());

        serverCard.add(startBtn);
        serverCard.add(stopBtn);
        serverCard.add(restartBtn);
        add(serverCard, BorderLayout.NORTH);

        // Center: Config Table
        String[] columns = {"Configuration Key", "Runtime Value"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        configTable = new JTable(tableModel);
        configTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        configTable.setRowHeight(24);
        add(new JScrollPane(configTable), BorderLayout.CENTER);

        // South: Config Actions
        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 6));
        JButton editBtn = new JButton("Edit Selected Parameter");
        editBtn.addActionListener(e -> editSelectedConfig());
        southPanel.add(editBtn);

        JButton resetBtn = new JButton("Reset to Defaults");
        resetBtn.addActionListener(e -> resetDefaults());
        southPanel.add(resetBtn);

        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> refreshData());
        southPanel.add(refreshBtn);

        add(southPanel, BorderLayout.SOUTH);

        refreshData();
    }

    public void bindServer(ServerManager serverManager) {
        this.serverManager = serverManager;
        refreshData();
    }

    public void refreshData() {
        if (serverManager != null) {
            String status = serverManager.getServerStatus();
            int port = serverManager.getBoundPort();
            serverStatusLabel.setText(String.format("Gateway Status: %s (Port: %d, VIP: %s)",
                    status, port > 0 ? port : 8443, serverManager.getGatewayIp()));
            serverStatusLabel.setForeground("RUNNING".equals(status) ? new Color(0, 140, 0) : Color.RED);
            startBtn.setEnabled(!"RUNNING".equals(status));
            stopBtn.setEnabled("RUNNING".equals(status));
            restartBtn.setEnabled("RUNNING".equals(status));
        } else {
            serverStatusLabel.setText("Gateway Status: STOPPED (Port: 8443, VIP: 10.8.0.1)");
            serverStatusLabel.setForeground(Color.RED);
            startBtn.setEnabled(true);
            stopBtn.setEnabled(false);
            restartBtn.setEnabled(false);
        }

        if (configManager != null) {
            Map<String, String> configs = configManager.getAllConfigs();
            tableModel.setRowCount(0);
            for (Map.Entry<String, String> e : configs.entrySet()) {
                tableModel.addRow(new Object[]{e.getKey(), e.getValue()});
            }
        }
    }

    private void editSelectedConfig() {
        int row = configTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Please select a configuration parameter row to edit.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String key = String.valueOf(tableModel.getValueAt(row, 0));

        String input = UiSafe.showInputDialog(this, "Enter new value for '" + key + "':", "Edit Configuration: " + key, JOptionPane.PLAIN_MESSAGE);
        if (input != null && !input.trim().isEmpty()) {
            try {
                configManager.setConfig(adminUsername, key, input.trim());
                UiSafe.showMessageDialog(this, "Updated '" + key + "' successfully.", "Configuration Updated", JOptionPane.INFORMATION_MESSAGE);
                refreshData();
            } catch (Exception ex) {
                UiSafe.showMessageDialog(this, "Validation Error: " + ex.getMessage(), "Invalid Configuration", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void resetDefaults() {
        int confirm = UiSafe.showConfirmDialog(this,
                "Reset all configuration parameters to standard production defaults?",
                "Confirm Reset", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (confirm == JOptionPane.YES_OPTION) {
            configManager.resetToDefaults(adminUsername);
            UiSafe.showMessageDialog(this, "Configurations reset to production defaults.", "Reset Complete", JOptionPane.INFORMATION_MESSAGE);
            refreshData();
        }
    }

    private void startServer() {
        if (serverManager == null) return;
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() throws Exception {
                serverManager.startServer(8443);
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    refreshData();
                } catch (Exception e) {
                    UiSafe.showMessageDialog(ConfigPanel.this, "Failed to start server: " + e.getMessage(), "Server Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }

    private void stopServer() {
        if (serverManager == null) return;
        serverManager.stopServer();
        refreshData();
    }

    private void restartServer() {
        if (serverManager == null) return;
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() throws Exception {
                serverManager.restartServer(8443);
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    refreshData();
                } catch (Exception e) {
                    UiSafe.showMessageDialog(ConfigPanel.this, "Failed to restart server: " + e.getMessage(), "Server Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        };
        worker.execute();
    }
}

