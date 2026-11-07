package com.officevpn.gui.admin;

import com.officevpn.admin.AlertManager;
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
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * Headquarters Admin Dashboard Alerts &amp; Incident Response Panel.
 */
public final class AlertsPanel extends JPanel {

    private static final long serialVersionUID = 1L;
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private final transient AlertManager alertManager;
    private final DefaultTableModel tableModel;
    private final JTable alertTable;
    private final JLabel badgeLabel = new JLabel("Unread: 0");

    public AlertsPanel(AlertManager alertManager) {
        super(new BorderLayout(8, 8));
        this.alertManager = alertManager;
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top Banner / Controls
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        badgeLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        badgeLabel.setForeground(new Color(180, 20, 20));
        topPanel.add(badgeLabel);

        JButton markReadBtn = new JButton("Mark as Read");
        markReadBtn.setFont(new Font("SansSerif", Font.PLAIN, 12));
        markReadBtn.setForeground(new Color(15, 75, 160));
        markReadBtn.addActionListener(e -> markSelectedAlertRead());
        topPanel.add(markReadBtn);

        JButton refreshBtn = new JButton("Refresh Alerts");
        refreshBtn.setFont(new Font("SansSerif", Font.PLAIN, 12));
        refreshBtn.setForeground(new Color(15, 23, 42));
        refreshBtn.addActionListener(e -> refreshAlerts());
        topPanel.add(refreshBtn);

        JButton clearOldBtn = new JButton("Clear Old (>30 Days)");
        clearOldBtn.setFont(new Font("SansSerif", Font.PLAIN, 12));
        clearOldBtn.setForeground(new Color(180, 25, 25));
        clearOldBtn.addActionListener(e -> clearOldAlerts());
        topPanel.add(clearOldBtn);

        add(topPanel, BorderLayout.NORTH);

        // Table
        String[] columns = {"ID", "Type", "Severity", "User / Subject", "Message", "Timestamp", "Read?"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        alertTable = new JTable(tableModel);
        alertTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        alertTable.setRowHeight(22);
        alertTable.setDefaultRenderer(Object.class, new AlertCellRenderer());

        add(new JScrollPane(alertTable), BorderLayout.CENTER);
        refreshAlerts();
    }

    public void refreshAlerts() {
        if (alertManager == null) return;

        SwingWorker<List<AlertManager.SystemAlert>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<AlertManager.SystemAlert> doInBackground() {
                return alertManager.getAllAlerts();
            }

            @Override
            protected void done() {
                try {
                    List<AlertManager.SystemAlert> alerts = get();
                    tableModel.setRowCount(0);
                    int unreadCount = 0;
                    int criticalCount = 0;

                    for (AlertManager.SystemAlert a : alerts) {
                        if (!a.isRead()) {
                            unreadCount++;
                            if (a.severity() == AlertManager.AlertSeverity.CRITICAL) {
                                criticalCount++;
                            }
                        }
                        tableModel.addRow(new Object[]{
                                a.id(),
                                a.type().name(),
                                a.severity().name(),
                                a.username(),
                                a.message(),
                                TIME_FORMAT.format(Instant.ofEpochMilli(a.timestamp())),
                                a.isRead() ? "READ" : "UNREAD"
                        });
                    }

                    badgeLabel.setText(String.format("Unread Alerts: %d (Critical: %d)", unreadCount, criticalCount));
                    badgeLabel.setForeground(criticalCount > 0 ? Color.RED : new Color(40, 100, 160));
                } catch (Exception ignored) {}
            }
        };
        worker.execute();
    }

    private void markSelectedAlertRead() {
        int selected = alertTable.getSelectedRow();
        if (selected < 0) {
            UiSafe.showMessageDialog(this, "Please select an alert row to mark as read.", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        long id = ((Number) tableModel.getValueAt(selected, 0)).longValue();
        alertManager.markAlertRead(id);
        refreshAlerts();
    }

    private void clearOldAlerts() {
        int cleared = alertManager.clearOldAlerts(30);
        UiSafe.showMessageDialog(this, "Cleared " + cleared + " old alerts.", "Clear Alerts", JOptionPane.INFORMATION_MESSAGE);
        refreshAlerts();
    }

    private static class AlertCellRenderer extends DefaultTableCellRenderer {
        private static final long serialVersionUID = 1L;
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
            String severity = String.valueOf(table.getModel().getValueAt(row, 2));
            String status = String.valueOf(table.getModel().getValueAt(row, 6));

            if (!isSelected) {
                if ("CRITICAL".equalsIgnoreCase(severity) && "UNREAD".equalsIgnoreCase(status)) {
                    c.setBackground(new Color(255, 235, 235));
                    c.setForeground(new Color(180, 0, 0));
                } else if ("WARNING".equalsIgnoreCase(severity) && "UNREAD".equalsIgnoreCase(status)) {
                    c.setBackground(new Color(255, 248, 230));
                    c.setForeground(new Color(150, 80, 0));
                } else {
                    c.setBackground(Color.WHITE);
                    c.setForeground(Color.BLACK);
                }
            }
            return c;
        }
    }
}


