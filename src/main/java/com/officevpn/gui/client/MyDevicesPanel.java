package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Client Portal Panel displaying registered hardware device profiles and trust status.
 */
public final class MyDevicesPanel extends JPanel {

    private static final long serialVersionUID = 1L;
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault());

    private final transient VpnClientEngine clientEngine;
    private final DefaultTableModel tableModel;
    private final JTable table;
    private final JLabel headerLabel = new JLabel("Authorized Employee Devices");

    public MyDevicesPanel(VpnClientEngine clientEngine) {
        super(new BorderLayout(10, 10));
        this.clientEngine = clientEngine;
        setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        headerLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        headerLabel.setForeground(new Color(25, 75, 150));
        topPanel.add(headerLabel);

        JButton refreshBtn = new JButton("Refresh Devices");
        refreshBtn.addActionListener(e -> refreshDevices());
        topPanel.add(refreshBtn);

        add(topPanel, BorderLayout.NORTH);

        String[] columns = {"Device Name / Model", "Hardware Fingerprint", "Trust Status", "Device Quota", "Last Telemetry"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        table = new JTable(tableModel);
        table.setRowHeight(24);
        com.officevpn.gui.UiSafe.configureSafeTable(table);
        add(new JScrollPane(table), BorderLayout.CENTER);

        refreshDevices();
    }

    public void refreshDevices() {
        tableModel.setRowCount(0);
        String devName = com.officevpn.util.HardwareUtil.getAuthenticDeviceName();
        if (clientEngine != null && clientEngine.getUsername() != null && !clientEngine.getUsername().isBlank()) {
            devName = devName + " [" + clientEngine.getUsername() + "]";
        }
        String fp = com.officevpn.util.HardwareUtil.getAuthenticHardwareFingerprint();
        String timeStr = TIME_FORMAT.format(Instant.now());

        tableModel.addRow(new Object[]{
                devName,
                fp,
                "TRUSTED / ACTIVE",
                "2 Devices (Corporate Limit)",
                timeStr
        });
    }
}


