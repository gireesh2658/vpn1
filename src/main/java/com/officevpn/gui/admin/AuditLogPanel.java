package com.officevpn.gui.admin;

import com.officevpn.db.DatabaseManager;
import com.officevpn.model.AuditVerifyResult;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Immutable Security Audit Log Panel for the Headquarters Admin Dashboard.
 * <p>
 * Displays persistent security audit events (authenticated tunnels, RBAC
 * denials,
 * identity spoofing alerts, and password failures) stored in SQLite with
 * cryptographic HMAC chain verification.
 */
public final class AuditLogPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private transient DatabaseManager databaseManager;
    private final DefaultTableModel tableModel;
    private final JTable auditTable;
    private final JComboBox<String> filterCombo;
    private final JButton refreshButton = new JButton("Refresh Audit Logs");
    private final JButton verifyButton = new JButton("Verify Integrity");
    private final JButton copyAnchorButton = new JButton("Copy anchor");
    private final JLabel integrityLabel = new JLabel("Integrity: Not Checked");
    private final JLabel countLabel = new JLabel("Entries Displayed: 0");

    private final SimpleDateFormat timeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public AuditLogPanel(DatabaseManager databaseManager) {
        this(databaseManager, System::currentTimeMillis);
    }

    public AuditLogPanel(DatabaseManager databaseManager, java.util.function.LongSupplier timeSupplier) {
        this.databaseManager = databaseManager;
        this.timeSupplier = (timeSupplier != null) ? timeSupplier : System::currentTimeMillis;

        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top Filter Bar
        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        topBar.setBorder(BorderFactory.createTitledBorder("Audit Filter & Chain Verification"));

        topBar.add(new JLabel("Filter:"));
        filterCombo = new JComboBox<>(new String[] {
                "ALL EVENTS",
                "TUNNEL_ESTABLISHED",
                "TUNNEL_TERMINATED",
                "AUTH_SUCCESS",
                "AUTH_FAILURE",
                "RBAC_VIOLATION",
                "SECURITY_ALERT",
                "USER_STATUS_CHANGE"
        });
        filterCombo.addActionListener(e -> loadAuditLogs());
        topBar.add(filterCombo);

        topBar.add(refreshButton);
        refreshButton.addActionListener(e -> loadAuditLogs());

        topBar.add(verifyButton);
        verifyButton.addActionListener(e -> verifyChainIntegrity());

        JButton exportCsvButton = new JButton("Export CSV");
        exportCsvButton.addActionListener(e -> exportAuditLogsToCsv());
        topBar.add(exportCsvButton);

        topBar.add(copyAnchorButton);
        copyAnchorButton.addActionListener(e -> {
            if (databaseManager != null) {
                String anchor = databaseManager.currentAnchor();
                if (anchor != null && !anchor.isEmpty()) {
                    java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                            .setContents(new java.awt.datatransfer.StringSelection(anchor), null);
                    JOptionPane.showMessageDialog(this, "Audit anchor copied to clipboard:\n" + anchor, "Anchor Copied",
                            JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(this, "No audit anchor available to copy.", "Anchor Not Available",
                            JOptionPane.WARNING_MESSAGE);
                }
            }
        });

        integrityLabel.setFont(integrityLabel.getFont().deriveFont(Font.BOLD));
        topBar.add(integrityLabel);

        add(topBar, BorderLayout.NORTH);

        // Center Table
        String[] columnNames = {
                "Seq", "Timestamp", "Event Type", "Username", "Dept", "Actor", "Remote IP", "Details"
        };

        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        auditTable = new JTable(tableModel);
        com.officevpn.gui.UiSafe.configureSafeTable(auditTable);
        auditTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        auditTable.setFont(new Font("SansSerif", Font.PLAIN, 12));
        auditTable.setRowHeight(22);

        // Custom renderer for Event Type (Security alerts colored red, auth green),
        // wrapped for UI safety
        DefaultTableCellRenderer eventTypeRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                    boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                String event = String.valueOf(value);
                if (event.contains("ALERT") || event.contains("VIOLATION") || event.contains("FAILURE")) {
                    c.setForeground(new Color(180, 0, 0));
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else if (event.contains("ESTABLISHED") || event.contains("SUCCESS")) {
                    c.setForeground(new Color(0, 130, 0));
                    c.setFont(c.getFont().deriveFont(Font.BOLD));
                } else {
                    c.setForeground(Color.BLACK);
                }
                return c;
            }
        };
        // Wrapped for UI safety
        auditTable.getColumnModel().getColumn(2).setCellRenderer(com.officevpn.gui.UiSafe.wrap(eventTypeRenderer));

        auditTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        auditTable.getColumnModel().getColumn(1).setPreferredWidth(130);
        auditTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        auditTable.getColumnModel().getColumn(3).setPreferredWidth(90);
        auditTable.getColumnModel().getColumn(4).setPreferredWidth(70);
        auditTable.getColumnModel().getColumn(5).setPreferredWidth(90);
        auditTable.getColumnModel().getColumn(6).setPreferredWidth(100);
        auditTable.getColumnModel().getColumn(7).setPreferredWidth(300);
        com.officevpn.gui.UiSafe.disableHtml(integrityLabel);
        com.officevpn.gui.UiSafe.disableHtml(countLabel);

        add(new JScrollPane(auditTable), BorderLayout.CENTER);

        // Bottom status
        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bottomBar.add(countLabel);
        add(bottomBar, BorderLayout.SOUTH);

        this.drainTimer = new javax.swing.Timer(250, e -> drainAuditQueue(MAX_DRAIN_PER_TICK));
        this.drainTimer.start();

        loadAuditLogs();
    }

    public void verifyChainIntegrity() {
        if (databaseManager == null)
            return;
        verifyButton.setEnabled(false);
        integrityLabel.setText("Integrity: Verifying...");
        integrityLabel.setForeground(Color.BLACK);

        new SwingWorker<AuditVerifyResult, Void>() {
            @Override
            protected AuditVerifyResult doInBackground() {
                return databaseManager.verifyAuditChain();
            }

            @Override
            protected void done() {
                verifyButton.setEnabled(true);
                try {
                    AuditVerifyResult result = get();
                    if (result.status() == AuditVerifyResult.AuditStatus.OK) {
                        integrityLabel.setText("Integrity: VERIFIED (" + result.checkedRows() + " rows)");
                        integrityLabel.setForeground(new Color(0, 130, 0));
                    } else if (result.status() == AuditVerifyResult.AuditStatus.KEY_MISSING) {
                        integrityLabel.setText("Integrity: UNVERIFIABLE (key missing)");
                        integrityLabel.setForeground(Color.ORANGE);
                    } else {
                        integrityLabel.setText(
                                "Integrity: BROKEN at seq " + result.brokenSeq() + " (" + result.status() + ")");
                        integrityLabel.setForeground(Color.RED);
                    }
                } catch (Exception ex) {
                    integrityLabel.setText("Integrity: ERROR (" + ex.getMessage() + ")");
                    integrityLabel.setForeground(Color.RED);
                }
            }
        }.execute();
    }

    public void exportAuditLogsToCsv() {
        if (databaseManager == null) return;
        new SwingWorker<Integer, Void>() {
            private java.nio.file.Path path;

            @Override
            protected Integer doInBackground() throws Exception {
                path = java.nio.file.Path.of("audit_logs_export.csv");
                com.officevpn.admin.AuditService svc = new com.officevpn.admin.AuditService(databaseManager);
                return svc.exportAuditToCsv(path);
            }

            @Override
            protected void done() {
                try {
                    int count = get();
                    JOptionPane.showMessageDialog(AuditLogPanel.this,
                            "Successfully exported " + count + " audit entries to:\n" + path.toAbsolutePath(),
                            "Export Audit Complete", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(AuditLogPanel.this,
                            "Export failed: " + ex.getMessage(),
                            "Export Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    public void setDatabaseManager(DatabaseManager databaseManager) {
        this.databaseManager = databaseManager;
        loadAuditLogs();
    }

    public static final int MAX_DRAIN_PER_TICK = 200;
    public static final int MAX_ROWS = 500;

    private final transient java.util.Queue<Object[]> auditQueue = new java.util.concurrent.ConcurrentLinkedQueue<>();
    private final javax.swing.Timer drainTimer;

    private final java.util.concurrent.atomic.AtomicLong lastAuditLoadTime = new java.util.concurrent.atomic.AtomicLong(
            0);
    private transient java.util.function.LongSupplier timeSupplier = System::currentTimeMillis;
    private final java.util.concurrent.atomic.AtomicInteger reloadCount = new java.util.concurrent.atomic.AtomicInteger(
            0);
    private final java.util.concurrent.atomic.AtomicBoolean queryRanOffEdt = new java.util.concurrent.atomic.AtomicBoolean(
            false);
    private transient Runnable beforeQueryHook = null;

    // Test seam
    public int getReloadCount() {
        return reloadCount.get();
    }

    // Test seam
    public boolean isQueryRanOffEdt() {
        return queryRanOffEdt.get();
    }

    // Test seam
    public void setBeforeQueryHook(Runnable hook) {
        this.beforeQueryHook = hook;
    }

    // Test seam
    public java.util.Queue<Object[]> getAuditQueue() {
        return auditQueue;
    }

    // Test seam
    public JTable getAuditTable() {
        return auditTable;
    }

    public int drainAuditQueue(int maxDrain) {
        int drained = 0;
        while (drained < maxDrain && !auditQueue.isEmpty()) {
            Object[] row = auditQueue.poll();
            if (row != null) {
                tableModel.addRow(row);
                drained++;
            }
        }
        if (tableModel.getRowCount() > MAX_ROWS) {
            int excess = tableModel.getRowCount() - MAX_ROWS;
            for (int i = 0; i < excess; i++) {
                tableModel.removeRow(0);
            }
        }
        return drained;
    }

    public void loadAuditLogs() {
        loadAuditLogs(false);
    }

    public void loadAuditLogs(boolean force) {
        if (databaseManager == null)
            return;
        long now = timeSupplier.getAsLong();
        if (!force && (now - lastAuditLoadTime.get() < 2000)) {
            return; // Debounced to max once per 2 seconds
        }
        lastAuditLoadTime.set(now);
        reloadCount.incrementAndGet();

        String selectedFilter = (String) filterCombo.getSelectedItem();

        java.util.concurrent.CompletableFuture.supplyAsync(() -> {
            queryRanOffEdt.set(!SwingUtilities.isEventDispatchThread());
            if (beforeQueryHook != null) {
                beforeQueryHook.run();
            }
            return databaseManager.getRecentAuditLogs(200);
        }).thenAccept(logs -> SwingUtilities.invokeLater(() -> {
            tableModel.setRowCount(0);
            auditQueue.clear();
            for (DatabaseManager.AuditLogEntry entry : logs) {
                if (selectedFilter != null && !"ALL EVENTS".equals(selectedFilter)) {
                    if (!selectedFilter.equalsIgnoreCase(entry.eventType())) {
                        continue;
                    }
                }
                auditQueue.offer(new Object[] {
                        entry.seq() > 0 ? entry.seq() : entry.id(),
                        com.officevpn.gui.UiSafe.text(timeFormat.format(new Date(entry.timestamp())), 32),
                        com.officevpn.gui.UiSafe.text(entry.eventType(), 32),
                        com.officevpn.gui.UiSafe.text(entry.username(), 32),
                        com.officevpn.gui.UiSafe.text(entry.department(), 32),
                        com.officevpn.gui.UiSafe.text(entry.actor() != null ? entry.actor() : "-", 32),
                        com.officevpn.gui.UiSafe.text(entry.remoteIp() != null ? entry.remoteIp() : entry.ipAddress(),
                                32),
                        com.officevpn.gui.UiSafe.text(entry.details(), 256)
                });
            }
            drainAuditQueue(MAX_DRAIN_PER_TICK);
            countLabel.setText("Entries Displayed: " + tableModel.getRowCount() + " (Filtered from " + logs.size()
                    + " total recent events)");
        }));
    }
}

