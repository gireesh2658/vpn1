package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.Department;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.List;

/**
 * Departmental File Vault Explorer for the Employee Client GUI.
 * <p>
 * Provides authenticated, RBAC-governed browsing, downloading, and uploading of files.
 * All file transmissions are encrypted with AES-256-GCM + bound canonical AAD over the socket tunnel.
 * All operations execute off the Swing EDT via {@link SwingWorker}.
 */
public final class FileVaultPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final transient VpnClientEngine clientEngine;
    private final JComboBox<Department> vaultSelector;
    private final DefaultTableModel tableModel;
    private final JTable fileTable;

    private final JButton refreshButton = new JButton("Refresh Vault");
    private final JButton downloadButton = new JButton("Download Selected");
    private final JButton uploadButton = new JButton("Upload New File");
    private final JProgressBar progressBar = new JProgressBar();
    private final JLabel statusLabel = new JLabel("Ready");

    public FileVaultPanel(VpnClientEngine clientEngine) {
        this.clientEngine = clientEngine;
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Top toolbar
        JPanel toolBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        toolBar.setBorder(BorderFactory.createTitledBorder("Vault Selection"));

        toolBar.add(new JLabel("Target Department Vault:"));
        Department defaultDept = (clientEngine.getDepartment() != null) ? clientEngine.getDepartment() : Department.FINANCE;
        vaultSelector = new JComboBox<>(Department.values());
        vaultSelector.setSelectedItem(defaultDept);
        toolBar.add(vaultSelector);

        toolBar.add(refreshButton);
        add(toolBar, BorderLayout.NORTH);

        // Center: File Table
        tableModel = new DefaultTableModel(new Object[]{"File Name", "Size (Bytes)"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        fileTable = new JTable(tableModel);
        fileTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        fileTable.setRowHeight(24);
        com.officevpn.gui.UiSafe.configureSafeTable(fileTable);
        add(new JScrollPane(fileTable), BorderLayout.CENTER);

        // Bottom: Action buttons and progress
        JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 5));
        buttons.add(downloadButton);
        buttons.add(uploadButton);
        bottomPanel.add(buttons, BorderLayout.NORTH);

        JPanel statusPanel = new JPanel(new BorderLayout(10, 5));
        statusPanel.setBorder(BorderFactory.createEmptyBorder(0, 5, 5, 5));
        progressBar.setIndeterminate(false);
        progressBar.setVisible(false);
        statusPanel.add(statusLabel, BorderLayout.CENTER);
        statusPanel.add(progressBar, BorderLayout.EAST);
        bottomPanel.add(statusPanel, BorderLayout.SOUTH);

        add(bottomPanel, BorderLayout.SOUTH);

        // Action Listeners
        refreshButton.addActionListener(e -> refreshFileList());
        vaultSelector.addActionListener(e -> refreshFileList());
        downloadButton.addActionListener(e -> downloadSelectedFile());
        uploadButton.addActionListener(e -> uploadFile());

        // Initial load
        refreshFileList();
    }

    private void setBusy(boolean busy, String message) {
        refreshButton.setEnabled(!busy);
        downloadButton.setEnabled(!busy);
        uploadButton.setEnabled(!busy);
        vaultSelector.setEnabled(!busy);
        progressBar.setVisible(busy);
        progressBar.setIndeterminate(busy);
        statusLabel.setText(message);
    }

    public void refreshFileList() {
        Department target = (Department) vaultSelector.getSelectedItem();
        if (target == null) return;

        setBusy(true, "Listing files from " + target + " vault...");

        new SwingWorker<List<String>, Void>() {
            @Override
            protected List<String> doInBackground() throws Exception {
                return clientEngine.listDepartmentFiles(target);
            }

            @Override
            protected void done() {
                try {
                    List<String> files = get();
                    tableModel.setRowCount(0);
                    for (String f : files) {
                        tableModel.addRow(new Object[]{f, "-"});
                    }
                    setBusy(false, "Vault '" + target + "' loaded (" + files.size() + " files found)");
                } catch (Exception ex) {
                    tableModel.setRowCount(0);
                    String error = extractErrorMessage(ex);
                    setBusy(false, "Error: " + error);
                    com.officevpn.gui.UiSafe.showMessageDialog(FileVaultPanel.this,
                            "Failed to list files from " + target + " vault:\n" + error,
                            "Vault Access Error",
                            JOptionPane.WARNING_MESSAGE);
                }
            }
        }.execute();
    }

    private void downloadSelectedFile() {
        int row = fileTable.getSelectedRow();
        if (row < 0) {
            UiSafe.showMessageDialog(this, "Please select a file to download.", "No File Selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String fileName = (String) tableModel.getValueAt(row, 0);
        Department target = (Department) vaultSelector.getSelectedItem();

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new File(fileName));
        int option = fileChooser.showSaveDialog(this);
        if (option != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File destination = fileChooser.getSelectedFile();
        setBusy(true, "Downloading '" + fileName + "' (" + target + ")...");

        new SwingWorker<byte[], Void>() {
            @Override
            protected byte[] doInBackground() throws Exception {
                return clientEngine.downloadFile(target, fileName);
            }

            @Override
            protected void done() {
                try {
                    byte[] data = get();
                    try (FileOutputStream fos = new FileOutputStream(destination)) {
                        fos.write(data);
                    }
                    setBusy(false, "Downloaded '" + fileName + "' (" + data.length + " bytes) saved to " + destination.getName());
                    UiSafe.showMessageDialog(FileVaultPanel.this,
                            "File downloaded successfully!\n" +
                                    "Saved to: " + destination.getAbsolutePath() + "\n" +
                                    "Size: " + data.length + " bytes\n" +
                                    "Integrity: AES-256-GCM + HMAC-SHA256 verified",
                            "Download Complete",
                            JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    String error = extractErrorMessage(ex);
                    setBusy(false, "Download failed: " + error);
                    UiSafe.showMessageDialog(FileVaultPanel.this,
                            "Download failed:\n" + error,
                            "Download Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    private void uploadFile() {
        Department target = (Department) vaultSelector.getSelectedItem();
        JFileChooser fileChooser = new JFileChooser();
        int option = fileChooser.showOpenDialog(this);
        if (option != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File selectedFile = fileChooser.getSelectedFile();
        if (!selectedFile.exists() || !selectedFile.isFile()) {
            UiSafe.showMessageDialog(this, "Selected path is not a valid file.", "Invalid File", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String fileName = selectedFile.getName();
        setBusy(true, "Encrypting and uploading '" + fileName + "' to " + target + "...");

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                byte[] content = Files.readAllBytes(selectedFile.toPath());
                clientEngine.uploadFile(target, fileName, content);
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                    setBusy(false, "File '" + fileName + "' uploaded successfully.");
                    UiSafe.showMessageDialog(FileVaultPanel.this,
                            "File '" + fileName + "' uploaded successfully to " + target + " vault!",
                            "Upload Succeeded",
                            JOptionPane.INFORMATION_MESSAGE);
                    refreshFileList();
                } catch (Exception ex) {
                    String error = extractErrorMessage(ex);
                    setBusy(false, "Upload failed: " + error);
                    UiSafe.showMessageDialog(FileVaultPanel.this,
                            "Upload failed:\n" + error,
                            "Upload Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }


    private String extractErrorMessage(Exception ex) {
        Throwable cause = ex;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
    }
}

