package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.gui.UiSafe;
import com.officevpn.protocol.VpnPacket;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Encrypted Office Intranet Chat Panel for the Employee Client GUI.
 * <p>
 * Subscribes to real-time chat broadcasts delivered over the VPN tunnel.
 * All chat payloads are encrypted end-to-end via AES-256-GCM.
 * Thread-safe: All UI mutations occur strictly on the Swing Event Dispatch Thread.
 */
public final class ChatPanel extends JPanel implements VpnClientEngine.ClientEventListener {

    private static final long serialVersionUID = 1L;

    private final transient VpnClientEngine clientEngine;
    private final JTextArea chatArea = new JTextArea();
    private final JTextField messageField = new JTextField();
    private final JButton sendButton = new JButton("Send Message");
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");

    public ChatPanel(VpnClientEngine clientEngine) {
        this.clientEngine = clientEngine;
        this.clientEngine.addClientEventListener(this);

        setLayout(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Center: Chat History
        chatArea.setEditable(false);
        chatArea.setLineWrap(true);
        chatArea.setWrapStyleWord(true);
        chatArea.setFont(new Font("SansSerif", Font.PLAIN, 13));
        chatArea.setBackground(new Color(250, 250, 252));
        com.officevpn.gui.UiSafe.disableHtml(chatArea);
        chatArea.append("=== Encrypted Office Intranet Chat (Broadcast Channel) ===\n");
        chatArea.append("All messages are encrypted with AES-256-GCM and authenticated over the 10.8.0.x tunnel.\n\n");

        JScrollPane scrollPane = new JScrollPane(chatArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Intranet Chat Messages"));
        add(scrollPane, BorderLayout.CENTER);

        // Bottom: Message composer
        JPanel inputPanel = new JPanel(new BorderLayout(8, 0));
        inputPanel.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        messageField.setFont(new Font("SansSerif", Font.PLAIN, 13));
        inputPanel.add(messageField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);

        add(inputPanel, BorderLayout.SOUTH);

        // Action Listeners
        sendButton.addActionListener(this::handleSendMessage);
        messageField.addActionListener(this::handleSendMessage);
    }

    private void handleSendMessage(ActionEvent e) {
        String text = messageField.getText().trim();
        if (text.isEmpty()) {
            return;
        }

        messageField.setText("");
        messageField.setEnabled(false);
        sendButton.setEnabled(false);

        new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                clientEngine.sendChatMessage(text);
                return null;
            }

            @Override
            protected void done() {
                messageField.setEnabled(true);
                sendButton.setEnabled(true);
                messageField.requestFocusInWindow();
                try {
                    get();
                } catch (Exception ex) {
                    UiSafe.showMessageDialog(ChatPanel.this,
                            "Failed to deliver chat message: " + ex.getMessage(),
                            "Chat Delivery Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    public javax.swing.JTextArea getChatArea() {
        return chatArea;
    }

    @Override
    public void onChatMessage(String senderUser, String senderDept, String senderVip, String message) {
        SwingUtilities.invokeLater(() -> {
            String timeStr = timeFormat.format(new Date());
            String safeSender = com.officevpn.gui.UiSafe.text(senderUser, 32);
            String safeDept = com.officevpn.gui.UiSafe.text(senderDept, 32);
            String safeVip = com.officevpn.gui.UiSafe.text(senderVip, 32);
            String safeMsg = com.officevpn.gui.UiSafe.text(message, 1024);
            String formattedLine = String.format("[%s] %s (%s @ %s): %s%n",
                    timeStr, safeSender, safeDept, safeVip, safeMsg);
            chatArea.append(formattedLine);
            chatArea.setCaretPosition(chatArea.getDocument().getLength());
        });
    }

    @Override
    public void onPacketSniffed(VpnPacket packet, String direction) {
        // Handled in ConnectionStatusPanel
    }

    @Override
    public void onConnectionStateChanged(String state) {
        SwingUtilities.invokeLater(() -> {
            chatArea.append("[" + timeFormat.format(new Date()) + "] [SYSTEM] " + state + "\n");
            chatArea.setCaretPosition(chatArea.getDocument().getLength());
        });
    }
}


