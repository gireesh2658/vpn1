package com.officevpn.gui.admin;

import com.officevpn.gui.UiSafe;
import com.officevpn.protocol.VpnPacket;
import com.officevpn.server.ServerEventListener;
import com.officevpn.server.VpnGatewayServer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Live Server Event Log Panel for the Headquarters Admin Dashboard.
 * <p>
 * Subscribes to {@link ServerEventListener#onServerLog(String)} to display
 * timestamped lifecycle, diagnostic, and network gateway events.
 * Hardened with EDT protection, non-blocking queue coalescing (max 200/tick),
 * and HTML disablement.
 */
public final class ServerLogPanel extends JPanel implements ServerEventListener {

    private static final long serialVersionUID = 1L;

    public static final int MAX_DRAIN_PER_TICK = 200;
    public static final int MAX_LINES = 500;

    private final JTextArea logArea = new JTextArea();
    private final JButton clearButton = new JButton("Clear Logs");
    private final SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");

    private final transient Queue<String> logQueue = new ConcurrentLinkedQueue<>();
    private final Timer drainTimer;

    public ServerLogPanel() {
        setLayout(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        logArea.setBackground(new Color(248, 248, 252));
        UiSafe.disableHtml(logArea);

        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Headquarters Gateway Event Log"));
        add(scrollPane, BorderLayout.CENTER);

        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        clearButton.addActionListener(e -> {
            logQueue.clear();
            logArea.setText("");
        });
        bottomBar.add(clearButton);
        add(bottomBar, BorderLayout.SOUTH);

        // 250 ms coalescing timer for EDT protection
        this.drainTimer = new Timer(250, e -> drainLogQueue(MAX_DRAIN_PER_TICK));
        this.drainTimer.start();
    }

    public int drainLogQueue(int maxDrain) {
        int drained = 0;
        StringBuilder sb = new StringBuilder();
        while (drained < maxDrain && !logQueue.isEmpty()) {
            String line = logQueue.poll();
            if (line != null) {
                sb.append(line).append("\n");
                drained++;
            }
        }
        if (drained > 0) {
            logArea.append(sb.toString());
            if (logArea.getLineCount() > MAX_LINES + 1) {
                try {
                    int excess = logArea.getLineCount() - (MAX_LINES + 1);
                    int end = logArea.getLineEndOffset(excess);
                    logArea.replaceRange("", 0, end);
                } catch (Exception ignored) {}
            }
            logArea.setCaretPosition(logArea.getDocument().getLength());
        }
        return drained;
    }

    // Test seam
    public Queue<String> getLogQueue() {
        return logQueue;
    }

    // Test seam
    public JTextArea getLogArea() {
        return logArea;
    }

    public void bindToServer(VpnGatewayServer server) {
        if (server != null) {
            server.addServerEventListener(this);
        }
    }

    public void unbindFromServer(VpnGatewayServer server) {
        if (server != null) {
            server.removeServerEventListener(this);
        }
    }

    @Override
    public void onServerLog(String message) {
        if (message == null) return;
        String time = timeFormat.format(new Date());
        logQueue.offer("[" + time + "] " + UiSafe.text(message, 512));
    }

    @Override
    public void onPacketSniffed(VpnPacket rawPacket, String direction) {
        // Handled in PacketMonitorPanel
    }

    @Override
    public void onSessionUpdated() {
        // Handled in ConnectedClientsPanel
    }

    @Override
    public void onChatBroadcast(String senderUser, String senderDept, String senderVip, String message) {
        onServerLog(String.format("[CHAT BROADCAST] [%s@%s (%s)]: %s",
                UiSafe.text(senderUser, 64),
                UiSafe.text(senderVip, 32),
                UiSafe.text(senderDept, 32),
                UiSafe.text(message, 512)));
    }
}

