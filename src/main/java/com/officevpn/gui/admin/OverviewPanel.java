package com.officevpn.gui.admin;

import com.officevpn.admin.MetricsCollector;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import javax.swing.SwingWorker;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.GridLayout;

/**
 * Headquarters Admin Dashboard Overview panel featuring 6 live operational metric cards.
 * Automatically refreshed every 5 seconds via non-blocking background workers.
 */
public final class OverviewPanel extends JPanel {

    private static final long serialVersionUID = 1L;

    private final transient MetricsCollector metricsCollector;
    private final JLabel activeSessionsVal = new JLabel("-", SwingConstants.CENTER);
    private final JLabel totalUsersVal = new JLabel("-", SwingConstants.CENTER);
    private final JLabel connectionsTodayVal = new JLabel("-", SwingConstants.CENTER);
    private final JLabel uptimeVal = new JLabel("-", SwingConstants.CENTER);
    private final JLabel avgLatencyVal = new JLabel("-", SwingConstants.CENTER);
    private final JLabel bandwidthTodayVal = new JLabel("-", SwingConstants.CENTER);
    private final Timer refreshTimer;

    public OverviewPanel(MetricsCollector metricsCollector) {
        super(new GridLayout(2, 3, 14, 14));
        this.metricsCollector = metricsCollector;
        setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        setBackground(new Color(245, 248, 252));

        add(createMetricCard("Active Sessions", activeSessionsVal, new Color(16, 128, 55)));
        add(createMetricCard("Total Users", totalUsersVal, new Color(2, 99, 186)));
        add(createMetricCard("Connections Today", connectionsTodayVal, new Color(126, 34, 150)));
        add(createMetricCard("Server Uptime", uptimeVal, new Color(14, 116, 144)));
        add(createMetricCard("Avg Round-Trip Latency", avgLatencyVal, new Color(194, 65, 12)));
        add(createMetricCard("Bandwidth Consumed Today", bandwidthTodayVal, new Color(190, 24, 24)));

        this.refreshTimer = new Timer(5000, e -> refreshMetrics());
        this.refreshTimer.start();
        refreshMetrics();
    }

    private JPanel createMetricCard(String title, JLabel valueLabel, Color accentColor) {
        JPanel card = new JPanel(new BorderLayout(8, 8));
        card.setBackground(Color.WHITE);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(203, 213, 225), 1),
                BorderFactory.createEmptyBorder(18, 16, 18, 16)
        ));

        JLabel titleLabel = new JLabel(title, SwingConstants.CENTER);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 14));
        titleLabel.setForeground(new Color(51, 65, 85));

        valueLabel.setFont(new Font("SansSerif", Font.BOLD, 30));
        valueLabel.setForeground(accentColor);

        card.add(titleLabel, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);
        return card;
    }

    public void refreshMetrics() {
        if (metricsCollector == null) {
            return;
        }

        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            private int sessions;
            private int users;
            private int connections;
            private long uptimeSec;
            private long latencyMs;
            private long bytesToday;

            @Override
            protected Void doInBackground() {
                sessions = metricsCollector.getActiveSessionCount();
                users = metricsCollector.getTotalUsers();
                connections = metricsCollector.getConnectionsToday();
                uptimeSec = metricsCollector.getUptimeSeconds();
                latencyMs = metricsCollector.getAverageLatencyMs();
                bytesToday = metricsCollector.getBandwidthUsedToday();
                return null;
            }

            @Override
            protected void done() {
                activeSessionsVal.setText(String.valueOf(sessions));
                totalUsersVal.setText(String.valueOf(users));
                connectionsTodayVal.setText(String.valueOf(connections));

                long hours = uptimeSec / 3600;
                long mins = (uptimeSec % 3600) / 60;
                long secs = uptimeSec % 60;
                uptimeVal.setText(String.format("%02d:%02d:%02d", hours, mins, secs));

                avgLatencyVal.setText(latencyMs + " ms");

                if (bytesToday >= 1024 * 1024) {
                    bandwidthTodayVal.setText(String.format("%.2f MB", bytesToday / (1024.0 * 1024.0)));
                } else if (bytesToday >= 1024) {
                    bandwidthTodayVal.setText(String.format("%.2f KB", bytesToday / 1024.0));
                } else {
                    bandwidthTodayVal.setText(bytesToday + " B");
                }
            }
        };
        worker.execute();
    }

    public void stopTimer() {
        if (refreshTimer != null && refreshTimer.isRunning()) {
            refreshTimer.stop();
        }
    }
}


