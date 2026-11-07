package com.officevpn.gui;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JTable;

import javax.swing.table.TableCellRenderer;
import java.awt.Component;

/**
 * UI Safety and Sanitization Utility for Swing Desktop Components.
 * Prevents HTML/CSS injection, disables tooltip vector risks, strips control characters,
 * and enforces safe rendering boundaries across tables, lists, and dialogs.
 */
public final class UiSafe {

    public static final String HTML_DISABLE_KEY = "html.disable";

    private UiSafe() {}

    /**
     * Explicitly disables Swing's internal HTML renderer on the given component
     * and clears any existing HTML view hierarchy.
     */
    public static void disableHtml(JComponent component) {
        if (component != null) {
            component.putClientProperty(HTML_DISABLE_KEY, Boolean.TRUE);
            component.putClientProperty(javax.swing.plaf.basic.BasicHTML.propertyKey, null);
        }
    }

    /**
     * Sanitizes external untrusted text:
     * - Null-safe (returns empty string for null)
     * - Replaces control characters (newlines, tabs, bells, etc.) with '?'
     * - Preserves literal '<' and '>' characters without HTML entity escaping
     * - Truncates strings exceeding {@code max} length, appending a trailing '~'
     */
    public static String text(String s, int max) {
        if (s == null) {
            return "";
        }
        String sanitized = s.replaceAll("[\\p{Cntrl}]", "?");
        if (max > 0 && sanitized.length() > max) {
            return sanitized.substring(0, max - 1) + "~";
        }
        return sanitized;
    }

    /**
     * Wraps a {@link TableCellRenderer} with defensive HTML disabling and text sanitization.
     */
    public static TableCellRenderer wrap(TableCellRenderer delegate) {
        if (delegate == null) {
            return null;
        }
        if (delegate instanceof JComponent jc) {
            disableHtml(jc);
        }
        return (table, value, isSelected, hasFocus, row, column) -> {
            Component c = delegate.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (c instanceof JComponent jc) {
                disableHtml(jc);
                jc.setToolTipText(null); // Clear tooltips to defeat tooltip injection vectors
            }
            if (c instanceof JLabel label && value != null) {
                label.setText(text(value.toString(), 256));
            }
            return c;
        };
    }


    /**
     * Hardens a JTable: wraps all default renderers and column renderers with {@link #wrap(TableCellRenderer)}.
     */
    public static void configureSafeTable(JTable table) {
        if (table == null) return;
        disableHtml(table);

        table.setDefaultRenderer(Object.class, wrap(table.getDefaultRenderer(Object.class)));
        table.setDefaultRenderer(String.class, wrap(table.getDefaultRenderer(String.class)));
        table.setDefaultRenderer(Number.class, wrap(table.getDefaultRenderer(Number.class)));
        table.setDefaultRenderer(Boolean.class, wrap(table.getDefaultRenderer(Boolean.class)));

        for (int i = 0; i < table.getColumnModel().getColumnCount(); i++) {
            TableCellRenderer colRenderer = table.getColumnModel().getColumn(i).getCellRenderer();
            if (colRenderer != null) {
                table.getColumnModel().getColumn(i).setCellRenderer(wrap(colRenderer));
            }
        }
    }


    /**
     * Displays a JOptionPane message dialog with HTML rendering disabled on the message component.
     * Safely no-ops in headless environments.
     */
    public static void showMessageDialog(Component parent, Object externalMsg, String title, int messageType) {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            return;
        }
        Object safeMsg = externalMsg;
        if (externalMsg instanceof String s) {
            JLabel label = new JLabel(text(s, 1024));
            disableHtml(label);
            safeMsg = label;
        } else if (externalMsg instanceof JComponent jc) {
            disableHtml(jc);
        }
        JOptionPane.showMessageDialog(parent, safeMsg, title, messageType);
    }

    public static void showMessageDialog(Component parent, String externalMsg, String title, int messageType) {
        showMessageDialog(parent, (Object) externalMsg, title, messageType);
    }

    public static int showConfirmDialog(Component parent, Object message, String title, int optionType, int messageType) {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            return JOptionPane.CANCEL_OPTION;
        }
        Object safeMsg = message;
        if (message instanceof String s) {
            JLabel label = new JLabel(text(s, 1024));
            disableHtml(label);
            safeMsg = label;
        } else if (message instanceof JComponent jc) {
            disableHtml(jc);
        }
        return JOptionPane.showConfirmDialog(parent, safeMsg, title, optionType, messageType);
    }

    public static String showInputDialog(Component parent, Object message, String title, int messageType) {
        if (java.awt.GraphicsEnvironment.isHeadless()) {
            return null;
        }
        Object safeMsg = message;
        if (message instanceof String s) {
            JLabel label = new JLabel(text(s, 1024));
            disableHtml(label);
            safeMsg = label;
        } else if (message instanceof JComponent jc) {
            disableHtml(jc);
        }
        return JOptionPane.showInputDialog(parent, safeMsg, title, messageType);
    }
}
