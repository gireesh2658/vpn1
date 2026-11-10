package com.officevpn.gui;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Dialog;
import javafx.scene.control.DialogPane;
import javafx.scene.control.Label;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextInputDialog;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.stage.Window;

import java.net.URL;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/**
 * Shared JavaFX UI safety, styling, table configuration, clipboard, and dialog utilities.
 * Neutralizes control characters / directional overrides and applies the Office VPN dark theme consistently.
 */
public final class UiSafe {

    public static final String THEME_CSS_RESOURCE = "/styles/officevpn-theme.css";

    private UiSafe() {}

    /**
     * Normalizes untrusted text for safe display in JavaFX controls: strips control/format
     * characters, collapses newlines/tabs to spaces, and bounds total length.
     */
    public static String text(String raw, int maxLen) {
        if (raw == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(Math.min(raw.length(), Math.max(0, maxLen)));
        for (int i = 0; i < raw.length(); i++) {
            char ch = raw.charAt(i);
            if (ch == '\r' || ch == '\n' || ch == '\t' || ch == ' ') {
                if (!sb.isEmpty() && sb.charAt(sb.length() - 1) != ' ') {
                    sb.append(' ');
                }
            } else if (!Character.isISOControl(ch) && Character.getType(ch) != Character.FORMAT) {
                sb.append(ch);
            }
            if (maxLen > 0 && sb.length() >= maxLen) {
                break;
            }
        }
        return sb.toString().trim();
    }

    public static void applyTheme(Scene scene) {
        if (scene == null) {
            return;
        }
        URL cssUrl = UiSafe.class.getResource(THEME_CSS_RESOURCE);
        if (cssUrl != null) {
            String urlStr = cssUrl.toExternalForm();
            if (!scene.getStylesheets().contains(urlStr)) {
                scene.getStylesheets().add(urlStr);
            }
        }
    }

    public static void applyTheme(DialogPane pane) {
        if (pane == null) {
            return;
        }
        URL cssUrl = UiSafe.class.getResource(THEME_CSS_RESOURCE);
        if (cssUrl != null) {
            String urlStr = cssUrl.toExternalForm();
            if (!pane.getStylesheets().contains(urlStr)) {
                pane.getStylesheets().add(urlStr);
            }
        }
        if (!pane.getStyleClass().contains("dialog-pane")) {
            pane.getStyleClass().add("dialog-pane");
        }
    }

    public static <T> void configureSafeTable(TableView<T> table) {
        if (table == null) {
            return;
        }
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
        Label placeholder = new Label("No records to display");
        placeholder.getStyleClass().add("muted-label");
        table.setPlaceholder(placeholder);
    }

    public static <T> TableColumn<T, String> safeColumn(String title, Function<T, String> extractor, double prefWidth) {
        TableColumn<T, String> col = new TableColumn<>(title);
        col.setPrefWidth(prefWidth);
        col.setCellValueFactory(cellData -> new javafx.beans.property.SimpleStringProperty(
                text(extractor.apply(cellData.getValue()), 256)
        ));
        return col;
    }

    public static <T> TableColumn<T, String> withBounds(TableColumn<T, String> col, double minWidth, double maxWidth) {
        if (minWidth > 0) col.setMinWidth(minWidth);
        if (maxWidth > 0) col.setMaxWidth(maxWidth);
        return col;
    }

    public static <T> TableColumn<T, String> badgeColumn(
            String title,
            Function<T, String> textExtractor,
            Function<T, String> styleClassResolver,
            double prefWidth
    ) {
        TableColumn<T, String> col = new TableColumn<>(title);
        col.setPrefWidth(prefWidth);
        col.setCellValueFactory(cellData -> new javafx.beans.property.SimpleStringProperty(
                text(textExtractor.apply(cellData.getValue()), 64)
        ));
        col.setCellFactory(tc -> new TableCell<>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setGraphic(null);
                    setText(null);
                    return;
                }
                T rowItem = getTableRow() != null ? getTableRow().getItem() : null;
                Label pill = new Label(item);
                pill.getStyleClass().add("pill");
                String variant = (rowItem != null) ? styleClassResolver.apply(rowItem) : "pill-muted";
                pill.getStyleClass().add(variant != null ? variant : "pill-muted");
                setGraphic(pill);
                setText(null);
            }
        });
        return col;
    }

    public static void copyToClipboard(String value) {
        if (value == null) {
            return;
        }
        ClipboardContent content = new ClipboardContent();
        content.putString(value);
        Clipboard.getSystemClipboard().setContent(content);
    }

    public static void runOnFxThread(Runnable task) {
        if (task == null) {
            return;
        }
        if (Platform.isFxApplicationThread()) {
            task.run();
        } else {
            Platform.runLater(task);
        }
    }

    public static void showInfo(Window owner, String title, String message) {
        showAlert(Alert.AlertType.INFORMATION, owner, title, message);
    }

    public static void showWarning(Window owner, String title, String message) {
        showAlert(Alert.AlertType.WARNING, owner, title, message);
    }

    public static void showError(Window owner, String title, String message) {
        showAlert(Alert.AlertType.ERROR, owner, title, message);
    }

    public static boolean showConfirm(Window owner, String title, String header, String message) {
        Alert alert = createAlert(Alert.AlertType.CONFIRMATION, owner, title, header, message);
        Optional<ButtonType> res = alert.showAndWait();
        return res.isPresent() && res.get() == ButtonType.OK;
    }

    public static Optional<String> promptText(Window owner, String title, String header, String label, String initialValue) {
        TextInputDialog dialog = new TextInputDialog(initialValue != null ? initialValue : "");
        if (owner != null) {
            dialog.initOwner(owner);
        }
        dialog.setTitle(title);
        dialog.setHeaderText(header);
        dialog.setContentText(label);
        applyTheme(dialog.getDialogPane());
        return dialog.showAndWait();
    }

    public static <R> Dialog<R> createDialog(Window owner, String title, String header, Node content) {
        Dialog<R> dialog = new Dialog<>();
        if (owner != null) {
            dialog.initOwner(owner);
        }
        dialog.setTitle(title);
        dialog.setHeaderText(header);
        applyTheme(dialog.getDialogPane());
        if (content != null) {
            dialog.getDialogPane().setContent(content);
            dialog.getDialogPane().setPadding(new Insets(10));
        }
        return dialog;
    }

    public static void stylePrimaryDialogButton(Dialog<?> dialog, ButtonType buttonType) {
        if (dialog == null || buttonType == null) return;
        Node btn = dialog.getDialogPane().lookupButton(buttonType);
        if (btn != null && !btn.getStyleClass().contains("btn-primary")) {
            btn.getStyleClass().add("btn-primary");
        }
    }

    public static Window windowOf(Node node) {
        return (node != null && node.getScene() != null) ? node.getScene().getWindow() : null;
    }

    public static CompletableFuture<Void> runAsync(Runnable backgroundWork) {
        return CompletableFuture.runAsync(backgroundWork);
    }

    private static void showAlert(Alert.AlertType type, Window owner, String title, String message) {
        Alert alert = createAlert(type, owner, title, null, message);
        alert.showAndWait();
    }

    private static Alert createAlert(Alert.AlertType type, Window owner, String title, String header, String message) {
        Alert alert = new Alert(type);
        if (owner != null) {
            alert.initOwner(owner);
        }
        alert.setTitle(title);
        alert.setHeaderText(header);
        Label body = new Label(message != null ? message : "");
        body.setWrapText(true);
        body.setMaxWidth(440);
        alert.getDialogPane().setContent(body);
        applyTheme(alert.getDialogPane());
        return alert;
    }
}
