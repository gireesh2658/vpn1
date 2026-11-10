package com.officevpn.gui.admin;

import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;

/**
 * JavaFX Real-Time Bounded Gateway Log Console.
 */
public final class ServerLogPanel extends VBox {

    private static final int MAX_LOG_LINES = 1000;
    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    private final Deque<String> logBuffer = new ArrayDeque<>(MAX_LOG_LINES + 1);
    private final TextField filterField = new TextField();
    private final CheckBox autoScrollCheck = new CheckBox("Auto-Scroll");
    private final Label countPill = new Label("0 Lines");
    private final TextArea consoleArea = new TextArea();

    public ServerLogPanel() {
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("admin.console.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("admin.console.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        countPill.getStyleClass().addAll("pill", "pill-muted");
        header.getChildren().addAll(titleBox, spacer, countPill);

        HBox toolbar = new HBox(10);
        toolbar.setAlignment(Pos.CENTER_LEFT);
        filterField.setPromptText("Filter console output...");
        filterField.setPrefWidth(260);
        filterField.textProperty().addListener((_, _, _) -> rerenderConsole());

        autoScrollCheck.setSelected(true);

        Button copyConsoleButton = new Button(Messages.get("admin.console.button.copyAll"));
        copyConsoleButton.getStyleClass().add("btn-secondary");
        copyConsoleButton.setOnAction(_ -> UiSafe.copyToClipboard(consoleArea.getText()));

        Button clearConsoleButton = new Button(Messages.get("admin.console.button.clear"));
        clearConsoleButton.getStyleClass().add("btn-danger");
        clearConsoleButton.setOnAction(_ -> {
            logBuffer.clear();
            consoleArea.clear();
            countPill.setText("0 Lines");
        });

        Region tbSpacer = new Region();
        HBox.setHgrow(tbSpacer, Priority.ALWAYS);
        toolbar.getChildren().addAll(filterField, autoScrollCheck, tbSpacer, copyConsoleButton, clearConsoleButton);

        consoleArea.setEditable(false);
        consoleArea.setWrapText(false);
        consoleArea.getStyleClass().add("console-area");
        VBox.setVgrow(consoleArea, Priority.ALWAYS);

        VBox card = new VBox(12, toolbar, consoleArea);
        card.getStyleClass().add("card");
        VBox.setVgrow(card, Priority.ALWAYS);

        getChildren().addAll(header, card);
    }

    public void appendLog(String rawLine) {
        String safe = UiSafe.text(rawLine, 512);
        String line = "[" + TIME_FMT.format(Instant.now()) + "] " + safe;
        UiSafe.runOnFxThread(() -> {
            if (logBuffer.size() >= MAX_LOG_LINES) {
                logBuffer.removeFirst();
            }
            logBuffer.addLast(line);
            countPill.setText(logBuffer.size() + " Lines");
            String filter = filterField.getText() != null ? filterField.getText().trim().toLowerCase(Locale.ROOT) : "";
            if (filter.isEmpty() || line.toLowerCase(Locale.ROOT).contains(filter)) {
                consoleArea.appendText(line + "\n");
                if (autoScrollCheck.isSelected()) {
                    consoleArea.positionCaret(consoleArea.getLength());
                }
            }
        });
    }

    private void rerenderConsole() {
        String filter = filterField.getText() != null ? filterField.getText().trim().toLowerCase(Locale.ROOT) : "";
        StringBuilder sb = new StringBuilder();
        for (String line : logBuffer) {
            if (filter.isEmpty() || line.toLowerCase(Locale.ROOT).contains(filter)) {
                sb.append(line).append('\n');
            }
        }
        consoleArea.setText(sb.toString());
        if (autoScrollCheck.isSelected()) {
            consoleArea.positionCaret(consoleArea.getLength());
        }
    }
}
