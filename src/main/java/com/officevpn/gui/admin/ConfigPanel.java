package com.officevpn.gui.admin;

import com.officevpn.admin.ConfigManager;
import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Allowlisted Runtime Configuration Governance Panel.
 */
public final class ConfigPanel extends VBox {

    public record ConfigEntryRow(String key, String value, String constraints) {}

    private final ConfigManager configManager;
    private final String adminUsername;

    private final TableView<ConfigEntryRow> table = new TableView<>();
    private final TextField selectedKeyField = new TextField();
    private final TextField newValueField = new TextField();
    private final Label feedbackLabel = new Label("");

    public ConfigPanel(ConfigManager configManager, String adminUsername) {
        if (adminUsername == null || adminUsername.isBlank()) {
            throw new IllegalArgumentException("Authenticated administrator username is required");
        }
        this.configManager = configManager;
        this.adminUsername = adminUsername.trim();
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
        refresh();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("admin.config.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("admin.config.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button refreshButton = new Button(Messages.get("common.refresh"));
        refreshButton.getStyleClass().add("btn-secondary");
        refreshButton.setOnAction(e -> refresh());

        Button resetDefaultsButton = new Button(Messages.get("admin.config.button.resetDefaults"));
        resetDefaultsButton.getStyleClass().add("btn-warning");
        resetDefaultsButton.setOnAction(e -> {
            if (UiSafe.showConfirm(UiSafe.windowOf(this), "Reset Configuration",
                    "Reset all allowlisted runtime parameters back to factory defaults?",
                    "This action is logged to the immutable audit trail.")) {
                resetDefaultsButton.setDisable(true);
                CompletableFuture.runAsync(() -> configManager.resetToDefaults(adminUsername))
                        .whenComplete((v, err) -> Platform.runLater(() -> {
                            resetDefaultsButton.setDisable(false);
                            if (err != null) {
                                Throwable cause = err.getCause() != null ? err.getCause() : err;
                                UiSafe.showError(UiSafe.windowOf(this), "Reset Failed", cause.getMessage());
                            } else {
                                refresh();
                                feedbackLabel.setText("All allowlisted settings reset to factory defaults.");
                            }
                        }));
            }
        });
        header.getChildren().addAll(titleBox, spacer, refreshButton, resetDefaultsButton);

        UiSafe.configureSafeTable(table);
        table.getColumns().add(UiSafe.safeColumn("Configuration Key", ConfigEntryRow::key, 240));
        table.getColumns().add(UiSafe.safeColumn("Current Value", ConfigEntryRow::value, 160));
        table.getColumns().add(UiSafe.safeColumn("Allowed Constraints", ConfigEntryRow::constraints, 340));
        VBox.setVgrow(table, Priority.ALWAYS);

        HBox editorRow = new HBox(10);
        editorRow.setAlignment(Pos.CENTER_LEFT);
        selectedKeyField.setPromptText("Select a parameter above");
        selectedKeyField.setEditable(false);
        selectedKeyField.setPrefWidth(250);
        selectedKeyField.getStyleClass().add("mono-text");

        newValueField.setPromptText("Enter new value...");
        newValueField.setPrefWidth(220);

        Button saveSettingButton = new Button(Messages.get("admin.config.button.saveSetting"));
        saveSettingButton.getStyleClass().add("btn-primary");
        saveSettingButton.setDisable(true);

        table.getSelectionModel().selectedItemProperty().addListener((obs, o, sel) -> {
            boolean has = sel != null;
            saveSettingButton.setDisable(!has);
            if (has) {
                selectedKeyField.setText(sel.key());
                newValueField.setText(sel.value());
                feedbackLabel.setText("Editing '" + sel.key() + "' (" + sel.constraints() + ")");
            } else {
                selectedKeyField.clear();
                newValueField.clear();
            }
        });

        saveSettingButton.setOnAction(e -> {
            String k = selectedKeyField.getText();
            String v = newValueField.getText();
            if (k == null || k.isBlank() || v == null) return;
            String cleanKey = k.trim();
            String cleanVal = v.trim();
            saveSettingButton.setDisable(true);
            CompletableFuture.runAsync(() -> configManager.setConfig(adminUsername, cleanKey, cleanVal))
                    .whenComplete((res, err) -> Platform.runLater(() -> {
                        saveSettingButton.setDisable(table.getSelectionModel().getSelectedItem() == null);
                        if (err != null) {
                            Throwable cause = err.getCause() != null ? err.getCause() : err;
                            UiSafe.showError(UiSafe.windowOf(this), "Validation Rejected", cause.getMessage());
                        } else {
                            refresh();
                            feedbackLabel.setText("Saved '" + cleanKey + "' = '" + cleanVal + "' cleanly.");
                        }
                    }));
        });

        feedbackLabel.getStyleClass().add("muted-label");
        editorRow.getChildren().addAll(selectedKeyField, newValueField, saveSettingButton);

        VBox card = new VBox(12, table, editorRow, feedbackLabel);
        card.getStyleClass().add("card");
        VBox.setVgrow(card, Priority.ALWAYS);

        getChildren().addAll(header, card);
    }

    public void refresh() {
        Map<String, String> all = configManager.getAllConfigs();
        table.getItems().setAll(all.entrySet().stream()
                .map(e -> new ConfigEntryRow(e.getKey(), e.getValue(), describeConstraint(e.getKey())))
                .toList());
    }

    private static String describeConstraint(String key) {
        return switch (key) {
            case "server.port" -> "Integer port in range 1 - 65535";
            case "session.timeoutMinutes" -> "Integer idle timeout 1 - 10080 minutes";
            case "tunnel.mode" -> "SPLIT or FULL";
            case "bandwidth.defaultKbpsPerUser" -> "Integer >= 64 Kbps";
            case "dns.leakProtection", "compression.enabled", "siteToSite.enabled" -> "Boolean: true or false";
            default -> "Allowlisted runtime setting";
        };
    }
}
