package com.officevpn.gui.admin;

import com.officevpn.admin.ConfigManager;
import com.officevpn.gui.UiSafe;
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
        this.configManager = configManager;
        this.adminUsername = adminUsername != null ? adminUsername : "admin_hq";
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
        refresh();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label("Gateway Runtime Configuration");
        title.getStyleClass().add("page-title");
        Label subtitle = new Label("Inspect and adjust allowlisted gateway parameters with strict validation & MySQL audit logging");
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button refreshBtn = new Button("Refresh");
        refreshBtn.getStyleClass().add("btn-secondary");
        refreshBtn.setOnAction(e -> refresh());

        Button resetBtn = new Button("Reset All Defaults");
        resetBtn.getStyleClass().add("btn-warning");
        resetBtn.setOnAction(e -> {
            if (UiSafe.showConfirm(UiSafe.windowOf(this), "Reset Configuration",
                    "Reset all allowlisted runtime parameters back to secure factory defaults?",
                    "This action is logged to the immutable audit trail.")) {
                configManager.resetToDefaults(adminUsername);
                refresh();
                feedbackLabel.setText("All allowlisted settings reset to factory defaults.");
            }
        });
        header.getChildren().addAll(titleBox, spacer, refreshBtn, resetBtn);

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

        Button applyBtn = new Button("Apply & Audit");
        applyBtn.getStyleClass().add("btn-primary");
        applyBtn.setDisable(true);

        table.getSelectionModel().selectedItemProperty().addListener((obs, o, sel) -> {
            boolean has = sel != null;
            applyBtn.setDisable(!has);
            if (has) {
                selectedKeyField.setText(sel.key());
                newValueField.setText(sel.value());
                feedbackLabel.setText("Editing '" + sel.key() + "' (" + sel.constraints() + ")");
            } else {
                selectedKeyField.clear();
                newValueField.clear();
            }
        });

        applyBtn.setOnAction(e -> {
            String k = selectedKeyField.getText();
            String v = newValueField.getText();
            if (k == null || k.isBlank() || v == null) return;
            try {
                configManager.setConfig(adminUsername, k.trim(), v.trim());
                refresh();
                feedbackLabel.setText("Saved '" + k.trim() + "' = '" + v.trim() + "' cleanly.");
            } catch (IllegalArgumentException ex) {
                UiSafe.showError(UiSafe.windowOf(this), "Validation Rejected", ex.getMessage());
            }
        });

        feedbackLabel.getStyleClass().add("muted-label");
        editorRow.getChildren().addAll(selectedKeyField, newValueField, applyBtn);

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
