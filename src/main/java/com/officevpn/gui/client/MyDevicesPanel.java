package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.config.ConfigUtil;
import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import com.officevpn.util.HardwareUtil;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.util.List;

/**
 * JavaFX Client Local Hardware Identity &amp; Zero-Trust Session Binding Panel.
 */
public final class MyDevicesPanel extends VBox {

    public record IdentityPropertyRow(String attribute, String value, String trustBadge) {}

    private final VpnClientEngine engine;
    private final TableView<IdentityPropertyRow> table = new TableView<>();

    public MyDevicesPanel(VpnClientEngine engine) {
        this.engine = engine;
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("hardware.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("hardware.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        String fp = HardwareUtil.getAuthenticHardwareFingerprint();
        Button copyFingerprintButton = new Button(Messages.get("hardware.button.copyFp"));
        copyFingerprintButton.getStyleClass().add("btn-primary");
        Messages.configureAccessibleControl(copyFingerprintButton,
                Messages.get("hardware.button.copyFp"),
                Messages.get("hardware.tooltip.copyFp"));
        copyFingerprintButton.setOnAction(e -> {
            UiSafe.copyToClipboard(fp);
            UiSafe.showInfo(UiSafe.windowOf(this), "Fingerprint Copied",
                    "Copied authentic SHA-256 hardware fingerprint to clipboard:\n" + fp);
        });
        header.getChildren().addAll(titleBox, spacer, copyFingerprintButton);

        UiSafe.configureSafeTable(table);
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Security Attribute", IdentityPropertyRow::attribute, 225), 200, 245));
        table.getColumns().add(UiSafe.withBounds(UiSafe.safeColumn("Observed Value", IdentityPropertyRow::value, 510), 420, 0));
        table.getColumns().add(UiSafe.withBounds(UiSafe.badgeColumn("Verification Status", IdentityPropertyRow::trustBadge,
                r -> "ENFORCED".equals(r.trustBadge()) || "ACTIVE".equals(r.trustBadge()) ? "pill-success" : "pill-info", 145), 130, 155));
        VBox.setVgrow(table, Priority.ALWAYS);

        List<IdentityPropertyRow> rows = buildRows();
        table.getItems().setAll(rows);

        VBox card = new VBox(12, table);
        card.getStyleClass().add("card");
        VBox.setVgrow(card, Priority.ALWAYS);

        getChildren().addAll(header, card);
    }

    /**
     * Refreshes local hardware identity and active session attributes after login/disconnect.
     */
    public void refresh() {
        table.getItems().setAll(buildRows());
    }

    private List<IdentityPropertyRow> buildRows() {
        String fp = HardwareUtil.getAuthenticHardwareFingerprint();
        boolean authed = engine != null && engine.isConnected() && engine.isAuthenticated();
        String userVal = authed ? UiSafe.text(engine.getUsername(), 64) : "Not signed in";
        String deptVal = authed && engine.getDepartment() != null ? engine.getDepartment().name() : "-";
        String roleVal = authed && engine.getRole() != null ? engine.getRole().name() : "-";
        String vipVal = authed ? UiSafe.text(engine.getAssignedVirtualIp(), 32) : "0.0.0.0";
        String gwFp = (engine != null && engine.getServerFingerprint() != null && !engine.getServerFingerprint().isBlank())
                ? UiSafe.text(engine.getServerFingerprint(), 128) : "Not connected";
        return List.of(
                new IdentityPropertyRow("Authenticated Account", userVal, authed ? "ACTIVE" : "OFFLINE"),
                new IdentityPropertyRow("Assigned Department", deptVal, authed ? "ENFORCED" : "OFFLINE"),
                new IdentityPropertyRow("Assigned Role", roleVal, authed ? "ENFORCED" : "OFFLINE"),
                new IdentityPropertyRow("Virtual Tunnel IP", vipVal, authed ? "ACTIVE" : "OFFLINE"),
                new IdentityPropertyRow("Authentic Device Name", UiSafe.text(HardwareUtil.getAuthenticDeviceName(), 128), "VERIFIED"),
                new IdentityPropertyRow("Hardware SHA-256 Fingerprint", fp, "VERIFIED"),
                new IdentityPropertyRow("Account Device Enrollment Cap", ConfigUtil.getMaxDevicesPerUser() + " authorized hardware device(s)", "ENFORCED"),
                new IdentityPropertyRow("Pinned Gateway Fingerprint", gwFp, (engine != null && engine.getServerFingerprint() != null) ? "TOFU PINNED" : "PENDING")
        );
    }
}
