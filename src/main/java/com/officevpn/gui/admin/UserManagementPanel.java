package com.officevpn.gui.admin;

import com.officevpn.admin.PasswordPolicy;
import com.officevpn.admin.UsernamePolicy;
import com.officevpn.config.Messages;
import com.officevpn.db.DatabaseManager;
import com.officevpn.gui.UiSafe;
import com.officevpn.model.Department;
import com.officevpn.model.Role;
import com.officevpn.model.UserAccount;
import com.officevpn.security.TotpUtil;
import com.officevpn.server.VpnGatewayServer;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Dialog;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/**
 * JavaFX Enterprise User Lifecycle, RBAC, MFA TOTP &amp; Device Governance Panel.
 */
public final class UserManagementPanel extends VBox {

    private static final DateTimeFormatter DATE_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());

    public record UserRow(UserAccount account, boolean totpEnabled) {}

    private final DatabaseManager db;
    private volatile VpnGatewayServer gatewayServer;
    private final String adminUsername;
    private final Runnable onUsersMutated;

    private final TextField searchField = new TextField();
    private final ComboBox<String> deptFilter = new ComboBox<>();
    private final ComboBox<String> statusFilter = new ComboBox<>();
    private final TableView<UserRow> table = new TableView<>();
    private final List<UserRow> allRows = new ArrayList<>();
    private final Label statusFeedback = new Label("");

    public UserManagementPanel(
            DatabaseManager db,
            VpnGatewayServer gatewayServer,
            String adminUsername,
            Runnable onUsersMutated
    ) {
        if (adminUsername == null || adminUsername.isBlank()) {
            throw new IllegalArgumentException("Authenticated administrator username is required");
        }
        this.db = db;
        this.gatewayServer = gatewayServer;
        this.adminUsername = adminUsername.trim();
        this.onUsersMutated = onUsersMutated;

        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
        refresh();
    }

    public void setGatewayServer(VpnGatewayServer gatewayServer) {
        this.gatewayServer = gatewayServer;
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("admin.users.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("admin.users.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        statusFeedback.getStyleClass().add("muted-label");
        header.getChildren().addAll(titleBox, spacer, statusFeedback);

        // Filters
        HBox filterBar = new HBox(10);
        filterBar.setAlignment(Pos.CENTER_LEFT);
        searchField.setPromptText(Messages.get("admin.users.search.prompt"));
        searchField.setPrefWidth(220);
        searchField.textProperty().addListener((obs, o, n) -> applyFilter());

        deptFilter.getItems().add("ALL DEPARTMENTS");
        for (Department d : Department.values()) {
            deptFilter.getItems().add(d.name());
        }
        deptFilter.getSelectionModel().selectFirst();
        deptFilter.setOnAction(e -> applyFilter());

        statusFilter.getItems().addAll("ALL STATUS", "ACTIVE ONLY", "DISABLED ONLY");
        statusFilter.getSelectionModel().selectFirst();
        statusFilter.setOnAction(e -> applyFilter());

        Button refreshButton = new Button(Messages.get("common.refresh"));
        refreshButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(refreshButton, Messages.get("common.refresh"), null);
        refreshButton.setOnAction(e -> refresh());

        Button addEmployeeButton = new Button(Messages.get("admin.users.button.addEmployee"));
        addEmployeeButton.getStyleClass().add("btn-primary");
        Messages.configureAccessibleControl(addEmployeeButton, Messages.get("admin.users.button.addEmployee"), null);
        addEmployeeButton.setOnAction(e -> handleCreateUser());

        Region fSpacer = new Region();
        HBox.setHgrow(fSpacer, Priority.ALWAYS);
        filterBar.getChildren().addAll(searchField, deptFilter, statusFilter, refreshButton, fSpacer, addEmployeeButton);

        // Action Bar (selection bound)
        FlowPane actionBar = new FlowPane(8, 8);
        Button changePasswordButton = new Button(Messages.get("admin.users.button.resetPw"));
        Button changeRoleButton = new Button(Messages.get("admin.users.button.changeRole"));
        Button changeDepartmentButton = new Button(Messages.get("admin.users.button.changeDept"));
        Button toggleActiveButton = new Button(Messages.get("admin.users.button.disable"));
        toggleActiveButton.getStyleClass().add("btn-warning");
        Button removeEmployeeButton = new Button(Messages.get("admin.users.button.removeEmployee"));
        removeEmployeeButton.getStyleClass().add("btn-danger");
        Button unlockAccountButton = new Button(Messages.get("admin.users.button.unlock"));
        Button manageTotpButton = new Button(Messages.get("admin.users.button.manageTotp"));
        Button trustAllDevicesButton = new Button(Messages.get("admin.users.button.trustAll"));
        trustAllDevicesButton.getStyleClass().add("btn-success");
        Button revokeDevicesButton = new Button(Messages.get("admin.users.button.revokeDevices"));
        revokeDevicesButton.getStyleClass().add("btn-danger");

        List<Button> selectionButtons = List.of(
                changePasswordButton, changeRoleButton, changeDepartmentButton, toggleActiveButton,
                removeEmployeeButton, unlockAccountButton, manageTotpButton, trustAllDevicesButton, revokeDevicesButton
        );
        selectionButtons.forEach(b -> b.setDisable(true));

        table.getSelectionModel().selectedItemProperty().addListener((obs, o, sel) -> {
            boolean hasSel = sel != null;
            selectionButtons.forEach(b -> b.setDisable(!hasSel));
            if (hasSel) {
                toggleActiveButton.setText(sel.account().active()
                        ? Messages.get("admin.users.button.disable")
                        : Messages.get("admin.users.button.enable"));
            }
        });

        changePasswordButton.setOnAction(e -> handleResetPassword(selectedUser()));
        changeRoleButton.setOnAction(e -> handleChangeRole(selectedUser()));
        changeDepartmentButton.setOnAction(e -> handleChangeDept(selectedUser()));
        toggleActiveButton.setOnAction(e -> handleToggleActive(selectedUser()));
        removeEmployeeButton.setOnAction(e -> handleDeleteUser(selectedUser()));
        unlockAccountButton.setOnAction(e -> handleUnlockAccount(selectedUser()));
        manageTotpButton.setOnAction(e -> handleManageTotp(selectedRow()));
        trustAllDevicesButton.setOnAction(e -> handleTrustAllDevices(selectedUser()));
        revokeDevicesButton.setOnAction(e -> handleRevokeAllDevices(selectedUser()));

        actionBar.getChildren().addAll(
                changePasswordButton, changeRoleButton, changeDepartmentButton, toggleActiveButton,
                removeEmployeeButton, unlockAccountButton, manageTotpButton, trustAllDevicesButton, revokeDevicesButton
        );

        UiSafe.configureSafeTable(table);
        table.getColumns().add(UiSafe.safeColumn("ID", r -> String.valueOf(r.account().id()), 60));
        table.getColumns().add(UiSafe.safeColumn("Username", r -> r.account().username(), 150));
        table.getColumns().add(UiSafe.safeColumn("Department", r -> r.account().department().name(), 130));
        table.getColumns().add(UiSafe.badgeColumn("Role", r -> r.account().role().name(),
                r -> r.account().role() == Role.ADMIN ? "pill-danger"
                        : (r.account().role() == Role.AUDITOR ? "pill-warning" : "pill-info"), 110));
        table.getColumns().add(UiSafe.badgeColumn("TOTP 2FA", r -> r.totpEnabled() ? "ENABLED" : "OFF",
                r -> r.totpEnabled() ? "pill-success" : "pill-muted", 100));
        table.getColumns().add(UiSafe.badgeColumn("Status", r -> r.account().active() ? "ACTIVE" : "DISABLED",
                r -> r.account().active() ? "pill-success" : "pill-danger", 105));
        table.getColumns().add(UiSafe.safeColumn("Created",
                r -> DATE_FMT.format(Instant.ofEpochMilli(r.account().createdAt())), 150));
        VBox.setVgrow(table, Priority.ALWAYS);

        VBox card = new VBox(12, filterBar, actionBar, table);
        card.getStyleClass().add("card");
        VBox.setVgrow(card, Priority.ALWAYS);

        getChildren().addAll(header, card);
    }

    private UserAccount selectedUser() {
        UserRow row = table.getSelectionModel().getSelectedItem();
        return row != null ? row.account() : null;
    }

    private UserRow selectedRow() {
        return table.getSelectionModel().getSelectedItem();
    }

    public void refresh() {
        if (db.isClosed()) return;
        CompletableFuture.supplyAsync(() -> {
            if (db.isClosed()) return null;
            List<UserAccount> users = db.listAllUsers();
            List<UserRow> rows = new ArrayList<>(users.size());
            for (UserAccount u : users) {
                rows.add(new UserRow(u, db.isTotpEnabled(u.username())));
            }
            return rows;
        }).thenAccept(rows -> Platform.runLater(() -> {
            if (rows == null) return;
            allRows.clear();
            allRows.addAll(rows);
            applyFilter();
        }));
    }

    private void applyFilter() {
        String q = searchField.getText() != null ? searchField.getText().trim().toLowerCase(Locale.ROOT) : "";
        String dept = deptFilter.getValue();
        String status = statusFilter.getValue();
        table.getItems().setAll(allRows.stream().filter(r -> {
            UserAccount u = r.account();
            if (!q.isEmpty() && !u.username().toLowerCase(Locale.ROOT).contains(q)) {
                return false;
            }
            if (dept != null && !"ALL DEPARTMENTS".equals(dept) && !u.department().name().equals(dept)) {
                return false;
            }
            if ("ACTIVE ONLY".equals(status) && !u.active()) return false;
            if ("DISABLED ONLY".equals(status) && u.active()) return false;
            return true;
        }).toList());
    }

    private void handleCreateUser() {
        TextField userField = new TextField();
        userField.setPromptText("3-32 chars (letters, digits, _)");
        PasswordField passField = new PasswordField();
        passField.setPromptText("Min 12 chars with upper, lower, digit, symbol");
        Label genPreview = new Label("");
        genPreview.getStyleClass().add("mono-text");
        genPreview.setStyle("-fx-text-fill: #22d3ee;");

        Button genBtn = new Button(Messages.get("admin.users.dialog.generate"));
        genBtn.getStyleClass().add("btn-secondary");
        genBtn.setOnAction(e -> {
            String generated = PasswordPolicy.generateStrongPassword(16);
            passField.setText(generated);
            genPreview.setText(Messages.get("admin.users.dialog.generatedHidden"));
            UiSafe.copyToClipboard(generated);
        });

        ComboBox<Department> deptBox = new ComboBox<>();
        deptBox.getItems().addAll(Department.values());
        deptBox.setValue(Department.IT);

        ComboBox<Role> roleBox = new ComboBox<>();
        roleBox.getItems().addAll(Role.values());
        roleBox.setValue(Role.EMPLOYEE);

        VBox content = new VBox(8,
                new Label(Messages.get("common.label.username")), userField,
                new Label(Messages.get("admin.users.dialog.add.label.passphrase")), passField,
                new HBox(8, genBtn, genPreview),
                new Label(Messages.get("admin.users.dialog.add.label.department")), deptBox,
                new Label(Messages.get("admin.users.dialog.add.label.role")), roleBox
        );
        content.setPrefWidth(430);

        Dialog<ButtonType> dialog = UiSafe.createDialog(UiSafe.windowOf(this),
                Messages.get("admin.users.dialog.add.title"),
                Messages.get("admin.users.dialog.add.header"), content);
        ButtonType createType = new ButtonType(Messages.get("admin.users.button.addEmployee"), ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(createType, ButtonType.CANCEL);
        UiSafe.stylePrimaryDialogButton(dialog, createType);

        Optional<ButtonType> res = dialog.showAndWait();
        if (res.isEmpty() || res.get() != createType) {
            return;
        }

        String uname = userField.getText() != null ? userField.getText().trim() : "";
        char[] pw = passField.getText().toCharArray();
        Department dept = deptBox.getValue();
        Role role = roleBox.getValue();

        try {
            UsernamePolicy.validateUsername(uname);
            PasswordPolicy.validatePassword(pw, uname);
        } catch (IllegalArgumentException ex) {
            Arrays.fill(pw, '\0');
            UiSafe.showError(UiSafe.windowOf(this), "Validation Error", ex.getMessage());
            return;
        }

        runDbTask("Creating user " + uname + "...", () -> {
            try {
                db.createUser(uname, pw, dept, role, adminUsername);
                return "Created user '" + uname + "' (" + dept + " / " + role + ").";
            } finally {
                Arrays.fill(pw, '\0');
            }
        });
    }

    private void handleResetPassword(UserAccount target) {
        if (target == null) return;
        PasswordField passField = new PasswordField();
        passField.setPromptText("New strong passphrase (min 12 chars)");
        Label genPreview = new Label("");
        genPreview.getStyleClass().add("mono-text");
        genPreview.setStyle("-fx-text-fill: #22d3ee;");

        Button genBtn = new Button(Messages.get("admin.users.dialog.generate"));
        genBtn.getStyleClass().add("btn-secondary");
        genBtn.setOnAction(e -> {
            String generated = PasswordPolicy.generateStrongPassword(16);
            passField.setText(generated);
            genPreview.setText(Messages.get("admin.users.dialog.generatedHidden"));
            UiSafe.copyToClipboard(generated);
        });

        VBox content = new VBox(8, new Label(Messages.format("admin.users.dialog.reset.label", target.username())),
                passField, genBtn, genPreview);
        content.setPrefWidth(420);
        Dialog<ButtonType> dialog = UiSafe.createDialog(UiSafe.windowOf(this),
                Messages.get("admin.users.dialog.reset.title"),
                Messages.format("admin.users.dialog.reset.header", target.username()), content);
        ButtonType okType = new ButtonType(Messages.get("client.password.button.save"), ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(okType, ButtonType.CANCEL);
        UiSafe.stylePrimaryDialogButton(dialog, okType);

        if (dialog.showAndWait().orElse(ButtonType.CANCEL) != okType) return;
        char[] pw = passField.getText().toCharArray();
        try {
            PasswordPolicy.validatePassword(pw, target.username());
        } catch (IllegalArgumentException ex) {
            Arrays.fill(pw, '\0');
            UiSafe.showError(UiSafe.windowOf(this), "Invalid Passphrase", ex.getMessage());
            return;
        }
        runDbTask("Resetting password for " + target.username() + "...", () -> {
            try {
                db.resetPassword(target.username(), pw, adminUsername);
                return "Password reset cleanly for '" + target.username() + "'.";
            } finally {
                Arrays.fill(pw, '\0');
            }
        });
    }

    private void handleChangeRole(UserAccount target) {
        if (target == null) return;
        ComboBox<Role> box = new ComboBox<>();
        box.getItems().addAll(Role.values());
        box.setValue(target.role());
        VBox content = new VBox(8, new Label(Messages.format("admin.users.dialog.role.label", target.username())), box);
        Dialog<ButtonType> dialog = UiSafe.createDialog(UiSafe.windowOf(this),
                Messages.get("admin.users.dialog.role.title"),
                Messages.format("admin.users.dialog.role.header", target.username()), content);
        ButtonType okType = new ButtonType(Messages.get("admin.users.dialog.role.save"), ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(okType, ButtonType.CANCEL);
        if (dialog.showAndWait().orElse(ButtonType.CANCEL) != okType) return;
        Role newRole = box.getValue();
        runDbTask("Updating role...", () -> {
            db.changeRole(target.username(), newRole, adminUsername);
            return "Updated role of '" + target.username() + "' to " + newRole + ".";
        });
    }

    private void handleChangeDept(UserAccount target) {
        if (target == null) return;
        ComboBox<Department> box = new ComboBox<>();
        box.getItems().addAll(Department.values());
        box.setValue(target.department());
        VBox content = new VBox(8, new Label(Messages.format("admin.users.dialog.dept.label", target.username())), box);
        Dialog<ButtonType> dialog = UiSafe.createDialog(UiSafe.windowOf(this),
                Messages.get("admin.users.dialog.dept.title"),
                Messages.format("admin.users.dialog.dept.header", target.username()), content);
        ButtonType okType = new ButtonType(Messages.get("admin.users.dialog.dept.save"), ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(okType, ButtonType.CANCEL);
        if (dialog.showAndWait().orElse(ButtonType.CANCEL) != okType) return;
        Department newDept = box.getValue();
        runDbTask("Updating department...", () -> {
            db.changeDepartment(target.username(), newDept, adminUsername);
            return "Updated department of '" + target.username() + "' to " + newDept + ".";
        });
    }

    private void handleToggleActive(UserAccount target) {
        if (target == null) return;
        boolean newState = !target.active();
        String verb = newState ? "Enable" : "Disable";
        if (!UiSafe.showConfirm(UiSafe.windowOf(this), verb + " Account",
                verb + " account '" + target.username() + "'?",
                newState ? "The user will be permitted to establish VPN sessions."
                        : "The user will be blocked and any live sessions immediately disconnected.")) {
            return;
        }
        runDbTask(verb + " account...", () -> {
            db.setUserActiveStatus(target.username(), newState, adminUsername);
            if (!newState && gatewayServer != null) {
                gatewayServer.disconnectUser(target.username(), "Account disabled by admin", adminUsername);
            }
            return "User '" + target.username() + "' is now " + (newState ? "ACTIVE" : "DISABLED") + ".";
        });
    }

    private void handleDeleteUser(UserAccount target) {
        if (target == null) return;
        if (!UiSafe.showConfirm(UiSafe.windowOf(this), "Soft-Delete Account",
                "Soft-delete (deactivate) '" + target.username() + "'?",
                "This deactivates login access while preserving tamper-evident audit trails.")) {
            return;
        }
        runDbTask("Deactivating account...", () -> {
            db.deleteUser(target.username(), adminUsername);
            if (gatewayServer != null) {
                gatewayServer.disconnectUser(target.username(), "Account deleted by admin", adminUsername);
            }
            return "Soft-deleted account '" + target.username() + "'.";
        });
    }

    private void handleUnlockAccount(UserAccount target) {
        if (target == null) return;
        runDbTask("Unlocking account...", () -> {
            db.unlockAccount(target.username(), adminUsername);
            return "Cleared progressive brute-force lockouts for '" + target.username() + "'.";
        });
    }

    private void handleManageTotp(UserRow row) {
        if (row == null) return;
        UserAccount u = row.account();
        if (row.totpEnabled()) {
            if (!UiSafe.showConfirm(UiSafe.windowOf(this), "Disable TOTP 2FA",
                    "Disable Two-Factor Authentication for '" + u.username() + "'?",
                    "The user will authenticate with password only until re-enrolled.")) {
                return;
            }
            runDbTask("Disabling TOTP...", () -> {
                db.disableTotp(u.username(), adminUsername);
                return "Disabled TOTP 2FA for '" + u.username() + "'.";
            });
        } else {
            String secret = TotpUtil.generateSecret();
            String encodedUser = java.net.URLEncoder.encode(u.username(), java.nio.charset.StandardCharsets.UTF_8);
            String uri = "otpauth://totp/OfficeVPN:" + encodedUser + "?secret=" + secret + "&issuer=OfficeVPN";
            VBox box = new VBox(8);
            Label sLbl = new Label("Base32 Secret: " + secret);
            sLbl.getStyleClass().add("mono-text");
            sLbl.setStyle("-fx-text-fill: #22d3ee; -fx-font-weight: bold;");
            TextField uriField = new TextField(uri);
            uriField.setEditable(false);
            uriField.getStyleClass().add("mono-text");
            Button copyBtn = new Button(Messages.get("admin.users.dialog.totp.copySecret"));
            copyBtn.getStyleClass().add("btn-secondary");
            copyBtn.setOnAction(e -> UiSafe.copyToClipboard(secret));
            Button copyUriBtn = new Button(Messages.get("admin.users.dialog.totp.copyUri"));
            copyUriBtn.getStyleClass().add("btn-secondary");
            copyUriBtn.setOnAction(e -> UiSafe.copyToClipboard(uri));
            box.getChildren().addAll(
                    new Label(Messages.get("admin.users.dialog.totp.instruction")),
                    sLbl, new Label("otpauth URI"), uriField, new HBox(8, copyBtn, copyUriBtn));
            box.setPrefWidth(480);

            Dialog<ButtonType> dialog = UiSafe.createDialog(UiSafe.windowOf(this),
                    Messages.get("admin.users.dialog.totp.title"),
                    Messages.format("admin.users.dialog.totp.header", u.username()), box);
            ButtonType saveBtn = new ButtonType(Messages.get("admin.users.dialog.totp.save"), ButtonBar.ButtonData.OK_DONE);
            dialog.getDialogPane().getButtonTypes().addAll(saveBtn, ButtonType.CANCEL);
            UiSafe.stylePrimaryDialogButton(dialog, saveBtn);
            if (dialog.showAndWait().orElse(ButtonType.CANCEL) != saveBtn) return;

            runDbTask("Saving TOTP secret...", () -> {
                db.saveTotpSecret(u.username(), secret);
                db.logAuditEvent("ADMIN_TOTP_ENABLED", u.username(), u.department().name(),
                        "Enabled TOTP MFA via dashboard", adminUsername, "local");
                return "TOTP 2FA enabled for '" + u.username() + "'.";
            });
        }
    }

    private void handleTrustAllDevices(UserAccount target) {
        if (target == null) return;
        runDbTask("Trusting devices...", () -> {
            int n = db.trustAllDevicesForUser(target.username());
            if (n > 0) {
                db.logAuditEvent("ALL_DEVICES_TRUSTED", target.username(), target.department().name(),
                        "All registered devices trusted (count=" + n + ")", adminUsername, "local");
            }
            return "Marked " + n + " device(s) as TRUSTED for '" + target.username() + "'.";
        });
    }

    private void handleRevokeAllDevices(UserAccount target) {
        if (target == null) return;
        if (!UiSafe.showConfirm(UiSafe.windowOf(this), "Revoke All Devices",
                "Revoke trust for all registered hardware of '" + target.username() + "'?",
                "New logins from those devices will be blocked fail-closed.")) {
            return;
        }
        runDbTask("Revoking devices...", () -> {
            int n = db.revokeAllDevicesForUser(target.username());
            if (n > 0) {
                db.logAuditEvent("ALL_DEVICES_REVOKED", target.username(), target.department().name(),
                        "All registered devices revoked (count=" + n + ")", adminUsername, "local");
            }
            return "Revoked trust on " + n + " device(s) for '" + target.username() + "'.";
        });
    }

    private void runDbTask(String busyMsg, Supplier<String> work) {
        statusFeedback.setText(busyMsg);
        CompletableFuture.supplyAsync(work).whenComplete((msg, err) -> Platform.runLater(() -> {
            if (err != null) {
                Throwable cause = err.getCause() != null ? err.getCause() : err;
                statusFeedback.setText("Error: " + cause.getMessage());
                UiSafe.showError(UiSafe.windowOf(this), "Operation Failed", cause.getMessage());
            } else {
                statusFeedback.setText(msg);
                refresh();
                if (onUsersMutated != null) {
                    onUsersMutated.run();
                }
            }
        }));
    }
}
