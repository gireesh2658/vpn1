package com.officevpn.ui.components;

import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.WorkModeProfile;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Tokens;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.AccessibleRole;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.Skin;
import javafx.scene.control.SkinBase;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import org.kordamp.ikonli.feather.Feather;

import java.util.Comparator;
import java.util.List;
import java.util.function.Consumer;

/**
 * WorkModes presents routing profiles (Split Tunnel, Office Only, Full Tunnel, Guest-Safe)
 * as stacked warm swatch cards with pin & recent prioritization, a Connect-and-Go action that
 * activates the tunnel and launches a target workspace URL, and an inline Edit side sheet.
 */
public final class WorkModes extends Control {

    private final ObservableList<WorkModeProfile> profiles = FXCollections.observableArrayList();
    private final ObjectProperty<WorkModeProfile> activeProfile = new SimpleObjectProperty<>(null);
    private final ObjectProperty<Consumer<WorkModeProfile>> onActivateProfile = new SimpleObjectProperty<>(p -> {});
    private final ObjectProperty<Consumer<WorkModeProfile>> onTogglePin = new SimpleObjectProperty<>(p -> {});
    private final ObjectProperty<Consumer<WorkModeProfile>> onSaveProfile = new SimpleObjectProperty<>(p -> {});
    private final ObjectProperty<Consumer<WorkModeProfile>> onConnectAndGo = new SimpleObjectProperty<>(p -> {});

    public WorkModes() {
        getStyleClass().setAll("work-modes");
        setFocusTraversable(true);
        setAccessibleRole(AccessibleRole.LIST_VIEW);
        setAccessibleText("Work Modes profile selector");
    }

    public void bindService(VpnClientService service, Consumer<String> toastCallback) {
        if (service == null) return;
        Runnable sync = () -> profiles.setAll(service.workModes());
        service.workModes().addListener((ListChangeListener<WorkModeProfile>) c -> sync.run());
        sync.run();
        activeProfile.set(service.activeWorkModeProperty().get());
        service.activeWorkModeProperty().addListener((obs, o, n) -> activeProfile.set(n));

        onActivateProfile.set(p -> {
            if (p != null) service.activateWorkMode(p.id());
        });
        onTogglePin.set(p -> {
            if (p != null) service.togglePinWorkMode(p.id());
        });
        onSaveProfile.set(service::updateWorkMode);
        onConnectAndGo.set(p -> {
            if (p != null) {
                service.activateWorkMode(p.id());
                service.connect();
                if (toastCallback != null) {
                    toastCallback.accept("Connect-and-Go: tunnel armed -> opening " + p.launchUrl());
                }
            }
        });
    }

    public static Node createStandaloneDemo(VpnClientService service) {
        WorkModes wm = new WorkModes();
        wm.bindService(service, null);
        return wm;
    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new WorkModesSkin(this);
    }

    public ObservableList<WorkModeProfile> profiles() { return profiles; }
    public ObjectProperty<WorkModeProfile> activeProfileProperty() { return activeProfile; }
    public ObjectProperty<Consumer<WorkModeProfile>> onActivateProfileProperty() { return onActivateProfile; }
    public ObjectProperty<Consumer<WorkModeProfile>> onTogglePinProperty() { return onTogglePin; }
    public ObjectProperty<Consumer<WorkModeProfile>> onSaveProfileProperty() { return onSaveProfile; }
    public ObjectProperty<Consumer<WorkModeProfile>> onConnectAndGoProperty() { return onConnectAndGo; }

    private static final class WorkModesSkin extends SkinBase<WorkModes> {

        private final HBox splitRoot = new HBox(16);
        private final VBox cardsColumn = new VBox(10);
        private final VBox sideSheet = new VBox(10);

        private final TextField subtitleField = new TextField();
        private final TextField urlField = new TextField();
        private final TextField dnsField = new TextField();
        private final Label sheetTitle = new Label("Edit Mode");
        private WorkModeProfile editingTarget;

        WorkModesSkin(WorkModes control) {
            super(control);

            HBox.setHgrow(cardsColumn, Priority.ALWAYS);
            setupEditSheet(control);

            splitRoot.getChildren().addAll(cardsColumn, sideSheet);
            getChildren().add(splitRoot);

            control.profiles().addListener((ListChangeListener<WorkModeProfile>) c -> rebuildCards());
            control.activeProfileProperty().addListener((obs, o, n) -> rebuildCards());
            rebuildCards();
        }

        private void setupEditSheet(WorkModes control) {
            sideSheet.getStyleClass().add("ia-card-paper");
            sideSheet.setPadding(new Insets(16));
            sideSheet.setMinWidth(260);
            sideSheet.setPrefWidth(290);
            sideSheet.setEffect(Tokens.createContactShadow());
            sideSheet.setVisible(false);
            sideSheet.setManaged(false);

            sheetTitle.getStyleClass().add("ia-card-title");
            Label l1 = new Label("Description");
            l1.getStyleClass().add("ia-section-label");
            Label l2 = new Label("Connect-and-Go URL / App");
            l2.getStyleClass().add("ia-section-label");
            Label l3 = new Label("DNS Policy");
            l3.getStyleClass().add("ia-section-label");

            Button saveBtn = new Button("Save Profile");
            saveBtn.getStyleClass().add("ia-btn-marigold");
            saveBtn.setOnAction(e -> {
                if (editingTarget != null) {
                    WorkModeProfile updated = editingTarget.withEdited(
                            subtitleField.getText().trim(),
                            urlField.getText().trim(),
                            dnsField.getText().trim()
                    );
                    var cb = control.onSaveProfileProperty().get();
                    if (cb != null) cb.accept(updated);
                }
                closeSheet();
            });

            Button cancelBtn = new Button("Close");
            cancelBtn.setOnAction(e -> closeSheet());

            HBox actions = new HBox(8, saveBtn, cancelBtn);
            sideSheet.getChildren().addAll(sheetTitle, l1, subtitleField, l2, urlField, l3, dnsField, actions);
        }

        private void openSheet(WorkModeProfile p) {
            editingTarget = p;
            sheetTitle.setText("Edit: " + p.name());
            subtitleField.setText(p.subtitle());
            urlField.setText(p.launchUrl());
            dnsField.setText(p.dnsPolicy());
            sideSheet.setVisible(true);
            sideSheet.setManaged(true);
        }

        private void closeSheet() {
            editingTarget = null;
            sideSheet.setVisible(false);
            sideSheet.setManaged(false);
        }

        private void rebuildCards() {
            cardsColumn.getChildren().clear();
            WorkModeProfile active = getSkinnable().activeProfileProperty().get();

            List<WorkModeProfile> sorted = getSkinnable().profiles().stream()
                    .sorted(Comparator
                            .comparing(WorkModeProfile::pinned).reversed()
                            .thenComparing(Comparator.comparingLong(WorkModeProfile::lastUsedEpochMs).reversed()))
                    .toList();

            for (WorkModeProfile p : sorted) {
                cardsColumn.getChildren().add(createSwatchCard(p, active != null && active.id().equals(p.id())));
            }
        }

        private HBox createSwatchCard(WorkModeProfile p, boolean isActive) {
            Region swatchBar = new Region();
            swatchBar.setMinWidth(6);
            swatchBar.setPrefWidth(6);
            swatchBar.setStyle("-fx-background-color: " + resolveAccentHex(p.accentRole()) + "; -fx-background-radius: 6px;");

            Label name = new Label(p.name());
            name.setFont(Fonts.displaySemiBold(15.5));
            name.setTextFill(Tokens.INK);

            Label typePill = new Label(p.profileType().label());
            typePill.getStyleClass().addAll("ia-pill", isActive ? "ia-pill-marigold" : "ia-pill-sand");

            HBox titleRow = new HBox(8, name, typePill);
            if (p.pinned()) {
                Label pinPill = new Label("Pinned");
                pinPill.getStyleClass().addAll("ia-pill", "ia-pill-peacock");
                titleRow.getChildren().add(pinPill);
            }
            titleRow.setAlignment(Pos.CENTER_LEFT);

            Label sub = new Label(p.subtitle());
            sub.getStyleClass().add("ia-subtitle");

            Label meta = new Label("DNS: " + p.dnsPolicy() + "  •  Go: " + p.launchUrl());
            meta.setFont(Fonts.monoRegular(11));
            meta.setTextFill(Tokens.SOFT_INK);

            VBox info = new VBox(4, titleRow, sub, meta);
            info.setMinWidth(0);
            HBox.setHgrow(info, Priority.ALWAYS);

            Button pinBtn = new Button(p.pinned() ? "Unpin" : "Pin");
            pinBtn.setGraphic(Icons.soft(Feather.BOOKMARK, 13));
            pinBtn.setMinWidth(Region.USE_PREF_SIZE);
            pinBtn.setOnAction(e -> {
                var cb = getSkinnable().onTogglePinProperty().get();
                if (cb != null) cb.accept(p);
                e.consume();
            });

            Button editBtn = new Button("Edit");
            editBtn.setGraphic(Icons.ink(Feather.EDIT_2, 13));
            editBtn.setMinWidth(Region.USE_PREF_SIZE);
            editBtn.setOnAction(e -> {
                openSheet(p);
                e.consume();
            });

            Button goBtn = new Button("Connect & Go");
            goBtn.getStyleClass().add("ia-btn-marigold");
            goBtn.setGraphic(Icons.ink(Feather.ARROW_UP_RIGHT, 13));
            goBtn.setMinWidth(Region.USE_PREF_SIZE);
            goBtn.setOnAction(e -> {
                var cb = getSkinnable().onConnectAndGoProperty().get();
                if (cb != null) cb.accept(p);
                e.consume();
            });

            HBox buttons = new HBox(8, pinBtn, editBtn, goBtn);
            buttons.setAlignment(Pos.CENTER_RIGHT);
            buttons.setMinWidth(Region.USE_PREF_SIZE);

            HBox card = new HBox(14, swatchBar, info, buttons);
            card.getStyleClass().add("work-mode-swatch");
            if (isActive) {
                card.getStyleClass().add("work-mode-swatch-active");
            }
            card.setAlignment(Pos.CENTER_LEFT);
            card.setOnMouseClicked(e -> {
                var cb = getSkinnable().onActivateProfileProperty().get();
                if (cb != null) cb.accept(p);
            });
            return card;
        }

        private static String resolveAccentHex(String role) {
            if (role == null) return Tokens.PEACOCK_HEX;
            return switch (role) {
                case "marigold" -> Tokens.MARIGOLD_HEX;
                case "coral"    -> Tokens.CORAL_HEX;
                case "lilac"    -> Tokens.LILAC_HEX;
                default         -> Tokens.PEACOCK_HEX;
            };
        }
    }
}
