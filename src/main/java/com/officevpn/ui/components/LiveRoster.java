package com.officevpn.ui.components;

import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.EmployeeSessionItem;
import com.officevpn.ui.service.VpnModels.InviteKeyState;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.AccessibleRole;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.Skin;
import javafx.scene.control.SkinBase;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.util.Duration;
import org.kordamp.ikonli.feather.Feather;

import java.util.Locale;
import java.util.function.Consumer;

/**
 * Administrative LiveRoster console combining:
 * <ul>
 *   <li>Live connected employee avatar chips with compliance presence rings</li>
 *   <li>Filterable {@code SessionTable} (OS, posture chips, live tunnel uptime) with a
 *       deliberate slide-to-revoke friction interaction</li>
 *   <li>Invite and enrollment setup-key card with one-click clipboard copy and expiry countdown</li>
 * </ul>
 */
public final class LiveRoster extends Control {

    private final ObservableList<EmployeeSessionItem> sessions = FXCollections.observableArrayList();
    private final ObjectProperty<InviteKeyState> inviteKey = new SimpleObjectProperty<>(null);
    private final ObjectProperty<Consumer<String>> onRevokeSession = new SimpleObjectProperty<>(_ -> {});
    private final ObjectProperty<Runnable> onRotateInvite = new SimpleObjectProperty<>(() -> {});

    public LiveRoster() {
        getStyleClass().setAll("live-roster");
        setFocusTraversable(false);
        setAccessibleRole(AccessibleRole.PARENT);
        setAccessibleText("Live Employee Roster, Session Table, and Invite Card");
    }

    public void bindService(VpnClientService service, Consumer<String> toastCallback) {
        if (service == null) return;
        Runnable syncRoster = () -> sessions.setAll(service.activeRoster());
        service.activeRoster().addListener((ListChangeListener<EmployeeSessionItem>) _ -> syncRoster.run());
        syncRoster.run();

        inviteKey.set(service.inviteKeyProperty().get());
        service.inviteKeyProperty().addListener((_, _, n) -> inviteKey.set(n));

        onRevokeSession.set(id -> {
            service.revokeSession(id);
            if (toastCallback != null) toastCallback.accept("Session " + id + " revoked and VIP reclaimed.");
        });
        onRotateInvite.set(() -> {
            service.rotateInviteKey();
            if (toastCallback != null) toastCallback.accept("New 15-minute enrollment setup key generated.");
        });
    }

    public static Node createStandaloneDemo(VpnClientService service) {
        LiveRoster roster = new LiveRoster();
        roster.bindService(service, null);
        return roster;
    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new LiveRosterSkin(this);
    }

    public ObservableList<EmployeeSessionItem> sessions() { return sessions; }
    public ObjectProperty<InviteKeyState> inviteKeyProperty() { return inviteKey; }
    public ObjectProperty<Consumer<String>> onRevokeSessionProperty() { return onRevokeSession; }
    public ObjectProperty<Runnable> onRotateInviteProperty() { return onRotateInvite; }

    /**
     * Deliberate slide-to-revoke control preventing accidental single-click disconnects.
     */
    private static final class SlideToRevokeTrack extends StackPane {
        private final SimpleDoubleProperty progress = new SimpleDoubleProperty(0.0);
        private final Label prompt = new Label("Slide revoke →");
        private final Region thumb = new Region();
        private final Pane trackPane = new Pane();
        private double startX;
        private double baseProg;

        SlideToRevokeTrack(String username, Runnable onTriggered) {
            setMinSize(128, 28);
            setPrefSize(134, 28);
            setMaxSize(142, 28);
            setStyle("-fx-background-color: #FEECE9; -fx-background-radius: 999px; -fx-border-color: #F4C3BC; -fx-border-radius: 999px;");
            setFocusTraversable(true);
            setAccessibleRole(AccessibleRole.BUTTON);
            setAccessibleText("Slide or press Enter to revoke session for " + username);

            prompt.setFont(Fonts.monoMedium(10));
            prompt.setTextFill(Tokens.CORAL_TEXT);
            prompt.setMouseTransparent(true);
            prompt.setPadding(new Insets(0, 9, 0, 26));
            StackPane.setAlignment(prompt, Pos.CENTER_RIGHT);

            thumb.setMinSize(22, 22);
            thumb.setMaxSize(22, 22);
            thumb.setManaged(false);
            thumb.setStyle("-fx-background-color: #F4604C; -fx-background-radius: 999px;");

            trackPane.getChildren().add(thumb);
            getChildren().addAll(prompt, trackPane);

            progress.addListener((_, _, n) -> {
                double maxTravel = Math.max(20.0, getWidth() - 28.0);
                thumb.resizeRelocate(3.0 + n.doubleValue() * maxTravel, 3.0, 22.0, 22.0);
                prompt.setOpacity(1.0 - n.doubleValue() * 0.8);
            });
            widthProperty().addListener((_, _, _) -> progress.set(progress.get()));
            thumb.resizeRelocate(3.0, 3.0, 22.0, 22.0);

            thumb.setOnMousePressed(e -> {
                startX = e.getSceneX();
                baseProg = progress.get();
                e.consume();
            });
            thumb.setOnMouseDragged(e -> {
                double maxTravel = Math.max(20.0, getWidth() - 28.0);
                double p = Math.max(0.0, Math.min(1.0, baseProg + (e.getSceneX() - startX) / maxTravel));
                progress.set(p);
                e.consume();
            });
            thumb.setOnMouseReleased(e -> {
                if (progress.get() >= 0.78) {
                    progress.set(1.0);
                    onTriggered.run();
                } else {
                    new Timeline(new KeyFrame(Motion.FAST, new KeyValue(progress, 0.0, Motion.spring()))).play();
                }
                e.consume();
            });
            addEventHandler(KeyEvent.KEY_PRESSED, e -> {
                if (e.getCode() == KeyCode.ENTER || e.getCode() == KeyCode.SPACE) {
                    onTriggered.run();
                    e.consume();
                }
            });
        }
    }

    private static final class LiveRosterSkin extends SkinBase<LiveRoster> {

        private final VBox root = new VBox(14);
        private final FlowPane avatarsFlow = new FlowPane(10, 8);
        private final TextField filterBox = new TextField();
        private final TableView<EmployeeSessionItem> table = new TableView<>();

        private final Label inviteCodeLbl = new Label("OVPN-INV-4A10-9C20");
        private final Label expiryCountdownLbl = new Label("15m 00s");
        private final Label usesLbl = new Label("3 uses remaining");
        private final Label copyFeedbackLbl = new Label("");
        private Timeline liveClock;

        LiveRosterSkin(LiveRoster control) {
            super(control);

            // Top Row: Avatar Presence Chips + Invite Setup Card side by side
            VBox rosterSummary = new VBox(8);
            Label rosterTitle = new Label("Connected Presence Roster");
            rosterTitle.getStyleClass().add("ia-card-title");
            Label rosterSub = new Label("Live employee presence rings colored by posture health");
            rosterSub.getStyleClass().add("ia-subtitle");
            rosterSummary.getChildren().addAll(rosterTitle, rosterSub, avatarsFlow);
            rosterSummary.getStyleClass().add("ia-card-paper");
            rosterSummary.setPadding(new Insets(14));
            HBox.setHgrow(rosterSummary, Priority.ALWAYS);

            VBox inviteCard = buildInviteCard(control);
            inviteCard.setMinWidth(280);
            inviteCard.setPrefWidth(320);

            HBox topGrid = new HBox(14, rosterSummary, inviteCard);

            // SessionTable section
            filterBox.setPromptText("Filter sessions by username, department, OS, or IP...");
            HBox.setHgrow(filterBox, Priority.ALWAYS);

            Label tblTitle = new Label("SessionTable");
            tblTitle.getStyleClass().add("ia-card-title");
            HBox filterBar = new HBox(12, tblTitle, filterBox);
            filterBar.setAlignment(Pos.CENTER_LEFT);

            setupTable(control);

            VBox tableCard = new VBox(10, filterBar, table);
            tableCard.getStyleClass().add("ia-card-paper");
            tableCard.setPadding(new Insets(14));

            root.getChildren().addAll(topGrid, tableCard);
            getChildren().add(root);

            control.sessions().addListener((ListChangeListener<EmployeeSessionItem>) _ -> rebuildAvatars());
            control.inviteKeyProperty().addListener((_, _, n) -> syncInvite(n));
            rebuildAvatars();
            syncInvite(control.inviteKeyProperty().get());

            liveClock = new Timeline(new KeyFrame(Duration.seconds(1), _ -> {
                updateInviteCountdown();
                table.refresh();
            }));
            liveClock.setCycleCount(Timeline.INDEFINITE);
            Motion.bindLifecycle(liveClock, control);
        }

        private VBox buildInviteCard(LiveRoster control) {
            VBox card = new VBox(8);
            card.getStyleClass().add("ia-card-paper");
            card.setPadding(new Insets(14));

            Label hdr = new Label("Invite & Setup Key");
            hdr.getStyleClass().add("ia-card-title");

            inviteCodeLbl.setFont(Fonts.monoBold(13.5));
            inviteCodeLbl.setTextFill(Tokens.INK);
            inviteCodeLbl.setPadding(new Insets(6, 10, 6, 10));
            inviteCodeLbl.setStyle("-fx-background-color: #FBF8F1; -fx-background-radius: 8px; -fx-border-color: #E6DCC6; -fx-border-radius: 8px;");
            inviteCodeLbl.setMaxWidth(Double.MAX_VALUE);

            expiryCountdownLbl.getStyleClass().addAll("ia-pill", "ia-pill-marigold");
            expiryCountdownLbl.setFont(Fonts.monoMedium(11));
            usesLbl.getStyleClass().add("ia-subtitle");

            Button copyBtn = new Button("Copy");
            copyBtn.getStyleClass().add("ia-btn-peacock");
            copyBtn.setGraphic(Icons.peacock(Feather.COPY, 12));
            copyBtn.setOnAction(_ -> {
                ClipboardContent cc = new ClipboardContent();
                cc.putString(inviteCodeLbl.getText());
                Clipboard.getSystemClipboard().setContent(cc);
                copyFeedbackLbl.setText("Copied setup key");
            });

            Button rotateBtn = new Button("Rotate");
            rotateBtn.setGraphic(Icons.ink(Feather.REFRESH_CW, 12));
            rotateBtn.setOnAction(_ -> {
                Runnable r = control.onRotateInviteProperty().get();
                if (r != null) r.run();
                copyFeedbackLbl.setText("");
            });

            copyFeedbackLbl.setFont(Fonts.uiMedium(11));
            copyFeedbackLbl.setTextFill(Tokens.PEACOCK_TEXT);

            HBox metaRow = new HBox(8, expiryCountdownLbl, usesLbl);
            metaRow.setAlignment(Pos.CENTER_LEFT);
            HBox btnRow = new HBox(8, copyBtn, rotateBtn, copyFeedbackLbl);
            btnRow.setAlignment(Pos.CENTER_LEFT);

            card.getChildren().addAll(hdr, inviteCodeLbl, metaRow, btnRow);
            return card;
        }

        private void setupTable(LiveRoster control) {
            FilteredList<EmployeeSessionItem> filtered = new FilteredList<>(control.sessions(), _ -> true);
            filterBox.textProperty().addListener((_, _, q) -> {
                String query = q == null ? "" : q.trim().toLowerCase(Locale.ROOT);
                filtered.setPredicate(item -> query.isEmpty()
                        || item.username().toLowerCase(Locale.ROOT).contains(query)
                        || item.department().toLowerCase(Locale.ROOT).contains(query)
                        || item.deviceOs().toLowerCase(Locale.ROOT).contains(query)
                        || item.virtualIp().contains(query));
            });

            table.setItems(filtered);
            table.setPrefHeight(270);
            table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);

            TableColumn<EmployeeSessionItem, String> colUser = new TableColumn<>("Employee");
            colUser.setCellValueFactory(cd -> new SimpleStringProperty(cd.getValue().username() + " • " + cd.getValue().department()));
            colUser.setMinWidth(135);

            TableColumn<EmployeeSessionItem, String> colVip = new TableColumn<>("Virtual IP");
            colVip.setCellValueFactory(cd -> new SimpleStringProperty(cd.getValue().virtualIp()));
            colVip.setMinWidth(84);
            colVip.setCellFactory(_ -> new TableCell<>() {
                @Override protected void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    setText(empty ? null : item);
                    setFont(Fonts.monoMedium(11.5));
                }
            });

            TableColumn<EmployeeSessionItem, String> colOs = new TableColumn<>("Device OS");
            colOs.setCellValueFactory(cd -> new SimpleStringProperty(cd.getValue().deviceOs()));
            colOs.setMinWidth(88);

            TableColumn<EmployeeSessionItem, EmployeeSessionItem> colPosture = new TableColumn<>("Posture");
            colPosture.setCellValueFactory(cd -> new SimpleObjectProperty<>(cd.getValue()));
            colPosture.setMinWidth(104);
            colPosture.setCellFactory(_ -> new TableCell<>() {
                @Override protected void updateItem(EmployeeSessionItem item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setGraphic(null);
                    } else {
                        Label pill = new Label(item.postureBadge());
                        String cls = !item.posturePassed() ? "ia-pill-coral"
                                : (item.postureBadge().contains("Warn") ? "ia-pill-marigold" : "ia-pill-peacock");
                        pill.getStyleClass().addAll("ia-pill", cls);
                        setGraphic(pill);
                    }
                }
            });

            TableColumn<EmployeeSessionItem, String> colDur = new TableColumn<>("Duration");
            colDur.setCellValueFactory(cd -> new SimpleStringProperty(formatDuration(cd.getValue().connectedAtMs())));
            colDur.setMinWidth(74);
            colDur.setCellFactory(_ -> new TableCell<>() {
                @Override protected void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);
                    setText(empty ? null : item);
                    setFont(Fonts.monoRegular(11.5));
                }
            });

            TableColumn<EmployeeSessionItem, EmployeeSessionItem> colRevoke = new TableColumn<>("Revoke");
            colRevoke.setCellValueFactory(cd -> new SimpleObjectProperty<>(cd.getValue()));
            colRevoke.setMinWidth(142);
            colRevoke.setCellFactory(_ -> new TableCell<>() {
                @Override protected void updateItem(EmployeeSessionItem item, boolean empty) {
                    super.updateItem(item, empty);
                    if (empty || item == null) {
                        setGraphic(null);
                    } else {
                        SlideToRevokeTrack slider = new SlideToRevokeTrack(item.username(), () -> {
                            var cb = control.onRevokeSessionProperty().get();
                            if (cb != null) cb.accept(item.sessionId());
                        });
                        setGraphic(slider);
                    }
                }
            });

            table.getColumns().setAll(java.util.List.of(colUser, colVip, colOs, colPosture, colDur, colRevoke));
        }

        private void rebuildAvatars() {
            avatarsFlow.getChildren().clear();
            for (EmployeeSessionItem item : getSkinnable().sessions()) {
                Label initials = new Label(item.initials());
                initials.setFont(Fonts.displaySemiBold(11.5));
                initials.setTextFill(Tokens.INK);

                String ringHex = item.posturePassed() ? Tokens.PEACOCK_HEX : Tokens.CORAL_HEX;
                StackPane circle = new StackPane(initials);
                circle.setMinSize(28, 28);
                circle.setMaxSize(28, 28);
                circle.setStyle("-fx-background-color: #FBF8F1; -fx-background-radius: 999px; -fx-border-color: " + ringHex + "; -fx-border-width: 2px; -fx-border-radius: 999px;");

                Label user = new Label(item.username());
                user.setFont(Fonts.uiSemiBold(12));
                user.setTextFill(Tokens.INK);

                Label gw = new Label(item.gatewayLabel());
                gw.setFont(Fonts.uiRegular(10.5));
                gw.setTextFill(Tokens.SOFT_INK);

                VBox txt = new VBox(0, user, gw);
                HBox chip = new HBox(8, circle, txt);
                chip.setAlignment(Pos.CENTER_LEFT);
                chip.getStyleClass().add("roster-avatar-chip");
                avatarsFlow.getChildren().add(chip);
            }
        }

        private void syncInvite(InviteKeyState st) {
            if (st == null) return;
            inviteCodeLbl.setText(st.setupKey());
            usesLbl.setText(st.remainingUses() + " uses left");
            updateInviteCountdown();
        }

        private void updateInviteCountdown() {
            InviteKeyState st = getSkinnable().inviteKeyProperty().get();
            if (st == null) return;
            long remSec = Math.max(0L, (st.expiresAtMs() - System.currentTimeMillis()) / 1000L);
            long min = remSec / 60L;
            long sec = remSec % 60L;
            expiryCountdownLbl.setText(String.format("Expires %02dm %02ds", min, sec));
        }

        private static String formatDuration(long startMs) {
            long sec = Math.max(0L, (System.currentTimeMillis() - startMs) / 1000L);
            long mins = sec / 60L;
            long rem = sec % 60L;
            if (mins >= 60) {
                return String.format("%dh %02dm", mins / 60, mins % 60);
            }
            return String.format("%02dm %02ds", mins, rem);
        }
    }
}
