package com.officevpn.ui.components;

import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.PostureCheck;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Tokens;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.css.PseudoClass;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.AccessibleRole;
import javafx.scene.Node;
import javafx.scene.canvas.Canvas;
import javafx.scene.canvas.GraphicsContext;
import javafx.scene.control.Button;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.Skin;
import javafx.scene.control.SkinBase;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.shape.ArcType;
import javafx.scene.shape.StrokeLineCap;
import org.kordamp.ikonli.feather.Feather;

import java.util.List;
import java.util.function.Consumer;

/**
 * PostureSeal displaying device endpoint compliance (OS Patched, Firewall On, Antivirus Present,
 * Disk Encrypted) as a segmented circular seal with interactive segment inspection and inline
 * remediation cards for any failing requirement.
 */
public final class PostureSeal extends Control {

    private static final PseudoClass PC_COMPLIANT = PseudoClass.getPseudoClass("compliant");

    private final ObservableList<PostureCheck> checks = FXCollections.observableArrayList();
    private final ObjectProperty<PostureCheck> selectedCheck = new SimpleObjectProperty<>(null);
    private final ObjectProperty<Consumer<String>> onRemediate = new SimpleObjectProperty<>(_ -> {});
    private final ObjectProperty<Runnable> onRescan = new SimpleObjectProperty<>(() -> {});

    public PostureSeal() {
        getStyleClass().setAll("posture-seal");
        setFocusTraversable(true);
        setAccessibleRole(AccessibleRole.PROGRESS_INDICATOR);
        setMinSize(260, Region.USE_PREF_SIZE);

        checks.addListener((ListChangeListener<PostureCheck>) _ -> syncComplianceState());
    }

    public void bindService(VpnClientService service) {
        if (service == null) return;
        Runnable sync = () -> {
            checks.setAll(service.postureChecks());
            PostureCheck failing = checks.stream().filter(p -> !p.passed()).findFirst().orElse(null);
            selectedCheck.set(failing != null ? failing : (checks.isEmpty() ? null : checks.get(0)));
        };
        service.postureChecks().addListener((ListChangeListener<PostureCheck>) _ -> sync.run());
        sync.run();
        onRemediate.set(service::remediatePostureCheck);
        onRescan.set(service::rerunPostureChecks);
    }

    public static Node createStandaloneDemo(VpnClientService service) {
        PostureSeal seal = new PostureSeal();
        seal.bindService(service);
        return seal;
    }

    private void syncComplianceState() {
        long passed = checks.stream().filter(PostureCheck::passed).count();
        boolean allGood = !checks.isEmpty() && passed == checks.size();
        pseudoClassStateChanged(PC_COMPLIANT, allGood);
        setAccessibleText("Device Posture Seal: " + passed + " of " + checks.size() + " checks compliant");
    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new PostureSealSkin(this);
    }

    public ObservableList<PostureCheck> checks() { return checks; }
    public ObjectProperty<PostureCheck> selectedCheckProperty() { return selectedCheck; }
    public ObjectProperty<Consumer<String>> onRemediateProperty() { return onRemediate; }
    public ObjectProperty<Runnable> onRescanProperty() { return onRescan; }

    private static final class PostureSealSkin extends SkinBase<PostureSeal> {

        private final VBox root = new VBox(12);
        private final Canvas ringCanvas = new Canvas(118, 118);
        private final VBox checksColumn = new VBox(6);
        private final VBox remediationCard = new VBox(6);
        private final Label remTitle = new Label();
        private final Label remBody = new Label();
        private final Button remActionBtn = new Button("Resolve Check");
        private final Label statusBadge = new Label();

        PostureSealSkin(PostureSeal control) {
            super(control);

            Label title = new Label("Device Posture Seal");
            title.getStyleClass().add("ia-card-title");
            title.setMinWidth(Region.USE_PREF_SIZE);

            statusBadge.getStyleClass().addAll("ia-pill", "ia-pill-peacock");
            statusBadge.setMinWidth(Region.USE_PREF_SIZE);

            Button rescanBtn = new Button("Re-check");
            rescanBtn.setGraphic(Icons.ink(Feather.REFRESH_CW, 12));
            rescanBtn.setMinWidth(Region.USE_PREF_SIZE);
            rescanBtn.setOnAction(_ -> {
                Runnable r = control.onRescanProperty().get();
                if (r != null) r.run();
            });

            Region sp = new Region();
            HBox.setHgrow(sp, Priority.ALWAYS);
            HBox header = new HBox(8, title, statusBadge, sp, rescanBtn);
            header.setAlignment(Pos.CENTER_LEFT);

            StackPane ringHolder = new StackPane(ringCanvas);
            ringHolder.setMinSize(118, 118);
            ringHolder.setMaxWidth(122);

            ringCanvas.setOnMouseClicked(e -> {
                List<PostureCheck> items = control.checks();
                if (items.isEmpty()) return;
                double dx = e.getX() - 59.0;
                double dy = 59.0 - e.getY();
                double ang = Math.toDegrees(Math.atan2(dy, dx));
                if (ang < 0) ang += 360.0;
                // Map angle clockwise from 90 deg top
                double clock = (450.0 - ang) % 360.0;
                int seg = Math.min(items.size() - 1, (int) (clock / (360.0 / items.size())));
                control.selectedCheckProperty().set(items.get(seg));
            });

            HBox.setHgrow(checksColumn, Priority.ALWAYS);
            HBox body = new HBox(14, ringHolder, checksColumn);
            body.setAlignment(Pos.CENTER_LEFT);

            // Inline Remediation Card shown cleanly when inspecting or failing
            remediationCard.setPadding(new Insets(10, 12, 10, 12));
            remediationCard.setStyle("-fx-background-color: #FEECE9; -fx-background-radius: 10px; -fx-border-color: #F4C3BC; -fx-border-radius: 10px;");
            remTitle.setFont(Fonts.uiSemiBold(12.5));
            remTitle.setTextFill(Tokens.CORAL_TEXT);
            remBody.setFont(Fonts.uiRegular(12));
            remBody.setTextFill(Tokens.INK);
            remBody.setWrapText(true);
            remActionBtn.getStyleClass().add("ia-btn-marigold");
            remActionBtn.setOnAction(_ -> {
                PostureCheck sel = control.selectedCheckProperty().get();
                if (sel != null && !sel.passed()) {
                    var cb = control.onRemediateProperty().get();
                    if (cb != null) cb.accept(sel.id());
                }
            });
            Region remSp = new Region();
            HBox.setHgrow(remSp, Priority.ALWAYS);
            HBox remHeader = new HBox(8, Icons.coral(Feather.ALERT_CIRCLE, 14), remTitle, remSp, remActionBtn);
            remHeader.setAlignment(Pos.CENTER_LEFT);
            remediationCard.getChildren().addAll(remHeader, remBody);

            root.getChildren().addAll(header, body, remediationCard);
            getChildren().add(root);

            control.checks().addListener((ListChangeListener<PostureCheck>) _ -> refreshAll());
            control.selectedCheckProperty().addListener((_, _, _) -> refreshAll());
            refreshAll();
        }

        private void refreshAll() {
            drawRing();
            rebuildChecksList();
            updateRemediation();
        }

        private void drawRing() {
            GraphicsContext g = ringCanvas.getGraphicsContext2D();
            double size = 118.0;
            g.clearRect(0, 0, size, size);

            List<PostureCheck> list = getSkinnable().checks();
            if (list.isEmpty()) return;

            double cx = size * 0.5;
            double cy = size * 0.5;
            double r = 44.0;
            double gap = 10.0;
            double sweep = (360.0 / list.size()) - gap;

            PostureCheck selected = getSkinnable().selectedCheckProperty().get();
            int passedCount = 0;

            for (int i = 0; i < list.size(); i++) {
                PostureCheck pc = list.get(i);
                if (pc.passed()) passedCount++;
                boolean isSel = selected != null && selected.id().equals(pc.id());
                double startAngle = 90.0 - i * (360.0 / list.size()) - gap * 0.5;

                g.setStroke(pc.passed() ? Tokens.PEACOCK : Tokens.CORAL);
                g.setLineWidth(isSel ? 11.5 : 8.5);
                g.setLineCap(StrokeLineCap.ROUND);
                g.strokeArc(cx - r, cy - r, r * 2, r * 2, startAngle, -sweep, ArcType.OPEN);
            }

            // Center Fraunces score
            g.setFill(Tokens.INK);
            g.setFont(Fonts.displaySemiBold(23));
            String score = passedCount + "/" + list.size();
            g.fillText(score, cx - 17, cy + 5);

            g.setFill(Tokens.SOFT_INK);
            g.setFont(Fonts.monoMedium(9.5));
            g.fillText(passedCount == list.size() ? "COMPLIANT" : "ACTION", cx - (passedCount == list.size() ? 27 : 18), cy + 19);

            statusBadge.getStyleClass().removeAll("ia-pill-peacock", "ia-pill-coral");
            if (passedCount == list.size()) {
                statusBadge.setText("4/4 Compliant");
                statusBadge.getStyleClass().add("ia-pill-peacock");
            } else {
                statusBadge.setText((list.size() - passedCount) + " Remediation");
                statusBadge.getStyleClass().add("ia-pill-coral");
            }
        }

        private void rebuildChecksList() {
            checksColumn.getChildren().clear();
            PostureCheck selected = getSkinnable().selectedCheckProperty().get();

            for (PostureCheck pc : getSkinnable().checks()) {
                boolean isSel = selected != null && selected.id().equals(pc.id());
                Label name = new Label(pc.title());
                name.setFont(Fonts.uiSemiBold(12.5));
                name.setTextFill(Tokens.INK);

                Label det = new Label(pc.observedDetail());
                det.getStyleClass().add("ia-subtitle");
                det.setWrapText(true);

                VBox txt = new VBox(1, name, det);
                txt.setMinWidth(0);
                HBox.setHgrow(txt, Priority.ALWAYS);

                HBox row = new HBox(8,
                        pc.passed() ? Icons.peacock(Feather.CHECK_CIRCLE, 14) : Icons.coral(Feather.ALERT_TRIANGLE, 14),
                        txt);
                row.setAlignment(Pos.CENTER_LEFT);
                row.setPadding(new Insets(6, 10, 6, 10));
                String bg = isSel ? (pc.passed() ? "#F2EBDC" : "#FEECE9") : "#FBF8F1";
                String bd = isSel ? (pc.passed() ? "#CBBCA0" : "#F4604C") : "#E6DCC6";
                row.setStyle("-fx-background-color: " + bg + "; -fx-background-radius: 9px; -fx-border-color: " + bd + "; -fx-border-radius: 9px; -fx-cursor: hand;");
                row.setOnMouseClicked(_ -> getSkinnable().selectedCheckProperty().set(pc));
                checksColumn.getChildren().add(row);
            }
        }

        private void updateRemediation() {
            PostureCheck sel = getSkinnable().selectedCheckProperty().get();
            boolean showTip = sel != null && !sel.passed();
            remediationCard.setVisible(showTip);
            remediationCard.setManaged(showTip);
            if (showTip) {
                remTitle.setText("Remediation: " + sel.title());
                remBody.setText(sel.remediationTip());
            }
        }
    }
}
