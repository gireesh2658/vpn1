package com.officevpn.ui.components;

import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.ConnectionState;
import com.officevpn.ui.service.VpnModels.OfficeBranch;
import com.officevpn.ui.service.VpnModels.OfficeResource;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
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
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.shape.StrokeLineCap;
import org.kordamp.ikonli.feather.Feather;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Schematic architectural top-down office floorplan replacing generic world-dot maps.
 * <p>
 * Protected resources (Finance Vault, Engineering Lab, HR Records, File Server, Printers, Intranet)
 * appear as drafted rooms inside HQ or remote branch floorplans. When the corporate tunnel connects,
 * a flowing ribbon weaves from the employee desk to the gateway door, eligible rooms animate a key-turn
 * unlock according to RBAC/profile policy, and hover or arrow-key focus inspects allowed hosts and ports.
 */
public final class OfficeAtlas extends Control {

    private static final PseudoClass PC_CONNECTED = PseudoClass.getPseudoClass("connected");

    private final ObjectProperty<OfficeBranch> activeBranch = new SimpleObjectProperty<>(OfficeBranch.HQ);
    private final BooleanProperty tunnelConnected = new SimpleBooleanProperty(false);
    private final StringProperty policySummary = new SimpleStringProperty("Policy: Split Tunnel • Engineering");
    private final ObservableList<OfficeResource> resources = FXCollections.observableArrayList();
    private final ObjectProperty<OfficeResource> inspectedRoom = new SimpleObjectProperty<>(null);

    public OfficeAtlas() {
        getStyleClass().setAll("office-atlas");
        setFocusTraversable(true);
        setAccessibleRole(AccessibleRole.IMAGE_VIEW);
        setMinSize(260, Region.USE_PREF_SIZE);

        tunnelConnected.addListener((_, _, n) -> pseudoClassStateChanged(PC_CONNECTED, Boolean.TRUE.equals(n)));
    }

    public void bindService(VpnClientService service) {
        if (service == null) return;
        tunnelConnected.bind(service.connectionStateProperty().isEqualTo(ConnectionState.CONNECTED));
        policySummary.bind(service.accessPolicySummaryProperty());

        Runnable syncResources = () -> resources.setAll(service.officeResources());
        service.officeResources().addListener((ListChangeListener<OfficeResource>) _ -> syncResources.run());
        syncResources.run();
    }

    public static Node createStandaloneDemo(VpnClientService service) {
        OfficeAtlas atlas = new OfficeAtlas();
        atlas.bindService(service);
        return atlas;
    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new OfficeAtlasSkin(this);
    }

    public ObjectProperty<OfficeBranch> activeBranchProperty() { return activeBranch; }
    public BooleanProperty tunnelConnectedProperty() { return tunnelConnected; }
    public StringProperty policySummaryProperty() { return policySummary; }
    public ObservableList<OfficeResource> resources() { return resources; }
    public ObjectProperty<OfficeResource> inspectedRoomProperty() { return inspectedRoom; }

    private static final class OfficeAtlasSkin extends SkinBase<OfficeAtlas> {

        private final VBox root = new VBox(12);
        private final HBox branchTabs = new HBox(6);
        private final Label policyPill = new Label();
        private final StackPane canvasHolder = new StackPane();
        private final Canvas canvas = new Canvas(560, 235);

        private final HBox inspectorBar = new HBox(10);
        private final Label inspectorRoomLbl = new Label("Hover or arrow-select a room");
        private final Label inspectorHostsLbl = new Label("Allowed hosts and TCP/UDP ports inspect here.");
        private final Label inspectorStatePill = new Label("Standby");

        private final Map<OfficeBranch, Button> tabButtons = new HashMap<>();
        private final Map<String, Double> lockAngles = new HashMap<>();
        private double flowPhase = 0.0;

        OfficeAtlasSkin(OfficeAtlas control) {
            super(control);

            Label title = new Label("Office Atlas");
            title.getStyleClass().add("ia-card-title");
            title.setMinWidth(Region.USE_PREF_SIZE);

            policyPill.textProperty().bind(control.policySummaryProperty());
            policyPill.getStyleClass().addAll("ia-pill", "ia-pill-lilac");

            for (OfficeBranch br : OfficeBranch.values()) {
                Button btn = new Button(br.name());
                btn.getStyleClass().add("atlas-tab");
                btn.setFocusTraversable(false);
                btn.setMinWidth(Region.USE_PREF_SIZE);
                btn.setOnAction(_ -> control.activeBranchProperty().set(br));
                tabButtons.put(br, btn);
                branchTabs.getChildren().add(btn);
            }
            branchTabs.setMinWidth(Region.USE_PREF_SIZE);

            Region sp = new Region();
            HBox.setHgrow(sp, Priority.ALWAYS);
            HBox header = new HBox(10, title, policyPill, sp, branchTabs);
            header.setAlignment(Pos.CENTER_LEFT);

            canvas.setManaged(false);
            canvasHolder.setMinSize(0, 210);
            canvasHolder.setPrefHeight(238);
            canvasHolder.setStyle("-fx-background-color: #FBF8F1; -fx-background-radius: 12px; -fx-border-color: #E6DCC6; -fx-border-radius: 12px;");
            canvasHolder.getChildren().add(canvas);
            VBox.setVgrow(canvasHolder, Priority.ALWAYS);

            // Inspector footer pill card (warm sand strip)
            inspectorBar.getStyleClass().add("ia-card-sand");
            inspectorBar.setPadding(new Insets(8, 12, 8, 12));
            inspectorBar.setAlignment(Pos.CENTER_LEFT);
            inspectorRoomLbl.setFont(Fonts.uiSemiBold(12.5));
            inspectorRoomLbl.setTextFill(Tokens.INK);
            inspectorHostsLbl.setFont(Fonts.monoRegular(11.5));
            inspectorHostsLbl.setTextFill(Tokens.SOFT_INK);
            Region insSpacer = new Region();
            HBox.setHgrow(insSpacer, Priority.ALWAYS);
            inspectorStatePill.getStyleClass().addAll("ia-pill", "ia-pill-sand");
            VBox insTexts = new VBox(2, inspectorRoomLbl, inspectorHostsLbl);
            inspectorBar.getChildren().addAll(Icons.ink(Feather.MAP_PIN, 14), insTexts, insSpacer, inspectorStatePill);

            root.getChildren().addAll(header, canvasHolder, inspectorBar);
            getChildren().add(root);

            Motion.CappedAnimationTimer timer = new Motion.CappedAnimationTimer(control) {
                @Override
                protected void onTick(long nowNs, double dtSeconds) {
                    boolean changed = false;
                    if (control.tunnelConnectedProperty().get()) {
                        flowPhase = (flowPhase + dtSeconds * 42.0) % 28.0;
                        changed = true;
                    }
                    for (OfficeResource res : control.resources()) {
                        double target = res.unlocked() ? 90.0 : 0.0;
                        double cur = lockAngles.getOrDefault(res.id(), target);
                        if (Math.abs(target - cur) > 0.5) {
                            double step = (target - cur) * Math.min(1.0, dtSeconds * 10.0);
                            lockAngles.put(res.id(), cur + step);
                            changed = true;
                        } else if (cur != target) {
                            lockAngles.put(res.id(), target);
                            changed = true;
                        }
                    }
                    if (changed) drawFloorplan();
                }
            };
            timer.bind();

            wireCanvasInteractions(control);

            canvasHolder.widthProperty().addListener((_, _, n) -> {
                canvas.setWidth(Math.max(120, n.doubleValue() - 4));
                canvas.relocate(2, 2);
                drawFloorplan();
            });
            canvasHolder.heightProperty().addListener((_, _, n) -> {
                canvas.setHeight(Math.max(120, n.doubleValue() - 4));
                canvas.relocate(2, 2);
                drawFloorplan();
            });
            control.activeBranchProperty().addListener((_, _, n) -> {
                updateTabHighlights(n);
                control.inspectedRoomProperty().set(null);
                updateInspector();
                drawFloorplan();
            });
            control.tunnelConnectedProperty().addListener((_, _, _) -> {
                updateInspector();
                drawFloorplan();
            });
            control.resources().addListener((ListChangeListener<OfficeResource>) _ -> {
                updateInspector();
                drawFloorplan();
            });

            updateTabHighlights(control.activeBranchProperty().get());
            updateInspector();
            drawFloorplan();
        }

        private void wireCanvasInteractions(OfficeAtlas control) {
            canvas.setOnMouseMoved(e -> {
                OfficeResource hit = hitTest(e.getX(), e.getY());
                if (hit != control.inspectedRoomProperty().get()) {
                    control.inspectedRoomProperty().set(hit);
                    updateInspector();
                    drawFloorplan();
                }
            });
            canvas.setOnMouseExited(_ -> drawFloorplan());
            canvas.setOnMouseClicked(e -> {
                control.requestFocus();
                OfficeResource hit = hitTest(e.getX(), e.getY());
                control.inspectedRoomProperty().set(hit);
                updateInspector();
                drawFloorplan();
            });
            control.addEventHandler(KeyEvent.KEY_PRESSED, e -> {
                List<OfficeResource> branchRooms = currentBranchRooms();
                if (branchRooms.isEmpty()) return;
                if (e.getCode() == KeyCode.RIGHT || e.getCode() == KeyCode.DOWN) {
                    OfficeResource cur = control.inspectedRoomProperty().get();
                    int idx = cur == null ? 0 : (branchRooms.indexOf(cur) + 1) % branchRooms.size();
                    control.inspectedRoomProperty().set(branchRooms.get(idx));
                    updateInspector();
                    drawFloorplan();
                    e.consume();
                } else if (e.getCode() == KeyCode.LEFT || e.getCode() == KeyCode.UP) {
                    OfficeResource cur = control.inspectedRoomProperty().get();
                    int idx = cur == null ? 0 : (branchRooms.indexOf(cur) - 1 + branchRooms.size()) % branchRooms.size();
                    control.inspectedRoomProperty().set(branchRooms.get(idx));
                    updateInspector();
                    drawFloorplan();
                    e.consume();
                }
            });
        }

        private List<OfficeResource> currentBranchRooms() {
            OfficeBranch branch = getSkinnable().activeBranchProperty().get();
            return getSkinnable().resources().stream()
                    .filter(r -> r.branch() == branch)
                    .toList();
        }

        private OfficeResource hitTest(double mx, double my) {
            double w = canvas.getWidth();
            double h = canvas.getHeight();
            double padX = 24;
            double padTop = 26;
            double padBot = 36;
            double floorW = w - padX * 2;
            double floorH = h - padTop - padBot;
            for (OfficeResource r : currentBranchRooms()) {
                double rx = padX + r.xNorm() * floorW;
                double ry = padTop + r.yNorm() * floorH;
                double rw = r.wNorm() * floorW;
                double rh = r.hNorm() * floorH;
                if (mx >= rx && mx <= rx + rw && my >= ry && my <= ry + rh) {
                    return r;
                }
            }
            return null;
        }

        private void updateTabHighlights(OfficeBranch active) {
            tabButtons.forEach((br, btn) -> {
                btn.getStyleClass().remove("atlas-tab-active");
                if (br == active) {
                    btn.getStyleClass().add("atlas-tab-active");
                }
            });
        }

        private void updateInspector() {
            OfficeResource room = getSkinnable().inspectedRoomProperty().get();
            List<OfficeResource> list = currentBranchRooms();
            if (room == null && !list.isEmpty()) {
                room = list.get(0);
            }
            inspectorStatePill.getStyleClass().removeAll("ia-pill-peacock", "ia-pill-coral", "ia-pill-sand");
            if (room == null) {
                inspectorRoomLbl.setText("No rooms registered for branch");
                inspectorHostsLbl.setText("Select a branch tab above.");
                inspectorStatePill.setText("Empty");
                inspectorStatePill.getStyleClass().add("ia-pill-sand");
                return;
            }
            inspectorRoomLbl.setText(room.roomName() + "  [" + room.department() + "]");
            inspectorHostsLbl.setText(room.hosts() + "  •  " + room.ports());
            if (!getSkinnable().tunnelConnectedProperty().get()) {
                inspectorStatePill.setText("Tunnel Closed");
                inspectorStatePill.getStyleClass().add("ia-pill-sand");
            } else if (room.unlocked()) {
                inspectorStatePill.setText("Key Turned • Open");
                inspectorStatePill.getStyleClass().add("ia-pill-peacock");
            } else {
                inspectorStatePill.setText("Policy Locked");
                inspectorStatePill.getStyleClass().add("ia-pill-coral");
            }
            getSkinnable().setAccessibleText("Office Atlas " + room.branch().displayName()
                    + ", inspecting " + room.roomName() + ", hosts " + room.hosts());
        }

        private void drawFloorplan() {
            double w = canvas.getWidth();
            double h = canvas.getHeight();
            if (w <= 30 || h <= 30) return;

            GraphicsContext g = canvas.getGraphicsContext2D();
            g.clearRect(0, 0, w, h);

            // Subtle architectural grid lines
            g.setStroke(Color.rgb(230, 220, 198, 0.52));
            g.setLineWidth(1.0);
            for (double gx = 20; gx < w; gx += 28) {
                g.strokeLine(gx, 0, gx, h);
            }
            for (double gy = 18; gy < h; gy += 28) {
                g.strokeLine(0, gy, w, gy);
            }

            double padX = 24;
            double padTop = 26;
            double padBot = 36;
            double floorW = Math.max(80, w - padX * 2);
            double floorH = Math.max(80, h - padTop - padBot);

            // Outer drafted building walls
            g.setFill(Color.rgb(255, 255, 255, 0.72));
            g.fillRoundRect(padX, padTop, floorW, floorH, 10, 10);
            g.setStroke(Tokens.HAIRLINE);
            g.setLineWidth(2.0);
            g.strokeRoundRect(padX, padTop, floorW, floorH, 10, 10);

            // Central horizontal hallway corridor
            double hallY = padTop + floorH * 0.49;
            g.setStroke(Color.rgb(106, 101, 128, 0.25));
            g.setLineWidth(1.2);
            g.setLineDashes(6, 5);
            g.strokeLine(padX + 12, hallY, padX + floorW - 12, hallY);
            g.setLineDashes((double[]) null);

            // Employee Desk Node (bottom-left corridor entry) & Gateway Door (top-right portal)
            double deskX = padX + 26;
            double deskY = h - 18;
            double doorX = padX + floorW - 36;
            double doorY = 14;

            boolean connected = getSkinnable().tunnelConnectedProperty().get();
            List<OfficeResource> rooms = currentBranchRooms();
            OfficeResource hovered = getSkinnable().inspectedRoomProperty().get();

            // Encrypted Tunnel Ribbon running from Employee Desk through corridor to Gateway Door
            if (connected) {
                g.setStroke(Color.rgb(14, 159, 154, 0.25));
                g.setLineWidth(8.0);
                g.setLineCap(StrokeLineCap.ROUND);
                g.beginPath();
                g.moveTo(deskX, deskY - 6);
                g.bezierCurveTo(deskX + 20, hallY, doorX - 40, hallY, doorX, doorY + 12);
                g.stroke();

                g.setStroke(Tokens.PEACOCK);
                g.setLineWidth(2.4);
                g.setLineDashes(10, 6);
                g.setLineDashOffset(-flowPhase);
                g.beginPath();
                g.moveTo(deskX, deskY - 6);
                g.bezierCurveTo(deskX + 20, hallY, doorX - 40, hallY, doorX, doorY + 12);
                g.stroke();
                g.setLineDashes((double[]) null);
                g.setLineDashOffset(0);
            }

            // Draw Rooms
            for (OfficeResource r : rooms) {
                double rx = padX + r.xNorm() * floorW;
                double ry = padTop + r.yNorm() * floorH;
                double rw = r.wNorm() * floorW;
                double rh = r.hNorm() * floorH;

                boolean isHovered = hovered != null && hovered.id().equals(r.id());
                boolean unlocked = r.unlocked();

                Color roomFill = unlocked && connected
                        ? Color.rgb(14, 159, 154, isHovered ? 0.16 : 0.09)
                        : (isHovered ? Tokens.SAND : Tokens.PAPER);
                Color roomBorder = isHovered ? Tokens.MARIGOLD
                        : (unlocked && connected ? Tokens.PEACOCK : Tokens.HAIRLINE);

                g.setFill(roomFill);
                g.fillRoundRect(rx, ry, rw, rh, 8, 8);
                g.setStroke(roomBorder);
                g.setLineWidth(isHovered ? 2.0 : 1.3);
                g.strokeRoundRect(rx, ry, rw, rh, 8, 8);

                // Branching thread from corridor to unlocked rooms
                if (connected && unlocked) {
                    double roomMidX = rx + rw * 0.5;
                    double edgeY = ry + rh * 0.5 < hallY ? ry + rh : ry;
                    g.setStroke(Color.rgb(14, 159, 154, 0.55));
                    g.setLineWidth(1.5);
                    g.strokeLine(roomMidX, hallY, roomMidX, edgeY);
                }

                // Room label & dept subtitle
                g.setFill(Tokens.INK);
                g.setFont(Fonts.uiSemiBold(11.5));
                g.fillText(r.roomName(), rx + 10, ry + 19);

                g.setFill(Tokens.SOFT_INK);
                g.setFont(Fonts.monoRegular(9.5));
                g.fillText(r.department(), rx + 10, ry + 34);

                // Key-turn mechanical lock icon in top-right of each room
                double angle = lockAngles.getOrDefault(r.id(), unlocked ? 90.0 : 0.0);
                drawKeyTurnBadge(g, rx + rw - 17, ry + 16, unlocked && connected, angle);
            }

            // Gateway Door emblem top-right
            g.setFill(connected ? Tokens.PEACOCK : Tokens.SAND);
            g.fillRoundRect(doorX - 38, 4, 92, 18, 9, 9);
            g.setStroke(connected ? Tokens.PEACOCK : Tokens.HAIRLINE);
            g.setLineWidth(1.0);
            g.strokeRoundRect(doorX - 38, 4, 92, 18, 9, 9);
            g.setFill(connected ? Color.WHITE : Tokens.INK);
            g.setFont(Fonts.uiSemiBold(10));
            g.fillText(connected ? "GATEWAY OPEN" : "GATEWAY DOOR", doorX - 30, 16);

            // Employee Desk emblem bottom-left
            g.setFill(Tokens.SAND);
            g.fillRoundRect(deskX - 18, h - 28, 128, 20, 10, 10);
            g.setStroke(Tokens.MARIGOLD);
            g.strokeRoundRect(deskX - 18, h - 28, 128, 20, 10, 10);
            g.setFill(Tokens.INK);
            g.setFont(Fonts.uiSemiBold(10));
            g.fillText("YOUR DESK • VIP", deskX - 8, h - 14);
        }

        private void drawKeyTurnBadge(GraphicsContext g, double cx, double cy, boolean unlocked, double angleDeg) {
            g.setFill(unlocked ? Tokens.PEACOCK_WASH : Color.rgb(242, 235, 220, 0.85));
            g.fillOval(cx - 10, cy - 10, 20, 20);
            g.setStroke(unlocked ? Tokens.PEACOCK : Tokens.SOFT_INK);
            g.setLineWidth(1.3);
            g.strokeOval(cx - 10, cy - 10, 20, 20);

            double rad = Math.toRadians(angleDeg);
            double dx = Math.cos(rad) * 5.0;
            double dy = Math.sin(rad) * 5.0;
            g.setStroke(unlocked ? Tokens.PEACOCK_TEXT : Tokens.SOFT_INK);
            g.setLineWidth(1.8);
            g.strokeLine(cx - dx, cy - dy, cx + dx, cy + dy);
            g.setFill(unlocked ? Tokens.PEACOCK_TEXT : Tokens.SOFT_INK);
            g.fillOval(cx - dx - 2, cy - dy - 2, 4, 4);
        }
    }
}
