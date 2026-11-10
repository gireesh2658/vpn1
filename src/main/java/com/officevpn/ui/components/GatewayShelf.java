package com.officevpn.ui.components;

import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels;
import com.officevpn.ui.service.VpnModels.GatewayNode;
import com.officevpn.ui.service.VpnModels.WorkModeProfile;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.beans.property.ObjectProperty;
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
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.Skin;
import javafx.scene.control.SkinBase;
import javafx.scene.control.TextField;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCodeCombination;
import javafx.scene.input.KeyCombination;
import javafx.scene.input.KeyEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.util.Duration;
import org.kordamp.ikonli.feather.Feather;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Branch-grouped GatewayShelf picker featuring liquid-level load vials, animated spark
 * favorites, fuzzy subsequence search, full keyboard navigation, and a Ctrl+K command palette.
 */
public final class GatewayShelf extends Control {

    public record PaletteAction(
            String category,
            String title,
            String detail,
            Runnable handler
    ) {}

    private static final PseudoClass PC_HAS_SELECTION = PseudoClass.getPseudoClass("selected");

    private final ObservableList<GatewayNode> gateways = FXCollections.observableArrayList();
    private final ObjectProperty<GatewayNode> selectedGateway = new SimpleObjectProperty<>(null);
    private final StringProperty searchQuery = new SimpleStringProperty("");
    private final ObjectProperty<Consumer<GatewayNode>> onConnectGateway = new SimpleObjectProperty<>(_ -> {});
    private final ObjectProperty<Consumer<GatewayNode>> onToggleFavorite = new SimpleObjectProperty<>(_ -> {});
    private final ObjectProperty<Runnable> onOpenCommandPalette = new SimpleObjectProperty<>(() -> {});

    public GatewayShelf() {
        getStyleClass().setAll("gateway-shelf");
        setFocusTraversable(true);
        setAccessibleRole(AccessibleRole.LIST_VIEW);
        selectedGateway.addListener((_, _, n) -> {
            pseudoClassStateChanged(PC_HAS_SELECTION, n != null);
            setAccessibleText("Gateway Shelf, selected " + (n != null ? n.city() + " " + n.latencyMs() + "ms" : "none"));
        });
    }

    public void bindService(VpnClientService service) {
        if (service == null) return;
        Runnable sync = () -> gateways.setAll(service.gateways());
        service.gateways().addListener((ListChangeListener<GatewayNode>) _ -> sync.run());
        sync.run();
        selectedGateway.set(service.selectedGatewayProperty().get());
        service.selectedGatewayProperty().addListener((_, _, n) -> selectedGateway.set(n));

        onConnectGateway.set(gw -> {
            if (gw != null) service.connect(gw.id());
        });
        onToggleFavorite.set(gw -> {
            if (gw != null) service.toggleFavoriteGateway(gw.id());
        });
    }

    public static Node createStandaloneDemo(VpnClientService service) {
        GatewayShelf shelf = new GatewayShelf();
        shelf.bindService(service);
        return shelf;
    }

    /**
     * Deterministic fuzzy subsequence match score (-1 if query characters do not appear in order).
     */
    public static int fuzzyScore(String candidate, String query) {
        return VpnModels.fuzzyScore(candidate, query);
    }

    /**
     * Reusable modal Command Palette overlay driven by Ctrl+K across AppShell or GatewayShelf.
     */
    public static StackPane createCommandPaletteOverlay(
            VpnClientService service,
            Consumer<String> onNavigateTab,
            Runnable onCloseOverlay
    ) {
        StackPane backdrop = new StackPane();
        backdrop.setStyle("-fx-background-color: rgba(242, 235, 220, 0.78);");
        backdrop.setPadding(new Insets(48, 24, 24, 24));
        backdrop.setAlignment(Pos.TOP_CENTER);

        VBox surface = new VBox(10);
        surface.getStyleClass().add("command-palette-surface");
        surface.setPadding(new Insets(14));
        surface.setMaxWidth(540);
        surface.setMaxHeight(380);
        surface.setEffect(Tokens.createAmbientShadow());

        TextField input = new TextField();
        input.setPromptText("Jump to gateway, toggle kill switch, switch mode, or open logs...");
        input.setFont(Fonts.uiMedium(13.5));

        HBox topRow = new HBox(10, Icons.ink(Feather.SEARCH, 16), input);
        topRow.setAlignment(Pos.CENTER_LEFT);
        HBox.setHgrow(input, Priority.ALWAYS);

        List<PaletteAction> allActions = buildPaletteActions(service, onNavigateTab, onCloseOverlay);
        ObservableList<PaletteAction> filtered = FXCollections.observableArrayList(allActions);
        ListView<PaletteAction> list = new ListView<>(filtered);
        list.setPrefHeight(260);
        list.setCellFactory(_ -> new ListCell<>() {
            @Override
            protected void updateItem(PaletteAction item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setGraphic(null);
                    setText(null);
                } else {
                    Label cat = new Label(item.category());
                    cat.getStyleClass().addAll("ia-pill", "ia-pill-sand");
                    Label title = new Label(item.title());
                    title.setFont(Fonts.uiSemiBold(12.5));
                    title.setTextFill(Tokens.INK);
                    Label det = new Label(item.detail());
                    det.setFont(Fonts.monoRegular(11));
                    det.setTextFill(Tokens.SOFT_INK);
                    Region sp = new Region();
                    HBox.setHgrow(sp, Priority.ALWAYS);
                    HBox row = new HBox(10, cat, title, sp, det);
                    row.setAlignment(Pos.CENTER_LEFT);
                    setGraphic(row);
                    setText(null);
                }
            }
        });
        if (!filtered.isEmpty()) list.getSelectionModel().select(0);

        input.textProperty().addListener((_, _, q) -> {
            filtered.setAll(allActions.stream()
                    .filter(a -> fuzzyScore(a.category() + " " + a.title() + " " + a.detail(), q) >= 0)
                    .toList());
            if (!filtered.isEmpty()) list.getSelectionModel().select(0);
        });

        Runnable runSelected = () -> {
            PaletteAction act = list.getSelectionModel().getSelectedItem();
            if (act != null) {
                act.handler().run();
            }
        };

        input.setOnKeyPressed(e -> {
            if (e.getCode() == KeyCode.DOWN && !filtered.isEmpty()) {
                int idx = Math.min(filtered.size() - 1, list.getSelectionModel().getSelectedIndex() + 1);
                list.getSelectionModel().select(idx);
                list.scrollTo(idx);
                e.consume();
            } else if (e.getCode() == KeyCode.UP && !filtered.isEmpty()) {
                int idx = Math.max(0, list.getSelectionModel().getSelectedIndex() - 1);
                list.getSelectionModel().select(idx);
                list.scrollTo(idx);
                e.consume();
            } else if (e.getCode() == KeyCode.ENTER) {
                runSelected.run();
                e.consume();
            } else if (e.getCode() == KeyCode.ESCAPE) {
                onCloseOverlay.run();
                e.consume();
            }
        });

        list.setOnMouseClicked(e -> {
            if (e.getClickCount() >= 1 && list.getSelectionModel().getSelectedItem() != null) {
                runSelected.run();
            }
        });

        backdrop.setOnMouseClicked(e -> {
            if (e.getTarget() == backdrop) onCloseOverlay.run();
        });

        Label hint = new Label("↑↓ navigate • Enter execute • Esc close");
        hint.getStyleClass().add("ia-mono-soft");
        surface.getChildren().addAll(topRow, list, hint);
        backdrop.getChildren().add(surface);
        backdrop.getProperties().put("paletteInput", input);
        return backdrop;
    }

    private static List<PaletteAction> buildPaletteActions(
            VpnClientService service,
            Consumer<String> onNavigateTab,
            Runnable closeOverlay
    ) {
        List<PaletteAction> out = new ArrayList<>();
        if (service != null) {
            for (GatewayNode gw : service.gateways()) {
                out.add(new PaletteAction("Gateway", "Connect to " + gw.city(), gw.latencyMs() + " ms • " + gw.branch(), () -> {
                    service.connect(gw.id());
                    closeOverlay.run();
                }));
            }
            for (WorkModeProfile wm : service.workModes()) {
                out.add(new PaletteAction("Mode", "Switch to " + wm.name(), wm.profileType().label(), () -> {
                    service.activateWorkMode(wm.id());
                    closeOverlay.run();
                }));
            }
            out.add(new PaletteAction("Safety", "Toggle Kill Switch",
                    service.killSwitchEnabledProperty().get() ? "Currently armed" : "Currently off", () -> {
                service.killSwitchEnabledProperty().set(!service.killSwitchEnabledProperty().get());
                closeOverlay.run();
            }));
        }
        if (onNavigateTab != null) {
            for (String tab : List.of("Home", "Gateways", "Modes", "Access", "Admin", "Logs", "Settings")) {
                out.add(new PaletteAction("Screen", "Open " + tab, "Navigate workspace", () -> {
                    onNavigateTab.accept(tab);
                    closeOverlay.run();
                }));
            }
        }
        return out;
    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new GatewayShelfSkin(this);
    }

    public ObservableList<GatewayNode> gateways() { return gateways; }
    public ObjectProperty<GatewayNode> selectedGatewayProperty() { return selectedGateway; }
    public StringProperty searchQueryProperty() { return searchQuery; }
    public ObjectProperty<Consumer<GatewayNode>> onConnectGatewayProperty() { return onConnectGateway; }
    public ObjectProperty<Consumer<GatewayNode>> onToggleFavoriteProperty() { return onToggleFavorite; }
    public ObjectProperty<Runnable> onOpenCommandPaletteProperty() { return onOpenCommandPalette; }

    private static final KeyCombination CTRL_K = new KeyCodeCombination(KeyCode.K, KeyCombination.CONTROL_DOWN);

    // Helper extension inside private scope (unused dummy avoided cleanly)
    private static void requestPaletteFocus(StackPane overlay) {
        Object o = overlay.getProperties().get("paletteInput");
        if (o instanceof TextField tf) tf.requestFocus();
    }

    private static final class GatewayShelfSkin extends SkinBase<GatewayShelf> {

        private final VBox root = new VBox(12);
        private final TextField searchBox = new TextField();
        private final Button paletteBtn = new Button("Ctrl+K");
        private final VBox branchesBox = new VBox(14);
        private final List<GatewayNode> orderedVisible = new ArrayList<>();
        private final Map<String, HBox> cardMap = new LinkedHashMap<>();

        GatewayShelfSkin(GatewayShelf control) {
            super(control);

            searchBox.setPromptText("Fuzzy search city, branch, or host (e.g. 'mun1' or 'blr')...");
            searchBox.textProperty().bindBidirectional(control.searchQueryProperty());
            HBox.setHgrow(searchBox, Priority.ALWAYS);

            paletteBtn.getStyleClass().add("ia-pill-sand");
            paletteBtn.setGraphic(Icons.ink(Feather.COMMAND, 13));
            paletteBtn.setFocusTraversable(false);
            paletteBtn.setOnAction(_ -> {
                Runnable r = control.onOpenCommandPaletteProperty().get();
                if (r != null) r.run();
            });

            HBox searchBar = new HBox(10, Icons.soft(Feather.SEARCH, 15), searchBox, paletteBtn);
            searchBar.setAlignment(Pos.CENTER_LEFT);
            searchBar.getStyleClass().add("ia-card-paper");
            searchBar.setPadding(new Insets(8, 12, 8, 12));

            root.getChildren().addAll(searchBar, branchesBox);
            getChildren().add(root);

            control.gateways().addListener((ListChangeListener<GatewayNode>) _ -> rebuildCards());
            control.searchQueryProperty().addListener((_, _, _) -> rebuildCards());
            control.selectedGatewayProperty().addListener((_, _, n) -> updateSelectionHighlight(n));

            control.addEventFilter(KeyEvent.KEY_PRESSED, e -> {
                if (CTRL_K.match(e)) {
                    Runnable r = control.onOpenCommandPaletteProperty().get();
                    if (r != null) r.run();
                    e.consume();
                } else if (e.getCode() == KeyCode.DOWN && !orderedVisible.isEmpty()) {
                    moveSelection(1);
                    e.consume();
                } else if (e.getCode() == KeyCode.UP && !orderedVisible.isEmpty()) {
                    moveSelection(-1);
                    e.consume();
                } else if (e.getCode() == KeyCode.ENTER) {
                    GatewayNode sel = control.selectedGatewayProperty().get();
                    if (sel != null) {
                        var cb = control.onConnectGatewayProperty().get();
                        if (cb != null) cb.accept(sel);
                    }
                    e.consume();
                }
            });

            rebuildCards();
        }

        private void moveSelection(int delta) {
            GatewayNode cur = getSkinnable().selectedGatewayProperty().get();
            int idx = 0;
            if (cur != null) {
                for (int i = 0; i < orderedVisible.size(); i++) {
                    if (orderedVisible.get(i).id().equals(cur.id())) {
                        idx = Math.max(0, Math.min(orderedVisible.size() - 1, i + delta));
                        break;
                    }
                }
            }
            getSkinnable().selectedGatewayProperty().set(orderedVisible.get(idx));
        }

        private void rebuildCards() {
            branchesBox.getChildren().clear();
            orderedVisible.clear();
            cardMap.clear();

            String q = getSkinnable().searchQueryProperty().get();
            List<GatewayNode> matches = getSkinnable().gateways().stream()
                    .filter(g -> fuzzyScore(g.city() + " " + g.branch() + " " + g.hostname(), q) >= 0)
                    .sorted(Comparator.comparing(GatewayNode::favorite).reversed().thenComparingInt(GatewayNode::latencyMs))
                    .toList();

            Map<String, List<GatewayNode>> grouped = new LinkedHashMap<>();
            for (GatewayNode g : matches) {
                grouped.computeIfAbsent(g.branch(), _ -> new ArrayList<>()).add(g);
            }

            if (grouped.isEmpty()) {
                Label empty = new Label("No gateways match \"" + q + "\"");
                empty.getStyleClass().add("ia-subtitle");
                branchesBox.getChildren().add(empty);
                return;
            }

            for (var entry : grouped.entrySet()) {
                Label branchHdr = new Label(entry.getKey().toUpperCase(Locale.ROOT));
                branchHdr.getStyleClass().add("ia-section-label");

                VBox shelfList = new VBox(8);
                for (GatewayNode gw : entry.getValue()) {
                    orderedVisible.add(gw);
                    HBox card = buildGatewayCard(gw);
                    cardMap.put(gw.id(), card);
                    shelfList.getChildren().add(card);
                }
                VBox section = new VBox(6, branchHdr, shelfList);
                branchesBox.getChildren().add(section);
            }
            updateSelectionHighlight(getSkinnable().selectedGatewayProperty().get());
        }

        private HBox buildGatewayCard(GatewayNode gw) {
            // Liquid-level load vial
            Canvas vial = drawLoadVial(gw.loadPercent());

            Label city = new Label(gw.city() + "  (" + gw.countryCode() + ")");
            city.setFont(Fonts.uiSemiBold(13.5));
            city.setTextFill(Tokens.INK);

            Label host = new Label(gw.hostname() + ":" + gw.port() + "  •  FP " + gw.fingerprintShort());
            host.setFont(Fonts.monoRegular(11));
            host.setTextFill(Tokens.SOFT_INK);

            VBox texts = new VBox(2, city, host);
            texts.setMinWidth(0);
            HBox.setHgrow(texts, Priority.ALWAYS);

            Label latencyPill = new Label(gw.latencyMs() + " ms");
            latencyPill.getStyleClass().addAll("ia-pill",
                    gw.latencyMs() < 35 ? "ia-pill-peacock" : (gw.latencyMs() < 65 ? "ia-pill-marigold" : "ia-pill-coral"));
            latencyPill.setFont(Fonts.monoMedium(11));
            latencyPill.setMinWidth(Region.USE_PREF_SIZE);

            Label loadLbl = new Label(gw.loadPercent() + "% load");
            loadLbl.getStyleClass().add("ia-mono-soft");
            loadLbl.setMinWidth(Region.USE_PREF_SIZE);

            Button starBtn = createSparkStarButton(gw);
            starBtn.setMinWidth(Region.USE_PREF_SIZE);
            Button connectBtn = new Button("Connect");
            connectBtn.getStyleClass().add("ia-btn-peacock");
            connectBtn.setFocusTraversable(false);
            connectBtn.setMinWidth(Region.USE_PREF_SIZE);
            connectBtn.setOnAction(e -> {
                getSkinnable().selectedGatewayProperty().set(gw);
                var cb = getSkinnable().onConnectGatewayProperty().get();
                if (cb != null) cb.accept(gw);
                e.consume();
            });

            HBox card = new HBox(12, vial, texts, loadLbl, latencyPill, starBtn, connectBtn);
            card.setAlignment(Pos.CENTER_LEFT);
            card.getStyleClass().add("gateway-card");
            card.setOnMouseClicked(_ -> getSkinnable().selectedGatewayProperty().set(gw));
            return card;
        }

        private Canvas drawLoadVial(int loadPct) {
            Canvas c = new Canvas(16, 36);
            GraphicsContext g = c.getGraphicsContext2D();
            g.setFill(Tokens.CANVAS);
            g.fillRoundRect(2, 2, 12, 32, 6, 6);

            double clamped = Math.max(8.0, Math.min(100.0, loadPct)) / 100.0;
            double fillH = 28.0 * clamped;
            double fillY = 32.0 - fillH;

            Color liquid = loadPct < 55 ? Tokens.PEACOCK : (loadPct < 82 ? Tokens.MARIGOLD : Tokens.CORAL);
            g.setFill(liquid);
            g.fillRoundRect(3.5, fillY, 9, fillH, 4, 4);

            // Meniscus highlight
            g.setFill(Color.rgb(255, 255, 255, 0.5));
            g.fillRect(4.5, fillY + 1, 7, 1.5);

            g.setStroke(Tokens.HAIRLINE);
            g.setLineWidth(1.2);
            g.strokeRoundRect(2, 2, 12, 32, 6, 6);
            return c;
        }

        private Button createSparkStarButton(GatewayNode gw) {
            Canvas sparkCanvas = new Canvas(26, 26);
            Button btn = new Button();
            btn.setGraphic(sparkCanvas);
            btn.setPadding(new Insets(2));
            btn.setFocusTraversable(false);
            btn.setAccessibleText((gw.favorite() ? "Unfavorite " : "Favorite ") + gw.city());

            var sparkProgress = new javafx.beans.property.SimpleDoubleProperty(0.0);
            Runnable drawStar = () -> {
                GraphicsContext g = sparkCanvas.getGraphicsContext2D();
                g.clearRect(0, 0, 26, 26);
                double p = sparkProgress.get();
                if (p > 0.02 && p < 0.98) {
                    g.setStroke(Tokens.MARIGOLD);
                    g.setLineWidth(1.4);
                    for (int i = 0; i < 6; i++) {
                        double ang = i * Math.PI / 3.0;
                        double r1 = 6.0 + p * 4.0;
                        double r2 = 8.0 + p * 5.0;
                        g.strokeLine(13 + Math.cos(ang) * r1, 13 + Math.sin(ang) * r1,
                                13 + Math.cos(ang) * r2, 13 + Math.sin(ang) * r2);
                    }
                }
                double cx = 13;
                double cy = 13;
                double[] xs = new double[10];
                double[] ys = new double[10];
                for (int i = 0; i < 10; i++) {
                    double rad = (i % 2 == 0) ? 7.0 : 3.2;
                    double a = -Math.PI / 2 + i * Math.PI / 5.0;
                    xs[i] = cx + Math.cos(a) * rad;
                    ys[i] = cy + Math.sin(a) * rad;
                }
                if (gw.favorite()) {
                    g.setFill(Tokens.MARIGOLD);
                    g.fillPolygon(xs, ys, 10);
                    g.setStroke(Tokens.MARIGOLD_TEXT);
                } else {
                    g.setStroke(Tokens.SOFT_INK);
                }
                g.setLineWidth(1.2);
                g.strokePolygon(xs, ys, 10);
            };
            sparkProgress.addListener((_, _, _) -> drawStar.run());
            drawStar.run();

            btn.setOnAction(e -> {
                if (!gw.favorite() && !Motion.isReduceMotion()) {
                    Timeline tl = new Timeline(
                            new KeyFrame(Duration.ZERO, new KeyValue(sparkProgress, 0.0)),
                            new KeyFrame(Motion.MEDIUM, new KeyValue(sparkProgress, 1.0))
                    );
                    tl.setOnFinished(_ -> {
                        sparkProgress.set(0.0);
                        var cb = getSkinnable().onToggleFavoriteProperty().get();
                        if (cb != null) cb.accept(gw);
                    });
                    tl.play();
                } else {
                    var cb = getSkinnable().onToggleFavoriteProperty().get();
                    if (cb != null) cb.accept(gw);
                }
                e.consume();
            });
            return btn;
        }

        private void updateSelectionHighlight(GatewayNode selected) {
            cardMap.forEach((id, node) -> {
                node.getStyleClass().remove("gateway-card-selected");
                if (selected != null && selected.id().equals(id)) {
                    node.getStyleClass().add("gateway-card-selected");
                }
            });
        }
    }

    // Small compilation hook keeping helper cleanly usable by AppShell
    public static void focusCommandPalette(StackPane paletteOverlay) {
        requestPaletteFocus(paletteOverlay);
    }
}
