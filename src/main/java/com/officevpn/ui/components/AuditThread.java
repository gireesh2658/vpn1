package com.officevpn.ui.components;

import com.officevpn.ui.service.VpnClientService;
import com.officevpn.ui.service.VpnModels.AuditCategory;
import com.officevpn.ui.service.VpnModels.AuditEventItem;
import com.officevpn.ui.theme.Fonts;
import com.officevpn.ui.theme.Icons;
import com.officevpn.ui.theme.Motion;
import com.officevpn.ui.theme.Tokens;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleDoubleProperty;
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
import javafx.scene.control.Button;
import javafx.scene.control.Control;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Skin;
import javafx.scene.control.SkinBase;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.paint.CycleMethod;
import javafx.scene.paint.LinearGradient;
import javafx.scene.paint.Stop;
import javafx.stage.FileChooser;
import javafx.util.Duration;
import org.kordamp.ikonli.feather.Feather;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * AuditThread drawing the cryptographic audit log as a grouped vertical timeline thread
 * with typed event glyphs (sign-in, policy change, revoke, failed attempt), animated warm paper
 * shimmer skeletons when loading, category filtering, and CSV export.
 */
public final class AuditThread extends Control {

    private static final PseudoClass PC_LOADING = PseudoClass.getPseudoClass("loading");

    private final ObservableList<AuditEventItem> events = FXCollections.observableArrayList();
    private final BooleanProperty loading = new SimpleBooleanProperty(false);
    private final StringProperty chainStatus = new SimpleStringProperty("CHAIN INTACT • HASH VERIFIED");
    private final ObjectProperty<AuditCategory> activeFilter = new SimpleObjectProperty<>(null);
    private final StringProperty searchText = new SimpleStringProperty("");
    private final ObjectProperty<Runnable> onRefresh = new SimpleObjectProperty<>(() -> {});
    private final ObjectProperty<Predicate<Path>> onExportCsv = new SimpleObjectProperty<>(_ -> false);

    public AuditThread() {
        getStyleClass().setAll("audit-thread");
        setFocusTraversable(true);
        setAccessibleRole(AccessibleRole.LIST_VIEW);
        setAccessibleText("Audit Thread cryptographic timeline");

        loading.addListener((_, _, n) -> pseudoClassStateChanged(PC_LOADING, Boolean.TRUE.equals(n)));
    }

    public void bindService(VpnClientService service, Consumer<String> toastCallback) {
        if (service == null) return;
        loading.bind(service.auditLoadingProperty());
        chainStatus.bind(service.auditChainStatusProperty());

        Runnable sync = () -> events.setAll(service.auditEvents());
        service.auditEvents().addListener((ListChangeListener<AuditEventItem>) _ -> sync.run());
        sync.run();

        onRefresh.set(service::refreshAuditLog);
        onExportCsv.set(path -> {
            boolean ok = service.exportAuditCsv(path);
            if (toastCallback != null) {
                toastCallback.accept(ok ? "Exported audit ledger CSV to " + path.getFileName() : "CSV export failed");
            }
            return ok;
        });
    }

    public static Node createStandaloneDemo(VpnClientService service) {
        AuditThread thread = new AuditThread();
        thread.bindService(service, null);
        return thread;
    }

    @Override
    protected Skin<?> createDefaultSkin() {
        return new AuditThreadSkin(this);
    }

    public ObservableList<AuditEventItem> events() { return events; }
    public BooleanProperty loadingProperty() { return loading; }
    public StringProperty chainStatusProperty() { return chainStatus; }
    public ObjectProperty<AuditCategory> activeFilterProperty() { return activeFilter; }
    public StringProperty searchTextProperty() { return searchText; }
    public ObjectProperty<Runnable> onRefreshProperty() { return onRefresh; }
    public ObjectProperty<Predicate<Path>> onExportCsvProperty() { return onExportCsv; }

    private static final class AuditThreadSkin extends SkinBase<AuditThread> {

        private final VBox root = new VBox(12);
        private final Label chainBadge = new Label();
        private final TextField searchBox = new TextField();
        private final VBox timelineBox = new VBox(14);
        private final Map<AuditCategory, Button> filterBtns = new LinkedHashMap<>();
        private final Button allBtn = new Button("All");
        private final SimpleDoubleProperty shimmerOffset = new SimpleDoubleProperty(-0.4);
        private Timeline shimmerAnim;

        AuditThreadSkin(AuditThread control) {
            super(control);

            Label title = new Label("Security Audit Thread");
            title.getStyleClass().add("ia-card-title");

            chainBadge.textProperty().bind(control.chainStatusProperty());
            chainBadge.getStyleClass().addAll("ia-pill", "ia-pill-peacock");
            chainBadge.setFont(Fonts.monoMedium(10.5));

            Button refreshBtn = new Button("Refresh");
            refreshBtn.setGraphic(Icons.ink(Feather.REFRESH_CW, 13));
            refreshBtn.setOnAction(_ -> {
                Runnable r = control.onRefreshProperty().get();
                if (r != null) r.run();
            });

            Button exportBtn = new Button("Export CSV");
            exportBtn.getStyleClass().add("ia-btn-marigold");
            exportBtn.setGraphic(Icons.ink(Feather.DOWNLOAD, 13));
            exportBtn.setOnAction(_ -> exportWithChooser(control));

            Region sp = new Region();
            HBox.setHgrow(sp, Priority.ALWAYS);
            HBox header = new HBox(10, title, chainBadge, sp, refreshBtn, exportBtn);
            header.setAlignment(Pos.CENTER_LEFT);

            // Category filters & search
            searchBox.setPromptText("Search actor, event, or IP...");
            searchBox.textProperty().bindBidirectional(control.searchTextProperty());
            HBox.setHgrow(searchBox, Priority.ALWAYS);

            allBtn.getStyleClass().add("atlas-tab");
            allBtn.setOnAction(_ -> control.activeFilterProperty().set(null));
            HBox filterPills = new HBox(6, allBtn);
            for (AuditCategory cat : AuditCategory.values()) {
                Button b = new Button(cat.label());
                b.getStyleClass().add("atlas-tab");
                b.setOnAction(_ -> control.activeFilterProperty().set(cat));
                filterBtns.put(cat, b);
                filterPills.getChildren().add(b);
            }

            HBox filterRow = new HBox(12, filterPills, searchBox);
            filterRow.setAlignment(Pos.CENTER_LEFT);

            ScrollPane scroller = new ScrollPane(timelineBox);
            scroller.setFitToWidth(true);
            scroller.setPrefHeight(330);
            VBox.setVgrow(scroller, Priority.ALWAYS);

            root.getChildren().addAll(header, filterRow, scroller);
            getChildren().add(root);

            shimmerAnim = new Timeline(
                    new KeyFrame(Duration.ZERO, new KeyValue(shimmerOffset, -0.4)),
                    new KeyFrame(Duration.millis(1100), new KeyValue(shimmerOffset, 1.4))
            );
            shimmerAnim.setCycleCount(Timeline.INDEFINITE);
            Motion.bindLifecycle(shimmerAnim, control);

            control.events().addListener((ListChangeListener<AuditEventItem>) _ -> rebuild());
            control.loadingProperty().addListener((_, _, _) -> rebuild());
            control.activeFilterProperty().addListener((_, _, _) -> {
                syncFilterButtons();
                rebuild();
            });
            control.searchTextProperty().addListener((_, _, _) -> rebuild());

            syncFilterButtons();
            rebuild();
        }

        private void exportWithChooser(AuditThread control) {
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Export Audit Thread CSV");
            chooser.setInitialFileName("office-vpn-audit.csv");
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV Ledger", "*.csv"));
            File selected = control.getScene() != null && control.getScene().getWindow() != null
                    ? chooser.showSaveDialog(control.getScene().getWindow())
                    : new File("office-vpn-audit.csv");
            if (selected != null) {
                var cb = control.onExportCsvProperty().get();
                if (cb != null) cb.test(selected.toPath());
            }
        }

        private void syncFilterButtons() {
            AuditCategory active = getSkinnable().activeFilterProperty().get();
            allBtn.getStyleClass().remove("atlas-tab-active");
            if (active == null) allBtn.getStyleClass().add("atlas-tab-active");
            filterBtns.forEach((cat, btn) -> {
                btn.getStyleClass().remove("atlas-tab-active");
                if (cat == active) btn.getStyleClass().add("atlas-tab-active");
            });
        }

        private void rebuild() {
            timelineBox.getChildren().clear();
            if (getSkinnable().loadingProperty().get()) {
                for (int i = 0; i < 4; i++) {
                    timelineBox.getChildren().add(createShimmerSkeletonRow());
                }
                return;
            }

            AuditCategory cat = getSkinnable().activeFilterProperty().get();
            String q = getSkinnable().searchTextProperty().get();
            String cleanQ = q == null ? "" : q.trim().toLowerCase(Locale.ROOT);

            List<AuditEventItem> visible = getSkinnable().events().stream()
                    .filter(e -> cat == null || e.category() == cat)
                    .filter(e -> cleanQ.isEmpty()
                            || e.headline().toLowerCase(Locale.ROOT).contains(cleanQ)
                            || e.actor().toLowerCase(Locale.ROOT).contains(cleanQ)
                            || e.detail().toLowerCase(Locale.ROOT).contains(cleanQ)
                            || e.remoteIp().contains(cleanQ))
                    .toList();

            if (visible.isEmpty()) {
                Label empty = new Label("No matching audit events.");
                empty.getStyleClass().add("ia-subtitle");
                timelineBox.getChildren().add(empty);
                return;
            }

            Map<String, List<AuditEventItem>> byDay = new LinkedHashMap<>();
            for (AuditEventItem item : visible) {
                byDay.computeIfAbsent(item.dayGroup(), _ -> new ArrayList<>()).add(item);
            }

            for (var entry : byDay.entrySet()) {
                Label dayHdr = new Label(entry.getKey().toUpperCase(Locale.ROOT));
                dayHdr.getStyleClass().add("ia-section-label");

                VBox groupEntries = new VBox(10);
                List<AuditEventItem> list = entry.getValue();
                for (int i = 0; i < list.size(); i++) {
                    boolean lastInDay = (i == list.size() - 1);
                    groupEntries.getChildren().add(buildTimelineRow(list.get(i), !lastInDay));
                }
                VBox dayBlock = new VBox(8, dayHdr, groupEntries);
                timelineBox.getChildren().add(dayBlock);
            }
        }

        private HBox buildTimelineRow(AuditEventItem item, boolean drawThreadLine) {
            Feather glyph;
            String ringHex;
            String bgHex;
            switch (item.category()) {
                case SIGN_IN -> { glyph = Feather.KEY; ringHex = Tokens.PEACOCK_HEX; bgHex = "#E5F6F5"; }
                case POLICY_CHANGE -> { glyph = Feather.SLIDERS; ringHex = Tokens.MARIGOLD_HEX; bgHex = "#FFF5DC"; }
                case REVOKE -> { glyph = Feather.SLASH; ringHex = Tokens.CORAL_HEX; bgHex = "#FEECE9"; }
                case FAILED_ATTEMPT -> { glyph = Feather.ALERT_TRIANGLE; ringHex = Tokens.CORAL_HEX; bgHex = "#FEECE9"; }
                default -> { glyph = Feather.ACTIVITY; ringHex = Tokens.LILAC_HEX; bgHex = "#EFEBFD"; }
            }

            Node glyphIcon = switch (item.category()) {
                case SIGN_IN -> Icons.peacock(glyph, 13);
                case POLICY_CHANGE -> Icons.marigold(glyph, 13);
                case REVOKE, FAILED_ATTEMPT -> Icons.coral(glyph, 13);
            };
            StackPane nodeCircle = new StackPane(glyphIcon);
            nodeCircle.setMinSize(28, 28);
            nodeCircle.setMaxSize(28, 28);
            nodeCircle.setStyle("-fx-background-color: " + bgHex + "; -fx-background-radius: 999px; -fx-border-color: " + ringHex + "; -fx-border-radius: 999px;");

            Region threadLine = new Region();
            threadLine.setMinWidth(1.5);
            threadLine.setMaxWidth(1.5);
            threadLine.setStyle("-fx-background-color: #E6DCC6;");
            threadLine.setVisible(drawThreadLine);
            VBox.setVgrow(threadLine, Priority.ALWAYS);

            VBox gutter = new VBox(3, nodeCircle, threadLine);
            gutter.setAlignment(Pos.TOP_CENTER);

            Label time = new Label(item.timeText());
            time.getStyleClass().add("ia-mono-soft");
            Label headline = new Label(item.headline());
            headline.setFont(Fonts.uiSemiBold(12.5));
            headline.setTextFill(Tokens.INK);

            Label actorPill = new Label(item.actor() + " • " + item.remoteIp());
            actorPill.getStyleClass().addAll("ia-pill", "ia-pill-sand");
            actorPill.setFont(Fonts.monoRegular(10));

            Region sp = new Region();
            HBox.setHgrow(sp, Priority.ALWAYS);

            HBox topLine = new HBox(8, time, headline, sp, actorPill);
            topLine.setAlignment(Pos.CENTER_LEFT);

            Label detail = new Label(item.detail());
            detail.getStyleClass().add("ia-subtitle");
            detail.setWrapText(true);

            VBox card = new VBox(4, topLine, detail);
            card.setPadding(new Insets(8, 12, 8, 12));
            card.setStyle("-fx-background-color: #FBF8F1; -fx-background-radius: 10px; -fx-border-color: #E6DCC6; -fx-border-radius: 10px;");
            HBox.setHgrow(card, Priority.ALWAYS);

            return new HBox(12, gutter, card);
        }

        private HBox createShimmerSkeletonRow() {
            Region dot = new Region();
            dot.setMinSize(28, 28);
            dot.setMaxSize(28, 28);
            dot.setStyle("-fx-background-color: #F2EBDC; -fx-background-radius: 999px;");

            Region bar = new Region();
            bar.setMinHeight(46);
            bar.setPrefHeight(48);
            HBox.setHgrow(bar, Priority.ALWAYS);
            bar.setBorder(new javafx.scene.layout.Border(new javafx.scene.layout.BorderStroke(
                    Tokens.HAIRLINE, javafx.scene.layout.BorderStrokeStyle.SOLID,
                    new javafx.scene.layout.CornerRadii(10), new javafx.scene.layout.BorderWidths(1))));

            Runnable paintShimmer = () -> {
                double p = shimmerOffset.get() < 0 ? 0.35 : shimmerOffset.get();
                LinearGradient lg = new LinearGradient(p - 0.35, 0, p + 0.35, 0, true, CycleMethod.NO_CYCLE,
                        new Stop(0.0, Tokens.SAND),
                        new Stop(0.5, Color.web("#FBF8F1")),
                        new Stop(1.0, Tokens.SAND));
                bar.setBackground(new javafx.scene.layout.Background(
                        new javafx.scene.layout.BackgroundFill(lg, new javafx.scene.layout.CornerRadii(10), Insets.EMPTY)));
            };
            shimmerOffset.addListener((_, _, _) -> paintShimmer.run());
            paintShimmer.run();
            return new HBox(12, dot, bar);
        }
    }
}
