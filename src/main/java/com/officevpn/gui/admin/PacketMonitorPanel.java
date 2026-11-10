package com.officevpn.gui.admin;

import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import com.officevpn.protocol.PacketType;
import com.officevpn.protocol.VpnPacket;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TableView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * JavaFX Live Wire Protocol &amp; AEAD Packet Sniffer Monitor.
 */
public final class PacketMonitorPanel extends VBox {

    private static final int MAX_PACKETS = 500;
    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss.SSS").withZone(ZoneId.systemDefault());

    public record SniffedFrame(
            String time,
            String direction,
            String packetType,
            String sequence,
            String payloadBytes,
            String aeadStatus,
            String sessionHint
    ) {}

    private final Deque<SniffedFrame> buffer = new ArrayDeque<>(MAX_PACKETS + 1);
    private final CheckBox captureActiveCheck = new CheckBox("Capture Active");
    private final ComboBox<String> directionFilter = new ComboBox<>();
    private final Label totalPill = new Label("0 Frames");
    private final TableView<SniffedFrame> table = new TableView<>();

    private long totalCount = 0;

    public PacketMonitorPanel() {
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("admin.sniffer.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("admin.sniffer.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        totalPill.getStyleClass().addAll("pill", "pill-info");
        header.getChildren().addAll(titleBox, spacer, totalPill);

        HBox toolbar = new HBox(10);
        toolbar.setAlignment(Pos.CENTER_LEFT);
        captureActiveCheck.setSelected(true);

        directionFilter.getItems().addAll("ALL DIRECTIONS", "INBOUND", "OUTBOUND");
        directionFilter.getSelectionModel().selectFirst();
        directionFilter.setOnAction(_ -> rerender());

        Button clearCaptureButton = new Button(Messages.get("admin.sniffer.button.clear"));
        clearCaptureButton.getStyleClass().add("btn-danger");
        clearCaptureButton.setOnAction(_ -> {
            buffer.clear();
            table.getItems().clear();
            totalCount = 0;
            totalPill.setText("0 Frames");
        });

        Region tbSpacer = new Region();
        HBox.setHgrow(tbSpacer, Priority.ALWAYS);
        toolbar.getChildren().addAll(captureActiveCheck, directionFilter, tbSpacer, clearCaptureButton);

        UiSafe.configureSafeTable(table);
        table.getColumns().add(UiSafe.safeColumn("Time", SniffedFrame::time, 110));
        table.getColumns().add(UiSafe.badgeColumn("Direction", SniffedFrame::direction,
                f -> "INBOUND".equalsIgnoreCase(f.direction()) ? "pill-info" : "pill-warning", 110));
        table.getColumns().add(UiSafe.safeColumn("Packet Type", SniffedFrame::packetType, 180));
        table.getColumns().add(UiSafe.safeColumn("Seq Num", SniffedFrame::sequence, 95));
        table.getColumns().add(UiSafe.safeColumn("Payload Size", SniffedFrame::payloadBytes, 110));
        table.getColumns().add(UiSafe.badgeColumn("AEAD / State", SniffedFrame::aeadStatus,
                f -> f.aeadStatus().contains("GCM") ? "pill-success" : "pill-muted", 160));
        table.getColumns().add(UiSafe.safeColumn("Session / Endpoint", SniffedFrame::sessionHint, 180));
        VBox.setVgrow(table, Priority.ALWAYS);

        VBox card = new VBox(12, toolbar, table);
        card.getStyleClass().add("card");
        VBox.setVgrow(card, Priority.ALWAYS);

        getChildren().addAll(header, card);
    }

    public void appendPacket(VpnPacket packet, String direction) {
        if (packet == null) return;
        UiSafe.runOnFxThread(() -> {
            if (!captureActiveCheck.isSelected()) {
                return;
            }
            totalCount++;
            totalPill.setText(totalCount + " Frames");
            String dirClean = (direction != null && direction.toUpperCase().contains("OUT")) ? "OUTBOUND" : "INBOUND";
            PacketType type = packet.getType();
            byte[] enc = packet.getEncryptedPayload();
            int len = enc != null ? enc.length : 0;
            String aead = (type == PacketType.HANDSHAKE_INIT || type == PacketType.HANDSHAKE_CHALLENGE || type == PacketType.HANDSHAKE_SESSION_KEY)
                    ? "ECDH-PSS-INIT"
                    : "AES-256-GCM AEAD";
            String endpoint = (packet.getSenderUsername() != null && !packet.getSenderUsername().isBlank())
                    ? packet.getSenderUsername() + " (" + packet.getSenderVirtualIp() + ")"
                    : (packet.getSenderVirtualIp() != null && !packet.getSenderVirtualIp().isBlank() ? packet.getSenderVirtualIp() : "-");
            SniffedFrame frame = new SniffedFrame(
                    TS_FMT.format(Instant.now()),
                    dirClean,
                    type != null ? type.name() : "UNKNOWN",
                    String.valueOf(packet.getSequenceNumber()),
                    len + " B",
                    aead,
                    UiSafe.text(endpoint, 48)
            );
            if (buffer.size() >= MAX_PACKETS) {
                buffer.removeLast();
            }
            buffer.addFirst(frame);
            String filter = directionFilter.getValue();
            if (filter == null || "ALL DIRECTIONS".equals(filter) || filter.equals(frame.direction())) {
                table.getItems().add(0, frame);
                if (table.getItems().size() > MAX_PACKETS) {
                    table.getItems().remove(MAX_PACKETS, table.getItems().size());
                }
            }
        });
    }

    private void rerender() {
        String filter = directionFilter.getValue();
        table.getItems().setAll(buffer.stream()
                .filter(f -> filter == null || "ALL DIRECTIONS".equals(filter) || filter.equals(f.direction()))
                .toList());
    }
}
