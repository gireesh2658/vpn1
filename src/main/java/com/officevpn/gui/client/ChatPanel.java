package com.officevpn.gui.client;

import com.officevpn.client.VpnClientEngine;
import com.officevpn.config.ConfigUtil;
import com.officevpn.config.Messages;
import com.officevpn.gui.UiSafe;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.CompletableFuture;

/**
 * JavaFX Encrypted Intranet Broadcast Chat &amp; System Announcement Feed.
 */
public final class ChatPanel extends VBox {

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private final VpnClientEngine engine;
    private final TextArea chatFeed = new TextArea();
    private final TextField composer = new TextField();
    private final Label statusPill = new Label(Messages.get("chat.pill.wire"));
    private Button sendButton;

    public ChatPanel(VpnClientEngine engine) {
        this.engine = engine;
        setSpacing(14);
        setPadding(new Insets(18));
        buildUi();
        syncAuthState();
    }

    /**
     * Enables encrypted chat controls once connected and authenticated to an Office VPN gateway.
     */
    public void syncAuthState() {
        boolean authed = engine != null && engine.isConnected() && engine.isAuthenticated();
        composer.setDisable(!authed);
        if (sendButton != null) {
            sendButton.setDisable(!authed);
        }
        statusPill.getStyleClass().removeAll("pill-success", "pill-muted");
        if (authed) {
            statusPill.setText(Messages.get("chat.pill.wire"));
            statusPill.getStyleClass().add("pill-success");
            composer.setPromptText(Messages.get("chat.prompt"));
        } else {
            statusPill.setText("OFFLINE — SIGN IN");
            statusPill.getStyleClass().add("pill-muted");
            composer.setPromptText("Connect & sign in on Home to message your department...");
        }
    }

    private void buildUi() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        VBox titleBox = new VBox(2);
        Label title = new Label(Messages.get("chat.title"));
        title.getStyleClass().add("page-title");
        Label subtitle = new Label(Messages.get("chat.subtitle"));
        subtitle.getStyleClass().add("page-subtitle");
        titleBox.getChildren().addAll(title, subtitle);
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        statusPill.getStyleClass().addAll("pill", "pill-success");
        header.getChildren().addAll(titleBox, spacer, statusPill);

        chatFeed.setEditable(false);
        chatFeed.setWrapText(true);
        chatFeed.getStyleClass().add("chat-area");
        chatFeed.setText(Messages.format("chat.welcome", ConfigUtil.getGatewayVirtualIp()));
        VBox.setVgrow(chatFeed, Priority.ALWAYS);

        composer.setPromptText(Messages.get("chat.prompt"));
        Messages.configureAccessibleControl(composer, Messages.get("chat.prompt"), null);
        HBox.setHgrow(composer, Priority.ALWAYS);

        sendButton = new Button(Messages.get("chat.button.send"));
        sendButton.getStyleClass().add("btn-primary");
        Messages.configureAccessibleControl(sendButton,
                Messages.get("chat.button.send"),
                Messages.get("chat.tooltip.send"));

        Button clearButton = new Button(Messages.get("chat.button.clear"));
        clearButton.getStyleClass().add("btn-secondary");
        Messages.configureAccessibleControl(clearButton,
                Messages.get("chat.button.clear"),
                Messages.get("chat.tooltip.clear"));
        clearButton.setOnAction(e -> chatFeed.clear());

        Runnable sendAction = () -> {
            String msg = composer.getText() != null ? composer.getText().trim() : "";
            if (msg.isEmpty()) return;
            composer.setDisable(true);
            sendButton.setDisable(true);
            CompletableFuture.runAsync(() -> {
                try {
                    engine.sendChatMessage(msg);
                } catch (Exception ex) {
                    throw new IllegalStateException(ex.getMessage(), ex);
                }
            }).whenComplete((v, err) -> Platform.runLater(() -> {
                composer.setDisable(false);
                sendButton.setDisable(false);
                if (err != null) {
                    Throwable cause = err.getCause() != null ? err.getCause() : err;
                    UiSafe.showError(UiSafe.windowOf(this), "Message Send Failed", cause.getMessage());
                } else {
                    composer.clear();
                    composer.requestFocus();
                }
            }));
        };

        sendButton.setOnAction(e -> sendAction.run());
        composer.setOnAction(e -> sendAction.run());

        HBox composerBar = new HBox(10, composer, sendButton, clearButton);
        composerBar.setAlignment(Pos.CENTER_LEFT);

        VBox card = new VBox(12, chatFeed, composerBar);
        card.getStyleClass().add("card");
        VBox.setVgrow(card, Priority.ALWAYS);

        getChildren().addAll(header, card);
    }

    public void appendChatMessage(String senderUser, String senderDept, String senderVip, String message) {
        String safeUser = UiSafe.text(senderUser, 32);
        String safeDept = UiSafe.text(senderDept, 32);
        String safeVip = UiSafe.text(senderVip, 32);
        String safeMsg = UiSafe.text(message, 1024);
        String ts = TIME_FMT.format(Instant.now());
        String formatted = String.format("[%s] [%s] %s (%s): %s%n", ts, safeDept, safeUser, safeVip, safeMsg);
        UiSafe.runOnFxThread(() -> {
            chatFeed.appendText(formatted);
            chatFeed.positionCaret(chatFeed.getLength());
        });
    }
}
