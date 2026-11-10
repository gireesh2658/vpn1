package com.officevpn.ui.theme;

import javafx.animation.Animation;
import javafx.animation.AnimationTimer;
import javafx.animation.FadeTransition;
import javafx.animation.Interpolator;
import javafx.animation.ParallelTransition;
import javafx.animation.SequentialTransition;
import javafx.animation.TranslateTransition;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.stage.Stage;
import javafx.stage.Window;
import javafx.util.Duration;

import java.util.List;

/**
 * Motion choreography utilities for Ivory Atelier.
 * <p>
 * Provides standard 120 / 220 / 420 ms durations, a crisp damped spring interpolator,
 * stagger helper, global {@link #reduceMotionProperty()}, 60 fps capped timers, and
 * automatic pause/resume bindings when the host {@link Stage} is iconified or hidden.
 */
public final class Motion {

    public static final Duration FAST   = Duration.millis(120);
    public static final Duration MEDIUM = Duration.millis(220);
    public static final Duration SLOW   = Duration.millis(420);

    private static final BooleanProperty REDUCE_MOTION = new SimpleBooleanProperty(false);

    private static final Interpolator SPRING_INTERPOLATOR = new Interpolator() {
        @Override
        protected double curve(double t) {
            if (t <= 0.0) return 0.0;
            if (t >= 1.0) return 1.0;
            // Damped underdamped spring response settled at t = 1
            double omega = 8.2;
            double zeta = 0.72;
            double envelope = Math.exp(-zeta * omega * t);
            double value = 1.0 - envelope * (Math.cos(omega * t) + (zeta / Math.sqrt(1.0 - zeta * zeta)) * Math.sin(omega * t));
            return Math.max(0.0, Math.min(1.08, value));
        }
    };

    private Motion() {
    }

    public static Interpolator spring() {
        return isReduceMotion() ? Interpolator.LINEAR : SPRING_INTERPOLATOR;
    }

    public static Duration resolve(Duration base) {
        return isReduceMotion() ? Duration.ONE : base;
    }

    public static BooleanProperty reduceMotionProperty() {
        return REDUCE_MOTION;
    }

    public static boolean isReduceMotion() {
        return REDUCE_MOTION.get();
    }

    public static void setReduceMotion(boolean reduce) {
        REDUCE_MOTION.set(reduce);
    }

    /**
     * Plays a crisp upward settle + fade-in stagger across cards or list items.
     */
    public static Animation staggerEnter(List<? extends Node> nodes, Duration delayStep) {
        if (isReduceMotion()) {
            for (Node n : nodes) {
                n.setOpacity(1.0);
                n.setTranslateY(0.0);
            }
            return new SequentialTransition();
        }
        ParallelTransition group = new ParallelTransition();
        int idx = 0;
        for (Node n : nodes) {
            n.setOpacity(0.0);
            n.setTranslateY(10.0);

            Duration delay = delayStep.multiply(idx++);
            FadeTransition ft = new FadeTransition(MEDIUM, n);
            ft.setFromValue(0.0);
            ft.setToValue(1.0);
            ft.setDelay(delay);

            TranslateTransition tt = new TranslateTransition(MEDIUM, n);
            tt.setFromY(10.0);
            tt.setToY(0.0);
            tt.setInterpolator(SPRING_INTERPOLATOR);
            tt.setDelay(delay);

            group.getChildren().addAll(ft, tt);
        }
        group.play();
        return group;
    }

    /**
     * Binds an indefinite {@link Animation} to automatically pause whenever its anchor node
     * is detached from a showing, non-iconified {@link Stage}.
     */
    public static void bindLifecycle(Animation animation, Node anchor) {
        Runnable evaluate = () -> {
            if (isAnchorVisible(anchor) && !isReduceMotion()) {
                if (animation.getStatus() != Animation.Status.RUNNING) {
                    animation.play();
                }
            } else {
                if (animation.getStatus() == Animation.Status.RUNNING) {
                    animation.pause();
                }
            }
        };
        attachLifecycleListeners(anchor, evaluate);
        evaluate.run();
    }

    /**
     * Determines whether an anchor node is currently inside a visible, restored window.
     */
    public static boolean isAnchorVisible(Node anchor) {
        if (anchor == null || !anchor.isVisible()) {
            return false;
        }
        Scene sc = anchor.getScene();
        if (sc == null) {
            return false;
        }
        Window win = sc.getWindow();
        if (win == null || !win.isShowing()) {
            return false;
        }
        if (win instanceof Stage st && st.isIconified()) {
            return false;
        }
        return true;
    }

    /**
     * Attaches scene/window/iconified listeners so animations and timers can react immediately
     * when the stage hides, iconifies, or restores.
     */
    public static void attachLifecycleListeners(Node anchor, Runnable evaluate) {
        if (anchor == null) {
            return;
        }
        REDUCE_MOTION.addListener((_, _, _) -> evaluate.run());
        anchor.visibleProperty().addListener((_, _, _) -> evaluate.run());
        anchor.sceneProperty().addListener((_, _, newScene) -> {
            if (newScene != null) {
                newScene.windowProperty().addListener((_, _, newWin) -> {
                    if (newWin != null) {
                        newWin.showingProperty().addListener((_, _, _) -> evaluate.run());
                        if (newWin instanceof Stage st) {
                            st.iconifiedProperty().addListener((_, _, _) -> evaluate.run());
                        }
                    }
                    evaluate.run();
                });
                Window w = newScene.getWindow();
                if (w != null) {
                    w.showingProperty().addListener((_, _, _) -> evaluate.run());
                    if (w instanceof Stage st) {
                        st.iconifiedProperty().addListener((_, _, _) -> evaluate.run());
                    }
                }
            }
            evaluate.run();
        });
        Scene current = anchor.getScene();
        if (current != null) {
            Window w = current.getWindow();
            if (w != null) {
                w.showingProperty().addListener((_, _, _) -> evaluate.run());
                if (w instanceof Stage st) {
                    st.iconifiedProperty().addListener((_, _, _) -> evaluate.run());
                }
            }
        }
    }

    /**
     * Abstract 60 fps capped {@link AnimationTimer} that pauses cleanly when hidden,
     * iconified, or when {@link Motion#isReduceMotion()} is enabled.
     */
    public abstract static class CappedAnimationTimer extends AnimationTimer {

        private static final long MIN_INTERVAL_NS = 16_000_000L; // ~60 fps cap
        private long lastTickNs = 0L;
        private final Node anchor;

        protected CappedAnimationTimer(Node anchor) {
            this.anchor = anchor;
        }

        @Override
        public final void handle(long now) {
            if (!isAnchorVisible(anchor)) {
                return;
            }
            if (lastTickNs > 0L && (now - lastTickNs) < MIN_INTERVAL_NS) {
                return;
            }
            double dtSeconds = lastTickNs == 0L ? 0.016 : Math.min(0.05, (now - lastTickNs) / 1_000_000_000.0);
            lastTickNs = now;
            onTick(now, dtSeconds);
        }

        public void bind() {
            attachLifecycleListeners(anchor, () -> {
                if (isAnchorVisible(anchor) && !isReduceMotion()) {
                    start();
                } else {
                    stop();
                }
            });
            if (isAnchorVisible(anchor) && !isReduceMotion()) {
                start();
            }
        }

        protected abstract void onTick(long nowNs, double dtSeconds);
    }
}

