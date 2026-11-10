# Ivory Atelier — JavaFX UI Component Library (`com.officevpn.ui`)

**Ivory Atelier** is a strictly light, warm-paper editorial design system for the Office VPN client and administrative console built cleanly atop JavaFX 25, AtlantaFX (`PrimerLight`), and Ikonli Feather icons.

---

## 1. Design Language & Tokens

Tokens are declared as looked-up colors in [`src/main/resources/ui/theme/ivory-atelier.css`](../src/main/resources/ui/theme/ivory-atelier.css) and mirrored programmatically in [`Tokens.java`](../src/main/java/com/officevpn/ui/theme/Tokens.java).

| Token | Hex | Role | Contrast-Safe Text Counterpart |
| :--- | :--- | :--- | :--- |
| `-ia-canvas` | `#FBF8F1` | Warm ivory page background | `#26233A` (`14.1:1`), `#6A6580` (`5.1:1`) |
| `-ia-paper` | `#FFFFFF` | Opaque layered card surface (`1px` hairline) | `#26233A` (`14.9:1`), `#6A6580` (`5.4:1`) |
| `-ia-sand` | `#F2EBDC` | Left navigation rail, inset badges, chips | `#26233A` (`12.6:1`), `#6A6580` (`4.53:1`) |
| `-ia-hairline` | `#E6DCC6` | Crisp `1px` borders, timeline threads, blueprint grid | — |
| `-ia-marigold` | `#FFB224` | Primary action accent, active indicator bar, upload band | `#26233A` (`9.2:1`), small text `#7A4B00` |
| `-ia-peacock` | `#0E9F9A` | Secure/connected state, download band, unlocked rooms | Small text `#096B67` (`6.2:1` on paper) |
| `-ia-coral` | `#F4604C` | Blocked, kill-switch lock, faulted loom, revoke | Small text `#BA2A1A` (`5.9:1` on paper) |
| `-ia-lilac` | `#7C6CF0` | Informational pills, RTT heartbeat pulse | Small text `#4F3CC9` (`7.3:1` on paper) |

### Elevation & Surface Rules
- No dark surfaces anywhere (including tooltips, tables, scrollbars, and command palette).
- `Tokens.wrapPaperCard(node, applyGrain)` builds a **nested two-layer warm-tinted shadow** (`DropShadow` ambient outer + close contact shadow inner) because JavaFX CSS natively permits only one shadow per node, and caches static cards with `CacheHint.SPEED`.
- Optional subtle paper grain is generated once into a `128x128` `WritableImage` (`Tokens.getPaperGrainImage()`) with strictly `<= 4%` pixel alpha opacity.

---

## 2. Typography & Motion Lifecycle

- **Fonts (`Fonts.java`)**: Loads bundled static OFL TTFs via `Font.loadFont` (`Fraunces`, `Fraunces SemiBold`, `Manrope`, `Manrope Medium`, `Manrope SemiBold`, `JetBrains Mono`, `JetBrains Mono Medium`), falling back to `Segoe UI` / `Consolas`. Referencing each reported family name ensures Medium/SemiBold weights render accurately rather than flattening to Regular/Bold.
- **Motion (`Motion.java`)**:
  - Standard durations: `Motion.FAST` (`120 ms`), `Motion.MEDIUM` (`220 ms`), `Motion.SLOW` (`420 ms`), plus damped `Motion.spring()` interpolator and `Motion.staggerEnter(...)`.
  - **Zero-Idle-CPU Lifecycle**: Continuous animations (`Motion.bindLifecycle`) and ~60 fps `Motion.CappedAnimationTimer` instances observe `stage.iconifiedProperty()`, `window.showingProperty()`, `node.sceneProperty()`, and `Motion.reduceMotionProperty()`, pausing immediately when minimized, hidden, or when Reduce Motion is enabled.

---

## 3. Component Catalog (`com.officevpn.ui.components`)

| Component | Control / Skin API | PseudoClasses | Keyboard & Accessibility |
| :--- | :--- | :--- | :--- |
| **`KeycardGate`** | `connectionStateProperty`, `statusCaptionProperty`, `onConnectRequested`, `onDisconnectRequested`, `trackHeightProperty` (CSS `-ia-track-height`) | `:disconnected`, `:connecting`, `:handshaking`, `:connected`, `:reconnecting`, `:blocked` | Focusable button role; hold **Space**/**Enter** `600 ms` with radial progress arc or drag card across track |
| **`HandshakeLoom`** | `completedStationsProperty`, `failedStationProperty`, `failureReasonProperty`, `cipherSuiteProperty`, `sealRadiusProperty` (CSS `-ia-seal-radius`) | `:running`, `:complete`, `:failed` | Accessible progress role; inline **Retry** action when a station frays |
| **`OfficeAtlas`** | `activeBranchProperty`, `tunnelConnectedProperty`, `resources()`, `inspectedRoomProperty` | `:connected` | **Left/Right/Up/Down** cycles schematic rooms; hover/focus inspects allowed hosts & TCP/UDP ports |
| **`PulseRibbon`** | `series()`, `downloadMbpsProperty`, `uploadMbpsProperty`, `latencyMsProperty`, `connectedProperty` | `:live` | **Left/Right** scrubs the 60-second Catmull-Rom spline history & RTT heartbeat strip |
| **`GatewayShelf`** | `gateways()`, `selectedGatewayProperty`, `searchQueryProperty`, `createCommandPaletteOverlay(...)` | `:selected` | Fuzzy subsequence search, **Up/Down** + **Enter** selection, **`Ctrl+K`** modal Command Palette |
| **`WorkModes`** | `profiles()`, `activeProfileProperty`, `onConnectAndGoProperty`, `onSaveProfileProperty` | `.work-mode-swatch-active` | Swatch pinning, `Connect & Go` launcher, inline slide-out Edit side sheet |
| **`SafetyLatches`** | `killSwitchProperty`, `autoConnectUntrustedWifiProperty`, `dnsLeakGuardProperty`, `splitApps()` | `:armed` (on `MechanicalLatch`) | Space/Enter spring-bolt toggles + drag-and-drop & arrow transfer across `SplitLanes` |
| **`PostureSeal`** | `checks()`, `selectedCheckProperty`, `onRemediateProperty`, `onRescanProperty` | `:compliant` | Click ring arcs or rows to expand failing remediation tips and one-click resolution |
| **`LiveRoster`** | `sessions()`, `inviteKeyProperty`, `onRevokeSessionProperty`, `onRotateInviteProperty` | — | Filterable `SessionTable`, avatar presence rings, copyable countdown setup key, **Slide-to-Revoke** slider (`>= 78%` or Enter) |
| **`AuditThread`** | `events()`, `loadingProperty`, `chainStatusProperty`, `activeFilterProperty`, `onExportCsvProperty` | `:loading` | Grouped timeline with warm shimmer skeleton loader, category filters, and CSV export |
| **`SignInCard`** | `verifierProperty`, `onSsoRequestedProperty`, `onAuthenticatedProperty`, `showErrorShake(String)` | `:otp-error` | 6-cell OTP with auto-advance, full-code paste distribution, Backspace traversal, error shake |
| **`Toasts`** | `push(Severity, title, msg)`, `createStandaloneDemo()` | — | Anchored corner slips with spring slide-in, hover pause, semantic accents |
| **`TrayFlyout`** | `install(...)`, `showFlyout(...)`, `createFlyoutContent(...)` | — | Windows `SystemTray` icon (`Platform.setImplicitExit(false)`) toggling solid `#FFFFFF` rounded undecorated stage above taskbar |

---

## 4. Service Separation & Backend Extension (`com.officevpn.ui.service`)

All UI screens depend strictly on the [`VpnClientService`](../src/main/java/com/officevpn/ui/service/VpnClientService.java) interface rather than sockets or SQL:
- **`MockVpnService`**: Standalone deterministic simulator for offline development, `ComponentGallery`, and `PreviewExporter`.
- **`BackendVpnServiceAdapter`**: Production bridge adapting `VpnClientEngine`, `TunnelManager`, `KillSwitchManager`, `DnsLeakProtection`, `DatabaseManager`, `MetricsCollector`, `AuditService`, and `VpnGatewayServer`, executing blocking handshakes/JDBC off-thread and marshaling all property updates via `Platform.runLater`.

### Adding a New Custom Control
1. Extend `javafx.scene.control.Control`, expose JavaFX properties and `Styleable` `CssMetaData` where themeable.
2. Place layout/rendering inside a private `SkinBase<T>` created in `createDefaultSkin()` to avoid JDK 25 `this-escape` warnings.
3. Attach continuous timers through `Motion.CappedAnimationTimer.bind()` or `Motion.bindLifecycle(...)` so minimized windows consume zero idle CPU.
4. Register a dedicated `.my-component` block in `ivory-atelier.css`, add a `createStandaloneDemo(VpnClientService)` helper, and include it in `ComponentGallery` and `PreviewExporter`.

