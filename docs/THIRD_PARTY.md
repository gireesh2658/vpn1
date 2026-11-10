# Third-Party Licenses & Assets Attribution

All external UI frameworks, icon fonts, font families, and runtime dependencies bundled in the **Ivory Atelier** Office VPN UI and backend use permissive open-source licenses (MIT, Apache 2.0, SIL Open Font License 1.1, or Eclipse Public License 2.0 / GPL-2.0 with Classpath Exception). No GPL-3.0 code or non-free assets are included.

| Component / Asset | Version | Source / Maintainer | License | Usage in Repository |
| :--- | :--- | :--- | :--- | :--- |
| **AtlantaFX Base** (`io.github.mkpaz:atlantafx-base`) | 3.0.0 | mkpaz / AtlantaFX | **MIT License** | Neutral `PrimerLight` CSS base for stock JavaFX controls (scrollbars, inputs, tables, tooltips) |
| **Ikonli JavaFX** (`org.kordamp.ikonli:ikonli-javafx`) | 12.4.0 | Andres Almiray / Kordamp | **Apache-2.0 License** | JavaFX `FontIcon` integration layer |
| **Ikonli Feather Pack** (`org.kordamp.ikonli:ikonli-feather-pack`) | 12.4.0 | Kordamp / Cole Bemis (Feather Icons) | **Apache-2.0** (wrapper) / **MIT License** (Feather glyphs) | Hairline icon glyphs wrapped by `com.officevpn.ui.theme.Icons` |
| **Fraunces** (`Fraunces-{Regular,SemiBold,Bold}.ttf`) | v38 | Undercase Type (Google Fonts repository) | **SIL Open Font License 1.1 (OFL)** | Editorial serif headlines and rolling odometer telemetry numerals (`src/main/resources/fonts/`) |
| **Manrope** (`Manrope-{Regular,Medium,SemiBold,Bold}.ttf`) | v23 | Mikhail Sharanda (Google Fonts repository) | **SIL Open Font License 1.1 (OFL)** | Primary UI sans-serif typography across all weights (`src/main/resources/fonts/`) |
| **JetBrains Mono** (`JetBrainsMono-{Regular,Medium,Bold}.ttf`) | v24 | JetBrains (Google Fonts repository) | **SIL Open Font License 1.1 (OFL)** | Monospace IPs, ports, setup keys, fingerprints, and counters (`src/main/resources/fonts/`) |
| **OpenJFX** (`javafx-controls`, `javafx-graphics`, `javafx-base`) | 25.0.5 | OpenJDK / Gluon | **GPL-2.0 with Classpath Exception** | Desktop JavaFX 25 LTS rendering runtime |
| **HikariCP** (`com.zaxxer:HikariCP`) | 7.1.0 | Brett Wooldridge | **Apache-2.0 License** | MySQL JDBC connection pool |
| **SLF4J** (`org.slf4j:slf4j-api`, `slf4j-simple`) | 2.0.16 | QOS.ch | **MIT License** | Diagnostic logging |
| **H2 Database Engine** (`com.h2database:h2`, test scope) | 2.4.240 | H2 Group | **MPL 2.0 / EPL 1.0** | In-memory MySQL-mode unit testing |

