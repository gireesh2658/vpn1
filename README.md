# Office VPN System — Secure Office Network Access

![Java 25 LTS](https://img.shields.io/badge/Java-25%20LTS-orange.svg)
![Maven](https://img.shields.io/badge/Maven-3.9+-blue.svg)
![MySQL](https://img.shields.io/badge/MySQL-HikariCP%20Pool-blue.svg)
![JavaFX](https://img.shields.io/badge/UI-JavaFX%2025-cyan.svg)
![Cryptography](https://img.shields.io/badge/Encryption-AES--256--GCM%20%2B%20ECDH%20PFS-green.svg)
![Protocol](https://img.shields.io/badge/Protocol-OFFICE--VPN--2.0-blueviolet.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

An application-level zero-trust encrypted intranet gateway and departmental access control framework implemented in modern Java (**JDK 25 LTS**).

---

## 1. Scope & Design Overview

`Office VPN System` is designed as an **application-level encrypted access gateway and zero-trust intranet system**. It provides authenticated client-server tunneling, departmental access partitioning, and end-to-end cryptographic protection for remote office workflows (file exchange, departmental messaging, and gateway telemetry).

### Feature & Implementation Status Matrix

| Capability | Status | Implementation Details |
| :--- | :--- | :--- |
| **Encrypted Wire Transport** | **Implemented** | `OFFICE-VPN-2.0` protocol over framed TCP with length-prefixed packet validation. |
| **Forward Secrecy (PFS)** | **Implemented** | Ephemeral ECDH on NIST curve `secp256r1` per session; old session keys cannot be recovered if server RSA key is compromised. |
| **Gateway Authentication** | **Implemented** | Long-term RSA-2048 key with RSASSA-PSS transcript signing and TOFU/pinned client store. |
| **Wire Encryption & AEAD** | **Implemented** | AES-256-GCM with 128-bit authentication tags and directional binding (`0x01` client-to-server, `0x02` server-to-client) in AAD. |
| **Directional Key Isolation** | **Implemented** | HKDF-SHA256 extracts independent `c2sKey` and `s2cKey` derived from the ECDH secret and transcript hash. |
| **Anti-Replay Protection** | **Implemented** | 128-bit sliding bitmap sequence window and per-session IV tracking applied post-authentication. |
| **Credential Security** | **Implemented** | PBKDF2WithHmacSHA256 with 600,000 iterations, 16-byte CSPRNG salt, and memory zeroization (`char[]` scrubbing). |
| **Multi-Factor Auth (MFA)** | **Implemented** | Optional RFC 6238 TOTP (off by default; scannable QR code + Base32 enrollment & live verifier in Admin `Manage 2FA`, constant-time check, step replay rejection, lockout counter). |
| **Device Trust & Quotas** | **Implemented** | Fail-closed device trust check; atomic auto-enrollment up to 3 devices per user in a single database transaction. |
| **Departmental Isolation** | **Implemented** | Role-based vaults (`FINANCE`, `HR`, `IT`, `HEADQUARTERS`) with canonical path confinement (`Path.toRealPath(NOFOLLOW_LINKS)`). |
| **Audit Logging** | **Implemented** | Forward-linked HMAC-SHA256 audit chaining with CRLF log injection neutralization. |
| **Administrative & Client GUI** | **Implemented** | Unified light-editorial **Ivory Atelier** JavaFX 25 consoles (`AdminDashboardApp` and `VpnClientApp`) with File Vault, Secure Chat, Device Trust, Password Change, Ping Latency, and QR MFA enrollment. |
| *Kernel TUN/TAP Driver* | *Future Scope* | Native OS virtual network adapter (`wintun.sys` / `/dev/net/tun`) for capturing full OS-level IP packets. |
| *OS Firewall & Route Hooking* | *Future Scope* | System routing table manipulation (`route add`) and firewall automation via platform APIs. |

---

## 2. Cryptographic Architecture (`OFFICE-VPN-2.0`)

The handshake and session transport follow a modern hybrid forward-secret design (1.5 RTT):

```
Client                                                              Server
  |                                                                   |
  | -------- 1. HANDSHAKE_INIT (ClientHello) -----------------------> |
  |      [proto="OFFICE-VPN-2.0", clientRandom (32B CSPRNG),          |
  |       clientEcPub (secp256r1 ephemeral key)]                      |
  |                                                                   |
  | <------- 2. HANDSHAKE_CHALLENGE (ServerHello) ------------------- |
  |      [serverRandom (32B CSPRNG), serverEcPub (secp256r1),         |
  |       serverRsaPub (RSA-2048), RSASSA-PSS Signature(Transcript)]   |
  |                                                                   |
  |  1. Verify serverRsaPub matches pinned fingerprint (or policy)    |
  |  2. Verify RSASSA-PSS signature over canonical transcript         |
  |  3. Validate serverEcPub satisfies secp256r1 curve equation       |
  |  4. Pin server fingerprint to store (strictly post-verification)  |
  |                                                                   |
  | -------- 3. HANDSHAKE_SESSION_KEY (KeyConfirm) -----------------> |
  |      [Status: CONFIRMED]                                          |
  |                                                                   |
  |  [Both sides compute ECDH Shared Secret (secp256r1)]              |
  |  [Salt = SHA-256(Transcript); HKDF derives c2sKey & s2cKey]       |
  |                                                                   |
  | <====== 4. Encrypted Tunnel Established (AES-256-GCM) ==========> |
  |      [Directional AEAD: AAD binds Header, SeqNum, DirectionByte]  |
```

1. **Transcript Signature:** Server signs the canonical transcript (`OFFICE-VPN-2.0 || clientRandom || serverRandom || clientEcPub || serverEcPub`) using RSASSA-PSS.
2. **Key Derivation:** HKDF-SHA256 derives 256-bit directional session keys (`c2sKey` and `s2cKey`) using `SHA-256(transcript)` as salt.
3. **Directional AEAD:** Every wire packet is encrypted with AES-256-GCM. The AAD includes packet metadata, sequence number, and a direction byte (`0x01` client-to-server, `0x02` server-to-client) preventing cross-stream packet reflection attacks.
4. **Automated Verification:** All cryptographic primitives, handshake mechanics, anti-replay sliding window, and auth flows are validated via JUnit 5 tests (`mvn -Pstrict verify`).

---

## 3. Tech Stack

- **Platform:** Java 25 LTS (OpenJDK 25)
- **Build System:** Apache Maven 3.9+
- **Database:** MySQL / MariaDB via `mysql-connector-j` 9.6.0 & HikariCP 7.1.0 connection pooling
- **Logging:** SLF4J 2.0.16 with `slf4j-simple`
- **Security:** Standard Java Cryptography Architecture (`java.security`, `javax.crypto`)
- **UI Framework:** JavaFX 25 (`javafx-controls`, `javafx-graphics`, `javafx-base`), AtlantaFX `atlantafx-base` 3.0.0, Ikonli Feather icons 12.4.0, bundled OFL typography (`Fraunces`, `Manrope`, `JetBrains Mono`), CSS themes (`officevpn-theme.css` & `ui/theme/ivory-atelier.css`), and centralized `i18n/messages.properties`

---

## 4. How to Build & Run

### Prerequisites
- JDK 25 LTS installed and on `PATH`
- Apache Maven 3.9+
- Running local MySQL 8+ instance (auto-initializes `office_vpn` schema; supply `db.user` / `db.password` externally via `~/.officevpn/db.properties`, `./config.local.properties`, `-Dofficevpn.db.*`, or `OFFICEVPN_DB_*` environment variables)

### Build & Run Full Verification Suite
```bash
mvn clean verify -Pstrict -Djava.awt.headless=true
```
*(In Windows PowerShell, quote `-D` flags: `mvn clean verify -Pstrict "-Djava.awt.headless=true"`.)*
This compiles with `-Xlint:all -Werror`, executes all **29 JUnit 5 tests** across 9 test suites (including full end-to-end encrypted wire, MFA, QR generation, vault, password rotation, device trust, RBAC authorization, and live Ivory Atelier adapter tests), and produces two shaded executable JARs in `target/`:
- `target/office-vpn-server.jar`
- `target/office-vpn-client.jar`

### First-Run Setup & Running Applications
On first startup with an empty MySQL database (`office_vpn`), the server initializes InnoDB tables + append-only `audit_logs` triggers and launches the **Initial Administrator Setup**:
1. Start local **MySQL Server 8.4** on `127.0.0.1:3306` and provide external credentials (`db.user` / `db.password`) in `~/.officevpn/db.properties` or `./config.local.properties`.
2. Launch the **Admin Gateway Console**:
   ```bash
   java -jar target/office-vpn-server.jar
   ```
   Or headless CLI Gateway without GUI:
   ```bash
   java -cp target/office-vpn-server.jar com.officevpn.server.VpnServer
   ```
3. Launch the **VPN Client Portal** (opens the unified **Ivory Atelier** workspace directly):
   ```bash
   java -jar target/office-vpn-client.jar
   ```
   Or launch the **Interactive Console CLI**:
   ```bash
   java -cp target/office-vpn-client.jar com.officevpn.client.ConsoleClient
   ```
4. Create the initial Headquarters administrator username and a strong passphrase meeting policy requirements (min 12 characters with upper, lower, numeric, and symbol chars).
5. Unlock or create the encrypted RSA-2048 identity keystore (`server_data/server_identity.key`) via `OFFICEVPN_KEYSTORE_PASS` or the interactive dialog.
6. **Optional MFA (TOTP 2FA):** Leave the 6-digit MFA boxes empty unless an admin enabled TOTP 2FA on your account via **Users -> Manage 2FA** (which displays a scannable QR code for Google/Microsoft Authenticator plus a live test verifier).

---

## 5. Project Structure & Configuration

All non-secret network, port, data directory, subnet, and pool settings are centralized in `src/main/resources/config.properties` (`ConfigUtil`), overlaid cleanly by external `~/.officevpn/db.properties` and `./config.local.properties`. All desktop UI strings are externalized in `src/main/resources/i18n/messages.properties` (`Messages`).

```
office-vpn-system/
|-- .github/
|   `-- workflows/
|       `-- ci.yml                       # GitHub Actions CI (strict build + headless JUnit suite)
|-- .gitignore
|-- LICENSE
|-- pom.xml
|-- README.md
`-- src/
    `-- main/
        |-- java/com/officevpn/
        |   |-- admin/                   # User lifecycle, bootstrap, policies, alerts, metrics, audit service
        |   |-- client/                  # Client engine, auto-reconnect, TOFU policies, ConsoleClient CLI
        |   |-- config/                  # ConfigUtil & Messages (ResourceBundle i18n helper)
        |   |-- db/                      # MySQL HikariCP connection pooling, schema init, HMAC audit chain
        |   |-- gui/                     # JavaFX enterprise dashboards (Admin and Client portals)
        |   |-- model/                   # Immutable domain models, roles, departments, audit records
        |   |-- network/                 # Bandwidth limiter, DNS leak guard, site-to-site peer manager
        |   |-- protocol/                # Binary wire framing, PacketType, VpnPacket
        |   |-- security/                # AES-GCM, ECDH PFS, HKDF, PBKDF2, TOTP, key pinning, replay window
        |   |-- server/                  # Gateway server, ClientHandler, VirtualIpPool, VpnSession, VpnServer
        |   |-- storage/                 # Department file vaults with atomic writes and path traversal defense
        |   |-- tunnel/                  # Split tunneling and full tunneling engines
        |   |-- ui/                      # Ivory Atelier unified client shell, components, BackendVpnServiceAdapter
        |   `-- util/                    # Authentic OS/network hardware telemetry
        `-- resources/
            |-- config.properties        # Centralized runtime, subnet, path, and MySQL configuration
            |-- i18n/messages.properties # Centralized user-facing UI strings & accessibility labels
            |-- fonts/                   # Bundled OFL static fonts (Fraunces, Manrope, JetBrains Mono)
            |-- styles/officevpn-theme.css
            `-- ui/theme/ivory-atelier.css
```

---

## 6. License

This project is licensed under the [MIT License](LICENSE) - see the `LICENSE` file for details.

**Author:** Gireesh (Copyright (c) 2026)
