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
| **Multi-Factor Auth (MFA)** | **Implemented** | RFC 6238 TOTP with constant-time equality check, step replay rejection, and progressive lockout counter. |
| **Device Trust & Quotas** | **Implemented** | Fail-closed device trust check; atomic auto-enrollment up to 3 devices per user in a single database transaction. |
| **Departmental Isolation** | **Implemented** | Role-based vaults (`FINANCE`, `HR`, `IT`, `HEADQUARTERS`) with canonical path confinement (`Path.toRealPath(NOFOLLOW_LINKS)`). |
| **Audit Logging** | **Implemented** | Forward-linked HMAC-SHA256 audit chaining with CRLF log injection neutralization. |
| **Administrative & Client GUI** | **Implemented** | JavaFX 25 cyber-defense dark desktop dashboards (`AdminDashboardApp` and `VpnClientApp`) with non-blocking async UX. |
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
- **UI Framework:** JavaFX 25 (`javafx-controls`, `javafx-graphics`, `javafx-base`) with `officevpn-theme.css` & `UiSafe` sanitization

---

## 4. How to Build & Run

### Prerequisites
- JDK 25 LTS installed and on `PATH`
- Apache Maven 3.9+
- Running MySQL 8+ or MariaDB 10.4+ instance (auto-creates `office_vpn` schema; configure credentials in `src/main/resources/config.properties` or via `-Dofficevpn.db.*` / `OFFICEVPN_DB_*` environment variables)

### Build Shaded Executable JARs
```bash
mvn clean verify -Pstrict -Djava.awt.headless=true
```
*(In Windows PowerShell, quote `-D` flags: `mvn clean verify -Pstrict "-Djava.awt.headless=true"`.)*
This produces two self-contained executable JavaFX + MySQL JARs in `target/`:
- `target/office-vpn-server.jar`
- `target/office-vpn-client.jar`

The strict profile compiles with `-Xlint:all -Werror` to guarantee zero compiler warnings.

### First-Run Administrator Setup & Running Apps
On first startup with a fresh MySQL database (`office_vpn`), the server initializes InnoDB tables + append-only `audit_logs` triggers and launches the **Administrator Bootstrap Setup**:
1. Start MySQL / MariaDB on `127.0.0.1:3306` (default `db.user=root`, empty `db.password`, or override in `config.properties`).
2. Launch the **Admin Gateway Suite**: `java -jar target/office-vpn-server.jar`
3. Launch the **VPN Client Portal**: `java -jar target/office-vpn-client.jar`
4. Enter the administrator username and a strong passphrase meeting policy requirements (min 12 characters with upper, lower, numeric, and symbol chars).
5. Unlock or create the server PKCS#12 identity keystore via `OFFICEVPN_KEYSTORE_PASS` or the interactive dialog.

> **Testing / Grading Demo Mode:** To auto-seed deterministic demo accounts (`admin_hq`, `alice_fin`, `bob_hr`, `charlie_it`, `david_auditor`):
> ```bash
> java "-Dofficevpn.demo=true" -jar target/office-vpn-server.jar
> ```

---

## 5. Project Structure

```
office-vpn-system/
|-- .github/
|   `-- workflows/
|       `-- ci.yml                  # GitHub Actions continuous integration workflow
|-- .gitignore
|-- LICENSE
|-- pom.xml
|-- README.md
`-- src/
    `-- main/
        |-- java/com/officevpn/
        |   |-- admin/              # User lifecycle, onboarding, offboarding, alerts, metrics, server control
        |   |-- client/             # Client engine, auto-reconnect, TOFU policies, console client
        |   |-- config/             # Central configuration utilities
        |   |-- db/                 # MySQL HikariCP connection pooling, schema init, audit trail
        |   |-- gui/                # JavaFX desktop cyber-defense dashboards (Admin and Client)
        |   |-- model/              # Immutable domain models and records
        |   |-- network/            # Bandwidth limiter, DNS leak guard, site-to-site tunnels
        |   |-- protocol/           # Binary wire packet framing, anti-replay sliding window
        |   |-- security/           # AES-GCM, ECDH PFS, HKDF, PBKDF2, TOTP, key pinning
        |   |-- server/             # Gateway server, connection guard, virtual IP pool, session manager
        |   |-- storage/            # Department file vaults with atomic writes and path traversal defense
        |   `-- tunnel/             # Split tunneling and full tunneling engines
        `-- resources/
            |-- config.properties   # Production runtime & MySQL configuration
            `-- styles/
                `-- officevpn-theme.css # JavaFX enterprise dark cyber-defense CSS theme
```

---

## 6. License

This project is licensed under the [MIT License](LICENSE) - see the `LICENSE` file for details.

**Author:** Gireesh (Copyright (c) 2026)
