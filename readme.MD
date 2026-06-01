# QWEOVOdetect

[中文文档](README.zh-CN.md)

**QWEOVOdetect** is an open-source SOCKS5 proxy auditing and abuse detection system. It passively inspects proxy traffic — extracting HTTP Host headers, TLS/QUIC SNI, detecting Shadowsocks-like encrypted tunnels, and identifying Trojan protocol signatures — then surfaces the results through a Vue 3 dashboard with management of block rules and forensic captures.

## Features

### SOCKS5 Proxy
- **TCP CONNECT** forwarding with transparent relay
- **UDP ASSOCIATE** native UDP relay with per-packet forwarding
- **Multiple inbound ports** — each independently configured with nickname, enabled state, and optional username/password authentication
- **Hot reload** — add, disable, or modify inbound ports and authentication without restarting the backend
- **Proxy Protocol** support for extracting real client IP addresses

### Deep Packet Inspection (DPI)
- **HTTP Host** detection from CONNECT headers
- **TLS SNI** extraction from Client Hello handshakes
- **QUIC SNI** detection from QUIC Initial packets (tagged as QUIC in the dashboard)
- **Shadowsocks / encrypted tunnel** heuristics
- **Trojan protocol** signature detection with high-risk target logging

### Blocking & Enforcement
- **Domain keyword blocking** — blocks connections where HTTP Host, TLS SNI, or QUIC SNI matches a keyword (e.g., blocking `tiktok` matches `tiktok.com`, `api-tiktok.example`, etc.)
- **Target IP blocking** — blocks connections destined for specific remote IP addresses
- TCP connections are terminated with RST where possible; QUIC matches are silently dropped

### Forensics
- **Per-port forensic capture** — record TLS SNI, QUIC SNI, Trojan, and SS hits to timestamped `.txt` files
- Configurable duration with auto-stop and manual stop
- One active forensic task per port at a time

### Dashboard & Management
- **Vue 3 frontend** with real-time statistics
- Per-port traffic breakdown and client overview
- HTTP / TLS / QUIC SNI rankings
- Encrypted tunnel trigger leaderboard
- High-risk SS / Trojan target addresses
- Block rule management (domain keywords and target IPs)
- Forensic task management
- Account settings, database configuration, and inbound port settings

### Data Storage
- **H2** (embedded file database) for local/development use
- **MySQL** for production deployments, with connection validation before saving

## Architecture

```
 QWEOVOdetect/
 ├─ src/main/java/org/detector/qweovodetect/
 │  ├─ server/          SOCKS5 server, TCP relay, UDP relay
 │  ├─ dpi/             DPI engines: HTTP, TLS SNI, QUIC SNI, SS, Trojan
 │  ├─ stats/           REST API, statistics service, forensics, DB entities & repositories
 │  ├─ config/          Security config, JWT, database config
 │  └─ tools/           Utilities
 ├─ src/main/resources/
 │  └─ application.yml  Spring Boot application configuration
 ├─ qweovo-front/       Vue 3 frontend (Vite)
 ├─ data/               Default H2 database directory (runtime)
 ├─ forensics/          Forensic capture output directory (runtime)
 ├─ build.gradle        Gradle build (Spring Boot 3.3, Java 21)
 └─ settings.gradle
```

### Key Backend Components

| Component | Role |
|---|---|
| `Socks5Server` | Manages SOCKS5 listener lifecycle and hot reload of inbound configurations |
| `Socks5Handler` | Handles SOCKS5 handshake, authentication, CONNECT, UDP ASSOCIATE, and Proxy Protocol |
| `RelayHandler` | Bidirectional TCP relay with client-side DPI inspection and blocking |
| `UdpRelayHandler` | Native UDP relay with QUIC Initial SNI extraction |
| `DpiEngine` | Entry point for HTTP Host, TLS SNI, and SS detection |
| `QuicSniDpiEngine` | QUIC Initial decryption and SNI extraction |
| `TrojanDpiEngineAsync` | Asynchronous Trojan protocol signature detection |
| `StatsService` | Persists detection results and aggregates high-risk targets |
| `BlockRuleService` | Manages block rule CRUD, caching, and matching against connections |
| `ForensicsService` | Manages forensic capture tasks, file writing, and auto-stop timers |

## Quick Start

### Prerequisites

- **Java 21** or later
- **Node.js 18+** and npm (for the frontend)
- **MySQL** (optional — H2 is used by default)

### First Launch

**1. Start the backend:**

```powershell
cd <project-directory>
.\gradlew.bat bootRun
```

**2. Start the frontend:**

```powershell
cd <project-directory>\qweovo-front
npm install
npm run dev
```

**3. Open the setup wizard:**

```
http://localhost:5173
```

On first launch, the frontend will guide you through initial configuration:

- Admin username and password
- Database type (H2 or MySQL)
- API listen address and port
- SOCKS5 inbound ports (port number, nickname, enabled state, authentication)

> **Important:** After saving the initial configuration, you **must restart the backend**. The frontend will display a "waiting for restart" page, and the backend API will refuse login until restarted. This ensures the runtime configuration is fully synchronized with the on-disk `cfg` file.

### Subsequent Configuration Changes

| Change | Requires Restart |
|---|---|
| SOCKS5 inbound ports (add, disable, change port, change auth) | **No** — hot reloaded |
| API listen address or port | **Yes** |
| Database type or connection settings | **Yes** |

## Block Rules

### Domain Keyword Blocking

A rule like `tiktok` will match any of the following in HTTP Host, TLS SNI, or QUIC SNI:

- `tiktok.com`
- `tiktokwwqe.com`
- `api-tiktok.example.com`

**Enforcement:**
- HTTP Host match → TCP connection closed (RST where possible)
- TLS SNI match → TCP connection closed (RST where possible)
- QUIC SNI match → UDP packet silently dropped

### Target IP Blocking

Blocks connections where the **destination** (remote) IP matches the rule — this is not source/client IP blocking. TCP CONNECT connections are blocked after DNS resolution; UDP relay packets are dropped after the SOCKS5 UDP target address is resolved.

Rules are stored in the database and cached in memory to avoid per-packet database lookups.

## Forensics

The forensic panel in the dashboard lets you capture detection events to a file for a specified port and duration.

- Select an inbound port, name the output file, and set a duration (e.g., 5 minutes)
- Output is written to `forensics/<filename>.txt` in the project directory
- One forensic task per port at a time; tasks auto-stop when the timer expires, or can be manually stopped

**Output format:**

```
2026-05-29 18:44:47 [TLS] port=19084 client=1.2.3.4 sni=example.com
2026-05-29 18:44:47 [QUIC] port=19084 client=1.2.3.4 target=8.8.8.8:443 sni=example.com
2026-05-29 18:44:47 [TROJAN] port=19084 client=1.2.3.4 target=8.8.8.8 upload=700 download=174
2026-05-29 18:44:47 [SS] port=19084 client=1.2.3.4 target=8.8.8.8
```

## Database Schema

| Table | Description |
|---|---|
| `sni_logs` | HTTP / TLS / QUIC SNI access records |
| `ss_logs` | Suspected Shadowsocks / encrypted tunnel records |
| `trojan_logs` | Trojan signature detection records |
| `risk_targets` | Aggregated high-risk target addresses |
| `block_rules` | Domain keyword and target IP block rules |

## Build

### Backend

```powershell
# Compile
.\gradlew.bat compileJava

# Package as executable JAR
.\gradlew.bat bootJar
```

### Frontend

```powershell
cd qweovo-front
npm run build
```

## Default Ports

| Service | Default |
|---|---|
| SOCKS5 | Configured in `cfg` (first default: `1080`) |
| API | `127.0.0.1:8080` |
| Frontend dev server | `http://localhost:5173` |

## Notes

- This project is intended for local research, detection, and visualization.
- UDP forwarding uses SOCKS5 native UDP relay. Regular UDP packets are forwarded normally; QUIC Initial packets are inspected for SNI (for statistics, blocking, and forensics).
- Trojan detection operates on TCP relay traffic.
- To obtain real client IPs, you need to modify the Xray core to execute the Proxy Protocol before the SOCKS5 handshake on outbound TCP connections, so the real client address is forwarded transparently.

## Security

- Do not commit runtime `cfg` files, database files, account credentials, tokens, or keys to version control.
- The `.gitignore` excludes `cfg`, `data/`, and `forensics/` directories by default.

## License

This project is licensed under the **GNU Affero General Public License v3.0**. See [LICENSE](LICENSE) for the full text.
