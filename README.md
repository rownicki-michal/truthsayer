# Truthsayer

> An SSH bastion that doesn't just forward connections — it understands them.

**Truthsayer** is an enterprise-grade SSH bastion host written in Go. It sits transparently between engineers and infrastructure, recording every session, analyzing command intent with a local LLM, and providing deep visibility through eBPF kernel hooks — all without sending a single byte of session data to an external service.

```
  Engineer        Truthsayer Bastion          Target Server
  ─────────       ──────────────────          ─────────────
  ssh user@       ┌──────────────────┐
  bastion ───────►│  Auth & GeoIP    │
                  │  JIT Cert (Vault)│──────► ssh target
                  │                  │◄──────
                  │  ┌────────────┐  │
                  │  │  Bridge    │  │  ◄── full PTY, stdin/stdout/stderr
                  │  │  + Filter  │  │
                  │  │  + AI      │  │  ◄── local Ollama, async, non-blocking
                  │  │  + eBPF    │  │  ◄── kernel-level syscall visibility
                  │  └────────────┘  │
                  │  Recorder (.cast)│  ◄── asciinema v2 format
                  │  Live Streamer   │  ◄── WebSocket for admins
                  └──────────────────┘
```

---

## Why Truthsayer?

Traditional SSH jump servers are blind. They forward traffic but have no awareness of what users actually do. Truthsayer changes that:

- **Sees through obfuscation** — a VTE terminal emulator processes raw bytes before the filter, so `r\m -rf /` is caught the same as `rm -rf /`
- **Local AI analysis** — a local LLM (Mistral 7B via Ollama) analyzes command buffers asynchronously. No session data ever reaches an external API
- **Kernel-level visibility** — an eBPF agent on target servers captures `execve`, `open`, and `connect` syscalls, providing visibility beyond what SSH exposes
- **Live intervention** — admins can observe sessions in real time, lock user input, or take over the keyboard entirely

---

## Features

| Feature | Status |
|---|---|
| Transparent SSH proxy (full PTY, vim/htop/tmux) | 🔧 In progress |
| Session recording — asciinema v2 `.cast` format | 📅 Planned (Phase 3) |
| Live session streaming over WebSocket | 📅 Planned (Phase 3) |
| Command filter with VTE anti-obfuscation | 📅 Planned (Phase 3) |
| Local LLM intent analysis (Ollama + Mistral 7B) | 📅 Planned (Phase 4) |
| JIT SSH certificates via HashiCorp Vault | 📅 Planned (Phase 4) |
| GeoIP impossible travel detection | 📅 Planned (Phase 4) |
| Admin session takeover & keyboard lock | 📅 Planned (Phase 4) |
| eBPF kernel-level syscall monitoring | 📅 Planned (Phase 5) |
| Prometheus metrics + Grafana dashboard | 📅 Planned (Phase 5) |
| React web panel with live session replay | 📅 Planned (Phase 5) |

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Go 1.22+ |
| SSH Protocol | `golang.org/x/crypto/ssh` |
| Terminal Emulation | `github.com/aymanbagabas/go-vte` |
| eBPF Agent | `cilium/ebpf` + Linux LSM hooks |
| Session Recording | asciinema v2 `.cast` |
| AI Analysis | Ollama + Mistral 7B (local) |
| Identity | LDAP / OIDC (Okta) |
| Secrets & PKI | HashiCorp Vault |
| GeoIP | MaxMind GeoLite2 |
| Metrics | Prometheus + Grafana |
| Database | PostgreSQL |
| Frontend | React + WebSocket |

---

## Project Structure

```
.
├── cmd/
│   ├── truthsayer/main.go       # Bastion server entrypoint
│   └── agent/main.go            # eBPF agent entrypoint
├── internal/
│   ├── proxy/
│   │   ├── server.go            # Inbound SSH listener
│   │   ├── client.go            # Outbound connection to target
│   │   └── auth.go              # Authentication callbacks
│   ├── heart/
│   │   ├── bridge.go            # Stream multiplexer (core data path)
│   │   └── terminal.go          # PTY and window-change propagation
│   ├── audit/
│   │   ├── recorder.go          # .cast session recording
│   │   └── streamer.go          # Live WebSocket streaming
│   ├── security/
│   │   ├── filter/engine.go     # Command filter (regex + Aho-Corasick)
│   │   ├── emulation/vte.go     # ANSI parser (anti-obfuscation)
│   │   ├── behavior/analyzer.go # Leaky bucket anomaly detection
│   │   ├── geo/checker.go       # GeoIP impossible travel
│   │   └── ai/agent.go          # Local LLM sidecar
│   ├── ca/signer.go             # JIT certificate issuance
│   ├── models/interfaces.go     # Core interfaces (Recorder, Filter, ...)
│   └── store/database.go        # PostgreSQL session store
├── pkg/ptyutil/                 # PTY/ANSI helpers
├── api/                         # gRPC proto (Bastion <-> eBPF Agent)
├── web/ui/                      # React admin panel
├── migrations/                  # PostgreSQL schema migrations
├── config.yaml
├── go.mod
└── roadmap                      # Detailed technical roadmap
```

---

## Getting Started

> **Note:** Truthsayer is under active development. The SSH proxy core is currently being built (Phase 1). The instructions below describe the target setup.

### Prerequisites

- Go 1.22+
- An SSH host key (for the bastion server identity)

```bash
ssh-keygen -t ed25519 -f ./certs/truthsayer_host_key -N ""
```

### Build & Run

```bash
git clone https://github.com/yourusername/truthsayer
cd truthsayer

go build ./cmd/truthsayer
./truthsayer --config config.yaml
```

### Configuration

```yaml
# config.yaml
server:
  port: 2222
  host: "0.0.0.0"
  host_key_path: "./certs/truthsayer_host_key"

target:
  default_addr: "192.168.1.100:22"
  default_user: "admin"

security:
  session_timeout: 3600

audit:
  storage_path: "./logs/audit_recordings"
  log_level: "info"
```

### Environment Variables

| Variable | Description |
|---|---|
| `TRUTHSAYER_PORT` | Override server port |
| `TRUTHSAYER_HOST` | Override bind address |
| `TRUTHSAYER_HOST_KEY` | Path to host key file |

### Connect

```bash
ssh -p 2222 youruser@bastion-host
```

---

## Development

```bash
# Run tests with race detector
go test -race ./...

# Run a specific package
go test -race ./internal/proxy/...
```

### Testing Philosophy

Every public interface is tested in isolation using in-memory transports:

- `net.Pipe()` — simulates TCP connections without network
- `io.Pipe()` — verifies data flow through the bridge
- `testcontainers-go` — integration tests against real PostgreSQL

---

## Roadmap

See [`roadmap`](./roadmap) for the full technical roadmap including all 6 development phases, milestones, risk analysis, and SLA targets.

**Current phase:** Phase 1 — SSH proxy core

---

## Security

Truthsayer is itself a security-critical component. A few design decisions worth noting:

- **Passwords are never logged.** The `PasswordCallback` captures credentials only to establish the outbound connection, then zeroes the memory.
- **Session data stays local.** The AI analysis runs entirely via a local Ollama instance. No command data is sent to any external API.
- **HostKey verification** is planned via HashiCorp Vault PKI (Milestone M4.5). Until then, builds are not suitable for production.

Found a vulnerability? Please open a private security advisory rather than a public issue.

---

## License

Apache License 2.0 — see [LICENSE](./LICENSE) for details.

---

## Status

🚧 **Early development — not production ready.**

The project is being built in the open. Contributions, feedback, and stars are welcome.
