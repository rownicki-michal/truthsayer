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
| Password authentication with opaque error messages | ✅ Done |
| Session recording — asciinema v2 `.cast` format | 🔧 In progress |
| Live session streaming over WebSocket | 📅 Planned |
| Command filter with VTE anti-obfuscation | 📅 Planned |
| Local LLM intent analysis (Ollama + Mistral 7B) | 📅 Planned |
| JIT SSH certificates via HashiCorp Vault | 📅 Planned |
| GeoIP impossible travel detection | 📅 Planned |
| Admin session takeover & keyboard lock | 📅 Planned |
| eBPF kernel-level syscall monitoring | 📅 Planned |
| Prometheus metrics + Grafana dashboard | 📅 Planned |
| React web panel with live session replay | 📅 Planned |

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
│   ├── truthsayer/main.go           # Bastion server entrypoint
│   └── agent/                       # eBPF agent entrypoint (planned)
├── internal/
│   ├── proxy/
│   │   ├── server.go                # Inbound SSH listener, connection limits
│   │   ├── client.go                # Outbound connection to target server
│   │   ├── auth.go                  # Authenticator — PasswordCallback
│   │   └── target_config.go         # TargetConfig DTO
│   ├── heart/
│   │   ├── bridge.go                # Bidirectional stream multiplexer
│   │   └── terminal.go              # PTY and window-change propagation
│   ├── audit/
│   │   ├── recorder.go              # asciinema v2 .cast session recording
│   │   └── streamer.go              # Live WebSocket streaming (planned)
│   ├── security/
│   │   ├── filter/
│   │   │   ├── engine.go            # Command filter — regex + Aho-Corasick
│   │   │   └── interceptor.go       # Bridge stdin interceptor
│   │   ├── emulation/
│   │   │   └── vte.go               # ANSI/VTE decoder (anti-obfuscation)
│   │   ├── behavior/
│   │   │   └── analyzer.go          # Leaky bucket + AI intent analysis
│   │   └── bpf/                     # eBPF hooks (planned)
│   ├── identity/
│   │   ├── provider.go              # Identity provider interface
│   │   └── ldap.go                  # LDAP/AD integration (planned)
│   ├── ca/
│   │   └── signer.go                # JIT certificate issuance via Vault
│   ├── config/
│   │   └── config.go                # Config loading — viper, YAML + env vars
│   ├── secrets/
│   │   └── vault.go                 # HashiCorp Vault client
│   ├── observability/
│   │   └── metrics.go               # Prometheus metrics
│   ├── api_impl/
│   │   └── service.go               # gRPC service implementation
│   ├── models/
│   │   └── interfaces.go            # Core interfaces (Recorder, Filter, ...)
│   └── store/
│       └── db.go                    # PostgreSQL session store
├── pkg/
│   ├── ebpf/
│   │   └── loader.go                # eBPF program loader
│   └── ptyutil/
│       └── ansi.go                  # PTY / ANSI helpers
├── api/                             # gRPC proto definitions (Bastion <-> Agent)
├── tests/
│   ├── e2e_login_test.go            # End-to-end: client → bastion → target
│   └── e2e_filter_test.go           # End-to-end: blocked command flow
├── web/ui/                          # React admin panel (planned)
├── config.yaml
├── go.mod
└── go.sum
```

---

## Getting Started

### Prerequisites

- Go 1.22+
- An SSH host key for the bastion server identity

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

Copy the example config and adjust to your environment:

```bash
cp internal/config/config.yaml.example config.yaml
```

```yaml
server:
  port: 2222
  host: "0.0.0.0"
  host_key_path: "./certs/truthsayer_host_key"

target:
  default_addr: "192.168.1.100:22"
  default_user: "admin"

auth:
  users:
    alice: "password123"   # plaintext for dev — hash for production

limits:
  max_connections: 100
  max_channels_per_conn: 10

security:
  session_timeout: 3600
  blacklist:
    - "rm -rf /"
    - "mkfs"

audit:
  storage_path: "./logs/sessions"
  log_level: "info"
```

### Environment Variables

| Variable | Description |
|---|---|
| `TRUTHSAYER_PORT` | Override server port |
| `TRUTHSAYER_HOST` | Override bind address |
| `TRUTHSAYER_HOST_KEY` | Path to host key file |
| `TARGET_ADDR` | Override target server address |
| `TARGET_USER` | Override target username |
| `AUDIT_STORAGE` | Override session recording path |
| `LOG_LEVEL` | Override log level |

### Connect

```bash
ssh -p 2222 youruser@bastion-host
```

---

## Development

### Setup

After cloning, enable Git hooks:

```bash
git config core.hooksPath .githooks
go install honnef.co/go/tools/cmd/staticcheck@latest
```

The pre-commit hook runs `gofmt`, `go vet`, `staticcheck`, and `go test -race` before every commit.

### Running Tests

```bash
# All packages with race detector
go test -race ./...

# Specific package
go test -race ./internal/proxy/...

# With verbose output
go test -race -v ./internal/audit/...
```

### Testing Philosophy

Every public interface is tested in isolation using in-memory transports:

- `net.Listener` on `127.0.0.1:0` — real TCP on a random port, avoids `net.Pipe()` deadlocks
- `io.Pipe()` / `bytes.Buffer` — verifies data flow through the bridge without SSH overhead
- `testcontainers-go` — integration tests against real PostgreSQL (planned)

---

## Security

Truthsayer is itself a security-critical component. A few design decisions worth noting:

- **Passwords are never logged.** The `PasswordCallback` captures credentials only to verify identity. Error messages are identical for wrong password and unknown user to prevent enumeration attacks.
- **Session data stays local.** The AI analysis runs entirely via a local Ollama instance. No command data is sent to any external API.
- **Host key verification** is planned via HashiCorp Vault PKI. Until then, builds are not suitable for production use.

Found a vulnerability? Please open a private security advisory rather than a public issue.

---

## License

Apache License 2.0 — see [LICENSE](./LICENSE) for details.

---

## Status

🚧 **Early development — not production ready.**

The project is being built in the open. Contributions, feedback, and stars are welcome.
