# Truthsayer

> An SSH bastion that doesn't just forward connections — it understands them.

> **Note:** This project is an experiment in evaluating the capabilities of LLMs
> in building a production-grade security system. All architectural decisions were
> made by the author — LLMs served as an implementation tool, not a decision maker.

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
                  │  │  + Filter  │  │  ◄── exec + PTY-aware shell filtering
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

- **Sees through obfuscation** — a VTE terminal emulator processes raw bytes before the filter, so `rm\033[A -rf /` is caught the same as `rm -rf /`
- **Filters interactive sessions** — PTY-aware filter intercepts commands in real-time shell sessions without breaking echo or line editing
- **Local AI analysis** — a local LLM (Mistral 7B via Ollama) analyzes command buffers asynchronously. No session data ever reaches an external API
- **Kernel-level visibility** — an eBPF agent on target servers captures `execve`, `open`, and `connect` syscalls, providing visibility beyond what SSH exposes
- **Live intervention** — admins can observe sessions in real time, lock user input, or take over the keyboard entirely

---

## Features

| Feature | Status |
|---|---|
| Transparent SSH proxy (exec + shell sessions) | ✅ Done |
| Password authentication with opaque error messages | ✅ Done |
| VTE terminal decoder (anti-obfuscation) | ✅ Done |
| Command filter engine (Aho-Corasick) | ✅ Done |
| PTY-aware shell session filtering | ✅ Done |
| Session recording — asciinema v2 `.cast` format | 🔧 In progress |
| Live session streaming over WebSocket | 📅 Planned |
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
| Terminal Emulation | `github.com/danielgatis/go-vte` |
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
│   │   │   ├── engine.go            # Command filter — Aho-Corasick
│   │   │   └── interceptor.go       # Bridge stdin interceptor (exec + PTY modes)
│   │   ├── emulation/
│   │   │   ├── vte.go               # VTE state machine — tokens, Apply, HasObfuscation
│   │   │   ├── decoder.go           # VTEDecoder, DecoderPipeline, DecodeResult
│   │   │   ├── dcs.go               # DCSDecoder — strips tmux/screen DCS wrappers
│   │   │   └── factory.go           # DecoderFactory — selects decoder from $TERM
│   │   ├── behavior/
│   │   │   └── analyzer.go          # Leaky bucket + AI intent analysis (planned)
│   │   └── bpf/                     # eBPF hooks (planned)
│   ├── identity/
│   │   ├── provider.go              # Identity provider interface
│   │   └── ldap.go                  # LDAP/AD integration (planned)
│   ├── ca/
│   │   └── signer.go                # JIT certificate issuance via Vault
│   ├── config/
│   │   ├── config.go                # Config loading — viper, YAML + env vars
│   │   └── config.yaml.example      # Annotated example configuration
│   ├── secrets/
│   │   └── vault.go                 # HashiCorp Vault client
│   ├── observability/
│   │   └── metrics.go               # Prometheus metrics
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
├── backlog                          # Sprint tickets and roadmap
├── tests/
│   ├── e2e_login_test.go            # End-to-end: client → bastion → target
│   └── e2e_filter_test.go           # End-to-end: blocked command flow
├── Dockerfile
├── config.yaml
├── go.mod
└── go.sum
```

---

## Configuration

```yaml
server:
  port: 2222
  host: "0.0.0.0"
  host_key_path: "./certs/bastion_key"

target:
  default_addr: "127.0.0.1:22"
  default_user: "dev-user"

auth:
  users:
    alice: "password123"   # plaintext for dev — bcrypt in Phase 4

limits:
  max_connections: 100
  max_channels_per_conn: 10

security:
  blacklist:
    - "rm -rf"
    - "mkfs"
  session_timeout: 3600
  on_block: "message"      # "message" or "disconnect"

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

---

## Security

Truthsayer is itself a security-critical component. A few design decisions worth noting:

- **Passwords are never logged.** The `PasswordCallback` captures credentials only to verify identity. Error messages are identical for wrong password and unknown user to prevent enumeration attacks.
- **PTY-aware filtering.** Commands in interactive shell sessions are inspected after the user presses Enter — without buffering keystrokes, so echo and line editing work normally.
- **Obfuscation-resistant.** The VTE terminal emulator decodes ANSI escape sequences before inspection, so `rm\033[A -rf /` is caught the same as `rm -rf /`.
- **Session data stays local.** The AI analysis runs entirely via a local Ollama instance. No command data is sent to any external API.
- **Host key verification** is planned via HashiCorp Vault PKI. Until then, builds are not suitable for production use.

Found a vulnerability? Please open a private security advisory rather than a public issue.

---

## License

Apache License 2.0 — see [LICENSE](./LICENSE) for details.

---

## Status

🚧 **Early development — not production ready.**

### Phase 1 — Core Proxy ✅ Complete
TBAS-001 ✅ Wire Authenticator into SSHServer  
TBAS-002 ✅ Auth users section in config  
TBAS-004 ✅ E2E login tests  

### Phase 2 — Terminal Emulation ✅ Complete
TBAS-101 ✅ VTE decoder with token-based obfuscation detection  
TBAS-102 ✅ VTEDecoder, DecoderPipeline, DecoderFactory  
TBAS-103 ✅ DCS decoder for tmux/screen  
TBAS-104 ✅ Fuzz tests for VTE and DCS decoders  

### Phase 3 — Security Filter Engine ✅ Complete
TBAS-201 ✅ Filter engine (Aho-Corasick)  
TBAS-202 ✅ Filter in bridge  
TBAS-203 ✅ E2E filter tests with execution counter  
TBAS-801 ✅ PTY-aware command filtering for interactive shell sessions  

### Phase 4 — Audit & Session Recording 🔧 In progress
TBAS-003 — Recorder in bridge (asciinema v2)  
TBAS-301 — Session ID generation  
TBAS-302 — Live session streaming over WebSocket  
TBAS-303 — Session metadata in PostgreSQL  

### Phase 5+ — AI, eBPF, Identity 📅 Planned

The project is being built in the open. Contributions, feedback, and stars are welcome.