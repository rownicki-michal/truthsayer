package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"truthsayer/internal/heart"
)

// LimitsConfig holds configurable resource limits for the server.
// TargetConfig is defined in target_config.go.
// Zero value means no limit. All values are loaded from config.yaml.
//
// Example config.yaml:
//
//	limits:
//	  max_connections: 100
//	  max_channels_per_conn: 10
type LimitsConfig struct {
	// MaxConnections is the maximum number of concurrent SSH connections
	// across all clients. Enforced by a semaphore — no race condition possible.
	// Recommended production value: 100–500 depending on server capacity.
	MaxConnections int

	// MaxChannelsPerConn is the maximum number of concurrent channels
	// within a single SSH connection. Each shell, exec or port-forward
	// request opens a new channel.
	// Recommended production value: 10.
	MaxChannelsPerConn int
}

// SSHServer represents a running instance of the Truthsayer bastion.
// It terminates inbound SSH sessions and proxies them to target servers
// via TargetClient.
type SSHServer struct {
	addr     string
	config   *ssh.ServerConfig
	hostKey  ssh.Signer
	target   TargetConfig
	limits   LimitsConfig
	listener net.Listener
	wg       sync.WaitGroup

	// connSem is a buffered channel used as a semaphore to enforce MaxConnections.
	// Acquiring a slot:  connSem <- struct{}{}
	// Releasing a slot: <-connSem
	//
	// A buffered channel of capacity N guarantees that at most N goroutines
	// can hold a slot simultaneously — no race condition, no atomic counters needed.
	// nil when MaxConnections is 0 (no limit configured).
	connSem chan struct{}

	// ready is closed by Start() once the listener is bound and accepting.
	// Tests and callers can block on <-s.Ready() to avoid polling s.listener.
	ready chan struct{}
}

// ptyRequest holds the PTY parameters sent by the client.
// Stored before "shell" or "exec" arrives so it can be forwarded to the target session.
type ptyRequest struct {
	Term        string
	Width       uint32
	Height      uint32
	PixelWidth  uint32
	PixelHeight uint32
	Modes       string
}

// windowChangeRequest holds the terminal resize signal sent by the client.
// Without propagating this, TUI applications (vim, htop, tmux) will render incorrectly.
type windowChangeRequest struct {
	Width       uint32
	Height      uint32
	PixelWidth  uint32
	PixelHeight uint32
}

// NewSSHServer initialises the bastion server.
// Accepts a pre-parsed host key (ssh.Signer) so the caller can source it
// from Vault, a database, or generate it in-memory for tests.
func NewSSHServer(
	addr string,
	hostKey ssh.Signer,
	auth AuthConfig,
	target TargetConfig,
	limits LimitsConfig,
) (*SSHServer, error) {
	authenticator, err := NewAuthenticator(auth)
	if err != nil {
		return nil, fmt.Errorf("invalid auth config: %w", err)
	}

	s := &SSHServer{
		addr:    addr,
		hostKey: hostKey,
		target:  target,
		limits:  limits,
		ready:   make(chan struct{}),
	}

	// Initialise the connection semaphore only when a limit is configured.
	// A nil semaphore means "no limit" — checked before every acquire.
	if limits.MaxConnections > 0 {
		s.connSem = make(chan struct{}, limits.MaxConnections)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: authenticator.Callback(),
		ServerVersion:    "SSH-2.0-TruthsayerBastion_1.0",
	}

	config.AddHostKey(hostKey)
	s.config = config

	return s, nil
}

// Start begins accepting connections and blocks until the context is cancelled
// or a SIGTERM/SIGINT signal is received.
//
// Graceful shutdown: the listener is closed first (no new connections),
// then the server waits for all active sessions to finish naturally.
func (s *SSHServer) Start(ctx context.Context) error {
	var err error
	s.listener, err = net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to start listener on %s: %w", s.addr, err)
	}
	log.Printf("[SSH] Truthsayer bastion listening on %s (max_connections=%d, max_channels_per_conn=%d)",
		s.addr, s.limits.MaxConnections, s.limits.MaxChannelsPerConn)

	// Signal that the listener is ready — unblocks Ready() waiters.
	// Closing a channel broadcasts to all receivers without race conditions.
	close(s.ready)

	// Watch for OS signals and context cancellation.
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
		select {
		case sig := <-quit:
			log.Printf("[SSH] Received signal %v — initiating graceful shutdown", sig)
		case <-ctx.Done():
			log.Printf("[SSH] Context cancelled — initiating graceful shutdown")
		}
		s.listener.Close()
	}()

	for {
		nConn, err := s.listener.Accept()
		if err != nil {
			if isListenerClosed(err) {
				log.Println("[SSH] Waiting for active sessions to finish...")
				s.wg.Wait()
				log.Println("[SSH] All sessions closed. Server stopped.")
				return nil
			}
			log.Printf("[SSH] Accept error: %v", err)
			continue
		}

		if s.connSem != nil {
			select {
			case s.connSem <- struct{}{}:
			default:
				log.Printf("[LIMIT] Connection rejected from %s: limit reached (%d/%d)",
					nConn.RemoteAddr(), len(s.connSem), cap(s.connSem))
				nConn.Close()
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if s.connSem != nil {
				defer func() { <-s.connSem }()
			}
			s.handleConnection(nConn)
		}()
	}
}

// handleConnection performs the SSH handshake, dials the target via TargetClient,
// and dispatches incoming channels to the appropriate handlers.
func (s *SSHServer) handleConnection(nConn net.Conn) {
	defer nConn.Close()

	clientConn, clientChans, clientReqs, err := ssh.NewServerConn(nConn, s.config)
	if err != nil {
		log.Printf("[SSH] Handshake failed with %s: %v", nConn.RemoteAddr(), err)
		return
	}
	defer clientConn.Close()
	log.Printf("[SSH] Connected: user=%s addr=%s client=%s",
		clientConn.User(), clientConn.RemoteAddr(), clientConn.ClientVersion())

	// Capture the client's SSH agent if they forwarded one.
	// Used by TargetClient when AgentForwarding is enabled in TargetConfig.
	var clientAgent agent.Agent
	go func() {
		for req := range clientReqs {
			switch req.Type {
			case "auth-agent-req@openssh.com":
				// TODO (Phase 4): wire up agent.NewClient(channel) here.
				req.Reply(true, nil)
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	// Dial the target — one TargetClient shared across all channels for this connection.
	targetClient, err := Dial(s.target, clientAgent)
	if err != nil {
		log.Printf("[PROXY] Cannot connect to target for user %s: %v", clientConn.User(), err)
		// Reject all pending channels with a descriptive reason.
		for newChannel := range clientChans {
			newChannel.Reject(ssh.ConnectionFailed, "target server unavailable")
		}
		return
	}
	defer targetClient.Close()
	log.Printf("[PROXY] Connected to target %s for user %s", targetClient.Addr(), clientConn.User())

	// Per-connection channel semaphore.
	var chanSem chan struct{}
	if s.limits.MaxChannelsPerConn > 0 {
		chanSem = make(chan struct{}, s.limits.MaxChannelsPerConn)
	}

	for newChannel := range clientChans {
		switch newChannel.ChannelType() {

		case "session":
			if chanSem != nil {
				select {
				case chanSem <- struct{}{}:
				default:
					log.Printf("[LIMIT] Channel rejected for user %s: limit reached (%d/%d)",
						clientConn.User(), len(chanSem), cap(chanSem))
					newChannel.Reject(ssh.ResourceShortage, "too many channels")
					continue
				}
			}

			clientChan, clientChanReqs, err := newChannel.Accept()
			if err != nil {
				log.Printf("[SSH] Failed to accept session channel: %v", err)
				if chanSem != nil {
					<-chanSem
				}
				continue
			}

			// Each channel gets its own independent session on the target.
			targetSession, err := targetClient.NewSession()
			if err != nil {
				log.Printf("[PROXY] Failed to open target session: %v", err)
				clientChan.Close()
				if chanSem != nil {
					<-chanSem
				}
				continue
			}

			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				if chanSem != nil {
					defer func() { <-chanSem }()
				}
				s.handleSession(clientConn, clientChan, clientChanReqs, targetSession)
			}()

		case "direct-tcpip":
			// TODO (Phase 1 → forwarding/): handle -L port forwarding.
			newChannel.Reject(ssh.Prohibited, "port forwarding not yet supported")
			log.Printf("[SSH] Rejected direct-tcpip channel (TODO: forwarding/)")

		default:
			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			log.Printf("[SSH] Rejected channel of type %q", newChannel.ChannelType())
		}
	}
}

// handleSession negotiates PTY/shell/exec requests and runs the bridge
// between the client channel and the target session.
func (s *SSHServer) handleSession(
	conn *ssh.ServerConn,
	clientChan ssh.Channel,
	clientReqs <-chan *ssh.Request,
	targetSession *ssh.Session,
) {
	defer clientChan.Close()
	defer targetSession.Close()

	log.Printf("[SESSION] Opened for user: %s", conn.User())

	targetStdin, err := targetSession.StdinPipe()
	if err != nil {
		log.Printf("[SESSION] Failed to get target stdin pipe: %v", err)
		return
	}
	targetStdout, err := targetSession.StdoutPipe()
	if err != nil {
		log.Printf("[SESSION] Failed to get target stdout pipe: %v", err)
		return
	}
	targetStderr, err := targetSession.StderrPipe()
	if err != nil {
		log.Printf("[SESSION] Failed to get target stderr pipe: %v", err)
		return
	}

	var ptyReq ptyRequest
	var hasPTY bool

	for req := range clientReqs {
		switch req.Type {

		case "pty-req":
			if err := ssh.Unmarshal(req.Payload, &ptyReq); err != nil {
				log.Printf("[SESSION] Failed to parse pty-req: %v", err)
				req.Reply(false, nil)
				continue
			}
			hasPTY = true
			log.Printf("[SESSION] PTY requested: term=%s %dx%d", ptyReq.Term, ptyReq.Width, ptyReq.Height)
			req.Reply(true, nil)

		case "window-change":
			var winch windowChangeRequest
			if err := ssh.Unmarshal(req.Payload, &winch); err != nil {
				log.Printf("[SESSION] Failed to parse window-change: %v", err)
				req.Reply(false, nil)
				continue
			}
			if err := targetSession.WindowChange(int(winch.Height), int(winch.Width)); err != nil {
				log.Printf("[SESSION] Failed to propagate window-change: %v", err)
			}
			req.Reply(true, nil)

		case "shell":
			req.Reply(true, nil)

			if hasPTY {
				if err := targetSession.RequestPty(
					ptyReq.Term,
					int(ptyReq.Height),
					int(ptyReq.Width),
					ssh.TerminalModes{},
				); err != nil {
					log.Printf("[SESSION] RequestPty failed: %v", err)
					io.WriteString(clientChan, "terminal setup failed\r\n")
					return
				}
			}

			if err := targetSession.Shell(); err != nil {
				log.Printf("[SESSION] Failed to start shell: %v", err)
				io.WriteString(clientChan, "failed to start shell on target server\r\n")
				return
			}

			// Phase 3 injection point:
			//   tee    := io.TeeReader(clientChan, recorder)
			//   stdin  := filter.WrapWriter(targetStdin)
			//   stdout := io.MultiWriter(clientChan, recorder, streamer)
			bridge := heart.NewBridge(clientChan, targetStdin, targetStdout, targetStderr)
			bridge.Run()

			if err := targetSession.Wait(); err != nil {
				log.Printf("[SESSION] Shell exited with error: %v", err)
			}
			return

		case "exec":
			var execPayload struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &execPayload); err != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			log.Printf("[SESSION] exec: %q", execPayload.Command)

			if err := targetSession.Start(execPayload.Command); err != nil {
				log.Printf("[SESSION] Failed to exec %q: %v", execPayload.Command, err)
				return
			}

			// Phase 3 injection point — identyczny jak przy shell.
			bridge := heart.NewBridge(clientChan, targetStdin, targetStdout, targetStderr)
			bridge.Run()

			if err := targetSession.Wait(); err != nil {
				log.Printf("[SESSION] Exec %q exited with error: %v", execPayload.Command, err)
			}
			return

		case "env":
			// TODO: selectively forward safe variables (LANG, LC_ALL, TZ).
			req.Reply(true, nil)

		default:
			log.Printf("[SESSION] Unsupported request type: %q", req.Type)
			req.Reply(false, nil)
		}
	}
}

// isListenerClosed reports whether the error was caused by closing the listener.
// The net package does not expose a dedicated error type for this case.
func isListenerClosed(err error) bool {
	if err == nil {
		return false
	}
	const msg = "use of closed network connection"
	e := err.Error()
	for i := 0; i <= len(e)-len(msg); i++ {
		if e[i:i+len(msg)] == msg {
			return true
		}
	}
	return false
}

// activeConns returns the current number of open connections.
// Reads directly from the semaphore length — no separate counter needed.
func (s *SSHServer) activeConns() int {
	if s.connSem == nil {
		return 0
	}
	return len(s.connSem)
}

// Ready returns a channel that is closed once the listener is bound and
// accepting connections. Use it in tests to avoid polling s.listener:
//
//	<-srv.Ready()  // blocks until Start() has bound the port
func (s *SSHServer) Ready() <-chan struct{} {
	return s.ready
}
