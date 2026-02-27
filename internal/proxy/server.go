package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"truthsayer/internal/audit"
	"truthsayer/internal/config"
	"truthsayer/internal/heart"
	"truthsayer/internal/security/emulation"
	"truthsayer/internal/security/filter"
)

func generateSessionID(user string) string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%d-%s-%s", time.Now().Unix(), user, hex.EncodeToString(b))
}

// LimitsConfig holds configurable resource limits for the server.
type LimitsConfig struct {
	MaxConnections     int
	MaxChannelsPerConn int
}

// SSHServer represents a running instance of the Truthsayer bastion.
type SSHServer struct {
	addr     string
	config   *ssh.ServerConfig
	hostKey  ssh.Signer
	target   TargetConfig
	limits   LimitsConfig
	listener net.Listener
	wg       sync.WaitGroup
	connSem  chan struct{}
	ready    chan struct{}

	// filter fields — initialised from config.Security
	filterEngine *filter.FilterEngine
	blockAction  filter.BlockAction

	auditStoragePath string
}

// ptyRequest holds the PTY parameters sent by the client.
type ptyRequest struct {
	Term        string
	Width       uint32
	Height      uint32
	PixelWidth  uint32
	PixelHeight uint32
	Modes       string
}

// windowChangeRequest holds the terminal resize signal sent by the client.
type windowChangeRequest struct {
	Width       uint32
	Height      uint32
	PixelWidth  uint32
	PixelHeight uint32
}

// NewSSHServer initialises the bastion server.
func NewSSHServer(
	addr string,
	hostKey ssh.Signer,
	auth AuthConfig,
	target TargetConfig,
	limits LimitsConfig,
	security config.Security,
	audit config.Audit,
) (*SSHServer, error) {
	authenticator, err := NewAuthenticator(auth)
	if err != nil {
		return nil, fmt.Errorf("invalid auth config: %w", err)
	}

	blockAction := filter.BlockAction(security.OnBlock)
	if blockAction != filter.BlockActionDisconnect {
		blockAction = filter.BlockActionMessage // safe default
	}

	s := &SSHServer{
		addr:             addr,
		hostKey:          hostKey,
		target:           target,
		limits:           limits,
		ready:            make(chan struct{}),
		filterEngine:     filter.NewFilterEngine(security.Blacklist),
		blockAction:      blockAction,
		auditStoragePath: audit.StoragePath,
	}

	if limits.MaxConnections > 0 {
		s.connSem = make(chan struct{}, limits.MaxConnections)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: authenticator.Callback(),
		ServerVersion:    "SSH-2.0-TruthsayerBastion_1.0",
	}
	cfg.AddHostKey(hostKey)
	s.config = cfg

	return s, nil
}

// Start begins accepting connections and blocks until the context is cancelled.
func (s *SSHServer) Start(ctx context.Context) error {
	var err error
	s.listener, err = net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to start listener on %s: %w", s.addr, err)
	}
	log.Printf("[SSH] Truthsayer bastion listening on %s (max_connections=%d, max_channels_per_conn=%d)",
		s.addr, s.limits.MaxConnections, s.limits.MaxChannelsPerConn)

	close(s.ready)

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

// handleConnection performs the SSH handshake and dispatches channels.
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

	var clientAgent agent.Agent
	go func() {
		for req := range clientReqs {
			switch req.Type {
			case "auth-agent-req@openssh.com":
				req.Reply(true, nil)
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	targetClient, err := Dial(s.target, clientAgent)
	if err != nil {
		log.Printf("[PROXY] Cannot connect to target for user %s: %v", clientConn.User(), err)
		for newChannel := range clientChans {
			newChannel.Reject(ssh.ConnectionFailed, "target server unavailable")
		}
		return
	}
	defer targetClient.Close()
	log.Printf("[PROXY] Connected to target %s for user %s", targetClient.Addr(), clientConn.User())

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
			newChannel.Reject(ssh.Prohibited, "port forwarding not yet supported")
			log.Printf("[SSH] Rejected direct-tcpip channel (TODO: forwarding/)")

		default:
			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			log.Printf("[SSH] Rejected channel of type %q", newChannel.ChannelType())
		}
	}
}

func (s *SSHServer) newPTYFilterWriter(targetStdin io.WriteCloser, clientChan ssh.Channel, term string) *filter.FilterWriter {
	if term == "" {
		term = "xterm"
	}
	decoder := emulation.NewDecoderFactory().FromTerm(term)
	return filter.NewPTYFilterWriter(targetStdin, clientChan, decoder, s.filterEngine, s.blockAction)
}

// handleSession negotiates PTY/shell/exec requests and runs the bridge.
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

			sessionID := generateSessionID(conn.User())
			recorder, recErr := audit.NewRecorder(s.auditStoragePath, sessionID, int(ptyReq.Width), int(ptyReq.Height))
			if recErr != nil {
				log.Printf("[SESSION] Failed to create recorder: %v — continuing without recording", recErr)
				recorder = nil
			}
			if recorder != nil {
				defer recorder.Close()
				log.Printf("[SESSION] Recording to %s", recorder.Path())
			}

			bridge := heart.NewBridge(clientChan, targetStdin, targetStdout, targetStderr)
			bridge.WithFilter(s.newPTYFilterWriter(targetStdin, clientChan, ptyReq.Term))
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

			decoder := emulation.NewDecoderFactory().FromTerm(ptyReq.Term)
			result := decoder.Decode([]byte(execPayload.Command))
			decision := s.filterEngine.Inspect(result.Visible)
			if decision.Block {
				msg := fmt.Sprintf("truthsayer: command blocked by policy: %s\r\n", decision.Reason)
				io.WriteString(clientChan, msg)
				exitStatus := struct{ Status uint32 }{1}
				clientChan.SendRequest("exit-status", false, ssh.Marshal(exitStatus))
				return
			}

			if err := targetSession.Start(execPayload.Command); err != nil {
				log.Printf("[SESSION] Failed to exec %q: %v", execPayload.Command, err)
				return
			}

			sessionID := generateSessionID(conn.User())

			const (
				defaultExecWidth  = 220
				defaultExecHeight = 50
			)
			recorder, recErr := audit.NewRecorder(s.auditStoragePath, sessionID, defaultExecWidth, defaultExecHeight)
			if recErr != nil {
				log.Printf("[SESSION] Failed to create recorder: %v — continuing without recording", recErr)
				recorder = nil
			}
			if recorder != nil {
				log.Printf("[SESSION] Recording to %s", recorder.Path())
			}

			bridge := heart.NewBridge(clientChan, targetStdin, targetStdout, targetStderr)
			if recorder != nil {
				bridge.WithRecorder(recorder)
			}

			waitErr := make(chan error, 1)
			go func() {
				waitErr <- targetSession.Wait()
			}()

			bridge.Run()
			if recorder != nil {
				recorder.Close()
			}

			exitCode := 0
			if err := <-waitErr; err != nil {
				log.Printf("[SESSION] Exec %q exited with error: %v", execPayload.Command, err)
				if exitErr, ok := err.(*ssh.ExitError); ok {
					exitCode = exitErr.ExitStatus()
				}
			}
			exitStatus := struct{ Status uint32 }{uint32(exitCode)}
			clientChan.SendRequest("exit-status", false, ssh.Marshal(exitStatus))
			return

		case "env":
			req.Reply(true, nil)

		default:
			log.Printf("[SESSION] Unsupported request type: %q", req.Type)
			req.Reply(false, nil)
		}
	}
}

// isListenerClosed reports whether the error was caused by closing the listener.
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

func (s *SSHServer) activeConns() int {
	if s.connSem == nil {
		return 0
	}
	return len(s.connSem)
}

func (s *SSHServer) Ready() <-chan struct{} {
	return s.ready
}

func (s *SSHServer) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}
