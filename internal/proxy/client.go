package proxy

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TargetClient manages a single SSH connection to a target server.
//
// One TargetClient is created per inbound client connection and shared
// across all channels opened within that connection. Each channel gets
// its own *ssh.Session via NewSession().
//
// Lifecycle:
//
//	Dial()       → establishes TCP + SSH connection to the target
//	NewSession() → opens a new channel (shell, exec, sftp)
//	Close()      → closes all sessions and the underlying TCP connection
//
// TargetConfig is defined in target_config.go.
type TargetClient struct {
	config TargetConfig
	conn   *ssh.Client
}

// Dial establishes an SSH connection to the target server described by cfg.
//
// clientAgent may be nil — it is only used when cfg.AgentForwarding is true.
// When the agent is nil but AgentForwarding is true, the method falls back
// to the next available auth method (certificate, private key, password).
//
// Returns an error when no authentication method is configured or when the
// TCP/SSH handshake with the target fails.
func Dial(cfg TargetConfig, clientAgent agent.Agent) (*TargetClient, error) {
	c := &TargetClient{config: cfg}

	methods := c.buildAuthMethods(clientAgent)
	if len(methods) == 0 {
		return nil, fmt.Errorf("no authentication method configured for target %s", cfg.Addr)
	}

	sshCfg := &ssh.ClientConfig{
		User: cfg.User,
		Auth: methods,
		// TODO (Phase 4): Replace with Vault PKI or known_hosts file verification.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		// Fail fast when the target is unreachable — do not hang the proxy.
		Timeout: 10 * time.Second,
	}

	conn, err := ssh.Dial("tcp", cfg.Addr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("dial target %s: %w", cfg.Addr, err)
	}

	c.conn = conn
	return c, nil
}

// DialWithConn establishes an SSH connection over an existing net.Conn.
//
// Used in tests to inject a pre-wired connection without opening a real
// TCP socket. Also useful for tunnelled or proxied connections.
func DialWithConn(cfg TargetConfig, netConn net.Conn, clientAgent agent.Agent) (*TargetClient, error) {
	c := &TargetClient{config: cfg}

	methods := c.buildAuthMethods(clientAgent)
	if len(methods) == 0 {
		return nil, fmt.Errorf("no authentication method configured for target %s", cfg.Addr)
	}

	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            methods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, cfg.Addr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh handshake with target %s: %w", cfg.Addr, err)
	}

	c.conn = ssh.NewClient(sshConn, chans, reqs)
	return c, nil
}

// NewSession opens a new SSH session (channel) on the existing connection.
//
// Each call to NewSession returns an independent *ssh.Session — the caller
// is responsible for closing it when the session ends.
func (c *TargetClient) NewSession() (*ssh.Session, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("target client not connected")
	}
	sess, err := c.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("open session on target %s: %w", c.config.Addr, err)
	}
	return sess, nil
}

// Close terminates the SSH connection to the target server.
// All sessions opened via NewSession() are closed as a side effect.
func (c *TargetClient) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// Addr returns the target server address (host:port).
func (c *TargetClient) Addr() string {
	return c.config.Addr
}

// User returns the username used to authenticate with the target server.
func (c *TargetClient) User() string {
	return c.config.User
}

// buildAuthMethods constructs the list of SSH auth methods from TargetConfig.
// Order matters — the SSH client tries each method in sequence until one succeeds.
//
// Priority (most secure first):
//
//	Agent forwarding  — client key never touches the bastion
//	JIT certificate   — short-lived cert signed by bastion CA (Phase 4)
//	Private key       — long-lived bastion key, should be rotated via Vault
//	Password          — dev/test only, never production
func (c *TargetClient) buildAuthMethods(clientAgent agent.Agent) []ssh.AuthMethod {
	var methods []ssh.AuthMethod

	// Agent forwarding: use the client's own SSH agent.
	// The bastion never sees the private key — it only asks the agent to sign.
	if c.config.AgentForwarding && clientAgent != nil {
		methods = append(methods, ssh.PublicKeysCallback(clientAgent.Signers))
	}

	// JIT certificate: short-lived cert issued by the bastion CA.
	// Enabled in Phase 4 (internal/ca). Targets trust only the CA public key.
	if c.config.CertSigner != nil {
		methods = append(methods, ssh.PublicKeys(c.config.CertSigner))
	}

	// Bastion private key: static key authorised in target's authorized_keys.
	// Should be loaded from Vault at startup, never read from disk.
	if c.config.PrivateKey != nil {
		methods = append(methods, ssh.PublicKeys(c.config.PrivateKey))
	}

	// Password: fallback for local development only.
	// Never configure this in a production environment.
	if c.config.Password != "" {
		methods = append(methods, ssh.Password(c.config.Password))
	}

	return methods
}
