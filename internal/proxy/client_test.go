package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// =============================================================================
// Helpers — local SSH server for TargetClient tests
// =============================================================================

// startTargetServer starts a minimal SSH server that accepts connections
// with the given password. Returns the address and host key for verification.
// Used as the "target server" in TargetClient tests.
func startTargetServer(t *testing.T, user, pass string) (addr string, hostKey ssh.PublicKey) {
	t.Helper()

	signer := generateTargetHostKey(t)
	hostKey = signer.PublicKey()

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(p) == pass {
				return nil, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr = ln.Addr().String()

	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sconn.Close()
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					newChan.Reject(ssh.Prohibited, "test server — no channels")
				}
			}(conn)
		}
	}()

	return addr, hostKey
}

// generateTargetHostKey generates a separate RSA key for the "target server".
// Separate from generateHostKey to avoid name conflicts in the same package.
func generateTargetHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

// newTargetClient creates a TargetClient with minimal configuration.
// Does not establish a connection — only initializes the struct.
func newTargetClient(cfg TargetConfig) *TargetClient {
	return &TargetClient{config: cfg}
}

// =============================================================================
// buildAuthMethods
// =============================================================================

func TestBuildAuthMethods_EmptyWhenNoCredentials(t *testing.T) {
	c := newTargetClient(TargetConfig{})
	assert.Empty(t, c.buildAuthMethods(nil))
}

func TestBuildAuthMethods_PasswordOnly(t *testing.T) {
	c := newTargetClient(TargetConfig{Password: "pass"})
	assert.Len(t, c.buildAuthMethods(nil), 1)
}

func TestBuildAuthMethods_PrivateKeyOnly(t *testing.T) {
	c := newTargetClient(TargetConfig{PrivateKey: generateTargetHostKey(t)})
	assert.Len(t, c.buildAuthMethods(nil), 1)
}

func TestBuildAuthMethods_CertSignerOnly(t *testing.T) {
	c := newTargetClient(TargetConfig{CertSigner: generateTargetHostKey(t)})
	assert.Len(t, c.buildAuthMethods(nil), 1)
}

func TestBuildAuthMethods_AgentForwardingIgnoredWithoutAgent(t *testing.T) {
	// AgentForwarding=true but agent is nil — no method should be added.
	c := newTargetClient(TargetConfig{AgentForwarding: true})
	assert.Empty(t, c.buildAuthMethods(nil))
}

func TestBuildAuthMethods_ThreeStaticMethods(t *testing.T) {
	signer := generateTargetHostKey(t)
	c := newTargetClient(TargetConfig{
		Password:   "pass",
		PrivateKey: signer,
		CertSigner: signer,
		// AgentForwarding without agent — does not count.
	})
	// cert + private key + password = 3
	assert.Len(t, c.buildAuthMethods(nil), 3)
}

func TestBuildAuthMethods_AgentWithNilSkipsForwarding(t *testing.T) {
	signer := generateTargetHostKey(t)
	c := newTargetClient(TargetConfig{
		AgentForwarding: true, // enabled but agent nil — skipped
		PrivateKey:      signer,
	})
	// Only private key — agent skipped
	assert.Len(t, c.buildAuthMethods(nil), 1)
}

func TestBuildAuthMethods_OnlyPasswordWhenOthersEmpty(t *testing.T) {
	c := newTargetClient(TargetConfig{Password: "only-pass"})
	methods := c.buildAuthMethods(nil)
	require.Len(t, methods, 1)
}

func TestBuildAuthMethods_EmptyPasswordNotAdded(t *testing.T) {
	// Empty password string should not add an auth method.
	c := newTargetClient(TargetConfig{Password: ""})
	assert.Empty(t, c.buildAuthMethods(nil))
}

// =============================================================================
// TargetClient — gettery
// =============================================================================

func TestTargetClient_Addr(t *testing.T) {
	c := newTargetClient(TargetConfig{Addr: "10.0.0.1:22"})
	assert.Equal(t, "10.0.0.1:22", c.Addr())
}

func TestTargetClient_User(t *testing.T) {
	c := newTargetClient(TargetConfig{User: "deploy"})
	assert.Equal(t, "deploy", c.User())
}

func TestTargetClient_AddrEmpty(t *testing.T) {
	c := newTargetClient(TargetConfig{})
	assert.Equal(t, "", c.Addr())
}

// =============================================================================
// TargetClient.Close — without a connection
// =============================================================================

func TestTargetClient_CloseWithoutConnection(t *testing.T) {
	// Close on an uninitialized client should not panic or return an error.
	c := newTargetClient(TargetConfig{})
	assert.NoError(t, c.Close())
}

func TestTargetClient_CloseIdempotent(t *testing.T) {
	// Multiple Close calls should not panic.
	c := newTargetClient(TargetConfig{})
	assert.NoError(t, c.Close())
	assert.NoError(t, c.Close())
}

// =============================================================================
// TargetClient.NewSession — without a connection
// =============================================================================

func TestTargetClient_NewSessionWithoutConnection(t *testing.T) {
	// NewSession on an uninitialized client should return an error.
	c := newTargetClient(TargetConfig{})
	sess, err := c.NewSession()
	assert.Error(t, err)
	assert.Nil(t, sess)
}

// =============================================================================
// Dial — errors when auth methods are missing
// =============================================================================

func TestDial_FailsWithNoAuthMethods(t *testing.T) {
	// TargetConfig without any auth method — Dial should return an error
	// before attempting a TCP connection.
	cfg := TargetConfig{Addr: "127.0.0.1:9999"} // port does not matter — error before dial
	_, err := Dial(cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no authentication method")
}

func TestDial_FailsWhenTargetUnreachable(t *testing.T) {
	// Port 1 is always unavailable — TCP error before SSH handshake.
	cfg := TargetConfig{
		Addr:     "127.0.0.1:1",
		User:     "user",
		Password: "pass",
	}
	_, err := Dial(cfg, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dial target")
}

// =============================================================================
// Dial — connection to local test server
// =============================================================================

func TestDial_SuccessWithPassword(t *testing.T) {
	addr, _ := startTargetServer(t, "deploy", "secret")

	cfg := TargetConfig{
		Addr:     addr,
		User:     "deploy",
		Password: "secret",
	}

	client, err := Dial(cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()

	assert.Equal(t, addr, client.Addr())
	assert.Equal(t, "deploy", client.User())
}

func TestDial_FailsWithWrongPassword(t *testing.T) {
	addr, _ := startTargetServer(t, "deploy", "correct")

	cfg := TargetConfig{
		Addr:     addr,
		User:     "deploy",
		Password: "wrong",
	}

	_, err := Dial(cfg, nil)
	assert.Error(t, err)
}

func TestDial_FailsWithWrongUser(t *testing.T) {
	addr, _ := startTargetServer(t, "deploy", "secret")

	cfg := TargetConfig{
		Addr:     addr,
		User:     "nobody",
		Password: "secret",
	}

	_, err := Dial(cfg, nil)
	assert.Error(t, err)
}

// =============================================================================
// DialWithConn — connection via existing net.Conn
// =============================================================================

func TestDialWithConn_SuccessWithPassword(t *testing.T) {
	addr, _ := startTargetServer(t, "deploy", "secret")

	cfg := TargetConfig{
		Addr:     addr,
		User:     "deploy",
		Password: "secret",
	}

	netConn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	require.NoError(t, err)

	client, err := DialWithConn(cfg, netConn, nil)
	require.NoError(t, err)
	defer client.Close()

	assert.Equal(t, addr, client.Addr())
}

func TestDialWithConn_FailsWithNoAuthMethods(t *testing.T) {
	addr, _ := startTargetServer(t, "deploy", "secret")

	cfg := TargetConfig{
		Addr: addr,
		User: "deploy",
		// No auth methods
	}

	netConn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { netConn.Close() })

	_, err = DialWithConn(cfg, netConn, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no authentication method")
}

// =============================================================================
// TargetClient — po udanym Dial
// =============================================================================

func TestTargetClient_CloseAfterDial(t *testing.T) {
	addr, _ := startTargetServer(t, "deploy", "secret")

	cfg := TargetConfig{Addr: addr, User: "deploy", Password: "secret"}
	client, err := Dial(cfg, nil)
	require.NoError(t, err)

	// Close should succeed without an error.
	assert.NoError(t, client.Close())
}

func TestTargetClient_NewSessionRejectedByTestServer(t *testing.T) {
	// Test server rejects all channels (Prohibited).
	// NewSession should return an error — but not panic.
	addr, _ := startTargetServer(t, "deploy", "secret")

	cfg := TargetConfig{Addr: addr, User: "deploy", Password: "secret"}
	client, err := Dial(cfg, nil)
	require.NoError(t, err)
	defer client.Close()

	_, err = client.NewSession()
	assert.Error(t, err, "test server rejects channels — NewSession should return an error")
}
