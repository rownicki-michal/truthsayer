package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"truthsayer/internal/config"
)

// =============================================================================
// Helpers
// =============================================================================

func generateHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

func minimalAuth() AuthConfig {
	return AuthConfig{Users: map[string]string{"testuser": "testpass"}}
}

func newTestServer(t *testing.T, auth AuthConfig, target TargetConfig, limits LimitsConfig) *SSHServer {
	t.Helper()
	hostKey := generateHostKey(t)
	s, err := NewSSHServer("127.0.0.1:0", hostKey, auth, target, limits, config.Security{})
	require.NoError(t, err)
	return s
}

func startServer(t *testing.T, auth AuthConfig, limits LimitsConfig) string {
	t.Helper()

	hostKey := generateHostKey(t)
	s, err := NewSSHServer("127.0.0.1:0", hostKey, auth, TargetConfig{}, limits, config.Security{})
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	s.listener = ln
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go s.Start(ctx) //nolint:errcheck
	return addr
}

func serverConfigFor(t *testing.T, auth AuthConfig) *ssh.ServerConfig {
	t.Helper()
	s := newTestServer(t, auth, TargetConfig{}, LimitsConfig{})
	return s.config
}

func dialWithPassword(t *testing.T, serverConfig *ssh.ServerConfig, user, pass string) error {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		sconn, _, _, err := ssh.NewServerConn(conn, serverConfig)
		if err == nil {
			sconn.Close()
		}
		srvErr <- err
	}()

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         3 * time.Second,
	}
	netConn, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { netConn.Close() })

	_, _, _, clientErr := ssh.NewClientConn(netConn, ln.Addr().String(), cfg)

	select {
	case <-srvErr:
	case <-time.After(3 * time.Second):
		t.Fatal("server goroutine timed out")
	}

	return clientErr
}

// =============================================================================
// isListenerClosed
// =============================================================================

func TestIsListenerClosed_NilError(t *testing.T) {
	assert.False(t, isListenerClosed(nil))
}

func TestIsListenerClosed_ExactMessage(t *testing.T) {
	err := errors.New("use of closed network connection")
	assert.True(t, isListenerClosed(err))
}

func TestIsListenerClosed_MessageWithPrefix(t *testing.T) {
	err := errors.New("accept tcp 0.0.0.0:2222: use of closed network connection")
	assert.True(t, isListenerClosed(err))
}

func TestIsListenerClosed_UnrelatedNetworkError(t *testing.T) {
	err := errors.New("accept tcp 0.0.0.0:2222: connection reset by peer")
	assert.False(t, isListenerClosed(err))
}

func TestIsListenerClosed_PartialMessage(t *testing.T) {
	err := errors.New("use of closed")
	assert.False(t, isListenerClosed(err))
}

func TestIsListenerClosed_EmptyError(t *testing.T) {
	err := errors.New("")
	assert.False(t, isListenerClosed(err))
}

func TestIsListenerClosed_ConnectionRefused(t *testing.T) {
	err := errors.New("dial tcp 127.0.0.1:22: connect: connection refused")
	assert.False(t, isListenerClosed(err))
}

func TestIsListenerClosed_RealListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go ln.Close()

	_, err = ln.Accept()
	require.Error(t, err)
	assert.True(t, isListenerClosed(err))
}

// =============================================================================
// NewSSHServer
// =============================================================================

func TestNewSSHServer_SemaphoreNilWhenNoLimit(t *testing.T) {
	s := newTestServer(t, minimalAuth(), TargetConfig{}, LimitsConfig{MaxConnections: 0})
	assert.Nil(t, s.connSem)
}

func TestNewSSHServer_SemaphoreCreatedWithCorrectCapacity(t *testing.T) {
	const limit = 42
	s := newTestServer(t, minimalAuth(), TargetConfig{}, LimitsConfig{MaxConnections: limit})
	require.NotNil(t, s.connSem)
	assert.Equal(t, limit, cap(s.connSem))
}

func TestNewSSHServer_SemaphoreInitiallyEmpty(t *testing.T) {
	s := newTestServer(t, minimalAuth(), TargetConfig{}, LimitsConfig{MaxConnections: 10})
	require.NotNil(t, s.connSem)
	assert.Equal(t, 0, len(s.connSem))
}

func TestNewSSHServer_ServerVersionSet(t *testing.T) {
	s := newTestServer(t, minimalAuth(), TargetConfig{}, LimitsConfig{})
	assert.Equal(t, "SSH-2.0-TruthsayerBastion_1.0", s.config.ServerVersion)
}

func TestNewSSHServer_InvalidAddrDoesNotFail(t *testing.T) {
	hostKey := generateHostKey(t)
	s, err := NewSSHServer("256.256.256.256:0", hostKey, minimalAuth(), TargetConfig{}, LimitsConfig{}, config.Security{})
	assert.NoError(t, err)
	assert.NotNil(t, s)
}

func TestNewSSHServer_LimitsStoredCorrectly(t *testing.T) {
	limits := LimitsConfig{MaxConnections: 50, MaxChannelsPerConn: 10}
	s := newTestServer(t, minimalAuth(), TargetConfig{}, limits)
	assert.Equal(t, limits, s.limits)
}

func TestNewSSHServer_TargetStoredCorrectly(t *testing.T) {
	target := TargetConfig{Addr: "10.0.0.1:22", User: "deploy", Password: "secret"}
	s := newTestServer(t, minimalAuth(), target, LimitsConfig{})
	assert.Equal(t, target, s.target)
}

// =============================================================================
// PasswordCallback
// =============================================================================

func TestPasswordCallback_AcceptsValidCredentials(t *testing.T) {
	auth := AuthConfig{Users: map[string]string{"alice": "secret"}}
	err := dialWithPassword(t, serverConfigFor(t, auth), "alice", "secret")
	assert.NoError(t, err)
}

func TestPasswordCallback_RejectsWrongPassword(t *testing.T) {
	auth := AuthConfig{Users: map[string]string{"alice": "secret"}}
	err := dialWithPassword(t, serverConfigFor(t, auth), "alice", "wrong")
	assert.Error(t, err)
}

func TestPasswordCallback_RejectsUnknownUser(t *testing.T) {
	auth := AuthConfig{Users: map[string]string{"alice": "secret"}}
	err := dialWithPassword(t, serverConfigFor(t, auth), "nobody", "secret")
	assert.Error(t, err)
}

func TestPasswordCallback_RejectsEmptyPassword(t *testing.T) {
	auth := AuthConfig{Users: map[string]string{"alice": "secret"}}
	err := dialWithPassword(t, serverConfigFor(t, auth), "alice", "")
	assert.Error(t, err)
}

func TestPasswordCallback_MultipleUsers(t *testing.T) {
	auth := AuthConfig{Users: map[string]string{
		"alice": "alicepass",
		"bob":   "bobpass",
		"carol": "carolpass",
	}}
	cfg := serverConfigFor(t, auth)
	for user, pass := range auth.Users {
		t.Run(user, func(t *testing.T) {
			assert.NoError(t, dialWithPassword(t, cfg, user, pass))
		})
	}
}

func TestPasswordCallback_UserCannotUseOthersPassword(t *testing.T) {
	auth := AuthConfig{Users: map[string]string{
		"alice": "alicepass",
		"bob":   "bobpass",
	}}
	cfg := serverConfigFor(t, auth)
	assert.Error(t, dialWithPassword(t, cfg, "alice", "bobpass"))
	assert.Error(t, dialWithPassword(t, cfg, "bob", "alicepass"))
}

func TestPasswordCallback_CaseSensitiveUsername(t *testing.T) {
	auth := AuthConfig{Users: map[string]string{"alice": "secret"}}
	err := dialWithPassword(t, serverConfigFor(t, auth), "Alice", "secret")
	assert.Error(t, err)
}

func TestPasswordCallback_CaseSensitivePassword(t *testing.T) {
	auth := AuthConfig{Users: map[string]string{"alice": "Secret"}}
	err := dialWithPassword(t, serverConfigFor(t, auth), "alice", "secret")
	assert.Error(t, err)
}

// =============================================================================
// activeConns
// =============================================================================

func TestActiveConns_ZeroWhenNoSemaphore(t *testing.T) {
	s := newTestServer(t, minimalAuth(), TargetConfig{}, LimitsConfig{})
	assert.Equal(t, 0, s.activeConns())
}

func TestActiveConns_ZeroWhenSemaphoreEmpty(t *testing.T) {
	s := newTestServer(t, minimalAuth(), TargetConfig{}, LimitsConfig{MaxConnections: 10})
	assert.Equal(t, 0, s.activeConns())
}

func TestActiveConns_ReflectsOccupiedSlots(t *testing.T) {
	s := newTestServer(t, minimalAuth(), TargetConfig{}, LimitsConfig{MaxConnections: 10})
	s.connSem <- struct{}{}
	s.connSem <- struct{}{}
	s.connSem <- struct{}{}
	assert.Equal(t, 3, s.activeConns())
	<-s.connSem
	assert.Equal(t, 2, s.activeConns())
}

func TestActiveConns_MaxCapacity(t *testing.T) {
	const limit = 5
	s := newTestServer(t, minimalAuth(), TargetConfig{}, LimitsConfig{MaxConnections: limit})
	for i := 0; i < limit; i++ {
		s.connSem <- struct{}{}
	}
	assert.Equal(t, limit, s.activeConns())
}

// =============================================================================
// Semafor
// =============================================================================

func TestSemaphore_RejectsWhenFull(t *testing.T) {
	s := newTestServer(t, minimalAuth(), TargetConfig{}, LimitsConfig{MaxConnections: 2})
	s.connSem <- struct{}{}
	s.connSem <- struct{}{}

	select {
	case s.connSem <- struct{}{}:
		t.Fatal("semafor pełny — trzeci slot nie powinien być dostępny")
	default:
	}
}

func TestSemaphore_AllowsAfterRelease(t *testing.T) {
	s := newTestServer(t, minimalAuth(), TargetConfig{}, LimitsConfig{MaxConnections: 1})
	s.connSem <- struct{}{}
	<-s.connSem

	select {
	case s.connSem <- struct{}{}:
	default:
		t.Fatal("slot powinien być dostępny po zwolnieniu")
	}
}

func TestSemaphore_ConcurrentAcquire(t *testing.T) {
	const limit = 5
	const goroutines = 20
	s := newTestServer(t, minimalAuth(), TargetConfig{}, LimitsConfig{MaxConnections: limit})

	var acquired int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case s.connSem <- struct{}{}:
				mu.Lock()
				acquired++
				mu.Unlock()
			default:
			}
		}()
	}

	wg.Wait()
	assert.Equal(t, limit, acquired)
	assert.Equal(t, limit, len(s.connSem))
}

// =============================================================================
// Start
// =============================================================================

func TestStart_ShutdownOnContextCancel(t *testing.T) {
	hostKey := generateHostKey(t)
	s, err := NewSSHServer("127.0.0.1:0", hostKey, minimalAuth(), TargetConfig{}, LimitsConfig{}, config.Security{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()

	select {
	case <-s.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("server did not become ready within 2s")
	}

	cancel()

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("serwer nie zatrzymał się w ciągu 3s")
	}
}

func TestStart_FailsOnInvalidAddr(t *testing.T) {
	hostKey := generateHostKey(t)
	s, err := NewSSHServer("256.256.256.256:0", hostKey, minimalAuth(), TargetConfig{}, LimitsConfig{}, config.Security{})
	require.NoError(t, err)
	assert.Error(t, s.Start(context.Background()))
}

func TestStart_FailsOnOccupiedPort(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { blocker.Close() })

	hostKey := generateHostKey(t)
	s, err := NewSSHServer(blocker.Addr().String(), hostKey, minimalAuth(), TargetConfig{}, LimitsConfig{}, config.Security{})
	require.NoError(t, err)
	assert.Error(t, s.Start(context.Background()))
}

func TestStart_AcceptsTCPConnections(t *testing.T) {
	addr := startServer(t, AuthConfig{Users: map[string]string{"u": "p"}}, LimitsConfig{})
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	conn.Close()
}

func TestStart_MultipleSequentialConnections(t *testing.T) {
	addr := startServer(t, AuthConfig{Users: map[string]string{"u": "p"}}, LimitsConfig{})
	for i := 0; i < 5; i++ {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		require.NoError(t, err, "połączenie %d", i)
		conn.Close()
	}
}

func TestStart_ConcurrentConnections(t *testing.T) {
	addr := startServer(t, AuthConfig{Users: map[string]string{"u": "p"}}, LimitsConfig{})

	const count = 10
	var wg sync.WaitGroup
	errs := make([]error, count)

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, time.Second)
			errs[idx] = err
			if conn != nil {
				conn.Close()
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "połączenie %d", i)
	}
}
