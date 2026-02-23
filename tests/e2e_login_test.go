package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"truthsayer/internal/proxy"
)

// =============================================================================
// Helpers
// =============================================================================

// generateSigner creates an ephemeral RSA key for test servers.
func generateSigner(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

// startTargetSSHServer starts a minimal SSH server that executes commands
// and returns their output. Represents the "target" server behind the bastion.
// Returns the address and host key for use in TargetConfig.
func startTargetSSHServer(t *testing.T, user, pass string) (addr string, hostKey ssh.PublicKey) {
	t.Helper()

	signer := generateSigner(t)
	hostKey = signer.PublicKey()

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(p) == pass {
				return nil, nil
			}
			return nil, fmt.Errorf("access denied")
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
			go handleTargetConn(conn, cfg)
		}
	}()

	return addr, hostKey
}

// handleTargetConn handles a single connection on the target SSH server.
// Supports only exec requests — returns the command output to the client.
func handleTargetConn(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()

	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unsupported")
			continue
		}

		ch, requests, err := newChan.Accept()
		if err != nil {
			return
		}

		go func(ch ssh.Channel, requests <-chan *ssh.Request) {
			// Do NOT use defer ch.Close() here — it would race with
			// exit-status delivery. We close explicitly after SendRequest.
			for req := range requests {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}

				var payload struct{ Command string }
				if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)

				cmd := exec.Command("sh", "-c", payload.Command)
				stdoutPipe, _ := cmd.StdoutPipe()
				stderrPipe, _ := cmd.StderrPipe()

				if err := cmd.Start(); err != nil {
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
					ch.Close()
					return
				}

				var copyWg sync.WaitGroup
				copyWg.Add(2)
				go func() {
					defer copyWg.Done()
					io.Copy(ch, stdoutPipe)
				}()
				go func() {
					defer copyWg.Done()
					io.Copy(ch.Stderr(), stderrPipe)
				}()

				// Wait for all output to be copied before signalling EOF.
				copyWg.Wait()

				exitCode := 0
				if err := cmd.Wait(); err != nil {
					if exitErr, ok := err.(*exec.ExitError); ok {
						exitCode = exitErr.ExitCode()
					}
				}

				// Send exit-status BEFORE closing — client must receive
				// it while the channel is still open.
				exitStatus := struct{ Status uint32 }{uint32(exitCode)}
				ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus))

				// Small yield to allow exit-status to be flushed before close.
				time.Sleep(10 * time.Millisecond)
				ch.Close()
				return
			}
		}(ch, requests)
	}
}

// simulateCommand removed — using exec.Command("sh", "-c", cmd) instead.

// startBastion starts the Truthsayer bastion and returns its address.
// Blocks until the bastion is ready to accept connections.
func startBastion(t *testing.T, targetAddr, targetUser, targetPass string) string {
	t.Helper()

	auth := proxy.AuthConfig{
		Users: map[string]string{"testuser": "testpass"},
	}
	target := proxy.TargetConfig{
		Addr:     targetAddr,
		User:     targetUser,
		Password: targetPass,
	}
	limits := proxy.LimitsConfig{}

	srv, err := proxy.NewSSHServer("127.0.0.1:0", generateSigner(t), auth, target, limits)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go srv.Start(ctx) //nolint:errcheck

	// Wait until bastion is ready — race-free via Ready() channel.
	select {
	case <-srv.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("bastion did not become ready within 3s")
	}

	return srv.Addr()
}

// execOverBastion connects to the bastion, runs a command via exec,
// and returns the combined output.
// Each call opens a fresh TCP connection to the bastion to avoid
// shared state between test cases.
func execOverBastion(t *testing.T, bastionAddr, user, pass, command string) string {
	t.Helper()

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", bastionAddr, cfg)
	require.NoError(t, err, "failed to connect to bastion")
	defer client.Close()

	session, err := client.NewSession()
	require.NoError(t, err, "failed to open session")
	defer session.Close()

	// Output() runs the command and collects stdout.
	// It waits for the remote process to exit — handles exit-status internally.
	out, err := session.Output(command)
	require.NoError(t, err, "command failed")

	return string(out)
}

// =============================================================================
// E2E Tests
// =============================================================================

func TestE2E_LoginAndExec(t *testing.T) {
	// Start target SSH server.
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")

	// Start bastion pointing at the target.
	bastionAddr := startBastion(t, targetAddr, "targetuser", "targetpass")

	// Connect through bastion and run a command.
	output := execOverBastion(t, bastionAddr, "testuser", "testpass", "echo hello")

	assert.Equal(t, "hello\n", output)
}

func TestE2E_WrongPasswordRejected(t *testing.T) {
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastion(t, targetAddr, "targetuser", "targetpass")

	cfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("wrongpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	_, err := ssh.Dial("tcp", bastionAddr, cfg)
	assert.Error(t, err, "wrong password should be rejected by bastion")
}

func TestE2E_UnknownUserRejected(t *testing.T) {
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastion(t, targetAddr, "targetuser", "targetpass")

	cfg := &ssh.ClientConfig{
		User:            "nobody",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	_, err := ssh.Dial("tcp", bastionAddr, cfg)
	assert.Error(t, err, "unknown user should be rejected by bastion")
}

func TestE2E_MultipleCommands(t *testing.T) {
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastion(t, targetAddr, "targetuser", "targetpass")

	// Each session.Run() opens a new exec channel — verify multiple work.
	commands := []struct {
		cmd      string
		expected string
	}{
		{"echo foo bar", "foo bar\n"},
		{"echo hello", "hello\n"},
		{"echo world", "world\n"},
	}

	for _, tc := range commands {
		t.Run(tc.cmd, func(t *testing.T) {
			output := execOverBastion(t, bastionAddr, "testuser", "testpass", tc.cmd)
			assert.Equal(t, tc.expected, output)
		})
	}
}

func TestE2E_TargetUnavailable(t *testing.T) {
	// Point bastion at a port nothing is listening on.
	bastionAddr := startBastion(t, "127.0.0.1:1", "targetuser", "targetpass")

	cfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", bastionAddr, cfg)
	require.NoError(t, err, "bastion auth should succeed even if target is down")
	defer client.Close()

	// Opening a session should fail because target is unreachable.
	session, err := client.NewSession()
	if err == nil {
		err = session.Run("echo hello")
		session.Close()
	}
	assert.Error(t, err, "session should fail when target is unavailable")
}
