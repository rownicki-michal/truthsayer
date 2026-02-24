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

	"truthsayer/internal/config"
	"truthsayer/internal/proxy"
)

func generateSigner(t *testing.T) ssh.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

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

				copyWg.Wait()

				exitCode := 0
				if err := cmd.Wait(); err != nil {
					if exitErr, ok := err.(*exec.ExitError); ok {
						exitCode = exitErr.ExitCode()
					}
				}

				exitStatus := struct{ Status uint32 }{uint32(exitCode)}
				ch.SendRequest("exit-status", false, ssh.Marshal(exitStatus))
				time.Sleep(10 * time.Millisecond)
				ch.Close()
				return
			}
		}(ch, requests)
	}
}

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
	security := config.Security{} // empty blacklist — no commands blocked in login tests

	srv, err := proxy.NewSSHServer("127.0.0.1:0", generateSigner(t), auth, target, limits, security)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go srv.Start(ctx) //nolint:errcheck

	select {
	case <-srv.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("bastion did not become ready within 3s")
	}

	return srv.Addr()
}

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

	out, err := session.Output(command)
	require.NoError(t, err, "command failed")

	return string(out)
}

// =============================================================================
// E2E Tests
// =============================================================================

func TestE2E_LoginAndExec(t *testing.T) {
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastion(t, targetAddr, "targetuser", "targetpass")
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
	assert.Error(t, err)
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
	assert.Error(t, err)
}

func TestE2E_MultipleCommands(t *testing.T) {
	targetAddr, _ := startTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastion(t, targetAddr, "targetuser", "targetpass")

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
	bastionAddr := startBastion(t, "127.0.0.1:1", "targetuser", "targetpass")

	cfg := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", bastionAddr, cfg)
	require.NoError(t, err)
	defer client.Close()

	session, err := client.NewSession()
	if err == nil {
		err = session.Run("echo hello")
		session.Close()
	}
	assert.Error(t, err)
}
