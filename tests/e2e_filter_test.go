package tests

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"truthsayer/internal/config"
	"truthsayer/internal/proxy"
)

// startCountingTargetSSHServer is like startTargetSSHServer but also returns
// an atomic counter that increments each time the target actually executes a
// command. Tests use this to assert that blocked commands never reach the target.
func startCountingTargetSSHServer(t *testing.T, user, pass string) (addr string, executed *atomic.Int64) {
	t.Helper()
	executed = &atomic.Int64{}

	signer := generateSigner(t)
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
			go handleCountingTargetConn(conn, cfg, executed)
		}
	}()

	return addr, executed
}

// handleCountingTargetConn is like handleTargetConn but increments executed
// before running the command.
func handleCountingTargetConn(conn net.Conn, cfg *ssh.ServerConfig, executed *atomic.Int64) {
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

				// increment BEFORE executing — proves target received the command
				executed.Add(1)

				cmd := exec.Command("sh", "-c", payload.Command)
				stdoutPipe, _ := cmd.StdoutPipe()
				stderrPipe, _ := cmd.StderrPipe()
				if err := cmd.Start(); err != nil {
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{1}))
					ch.Close()
					return
				}
				var wg sync.WaitGroup
				wg.Add(2)
				go func() { defer wg.Done(); io.Copy(ch, stdoutPipe) }()
				go func() { defer wg.Done(); io.Copy(ch.Stderr(), stderrPipe) }()
				wg.Wait()

				exitCode := 0
				if err := cmd.Wait(); err != nil {
					if exitErr, ok := err.(*exec.ExitError); ok {
						exitCode = exitErr.ExitCode()
					}
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exitCode)}))
				time.Sleep(10 * time.Millisecond)
				ch.Close()
				return
			}
		}(ch, requests)
	}
}

// startBastionWithFilter starts a bastion with a blacklist and returns its address.
func startBastionWithFilter(t *testing.T, targetAddr, targetUser, targetPass string, blacklist []string) string {
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
	security := config.Security{
		Blacklist: blacklist,
		OnBlock:   "message",
	}

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

// execOverBastionRaw connects to the bastion, runs a command and returns
// stdout output and any error — does NOT require NoError so blocked commands
// can be tested.
func execOverBastionRaw(t *testing.T, bastionAddr, user, pass, command string) (string, error) {
	t.Helper()

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", bastionAddr, cfg)
	require.NoError(t, err)
	defer client.Close()

	session, err := client.NewSession()
	require.NoError(t, err)
	defer session.Close()

	out, err := session.Output(command)
	return string(out), err
}

// =============================================================================
// E2E Filter Tests
// =============================================================================

func TestE2EFilter_AllowedCommand_ReachesTarget(t *testing.T) {
	targetAddr, executed := startCountingTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithFilter(t, targetAddr, "targetuser", "targetpass", []string{"rm -rf /"})

	output, err := execOverBastionRaw(t, bastionAddr, "testuser", "testpass", "echo hello")
	require.NoError(t, err)
	assert.Equal(t, "hello\n", output)
	assert.Equal(t, int64(1), executed.Load(), "allowed command must reach target exactly once")
}

func TestE2EFilter_BlockedCommand_NeverReachesTarget(t *testing.T) {
	targetAddr, executed := startCountingTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithFilter(t, targetAddr, "targetuser", "targetpass", []string{"rm -rf /"})

	_, err := execOverBastionRaw(t, bastionAddr, "testuser", "testpass", "rm -rf /")
	assert.Error(t, err, "blocked command should return an error to the client")
	assert.Equal(t, int64(0), executed.Load(), "blocked command must never reach target")
}

func TestE2EFilter_BlockedCommand_ClientReceivesBlockMessage(t *testing.T) {
	targetAddr, executed := startCountingTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithFilter(t, targetAddr, "targetuser", "targetpass", []string{"rm -rf /"})

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
	require.NoError(t, err)
	defer session.Close()

	var stdout strings.Builder
	session.Stdout = &stdout

	_ = session.Run("rm -rf /")
	assert.Contains(t, stdout.String(), "blocked by policy")
	assert.Equal(t, int64(0), executed.Load(), "blocked command must never reach target")
}

func TestE2EFilter_ObfuscatedCommand_IsBlocked(t *testing.T) {
	targetAddr, executed := startCountingTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithFilter(t, targetAddr, "targetuser", "targetpass", []string{"rm -rf /"})

	obfuscated := "rm\033[A -rf /"
	_, err := execOverBastionRaw(t, bastionAddr, "testuser", "testpass", obfuscated)
	assert.Error(t, err, "obfuscated variant should also be blocked")
	assert.Equal(t, int64(0), executed.Load(), "obfuscated blocked command must never reach target")
}

func TestE2EFilter_SessionContinuesAfterBlock(t *testing.T) {
	targetAddr, executed := startCountingTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithFilter(t, targetAddr, "targetuser", "targetpass", []string{"rm -rf /"})

	_, _ = execOverBastionRaw(t, bastionAddr, "testuser", "testpass", "rm -rf /")
	assert.Equal(t, int64(0), executed.Load(), "blocked command must not reach target")

	output, err := execOverBastionRaw(t, bastionAddr, "testuser", "testpass", "echo still alive")
	require.NoError(t, err)
	assert.Equal(t, "still alive\n", output)
	assert.Equal(t, int64(1), executed.Load(), "allowed command after block must reach target")
}

func TestE2EFilter_EmptyBlacklist_AllowsEverything(t *testing.T) {
	targetAddr, executed := startCountingTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithFilter(t, targetAddr, "targetuser", "targetpass", []string{})

	output, err := execOverBastionRaw(t, bastionAddr, "testuser", "testpass", "echo hello")
	require.NoError(t, err)
	assert.Equal(t, "hello\n", output)
	assert.Equal(t, int64(1), executed.Load(), "command must reach target when blacklist is empty")
}

func TestE2EFilter_MultiplePatterns(t *testing.T) {
	targetAddr, executed := startCountingTargetSSHServer(t, "targetuser", "targetpass")
	bastionAddr := startBastionWithFilter(t, targetAddr, "targetuser", "targetpass",
		[]string{"rm -rf /", "mkfs", "dd if=/dev/zero"},
	)

	blocked := []string{"rm -rf /", "mkfs.ext4 /dev/sda", "dd if=/dev/zero of=/dev/sda"}
	for _, cmd := range blocked {
		t.Run(cmd, func(t *testing.T) {
			_, err := execOverBastionRaw(t, bastionAddr, "testuser", "testpass", cmd)
			assert.Error(t, err, "command %q should be blocked", cmd)
		})
	}
	assert.Equal(t, int64(0), executed.Load(), "no blocked command must reach target")

	output, err := execOverBastionRaw(t, bastionAddr, "testuser", "testpass", "echo ok")
	require.NoError(t, err)
	assert.Equal(t, "ok\n", output)
	assert.Equal(t, int64(1), executed.Load(), "allowed command must reach target exactly once")
}
