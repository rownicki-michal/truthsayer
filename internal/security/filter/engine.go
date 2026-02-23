package filter

import (
	"errors"
	"strings"
)

type SimplePolicyEngine struct {
	buffer      strings.Builder
	blacklisted []string
}

func NewPolicyEngine(blacklist []string) *SimplePolicyEngine {
	return &SimplePolicyEngine{
		blacklisted: blacklist,
	}
}

func (e *SimplePolicyEngine) Verify(input []byte) (bool, error) {
	for _, b := range input {
		if b == 13 || b == 10 {
			cmd := e.buffer.String()
			e.buffer.Reset()

			if e.isForbidden(cmd) {
				return false, errors.New("command blocked by security policy: " + cmd)
			}
			continue
		}

		if b == 127 && e.buffer.Len() > 0 {
			curr := e.buffer.String()
			e.buffer.Reset()
			e.buffer.WriteString(curr[:len(curr)-1])
			continue
		}

		e.buffer.WriteByte(b)
	}

	return true, nil
}

func (e *SimplePolicyEngine) isForbidden(cmd string) bool {
	cleanCmd := strings.TrimSpace(strings.ToLower(cmd))
	for _, bad := range e.blacklisted {
		if strings.Contains(cleanCmd, bad) {
			return true
		}
	}
	return false
}

// TODO: Why stdin filtering alone is not enough.
//
// Filtering raw stdin bytes is vulnerable to obfuscation attacks:
//
//	Example 1: v\i\m /etc/shadow       — escape characters split the command
//	Example 2: alias x='rm -rf'; x /   — alias indirection
//	Example 3: printf "\x72\x6d" | sh  — hex encoding
//
// More robust approaches:
//
// 1. SSH Request Interception
//
// Before a shell opens, the SSH client sends exec or subsystem requests.
// When a user runs: ssh user@proxy "rm -rf /"
// the command arrives as a request payload, not as stdin bytes.
// The proxy must intercept these requests before forwarding them to the target.
//
// 2. PTY Emulation (Virtual Terminal State)
//
// Instead of matching raw bytes, the proxy should maintain a virtual terminal
// using a VTE library. The emulator knows what is actually rendered on the user's
// screen, making it resistant to ANSI escape obfuscation.
//
// 3. eBPF / Auditd Integration (Gold Standard)
//
// If you control the target server, the proxy can receive reports from an agent
// (or eBPF program) that hooks execve() syscalls. This is the only method that
// provides 100% certainty about what was actually executed.
//
// 4. Behavioral Analysis
//
// Monitor anomalous patterns: sudden paste of 10 KB of text (inline script),
// attempts to open many simultaneous SSH tunnels, or a window resize to 1×1
// (a common technique to hide ongoing activity).
