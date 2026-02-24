package filter

import (
	"bytes"
	"testing"

	"truthsayer/internal/security/emulation"

	"github.com/stretchr/testify/assert"
)

func newTestWriter(action BlockAction) (*FilterWriter, *bytes.Buffer, *bytes.Buffer) {
	target := &bytes.Buffer{}
	client := &bytes.Buffer{}
	decoder := emulation.NewVTEDecoder()
	engine := NewFilterEngine([]string{"rm -rf /"})
	fw := NewFilterWriter(target, client, decoder, engine, action)
	return fw, target, client
}

// =============================================================================
// Allowed commands
// =============================================================================

func TestFilterWriter_AllowedCommand_ReachesTarget(t *testing.T) {
	fw, target, _ := newTestWriter(BlockActionMessage)
	_, err := fw.Write([]byte("ls -la\r"))
	assert.NoError(t, err)
	assert.Equal(t, "ls -la\r", target.String())
}

func TestFilterWriter_EmptyLine_ForwardsEnter(t *testing.T) {
	fw, target, _ := newTestWriter(BlockActionMessage)
	_, err := fw.Write([]byte("\r"))
	assert.NoError(t, err)
	assert.Equal(t, "\r", target.String())
}

func TestFilterWriter_MultipleAllowedCommands(t *testing.T) {
	fw, target, _ := newTestWriter(BlockActionMessage)
	_, err := fw.Write([]byte("ls\r"))
	assert.NoError(t, err)
	_, err = fw.Write([]byte("pwd\n"))
	assert.NoError(t, err)
	assert.Equal(t, "ls\rpwd\n", target.String())
}

// =============================================================================
// Blocked commands — BlockActionMessage
// =============================================================================

func TestFilterWriter_BlockedCommand_NotSentToTarget(t *testing.T) {
	fw, target, _ := newTestWriter(BlockActionMessage)
	_, err := fw.Write([]byte("rm -rf /\r"))
	assert.NoError(t, err)
	assert.Empty(t, target.String())
}

func TestFilterWriter_BlockedCommand_ClientReceivesMessage(t *testing.T) {
	fw, _, client := newTestWriter(BlockActionMessage)
	_, err := fw.Write([]byte("rm -rf /\r"))
	assert.NoError(t, err)
	assert.Contains(t, client.String(), "command blocked by policy")
	assert.Contains(t, client.String(), "rm -rf /")
}

func TestFilterWriter_BlockedCommand_SessionContinues(t *testing.T) {
	fw, target, _ := newTestWriter(BlockActionMessage)
	_, _ = fw.Write([]byte("rm -rf /\r"))
	// Session continues — next command reaches target
	_, err := fw.Write([]byte("ls\r"))
	assert.NoError(t, err)
	assert.Equal(t, "ls\r", target.String())
}

// =============================================================================
// Blocked commands — BlockActionDisconnect
// =============================================================================

func TestFilterWriter_Disconnect_ReturnsErrSessionBlocked(t *testing.T) {
	fw, _, _ := newTestWriter(BlockActionDisconnect)
	_, err := fw.Write([]byte("rm -rf /\r"))
	assert.ErrorIs(t, err, ErrSessionBlocked)
}

func TestFilterWriter_Disconnect_ClientReceivesMessage(t *testing.T) {
	fw, _, client := newTestWriter(BlockActionDisconnect)
	_, _ = fw.Write([]byte("rm -rf /\r"))
	assert.Contains(t, client.String(), "command blocked by policy")
}

func TestFilterWriter_Disconnect_NothingSentToTarget(t *testing.T) {
	fw, target, _ := newTestWriter(BlockActionDisconnect)
	_, _ = fw.Write([]byte("rm -rf /\r"))
	assert.Empty(t, target.String())
}

// =============================================================================
// VTE obfuscation detection
// =============================================================================

func TestFilterWriter_ObfuscatedCommand_IsBlocked(t *testing.T) {
	fw, target, client := newTestWriter(BlockActionMessage)
	// "rm" + CursorUp + " -rf /" renders as "rm -rf /"
	_, err := fw.Write(append([]byte("rm\033[A -rf /"), '\r'))
	assert.NoError(t, err)
	assert.Empty(t, target.String())
	assert.Contains(t, client.String(), "command blocked by policy")
}
