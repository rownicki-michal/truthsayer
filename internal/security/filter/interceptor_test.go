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

func newPTYTestWriter(patterns []string, action BlockAction) (*FilterWriter, *bytes.Buffer, *bytes.Buffer) {
	target := &bytes.Buffer{}
	client := &bytes.Buffer{}
	decoder := emulation.NewVTEDecoder()
	engine := NewFilterEngine(patterns)
	fw := NewPTYFilterWriter(target, client, decoder, engine, action)
	return fw, target, client
}

// =============================================================================
// PTY mode — passthrough behaviour
// =============================================================================

func TestPTYFilterWriter_AllowedCommand_BytesReachTargetImmediately(t *testing.T) {
	fw, target, _ := newPTYTestWriter([]string{"mkfs"}, BlockActionMessage)
	fw.Write([]byte("ls"))
	// bytes must reach target before Enter
	assert.Equal(t, "ls", target.String())
}

func TestPTYFilterWriter_AllowedCommand_EnterForwarded(t *testing.T) {
	fw, target, _ := newPTYTestWriter([]string{"mkfs"}, BlockActionMessage)
	fw.Write([]byte("ls\r"))
	assert.Equal(t, "ls\r", target.String())
}

func TestPTYFilterWriter_BlockedCommand_EnterDropped(t *testing.T) {
	fw, target, _ := newPTYTestWriter([]string{"mkfs"}, BlockActionMessage)
	fw.Write([]byte("mkfs\r"))
	// "mkfs" bytes reached target (passthrough), but Enter must be dropped
	assert.Equal(t, "mkfs", target.String())
}

func TestPTYFilterWriter_BlockedCommand_ClientReceivesMessage(t *testing.T) {
	fw, _, client := newPTYTestWriter([]string{"mkfs"}, BlockActionMessage)
	fw.Write([]byte("mkfs\r"))
	assert.Contains(t, client.String(), "command blocked by policy")
}

func TestPTYFilterWriter_Backspace_UpdatesShadowBuffer(t *testing.T) {
	fw, target, client := newPTYTestWriter([]string{"mkfs"}, BlockActionMessage)
	// type "mkfs", backspace twice → shadow = "mk", then type "ls" → "mkls"
	// "mkls" is not blacklisted — Enter should be forwarded
	fw.Write([]byte("mkfs\x7f\x7fls\r"))
	assert.NotContains(t, client.String(), "command blocked by policy")
	assert.Contains(t, target.String(), "\r")
}

func TestPTYFilterWriter_CtrlC_ResetsShadowBuffer(t *testing.T) {
	fw, target, client := newPTYTestWriter([]string{"mkfs"}, BlockActionMessage)
	// type "mkfs", ctrl+c resets shadow buffer, then "ls" + Enter
	fw.Write([]byte("mkfs\x03ls\r"))
	assert.NotContains(t, client.String(), "command blocked by policy")
	assert.Contains(t, target.String(), "\r")
}

// =============================================================================
// PTY mode — obfuscated mkfs variants
// =============================================================================

func TestPTYFilterWriter_Obfuscated_CursorUp(t *testing.T) {
	fw, _, client := newPTYTestWriter([]string{"mkfs"}, BlockActionMessage)
	// "mk" + CursorUp ESC sequence + "fs" → VTE decodes to "mkfs"
	fw.Write(append([]byte("mk\033[Afs"), '\r'))
	assert.Contains(t, client.String(), "command blocked by policy")

}

func TestPTYFilterWriter_Obfuscated_Backspace(t *testing.T) {
	fw, _, client := newPTYTestWriter([]string{"mkfs"}, BlockActionMessage)
	// "mkXfs" + backspace over X → shadow = "mkfs"
	fw.Write([]byte("mkXfs\x7f\x7f\x7ffs\r"))
	assert.Contains(t, client.String(), "command blocked by policy")
}

func TestPTYFilterWriter_Obfuscated_Uppercase(t *testing.T) {
	fw, _, client := newPTYTestWriter([]string{"mkfs"}, BlockActionMessage)
	fw.Write([]byte("MKFS\r"))
	assert.Contains(t, client.String(), "command blocked by policy")
}
