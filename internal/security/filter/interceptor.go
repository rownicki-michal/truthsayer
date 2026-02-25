package filter

import (
	"fmt"
	"io"
	"log"

	"truthsayer/internal/security/emulation"
)

// TerminalDecoder is the minimal interface FilterWriter needs from a decoder.
type TerminalDecoder interface {
	Decode([]byte) emulation.DecodeResult
}

// BlockAction controls what happens when FilterWriter blocks a command.
type BlockAction string

const (
	// BlockActionMessage sends an error message to the client and continues the session.
	BlockActionMessage BlockAction = "message"

	// BlockActionDisconnect terminates the session immediately.
	BlockActionDisconnect BlockAction = "disconnect"
)

// ErrSessionBlocked is returned by FilterWriter.Write when BlockAction is
// BlockActionDisconnect and a blocked command is detected. The caller
// (bridge.Run) should treat this as a signal to close the session.
var ErrSessionBlocked = fmt.Errorf("session blocked by security policy")

// FilterWriter intercepts stdin bytes before they reach the target server.
//
// PTY / interactive shell mode (passthrough=true):
//   - Every byte is forwarded to target immediately — echo and line editing work normally.
//   - A shadow buffer tracks what the user has typed (with backspace/ctrl-c handling).
//   - On Enter: shadow buffer is inspected BEFORE Enter is forwarded.
//   - If blocked: Enter is dropped, client receives a block message.
//   - If allowed: Enter is forwarded to target.
//
// Exec mode (passthrough=false):
//   - Bytes are buffered until Enter, then inspected as a whole line.
//   - Used when the full command is known upfront (non-interactive exec).
//
// FilterWriter is NOT safe for concurrent use — one instance per session.
type FilterWriter struct {
	target      io.Writer // targetStdin
	client      io.Writer // client stdout — for block messages
	decoder     TerminalDecoder
	engine      *FilterEngine
	action      BlockAction
	passthrough bool   // true = PTY/shell mode, false = exec/buffered mode
	buf         []byte // shadow buffer (PTY) or accumulation buffer (exec)
}

// NewFilterWriter creates a FilterWriter in exec (buffered) mode.
func NewFilterWriter(
	target io.Writer,
	client io.Writer,
	decoder TerminalDecoder,
	engine *FilterEngine,
	action BlockAction,
) *FilterWriter {
	return &FilterWriter{
		target:      target,
		client:      client,
		decoder:     decoder,
		engine:      engine,
		action:      action,
		passthrough: false,
	}
}

// NewPTYFilterWriter creates a FilterWriter in PTY (passthrough) mode.
// Use this for interactive shell sessions where echo must work correctly.
func NewPTYFilterWriter(
	target io.Writer,
	client io.Writer,
	decoder TerminalDecoder,
	engine *FilterEngine,
	action BlockAction,
) *FilterWriter {
	return &FilterWriter{
		target:      target,
		client:      client,
		decoder:     decoder,
		engine:      engine,
		action:      action,
		passthrough: true,
	}
}

// Write intercepts stdin bytes.
func (f *FilterWriter) Write(p []byte) (int, error) {
	if f.passthrough {
		return f.writePTY(p)
	}
	return f.writeExec(p)
}

// writePTY handles PTY/shell mode:
// forwards bytes immediately, inspects shadow buffer on Enter.
func (f *FilterWriter) writePTY(p []byte) (int, error) {
	for _, b := range p {
		switch b {
		case '\r', '\n':
			// Inspect shadow buffer before forwarding Enter.
			if err := f.inspectAndEnter(b); err != nil {
				return 0, err
			}

		case 127, '\b': // backspace / DEL
			// Forward to target immediately.
			if _, err := f.target.Write([]byte{b}); err != nil {
				return 0, err
			}
			// Update shadow buffer.
			if len(f.buf) > 0 {
				f.buf = f.buf[:len(f.buf)-1]
			}

		case 3: // ctrl+c
			// Forward immediately and reset shadow buffer.
			if _, err := f.target.Write([]byte{b}); err != nil {
				return 0, err
			}
			f.buf = f.buf[:0]

		default:
			// Forward byte immediately to target — echo works normally.
			if _, err := f.target.Write([]byte{b}); err != nil {
				return 0, err
			}
			// Track in shadow buffer for inspection on Enter.
			f.buf = append(f.buf, b)
		}
	}
	return len(p), nil
}

// inspectAndEnter inspects the shadow buffer and forwards Enter if allowed.
func (f *FilterWriter) inspectAndEnter(enter byte) error {
	line := f.buf
	f.buf = f.buf[:0]

	log.Printf("[FILTER] shadow buffer raw: %q", line)

	if len(line) == 0 {
		_, err := f.target.Write([]byte{enter})
		return err
	}

	result := f.decoder.Decode(line)
	log.Printf("[FILTER] decoded visible: %q", result.Visible)

	decision := f.engine.Inspect(result.Visible)
	log.Printf("[FILTER] decision: block=%v reason=%q", decision.Block, decision.Reason)

	if !decision.Block {
		_, err := f.target.Write([]byte{enter})
		return err
	}

	return f.block(decision.Reason)
}

// writeExec handles exec/buffered mode:
// buffers bytes until Enter, then inspects the whole line.
func (f *FilterWriter) writeExec(p []byte) (int, error) {
	for _, b := range p {
		if b == '\r' || b == '\n' {
			if err := f.flushExec(b); err != nil {
				return 0, err
			}
			continue
		}
		f.buf = append(f.buf, b)
	}
	return len(p), nil
}

// flushExec inspects the buffered line and forwards line+Enter if allowed.
func (f *FilterWriter) flushExec(enter byte) error {
	line := f.buf
	f.buf = f.buf[:0]

	if len(line) == 0 {
		_, err := f.target.Write([]byte{enter})
		return err
	}

	result := f.decoder.Decode(line)
	decision := f.engine.Inspect(result.Visible)

	if !decision.Block {
		if _, err := f.target.Write(line); err != nil {
			return err
		}
		_, err := f.target.Write([]byte{enter})
		return err
	}

	return f.block(decision.Reason)
}

// block sends a block message to the client and returns an error if action is disconnect.
func (f *FilterWriter) block(reason string) error {
	msg := fmt.Sprintf("\r\ntruthsayer: command blocked by policy: %s\r\n", reason)
	switch f.action {
	case BlockActionDisconnect:
		_, _ = f.client.Write([]byte(msg))
		return ErrSessionBlocked
	default: // BlockActionMessage
		_, err := f.client.Write([]byte(msg))
		return err
	}
}
