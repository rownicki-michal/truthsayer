package filter

import (
	"fmt"
	"io"

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

// FilterWriter wraps targetStdin and intercepts stdin bytes before they reach
// the target server. It accumulates bytes line by line and on Enter:
//
//  1. Decodes the line with the VTE terminal emulator
//  2. Inspects the visible string with FilterEngine
//  3. If blocked: sends an error message to the client and drops the Enter,
//     or disconnects the session depending on BlockAction
//  4. If allowed: flushes the line (including Enter) to targetStdin
//
// FilterWriter is NOT safe for concurrent use — one instance per session.
type FilterWriter struct {
	target  io.Writer // targetStdin
	client  io.Writer // client stdout — for block messages
	decoder TerminalDecoder
	engine  *FilterEngine
	action  BlockAction
	buf     []byte
}

// NewFilterWriter creates a FilterWriter.
//
//   - target: targetStdin — bytes are written here when allowed
//   - client: client stdout — block messages are written here
//   - decoder: VTEDecoder created by DecoderFactory.FromTerm($TERM)
//   - engine: FilterEngine with loaded blacklist patterns
//   - action: BlockActionMessage or BlockActionDisconnect
func NewFilterWriter(
	target io.Writer,
	client io.Writer,
	decoder TerminalDecoder,
	engine *FilterEngine,
	action BlockAction,
) *FilterWriter {
	return &FilterWriter{
		target:  target,
		client:  client,
		decoder: decoder,
		engine:  engine,
		action:  action,
	}
}

// Write intercepts stdin bytes. It implements io.Writer and is used as a
// drop-in replacement for targetStdin in bridge.Run().
func (f *FilterWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\r' || b == '\n' {
			if err := f.flush(b); err != nil {
				return 0, err
			}
			continue
		}
		f.buf = append(f.buf, b)
	}
	return len(p), nil
}

// flush is called when Enter (\r or \n) is received.
// It decodes the buffered line, inspects it, and either blocks or forwards.
func (f *FilterWriter) flush(enter byte) error {
	line := f.buf
	f.buf = f.buf[:0]

	if len(line) == 0 {
		// Empty line — forward Enter as-is.
		_, err := f.target.Write([]byte{enter})
		return err
	}

	result := f.decoder.Decode(line)
	decision := f.engine.Inspect(result.Visible)

	if !decision.Block {
		// Allowed — forward line + Enter to target.
		if _, err := f.target.Write(line); err != nil {
			return err
		}
		_, err := f.target.Write([]byte{enter})
		return err
	}

	// Blocked.
	msg := fmt.Sprintf("\r\ntruthsayer: command blocked by policy: %s\r\n", decision.Reason)

	switch f.action {
	case BlockActionDisconnect:
		_, _ = f.client.Write([]byte(msg))
		return ErrSessionBlocked

	default: // BlockActionMessage
		_, err := f.client.Write([]byte(msg))
		return err
	}
}
