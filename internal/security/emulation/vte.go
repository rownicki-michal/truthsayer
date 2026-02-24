package emulation

import (
	"strings"

	vte "github.com/danielgatis/go-vte"
)

// =============================================================================
// Token types
// =============================================================================

// TokenKind identifies the type of a terminal event.
type TokenKind int

const (
	// TokenText is a printable character received via Print().
	TokenText TokenKind = iota

	// TokenBackspace is a backspace or delete character (0x08 or 0x7f).
	// Erases the last character from the visible buffer.
	TokenBackspace

	// TokenCursorUp moves the cursor N lines up (CSI <n> A).
	// Used for obfuscation: "rm\033[A -rf /" renders as "rm -rf /".
	TokenCursorUp

	// TokenCursorDown moves the cursor N lines down (CSI <n> B).
	TokenCursorDown

	// TokenCursorForward moves the cursor N columns right (CSI <n> C).
	TokenCursorForward

	// TokenCursorBack moves the cursor N columns left (CSI <n> D).
	// Equivalent to multiple backspaces for obfuscation purposes.
	TokenCursorBack

	// TokenEraseLine erases part of the current line (CSI <n> K).
	// n=0: cursor to end, n=1: start to cursor, n=2: entire line.
	TokenEraseLine

	// TokenEraseScreen erases part of the screen (CSI <n> J).
	// Typically ignored for command reconstruction purposes.
	TokenEraseScreen

	// TokenIgnored represents sequences that do not affect visible text:
	// OSC (title setting), DCS (device control), unknown CSI/ESC sequences.
	// Presence of TokenIgnored does NOT indicate obfuscation.
	TokenIgnored
)

// Token represents a single terminal event produced by the VTE parser.
type Token struct {
	Kind TokenKind

	// Rune holds the character for TokenText.
	Rune rune

	// N holds the repeat count for cursor movement and erase tokens.
	// Defaults to 1 when the escape sequence omits the parameter.
	N int
}

// IsControlSequence reports whether the token represents a control sequence
// that could be used to obfuscate commands (cursor movement, erase).
func (t Token) IsControlSequence() bool {
	switch t.Kind {
	case TokenCursorUp, TokenCursorDown, TokenCursorForward, TokenCursorBack,
		TokenEraseLine, TokenEraseScreen, TokenBackspace:
		return true
	}
	return false
}

// String returns a human-readable representation of a Token for debugging.
func (t Token) String() string {
	switch t.Kind {
	case TokenText:
		return "Text(" + string(t.Rune) + ")"
	default:
		return tokenKindString(t.Kind) + "(" + strings.Repeat(".", t.N) + ")"
	}
}

// tokenKindString maps TokenKind to a human-readable name for debugging.
func tokenKindString(k TokenKind) string {
	names := []string{
		"Text", "Backspace", "CursorUp", "CursorDown",
		"CursorForward", "CursorBack", "EraseLine", "EraseScreen", "Ignored",
	}
	if int(k) < len(names) {
		return names[k]
	}
	return "Unknown"
}

// =============================================================================
// Decoder
// =============================================================================

// Decoder parses raw terminal bytes into a slice of Tokens.
// It wraps github.com/danielgatis/go-vte which implements the Paul Williams
// state machine for DEC VT hardware terminals.
//
// Usage:
//
//	d := NewDecoder()
//	tokens := d.Decode(raw)
//	visible := d.Apply(tokens)
//	if d.HasObfuscation(tokens) { /* alert AI analyzer */ }
type Decoder struct{}

// NewDecoder creates a new Decoder instance.
func NewDecoder() *Decoder {
	return &Decoder{}
}

// Decode parses raw terminal bytes and returns a slice of Tokens.
// The parser handles VT100, VT220 and xterm escape sequences.
func (d *Decoder) Decode(raw []byte) []Token {
	c := &tokenCollector{}
	parser := vte.NewParser(c)
	for _, b := range raw {
		parser.Advance(b)
	}
	return c.tokens
}

// Apply reconstructs the visible string from a token slice by simulating
// how a terminal would render the sequence. Cursor movement and erase
// sequences modify the buffer the same way a real terminal would.
//
// This is the string the filter should inspect — not the raw bytes.
func (d *Decoder) Apply(tokens []Token) string {
	// buf holds the current line as a slice of runes.
	// cursor is the current write position within buf.
	buf := []rune{}
	cursor := 0

	for _, tok := range tokens {
		switch tok.Kind {
		case TokenText:
			if cursor < len(buf) {
				buf[cursor] = tok.Rune
			} else {
				buf = append(buf, tok.Rune)
			}
			cursor++

		case TokenBackspace:
			n := tok.N
			if n <= 0 {
				n = 1
			}
			for i := 0; i < n; i++ {
				if cursor > 0 {
					cursor--
					buf = buf[:cursor]
				}
			}

		case TokenCursorBack:
			n := tok.N
			if n <= 0 {
				n = 1
			}
			if cursor-n >= 0 {
				cursor -= n
			} else {
				cursor = 0
			}

		case TokenCursorForward:
			n := tok.N
			if n <= 0 {
				n = 1
			}
			if cursor+n <= len(buf) {
				cursor += n
			} else {
				cursor = len(buf)
			}

		case TokenCursorUp, TokenCursorDown:
			// Multi-line cursor movement — for single-line command inspection
			// we treat these as erasing from cursor to end of buffer,
			// which is the most common obfuscation pattern.
			buf = buf[:cursor]

		case TokenEraseLine:
			switch tok.N {
			case 0: // cursor to end of line
				buf = buf[:cursor]
			case 1: // start to cursor
				spaces := make([]rune, cursor)
				copy(buf, spaces)
				cursor = 0
			case 2: // entire line
				buf = []rune{}
				cursor = 0
			}

		case TokenEraseScreen, TokenIgnored:
			// Ignored for command reconstruction.
		}
	}

	return string(buf[:cursor])
}

// HasObfuscation reports whether the token slice contains control sequences
// that could be used to hide or alter the visible command.
//
// A true result does not mean the command is malicious — it is a signal
// for the AI analyzer to inspect more closely.
func (d *Decoder) HasObfuscation(tokens []Token) bool {
	for _, t := range tokens {
		if t.IsControlSequence() {
			return true
		}
	}
	return false
}

// =============================================================================
// tokenCollector — bridges vtparser callbacks to Token slice
// =============================================================================

type tokenCollector struct {
	tokens []Token
}

func (c *tokenCollector) append(t Token) {
	c.tokens = append(c.tokens, t)
}

func (c *tokenCollector) Print(r rune) {
	c.append(Token{Kind: TokenText, Rune: r})
}

func (c *tokenCollector) Execute(b byte) {
	switch b {
	case 0x08, 0x7f: // BS, DEL
		c.append(Token{Kind: TokenBackspace, N: 1})
	default:
		c.append(Token{Kind: TokenIgnored})
	}
}

func (c *tokenCollector) CsiDispatch(params [][]uint16, _ []byte, _ bool, r rune) {
	// params is [][]uint16 — each element is a sub-parameter list.
	// For simple sequences like [5D, params = [[5]], so params[0][0] = 5.
	firstParam := func() int {
		if len(params) > 0 && len(params[0]) > 0 {
			return int(params[0][0])
		}
		return 0
	}

	n := firstParam()
	if n == 0 {
		n = 1
	}

	switch r {
	case 'A': // Cursor Up
		c.append(Token{Kind: TokenCursorUp, N: n})
	case 'B': // Cursor Down
		c.append(Token{Kind: TokenCursorDown, N: n})
	case 'C': // Cursor Forward
		c.append(Token{Kind: TokenCursorForward, N: n})
	case 'D': // Cursor Back
		c.append(Token{Kind: TokenCursorBack, N: n})
	case 'K': // Erase in Line
		c.append(Token{Kind: TokenEraseLine, N: firstParam()})
	case 'J': // Erase in Display
		c.append(Token{Kind: TokenEraseScreen, N: firstParam()})
	default:
		c.append(Token{Kind: TokenIgnored})
	}
}

func (c *tokenCollector) EscDispatch(_ []byte, _ bool, _ byte) {
	c.append(Token{Kind: TokenIgnored})
}

func (c *tokenCollector) OscDispatch(_ [][]byte, _ bool) {
	c.append(Token{Kind: TokenIgnored})
}

// hook, put, unhook handle DCS sequences (tmux, screen).
// Ignored at this stage — handled by dedicated decoders in TBAS-103.
func (c *tokenCollector) Hook(_ [][]uint16, _ []byte, _ bool, _ rune)           {}
func (c *tokenCollector) Put(_ byte)                                            {}
func (c *tokenCollector) Unhook()                                               {}
func (c *tokenCollector) SosPmApcDispatch(_ vte.SosPmApcKind, _ []byte, _ bool) {}

// =============================================================================
// Package-level convenience functions
// =============================================================================

// Decode parses raw terminal bytes into tokens using a default Decoder.
func Decode(raw []byte) []Token {
	return NewDecoder().Decode(raw)
}

// Apply reconstructs the visible string from tokens using a default Decoder.
func Apply(tokens []Token) string {
	return NewDecoder().Apply(tokens)
}

// DecodeAndApply decodes raw bytes and returns the visible string in one call.
// Use when you only need the visible string and not the token slice.
func DecodeAndApply(raw []byte) string {
	d := NewDecoder()
	return d.Apply(d.Decode(raw))
}

// HasObfuscation reports whether raw bytes contain terminal control sequences.
func HasObfuscation(raw []byte) bool {
	d := NewDecoder()
	return d.HasObfuscation(d.Decode(raw))
}
