package emulation

import "testing"

// FuzzVTE fuzzes the VTEDecoder with arbitrary byte sequences.
// The only invariant: no panic, no infinite loop.
//
// Run with:
//
//	go test -fuzz=FuzzVTE -fuzztime=60s ./internal/security/emulation/
func FuzzVTE(f *testing.F) {
	// Seed corpus — known edge cases as starting points for mutation.
	seeds := [][]byte{
		// Plain text
		{},
		[]byte("cat"),
		[]byte("rm -rf /"),
		// Cursor movement
		[]byte("\033[A"),
		[]byte("\033[5A"),
		[]byte("\033[B"),
		[]byte("\033[C"),
		[]byte("\033[D"),
		[]byte("\033[99D"),
		// Erase sequences
		[]byte("\033[K"),
		[]byte("\033[1K"),
		[]byte("\033[2K"),
		[]byte("\033[2J"),
		// Backspace
		[]byte("\b"),
		[]byte("ab\bcd"),
		// Classic obfuscation pattern
		[]byte("rm\033[A -rf /"),
		// Color / OSC (ignored)
		[]byte("\033[31mcat\033[0m"),
		[]byte("\033]0;title\007"),
		// Truncated / malformed sequences
		[]byte{0x1B},
		[]byte{0x1B, 0x5B},
		[]byte{0x1B, 0x5B, 0xFF},
		// High bytes / invalid UTF-8
		[]byte{0xFF, 0xFE, 0x00},
		[]byte{0x80, 0x81, 0x82},
		// Very long input
		append([]byte("\033["), make([]byte, 1024)...),
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		// VTEDecoder — xterm path
		vte := NewVTEDecoder()
		_ = vte.Decode(raw)

		// DCS pipeline — tmux/screen path
		pipeline := NewDecoderPipeline(NewDCSDecoder(), NewVTEDecoder())
		_ = pipeline.Decode(raw)

		// Factory paths
		factory := NewDecoderFactory()
		_ = factory.FromTerm("xterm-256color").Decode(raw)
		_ = factory.FromTerm("tmux-256color").Decode(raw)
		_ = factory.FromTerm("screen").Decode(raw)
		_ = factory.FromTerm("").Decode(raw)
	})
}

// FuzzDCS fuzzes the DCS stripper in isolation.
func FuzzDCS(f *testing.F) {
	seeds := [][]byte{
		{},
		[]byte("cat"),
		// Valid DCS
		{0x1B, 0x50, 'c', 'a', 't', 0x1B, 0x5C},
		// DCS without terminator
		{0x1B, 0x50, 'c', 'a', 't'},
		// Nested escape inside DCS
		append([]byte{0x1B, 0x50}, append([]byte("rm\033[A -rf /"), 0x1B, 0x5C)...),
		// Multiple DCS wrappers
		{0x1B, 0x50, 'a', 0x1B, 0x5C, 'b', 0x1B, 0x50, 'c', 0x1B, 0x5C},
		// High bytes
		{0x1B, 0x50, 0xFF, 0xFE, 0x1B, 0x5C},
		// Empty DCS
		{0x1B, 0x50, 0x1B, 0x5C},
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		dcs := NewDCSDecoder()
		_ = dcs.Decode(raw)
	})
}
