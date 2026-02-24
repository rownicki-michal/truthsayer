package emulation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// DCSDecoder — stripDCS
// =============================================================================

func TestDCSDecoder_Name(t *testing.T) {
	assert.Equal(t, "dcs", NewDCSDecoder().Name())
}

func TestDCSDecoder_PlainText_PassesThrough(t *testing.T) {
	result := NewDCSDecoder().Decode([]byte("cat /etc/passwd"))
	assert.Equal(t, "cat /etc/passwd", result.Visible)
	assert.False(t, result.HasObfuscation)
}

func TestDCSDecoder_SingleWrapper_ExtractsInner(t *testing.T) {
	// ESC P <inner> ESC \
	raw := []byte{0x1B, 0x50, 'c', 'a', 't', 0x1B, 0x5C}
	result := NewDCSDecoder().Decode(raw)
	assert.Equal(t, "cat", result.Visible)
}

func TestDCSDecoder_InnerEscapeSequence_Preserved(t *testing.T) {
	// ESC P rm ESC[A -rf / ESC \  — cursor-up obfuscation inside DCS
	raw := append([]byte{0x1B, 0x50}, []byte("rm\033[A -rf /")...)
	raw = append(raw, 0x1B, 0x5C)
	result := NewDCSDecoder().Decode(raw)
	assert.Equal(t, "rm\033[A -rf /", result.Visible)
	// DCSDecoder does not evaluate obfuscation — VTEDecoder does
	assert.False(t, result.HasObfuscation)
}

func TestDCSDecoder_MultipleWrappers(t *testing.T) {
	// ESC P foo ESC \ bar ESC P baz ESC \
	raw := []byte{0x1B, 0x50, 'f', 'o', 'o', 0x1B, 0x5C,
		'b', 'a', 'r',
		0x1B, 0x50, 'b', 'a', 'z', 0x1B, 0x5C}
	result := NewDCSDecoder().Decode(raw)
	assert.Equal(t, "foobarbaz", result.Visible)
}

func TestDCSDecoder_MalformedDCS_PassesThroughInner(t *testing.T) {
	// DCS without terminator — inner bytes passed through verbatim, no panic
	raw := []byte{0x1B, 0x50, 'c', 'a', 't'}
	result := NewDCSDecoder().Decode(raw)
	assert.Equal(t, "cat", result.Visible)
}

func TestDCSDecoder_EmptyInput(t *testing.T) {
	result := NewDCSDecoder().Decode([]byte{})
	assert.Equal(t, "", result.Visible)
}

// =============================================================================
// Pipeline: DCSDecoder + VTEDecoder (tmux/screen flow)
// =============================================================================

func TestPipeline_DCS_VTE_ObfuscationDetected(t *testing.T) {
	// tmux tunnels "rm\033[A -rf /" inside a DCS wrapper
	raw := append([]byte{0x1B, 0x50}, []byte("rm\033[A -rf /")...)
	raw = append(raw, 0x1B, 0x5C)

	p := NewDecoderPipeline(NewDCSDecoder(), NewVTEDecoder())
	result := p.Decode(raw)
	assert.Equal(t, "rm -rf /", result.Visible)
	assert.True(t, result.HasObfuscation)
}

func TestPipeline_DCS_VTE_PlainCommand(t *testing.T) {
	raw := append([]byte{0x1B, 0x50}, []byte("ls -la")...)
	raw = append(raw, 0x1B, 0x5C)

	p := NewDecoderPipeline(NewDCSDecoder(), NewVTEDecoder())
	result := p.Decode(raw)
	assert.Equal(t, "ls -la", result.Visible)
	assert.False(t, result.HasObfuscation)
}

// =============================================================================
// DecoderFactory — tmux/screen routing
// =============================================================================

func TestDecoderFactory_TmuxReturnsPipeline(t *testing.T) {
	f := NewDecoderFactory()
	for _, term := range []string{"tmux", "tmux-256color", "TMUX-256COLOR"} {
		dec := f.FromTerm(term)
		assert.NotNil(t, dec, "term=%q", term)
		assert.Equal(t, "pipeline(dcs+vte)", dec.Name(), "term=%q", term)
	}
}

func TestDecoderFactory_ScreenReturnsPipeline(t *testing.T) {
	f := NewDecoderFactory()
	for _, term := range []string{"screen", "screen-256color"} {
		dec := f.FromTerm(term)
		assert.NotNil(t, dec, "term=%q", term)
		assert.Equal(t, "pipeline(dcs+vte)", dec.Name(), "term=%q", term)
	}
}

func TestDecoderFactory_XtermReturnsVTE(t *testing.T) {
	dec := NewDecoderFactory().FromTerm("xterm-256color")
	assert.Equal(t, "vte", dec.Name())
}

func TestDecoderFactory_UnknownReturnsVTE(t *testing.T) {
	dec := NewDecoderFactory().FromTerm("ghostty")
	assert.Equal(t, "vte", dec.Name())
}

func TestDecoderFactory_NeverReturnsNil(t *testing.T) {
	f := NewDecoderFactory()
	for _, term := range []string{"", "tmux", "screen", "xterm", "rxvt"} {
		assert.NotNil(t, f.FromTerm(term), "term=%q", term)
	}
}
