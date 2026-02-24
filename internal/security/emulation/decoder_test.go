package emulation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// VTEDecoder
// =============================================================================

func TestVTEDecoder_PlainText(t *testing.T) {
	result := NewVTEDecoder().Decode([]byte("cat /etc/passwd"))
	assert.Equal(t, "cat /etc/passwd", result.Visible)
	assert.False(t, result.HasObfuscation)
}

func TestVTEDecoder_CursorUpObfuscation(t *testing.T) {
	result := NewVTEDecoder().Decode([]byte("rm\033[A -rf /"))
	assert.Equal(t, "rm -rf /", result.Visible)
	assert.True(t, result.HasObfuscation)
}

func TestVTEDecoder_BackspaceObfuscation(t *testing.T) {
	result := NewVTEDecoder().Decode([]byte("ls\b\bcat"))
	assert.Equal(t, "cat", result.Visible)
	assert.True(t, result.HasObfuscation)
}

func TestVTEDecoder_ColorSequences_NoObfuscation(t *testing.T) {
	result := NewVTEDecoder().Decode([]byte("\033[31mcat\033[0m"))
	assert.Equal(t, "cat", result.Visible)
	assert.False(t, result.HasObfuscation)
}

func TestVTEDecoder_Name(t *testing.T) {
	assert.Equal(t, "vte", NewVTEDecoder().Name())
}

// =============================================================================
// DecoderPipeline
// =============================================================================

func TestDecoderPipeline_Name(t *testing.T) {
	p := NewDecoderPipeline(NewVTEDecoder(), NewVTEDecoder())
	assert.Equal(t, "pipeline(vte+vte)", p.Name())
}

func TestDecoderPipeline_SingleDecoder_SameAsDirectDecode(t *testing.T) {
	raw := []byte("rm\033[A -rf /")
	direct := NewVTEDecoder().Decode(raw)
	pipeline := NewDecoderPipeline(NewVTEDecoder()).Decode(raw)
	assert.Equal(t, direct.Visible, pipeline.Visible)
	assert.Equal(t, direct.HasObfuscation, pipeline.HasObfuscation)
}

func TestDecoderPipeline_ObfuscationPropagates(t *testing.T) {
	p := NewDecoderPipeline(NewVTEDecoder(), NewVTEDecoder())
	result := p.Decode([]byte("rm\033[A -rf /"))
	assert.True(t, result.HasObfuscation)
}

func TestDecoderPipeline_PlainText_NoObfuscation(t *testing.T) {
	p := NewDecoderPipeline(NewVTEDecoder(), NewVTEDecoder())
	result := p.Decode([]byte("ls -la"))
	assert.Equal(t, "ls -la", result.Visible)
	assert.False(t, result.HasObfuscation)
}

// =============================================================================
// DecoderFactory
// =============================================================================

func TestDecoderFactory_ReturnsVTEDecoder(t *testing.T) {
	f := NewDecoderFactory()
	for _, term := range []string{
		"xterm", "xterm-256color", "xterm-kitty",
		"vt100", "vt220", "linux",
		"tmux", "tmux-256color",
		"screen", "screen-256color",
		"rxvt", "alacritty", "foot", "ghostty",
		"", "XTERM-256COLOR",
	} {
		dec := f.FromTerm(term)
		assert.NotNil(t, dec, "term=%q should never return nil", term)
		assert.Equal(t, "vte", dec.Name(), "term=%q", term)
	}
}

func TestDecoderFactory_ReturnedDecoder_IsFunctional(t *testing.T) {
	dec := NewDecoderFactory().FromTerm("xterm-256color")
	result := dec.Decode([]byte("rm\033[A -rf /"))
	assert.Equal(t, "rm -rf /", result.Visible)
	assert.True(t, result.HasObfuscation)
}
