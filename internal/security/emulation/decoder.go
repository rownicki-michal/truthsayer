package emulation

import "strings"

// DecodeResult holds the output of a terminal decoder pass.
// Visible is the string a human would see on screen after the terminal
// has processed all escape sequences. HasObfuscation is true when the
// raw input contained control sequences that alter visible content
// (cursor movement, backspace, erase) — a signal for the filter engine
// to escalate to AI analysis.
type DecodeResult struct {
	Visible        string
	HasObfuscation bool
}

// =============================================================================
// Decoder — common interface (unexported, used internally by pipeline/factory)
// =============================================================================

// termDecoder is the minimal internal interface shared by VTEDecoder,
// DCSDecoder and DecoderPipeline. It is intentionally unexported — callers
// use concrete types returned by DecoderFactory.
type termDecoder interface {
	Decode([]byte) DecodeResult
	Name() string
}

// =============================================================================
// VTEDecoder
// =============================================================================

// VTEDecoder wraps the low-level Decoder and returns a DecodeResult.
// It handles VT100, VT220 and xterm escape sequences.
type VTEDecoder struct {
	d *Decoder
}

// NewVTEDecoder creates a VTEDecoder ready for use.
func NewVTEDecoder() *VTEDecoder {
	return &VTEDecoder{d: NewDecoder()}
}

// Decode processes raw bytes and returns the visible string and
// an obfuscation signal.
func (v *VTEDecoder) Decode(raw []byte) DecodeResult {
	tokens := v.d.Decode(raw)
	return DecodeResult{
		Visible:        v.d.Apply(tokens),
		HasObfuscation: v.d.HasObfuscation(tokens),
	}
}

// Name returns a human-readable identifier used in logs and metrics.
func (v *VTEDecoder) Name() string { return "vte" }

// =============================================================================
// DecoderPipeline
// =============================================================================

// DecoderPipeline applies a list of decoders in order.
// Each decoder receives the Visible output of the previous one as its input.
// HasObfuscation is true if any decoder in the chain detected obfuscation.
//
// Typical use: DCSDecoder strips tmux/screen wrappers, then VTEDecoder
// processes the inner terminal sequences.
type DecoderPipeline struct {
	decoders []termDecoder
}

// NewDecoderPipeline creates a pipeline from the provided decoders.
func NewDecoderPipeline(decoders ...termDecoder) *DecoderPipeline {
	return &DecoderPipeline{decoders: decoders}
}

// Decode applies each decoder in sequence.
func (p *DecoderPipeline) Decode(raw []byte) DecodeResult {
	result := DecodeResult{Visible: string(raw)}
	for _, dec := range p.decoders {
		next := dec.Decode([]byte(result.Visible))
		result.Visible = next.Visible
		if next.HasObfuscation {
			result.HasObfuscation = true
		}
	}
	return result
}

// Name returns a human-readable identifier for the pipeline.
func (p *DecoderPipeline) Name() string {
	names := make([]string, len(p.decoders))
	for i, d := range p.decoders {
		names[i] = d.Name()
	}
	return "pipeline(" + strings.Join(names, "+") + ")"
}
