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
// VTEDecoder
// =============================================================================

// VTEDecoder wraps the low-level Decoder and returns a DecodeResult.
// It handles VT100, VT220 and xterm escape sequences — the vast majority
// of what real SSH sessions produce.
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

// DecoderPipeline applies a list of VTEDecoders in order.
// Each decoder receives the Visible output of the previous one as its input.
// HasObfuscation is true if any decoder in the chain detected obfuscation.
//
// Useful for stacking specialised decoders — for example a TmuxDecoder
// that strips DCS wrappers followed by a VTEDecoder that processes the
// inner terminal data (TBAS-103).
type DecoderPipeline struct {
	decoders []*VTEDecoder
}

// NewDecoderPipeline creates a pipeline from the provided decoders.
func NewDecoderPipeline(decoders ...*VTEDecoder) *DecoderPipeline {
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
