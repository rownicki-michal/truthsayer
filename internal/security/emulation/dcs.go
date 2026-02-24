package emulation

import "bytes"

// DCSDecoder strips Device Control String (DCS) wrappers from raw terminal
// bytes before they reach the VTE state machine.
//
// DCS format: ESC P <payload> ESC \
// Both tmux and screen use DCS to tunnel inner terminal sequences through
// the outer terminal. Stripping the wrapper exposes the inner bytes so
// VTEDecoder can process them normally.
//
// DCSDecoder is intended to be used as the first stage in a DecoderPipeline:
//
//	NewDecoderPipeline(NewDCSDecoder(), NewVTEDecoder())
//
// Unknown or malformed sequences are passed through unchanged — nothing is
// silently dropped.
type DCSDecoder struct{}

// NewDCSDecoder creates a DCSDecoder.
func NewDCSDecoder() *DCSDecoder { return &DCSDecoder{} }

// Decode strips DCS wrappers and returns the inner bytes as Visible.
// HasObfuscation is always false — obfuscation detection is delegated
// to the VTEDecoder stage that follows in the pipeline.
func (d *DCSDecoder) Decode(raw []byte) DecodeResult {
	return DecodeResult{
		Visible:        string(stripDCS(raw)),
		HasObfuscation: false,
	}
}

// Name returns a human-readable identifier used in logs and metrics.
func (d *DCSDecoder) Name() string { return "dcs" }

// stripDCS removes all DCS wrappers (ESC P ... ESC \) from raw bytes.
// Content outside DCS sequences is preserved verbatim.
func stripDCS(raw []byte) []byte {
	// ESC P = 0x1B 0x50  — DCS introducer
	// ESC \ = 0x1B 0x5C  — string terminator (ST)
	dcsStart := []byte{0x1B, 0x50}
	dcsEnd := []byte{0x1B, 0x5C}

	var out []byte
	for len(raw) > 0 {
		start := bytes.Index(raw, dcsStart)
		if start == -1 {
			// No more DCS sequences — append remainder verbatim.
			out = append(out, raw...)
			break
		}
		// Append bytes before the DCS sequence.
		out = append(out, raw[:start]...)
		raw = raw[start+len(dcsStart):]

		end := bytes.Index(raw, dcsEnd)
		if end == -1 {
			// Malformed / incomplete DCS — append inner bytes verbatim.
			out = append(out, raw...)
			break
		}
		// Append the inner payload, skip the ST terminator.
		out = append(out, raw[:end]...)
		raw = raw[end+len(dcsEnd):]
	}
	return out
}
