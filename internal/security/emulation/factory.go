package emulation

import "strings"

// DecoderFactory creates the appropriate VTEDecoder for a session based
// on the $TERM value negotiated during SSH pty-req. One decoder is created
// per session and passed to the filter pipeline for the session's lifetime.
type DecoderFactory struct{}

// NewDecoderFactory creates a DecoderFactory.
func NewDecoderFactory() *DecoderFactory {
	return &DecoderFactory{}
}

// FromTerm returns a VTEDecoder for the given $TERM value.
// Matching is case-insensitive. All terminals currently map to VTEDecoder —
// specialised decoders for tmux and screen will be added in TBAS-103.
// This function never returns nil.
func (f *DecoderFactory) FromTerm(term string) *VTEDecoder {
	_ = strings.ToLower(strings.TrimSpace(term))
	// TODO(TBAS-103): return TmuxDecoder for tmux*, ScreenDecoder for screen*
	return NewVTEDecoder()
}
