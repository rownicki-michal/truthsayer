package emulation

import "strings"

// DecoderFactory creates the appropriate decoder for a session based on the
// $TERM value negotiated during SSH pty-req. One decoder is created per
// session and passed to the FilterWriter for the session's lifetime.
type DecoderFactory struct{}

// NewDecoderFactory creates a DecoderFactory.
func NewDecoderFactory() *DecoderFactory { return &DecoderFactory{} }

// FromTerm returns the appropriate decoder for the given $TERM value.
// Matching is case-insensitive. This function never returns nil.
//
//	xterm*, vt100, vt220, vt52, linux, unknown → VTEDecoder
//	tmux*, screen*                              → pipeline(dcs+vte)
func (f *DecoderFactory) FromTerm(term string) termDecoder {
	t := strings.ToLower(strings.TrimSpace(term))
	switch {
	case strings.HasPrefix(t, "tmux"), strings.HasPrefix(t, "screen"):
		return NewDecoderPipeline(NewDCSDecoder(), NewVTEDecoder())
	default:
		return NewVTEDecoder()
	}
}
