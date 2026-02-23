package heart

import (
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Bridge manages bidirectional data flow between the SSH client
// and the target server session.
//
// Operates on io.ReadWriter instead of ssh.Channel — this allows Phase 3
// to inject io.TeeReader, filter, and recorder without changing the Bridge structure.
type Bridge struct {
	client       io.ReadWriter  // client side (ssh.Channel)
	targetStdin  io.WriteCloser // stdin of the target session
	targetStdout io.Reader      // stdout of the target session
	targetStderr io.Reader      // stderr of the target session
}

// NewBridge creates a new bridge instance.
//
//	client     — SSH channel of the client (ssh.Channel implements io.ReadWriter)
//	stdin      — stdin of the target session  (targetSession.StdinPipe())
//	stdout     — stdout of the target session (targetSession.StdoutPipe())
//	stderr     — stderr of the target session (targetSession.StderrPipe())
func NewBridge(
	client io.ReadWriter,
	stdin io.WriteCloser,
	stdout io.Reader,
	stderr io.Reader,
) *Bridge {
	return &Bridge{
		client:       client,
		targetStdin:  stdin,
		targetStdout: stdout,
		targetStderr: stderr,
	}
}

// Run starts the bridge and blocks until all streams are done.
//
// Three goroutines run concurrently:
//   - target server stdout → client
//   - target server stderr → client
//   - client → target server stdin
//
// The injection point for Phase 3 is marked with a TODO comment.
func (b *Bridge) Run() {
	var wg sync.WaitGroup
	wg.Add(3)

	// Direction: target server stdout → client
	go func() {
		defer wg.Done()
		io.Copy(b.client, b.targetStdout)
	}()

	// Direction: target server stderr → client
	// If client is ssh.Channel — write to its separate stderr stream.
	// Otherwise stderr goes to the client stdout (fallback).
	go func() {
		defer wg.Done()
		if ch, ok := b.client.(ssh.Channel); ok {
			io.Copy(ch.Stderr(), b.targetStderr)
		} else {
			io.Copy(b.client, b.targetStderr)
		}
	}()

	// Direction: client → target server stdin
	//
	// TODO (Phase 3): Replace with:
	//
	//   tee := io.TeeReader(b.client, recorder)
	//   filtered := filter.WrapReader(tee)
	//   io.Copy(b.targetStdin, filtered)
	//
	go func() {
		defer wg.Done()
		io.Copy(b.targetStdin, b.client)

		// Closing stdin signals EOF to the target server
		// without closing the entire SSH channel.
		b.targetStdin.Close()
	}()

	wg.Wait()
}
