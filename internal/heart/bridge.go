package heart

import (
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Bridge manages bidirectional data flow between an SSH client
// and a target server session.
//
// Operates on io.ReadWriter instead of ssh.Channel — in Phase 3
// io.TeeReader, filter and recorder can be injected without changing
// the Bridge structure.
type Bridge struct {
	client       io.ReadWriter  // client side (ssh.Channel)
	targetStdin  io.WriteCloser // target session stdin
	targetStdout io.Reader      // target session stdout
	targetStderr io.Reader      // target session stderr

	// filter intercepts client stdin before it reaches targetStdin.
	// When nil, bytes are copied directly to targetStdin (no filtering).
	filter io.Writer
}

// NewBridge creates a new Bridge instance.
//
//	client     — SSH client channel (ssh.Channel implements io.ReadWriter)
//	stdin      — target session stdin  (targetSession.StdinPipe())
//	stdout     — target session stdout (targetSession.StdoutPipe())
//	stderr     — target session stderr (targetSession.StderrPipe())
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

// WithFilter attaches a FilterWriter to the bridge. Client stdin bytes will
// be written to fw instead of directly to targetStdin. fw is responsible for
// forwarding allowed bytes to targetStdin and dropping blocked commands.
//
// Call before Run().
func (b *Bridge) WithFilter(fw io.Writer) {
	b.filter = fw
}

// Run starts the bridge and blocks until all streams are done.
//
// Three goroutines run concurrently:
//   - target stdout → client
//   - target stderr → client
//   - client stdin  → filter (if set) or targetStdin
//
// The stdin goroutine drains all client input but is also unblocked
// when both output streams finish — this prevents deadlocks during
// exec commands where the client never closes its stdin explicitly.
func (b *Bridge) Run() {
	var wg sync.WaitGroup
	wg.Add(3)

	// outputDone is closed when both stdout and stderr are exhausted.
	outputDone := make(chan struct{})
	var outputWg sync.WaitGroup
	outputWg.Add(2)

	// Target stdout → client
	go func() {
		defer wg.Done()
		defer outputWg.Done()
		io.Copy(b.client, b.targetStdout)
	}()

	// Target stderr → client (or client.Stderr() when ssh.Channel)
	go func() {
		defer wg.Done()
		defer outputWg.Done()
		if ch, ok := b.client.(ssh.Channel); ok {
			io.Copy(ch.Stderr(), b.targetStderr)
		} else {
			io.Copy(b.client, b.targetStderr)
		}
	}()

	// Signal outputDone when both output streams finish.
	go func() {
		outputWg.Wait()
		close(outputDone)
	}()

	// Client stdin → filter (if set) or targetStdin directly.
	go func() {
		defer wg.Done()

		dst := b.stdinDst()

		copyDone := make(chan struct{})
		go func() {
			defer close(copyDone)
			io.Copy(dst, b.client)
		}()

		select {
		case <-copyDone:
			// Client closed its end — normal shell exit.
		case <-outputDone:
			// Remote process exited — stop reading client stdin.
		}
		b.targetStdin.Close()

		// Wait for the copy goroutine to drain.
		<-copyDone
	}()

	wg.Wait()
}

// stdinDst returns the destination writer for client stdin.
// If a filter is attached it takes priority, otherwise targetStdin is used.
func (b *Bridge) stdinDst() io.Writer {
	if b.filter != nil {
		return b.filter
	}
	return b.targetStdin
}
