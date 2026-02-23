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

// Run starts the bridge and blocks until all streams are done.
//
// Three goroutines run concurrently:
//   - target stdout → client
//   - target stderr → client
//   - client stdin  → target stdin
//
// The stdin goroutine drains all client input but is also unblocked
// when both output streams finish — this prevents deadlocks during
// exec commands where the client never closes its stdin explicitly.
//
// Phase 3 injection point marked with TODO below.
func (b *Bridge) Run() {
	var wg sync.WaitGroup
	wg.Add(3)

	// outputDone is closed when both stdout and stderr are exhausted.
	// Used to unblock stdin when the remote process exits.
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

	// Client stdin → target stdin
	//
	// TODO (Phase 3): Replace with:
	//   tee      := io.TeeReader(b.client, recorder)
	//   filtered := filter.WrapReader(tee)
	//   io.Copy(b.targetStdin, filtered)
	//
	// Runs the copy in a separate goroutine so outputDone can unblock
	// it by closing targetStdin when the remote process exits.
	go func() {
		defer wg.Done()

		copyDone := make(chan struct{})
		go func() {
			defer close(copyDone)
			io.Copy(b.targetStdin, b.client)
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
