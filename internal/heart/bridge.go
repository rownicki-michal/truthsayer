package heart

import (
	"context"
	"errors"
	"io"
	"log"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
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
	filter   io.Writer
	recorder io.Writer
	streamer io.Writer
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

// WithRecorder attaches a Recorder to the bridge. stdout and stderr frames
// are tee'd to the recorder for asciinema v2 session recording.
//
// Call before Run().
func (b *Bridge) WithRecorder(r io.Writer) {
	b.recorder = r
}

// WithStreamer attaches a Streamer to the bridge. stdout and stderr frames
// are tee'd to the streamer for live observer fan-out.
//
// Call before Run().
func (b *Bridge) WithStreamer(s io.Writer) {
	b.streamer = s
}

// Run starts the bridge and blocks until all streams are done.
//
// Three goroutines run concurrently:
//   - target stdout → client (+ recorder, + streamer if set)
//   - target stderr → client (+ recorder, + streamer if set)
//   - client stdin  → filter (if set) or targetStdin
//
// The stdin goroutine drains all client input but is also unblocked
// when both output streams finish — this prevents deadlocks during
// exec commands where the client never closes its stdin explicitly.
func (b *Bridge) Run() {
	eg, ctx := errgroup.WithContext(context.Background())
	eg.Go(func() error {
		_, err := io.Copy(b.outputDst(b.client), b.targetStdout)
		if err == nil {
			return io.EOF
		}
		return err
	})
	eg.Go(func() error {
		var clientDst io.Writer
		if ch, ok := b.client.(ssh.Channel); ok {
			clientDst = ch.Stderr()
		} else {
			clientDst = b.client
		}
		_, err := io.Copy(b.outputDst(clientDst), b.targetStderr)
		if err == nil {
			return io.EOF
		}
		return err
	})
	eg.Go(func() error {
		dst := b.stdinDst()
		_, err := io.Copy(dst, b.client)
		if err == nil {
			return io.EOF
		}
		return err

	})
	eg.Go(func() error {
		<-ctx.Done()
		return b.targetStdin.Close()
	})

	if err := eg.Wait(); err != nil {
		if errors.Is(err, io.EOF) {
			log.Println("[BRIDGE] session done")
		} else {
			log.Printf("[BRIDGE] session error: %v", err)
		}
	}
}

// outputDst builds the destination writer for an output stream (stdout/stderr).
// client is always included; recorder and streamer are added when set.
func (b *Bridge) outputDst(client io.Writer) io.Writer {
	writers := []io.Writer{client}
	if b.recorder != nil {
		writers = append(writers, b.recorder)
	}
	if b.streamer != nil {
		writers = append(writers, b.streamer)
	}
	if len(writers) == 1 {
		return writers[0]
	}
	return io.MultiWriter(writers...)
}

// stdinDst returns the destination writer for client stdin.
// If a filter is attached it takes priority, otherwise targetStdin is used.
func (b *Bridge) stdinDst() io.Writer {
	if b.filter != nil {
		return b.filter
	}
	return b.targetStdin
}
