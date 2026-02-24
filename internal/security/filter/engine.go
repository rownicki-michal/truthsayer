// Package filter implements command inspection for the Truthsayer SSH bastion.
//
// # Why raw stdin filtering is not enough
//
// Filtering raw stdin bytes is vulnerable to obfuscation attacks:
//
//	Example 1: rm\033[A -rf /         — ANSI cursor-up hides " -rf /"
//	Example 2: alias x='rm -rf'; x /  — alias indirection
//	Example 3: printf "\x72\x6d" | sh — hex encoding
//
// FilterEngine solves the first class of attacks by operating on the visible
// string produced by the VTE terminal emulator (emulation.VTEDecoder), not on
// raw bytes. Alias indirection and encoding attacks are handled by the AI
// analyzer (TBAS-501) and eBPF agent (TBAS-603).
package filter

import (
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
)

// FilterDecision is the result of inspecting a visible command string.
type FilterDecision struct {
	Block  bool
	Reason string // matched pattern, empty when Block is false
}

// FilterEngine inspects decoded command strings against a blacklist using
// the Aho-Corasick multi-pattern algorithm. Matching is O(n) in the length
// of the input regardless of the number of patterns.
//
// Patterns are loaded at startup and can be reloaded without restart by
// sending SIGHUP to the process.
//
// FilterEngine is safe for concurrent use — multiple sessions call Inspect
// simultaneously.
type FilterEngine struct {
	mu       sync.RWMutex
	trie     ahocorasick.AhoCorasick
	patterns []string
}

// NewFilterEngine creates a FilterEngine with the given patterns.
// Matching is case-insensitive.
func NewFilterEngine(patterns []string) *FilterEngine {
	e := &FilterEngine{}
	e.rebuild(patterns)
	return e
}

// Inspect checks whether visible contains any blacklisted pattern.
// visible should be the output of emulation.VTEDecoder.Decode().Visible —
// the string a human would see on screen after terminal processing.
func (e *FilterEngine) Inspect(visible string) FilterDecision {
	if visible == "" {
		return FilterDecision{}
	}

	e.mu.RLock()
	trie := e.trie
	patterns := e.patterns
	e.mu.RUnlock()

	matches := trie.FindAll(strings.ToLower(visible))
	if len(matches) == 0 {
		return FilterDecision{}
	}

	return FilterDecision{Block: true, Reason: patterns[matches[0].Pattern()]}
}

// Reload replaces the current pattern set with new ones.
// Safe to call from any goroutine — in-flight Inspect calls complete normally.
func (e *FilterEngine) Reload(patterns []string) {
	e.rebuild(patterns)
}

// WatchSIGHUP starts a goroutine that calls reload() whenever the process
// receives SIGHUP. Typically reload() calls e.Reload(cfg.Security.Blacklist).
// The goroutine exits when the provided done channel is closed.
func (e *FilterEngine) WatchSIGHUP(done <-chan struct{}, reload func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ch:
				reload()
			case <-done:
				return
			}
		}
	}()
}

// rebuild compiles the Aho-Corasick trie from patterns.
// All patterns are lowercased so Inspect can lowercase the haystack once.
func (e *FilterEngine) rebuild(patterns []string) {
	lower := make([]string, len(patterns))
	for i, p := range patterns {
		lower[i] = strings.ToLower(p)
	}

	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  false,
	})
	trie := builder.Build(lower)

	e.mu.Lock()
	e.trie = trie
	e.patterns = lower
	e.mu.Unlock()
}
