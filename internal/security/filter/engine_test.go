package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterEngine_BlocksExactMatch(t *testing.T) {
	e := NewFilterEngine([]string{"rm -rf /"})
	d := e.Inspect("rm -rf /")
	assert.True(t, d.Block)
	assert.Equal(t, "rm -rf /", d.Reason)
}

func TestFilterEngine_BlocksSubstring(t *testing.T) {
	// Pattern is a substring of the command
	e := NewFilterEngine([]string{"rm -rf /"})
	d := e.Inspect("sudo rm -rf / --no-preserve-root")
	assert.True(t, d.Block)
}

func TestFilterEngine_AllowsSafeCommand(t *testing.T) {
	e := NewFilterEngine([]string{"rm -rf /"})
	d := e.Inspect("ls -la")
	assert.False(t, d.Block)
	assert.Empty(t, d.Reason)
}

func TestFilterEngine_AllowsSimilarButSafeCommand(t *testing.T) {
	// "rm -rf /tmp/cache" DOES contain "rm -rf /" as substring — correctly blocked.
	// Admins who want to allow specific subpaths should use more precise patterns,
	// e.g. "rm -rf / " (trailing space) instead of "rm -rf /".
	e := NewFilterEngine([]string{"rm -rf /"})
	d := e.Inspect("rm -rf /tmp/cache")
	assert.True(t, d.Block)
}

func TestFilterEngine_CaseInsensitive(t *testing.T) {
	e := NewFilterEngine([]string{"mkfs"})
	assert.True(t, e.Inspect("MKFS /dev/sda").Block)
	assert.True(t, e.Inspect("Mkfs.ext4 /dev/sda").Block)
}

func TestFilterEngine_MultiplePatterns(t *testing.T) {
	e := NewFilterEngine([]string{"rm -rf /", "mkfs", "dd if=/dev/zero"})
	assert.True(t, e.Inspect("mkfs.ext4 /dev/sda").Block)
	assert.True(t, e.Inspect("dd if=/dev/zero of=/dev/sda").Block)
	assert.False(t, e.Inspect("echo hello").Block)
}

func TestFilterEngine_EmptyInput(t *testing.T) {
	e := NewFilterEngine([]string{"rm -rf /"})
	d := e.Inspect("")
	assert.False(t, d.Block)
}

func TestFilterEngine_EmptyPatterns(t *testing.T) {
	e := NewFilterEngine([]string{})
	d := e.Inspect("rm -rf /")
	assert.False(t, d.Block)
}

func TestFilterEngine_Reload(t *testing.T) {
	e := NewFilterEngine([]string{"rm -rf /"})
	assert.False(t, e.Inspect("mkfs /dev/sda").Block)

	e.Reload([]string{"mkfs"})
	assert.True(t, e.Inspect("mkfs /dev/sda").Block)
	// old pattern no longer active
	assert.False(t, e.Inspect("rm -rf /").Block)
}

func TestFilterEngine_ReasonContainsPattern(t *testing.T) {
	e := NewFilterEngine([]string{"rm -rf /", "mkfs"})
	d := e.Inspect("mkfs.ext4 /dev/sda")
	assert.True(t, d.Block)
	assert.Equal(t, "mkfs", d.Reason)
}

// =============================================================================
// Benchmark — 1000 patterns, 1KB input must complete in < 1ms
// =============================================================================

func BenchmarkFilterEngine_1000Patterns(b *testing.B) {
	patterns := make([]string, 1000)
	for i := range patterns {
		patterns[i] = "pattern_that_does_not_match_" + string(rune('a'+i%26))
	}
	patterns[999] = "rm -rf /"

	e := NewFilterEngine(patterns)
	input := string(make([]byte, 1024)) + "rm -rf /"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Inspect(input)
	}
}
