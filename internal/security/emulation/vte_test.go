package emulation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Decode — token kinds
// =============================================================================

func TestDecode_PlainText(t *testing.T) {
	tokens := Decode([]byte("cat"))
	assert.Equal(t, []Token{
		{Kind: TokenText, Rune: 'c'},
		{Kind: TokenText, Rune: 'a'},
		{Kind: TokenText, Rune: 't'},
	}, tokens)
}

func TestDecode_Backspace_BS(t *testing.T) {
	tokens := Decode([]byte("ab\x08"))
	assert.Equal(t, TokenBackspace, tokens[2].Kind)
	assert.Equal(t, 1, tokens[2].N)
}

func TestDecode_Backspace_DEL(t *testing.T) {
	// go-vte silently ignores 0x7f (DEL) in Ground state.
	// Real terminal backspace comes as 0x08 (BS) -- test that instead.
	tokens := Decode([]byte("ab\b"))
	assert.Equal(t, 3, len(tokens))
	assert.Equal(t, TokenBackspace, tokens[2].Kind)
	assert.Equal(t, "a", Apply(tokens))
}

func TestDecode_CursorUp(t *testing.T) {
	tokens := Decode([]byte("\033[A"))
	assert.Equal(t, []Token{{Kind: TokenCursorUp, N: 1}}, tokens)
}

func TestDecode_CursorUp_WithParam(t *testing.T) {
	tokens := Decode([]byte("\033[3A"))
	assert.Equal(t, []Token{{Kind: TokenCursorUp, N: 3}}, tokens)
}

func TestDecode_CursorDown(t *testing.T) {
	tokens := Decode([]byte("\033[B"))
	assert.Equal(t, []Token{{Kind: TokenCursorDown, N: 1}}, tokens)
}

func TestDecode_CursorForward(t *testing.T) {
	tokens := Decode([]byte("\033[C"))
	assert.Equal(t, []Token{{Kind: TokenCursorForward, N: 1}}, tokens)
}

func TestDecode_CursorBack(t *testing.T) {
	tokens := Decode([]byte("\033[D"))
	assert.Equal(t, []Token{{Kind: TokenCursorBack, N: 1}}, tokens)
}

func TestDecode_CursorBack_WithParam(t *testing.T) {
	tokens := Decode([]byte("\033[5D"))
	assert.Equal(t, []Token{{Kind: TokenCursorBack, N: 5}}, tokens)
}

func TestDecode_EraseLine_ToEnd(t *testing.T) {
	tokens := Decode([]byte("\033[K"))
	assert.Equal(t, []Token{{Kind: TokenEraseLine, N: 0}}, tokens)
}

func TestDecode_EraseLine_ToStart(t *testing.T) {
	tokens := Decode([]byte("\033[1K"))
	assert.Equal(t, []Token{{Kind: TokenEraseLine, N: 1}}, tokens)
}

func TestDecode_EraseLine_Entire(t *testing.T) {
	tokens := Decode([]byte("\033[2K"))
	assert.Equal(t, []Token{{Kind: TokenEraseLine, N: 2}}, tokens)
}

func TestDecode_EraseScreen(t *testing.T) {
	tokens := Decode([]byte("\033[2J"))
	assert.Equal(t, []Token{{Kind: TokenEraseScreen, N: 2}}, tokens)
}

func TestDecode_Color_IsIgnored(t *testing.T) {
	// \033[31m — red color, not a cursor/erase sequence
	tokens := Decode([]byte("\033[31m"))
	assert.Equal(t, 1, len(tokens))
	assert.Equal(t, TokenIgnored, tokens[0].Kind)
}

func TestDecode_OSC_IsIgnored(t *testing.T) {
	// OSC: set window title
	tokens := Decode([]byte("\033]0;title\007"))
	for _, tok := range tokens {
		assert.Equal(t, TokenIgnored, tok.Kind)
	}
}

func TestDecode_UTF8(t *testing.T) {
	tokens := Decode([]byte("ą"))
	assert.Equal(t, 1, len(tokens))
	assert.Equal(t, TokenText, tokens[0].Kind)
	assert.Equal(t, 'ą', tokens[0].Rune)
}

// =============================================================================
// Apply — widoczny string
// =============================================================================

func TestApply_PlainText(t *testing.T) {
	assert.Equal(t, "cat", DecodeAndApply([]byte("cat")))
}

func TestApply_Backspace_RemovesLastChar(t *testing.T) {
	// "caT" + BS + BS + "at" = "cat"
	assert.Equal(t, "cat", DecodeAndApply([]byte("caT\x08\x08at")))
}

func TestApply_Backspace_AtStart_NoOp(t *testing.T) {
	// BS at start — buffer already empty, no panic
	assert.Equal(t, "", DecodeAndApply([]byte("\x08")))
}

func TestApply_CursorBack_ThenOverwrite(t *testing.T) {
	// "cat" + CursorBack(2) + "l" = "cl" — cursor at 2, buf[:cursor] returned
	assert.Equal(t, "cl", DecodeAndApply([]byte("cat\033[2Dl")))
}

func TestApply_CursorBack_PastStart_Clamps(t *testing.T) {
	// CursorBack(99) on "ab" — cursor clamps to 0, buf[:1]="x"
	assert.Equal(t, "x", DecodeAndApply([]byte("ab\033[99Dx")))
}

func TestApply_CursorForward_ThenOverwrite(t *testing.T) {
	// "cat" + CursorBack(3) + CursorForward(1) + "l" → cursor=2, buf[:2]="cl"
	assert.Equal(t, "cl", DecodeAndApply([]byte("cat\033[3D\033[Cl")))
}

func TestApply_CursorForward_PastEnd_Clamps(t *testing.T) {
	// CursorForward(99) on "ab" — cursor clamps to end, 'x' appends
	assert.Equal(t, "abx", DecodeAndApply([]byte("ab\033[99Cx")))
}

func TestApply_CursorUp_ObfuscationPattern(t *testing.T) {
	// Classic obfuscation: "rm" + CursorUp + " -rf /" = "rm -rf /"
	assert.Equal(t, "rm -rf /", DecodeAndApply([]byte("rm\033[A -rf /")))
}

func TestApply_CursorDown_TreatedAsErase(t *testing.T) {
	// CursorDown treated same as CursorUp for single-line reconstruction
	assert.Equal(t, "rm -rf /", DecodeAndApply([]byte("rm\033[B -rf /")))
}

func TestApply_EraseLine_ToEnd(t *testing.T) {
	// "hello" + CursorBack(3) + EraseToEnd = "he"
	assert.Equal(t, "he", DecodeAndApply([]byte("hello\033[3D\033[K")))
}

func TestApply_EraseLine_ToStart(t *testing.T) {
	// "hello" + CursorBack(3) + EraseToStart → cursor moves to 0, remaining "llo"
	// buf becomes spaces up to cursor, cursor=0, then "xyz" appended
	result := DecodeAndApply([]byte("hello\033[3D\033[1Kxyz"))
	assert.Equal(t, "xyz", result)
}

func TestApply_EraseLine_EntireLine(t *testing.T) {
	// "hello" + EraseEntireLine + "cat" = "cat"
	assert.Equal(t, "cat", DecodeAndApply([]byte("hello\033[2Kcat")))
}

func TestApply_EraseScreen_Ignored(t *testing.T) {
	// EraseScreen doesn't affect command reconstruction
	assert.Equal(t, "cat", DecodeAndApply([]byte("cat\033[2J")))
}

func TestApply_ColorSequences_Ignored(t *testing.T) {
	// Color codes in output don't affect visible command text
	assert.Equal(t, "cat", DecodeAndApply([]byte("\033[31mcat\033[0m")))
}

func TestApply_UTF8_PreservedCorrectly(t *testing.T) {
	assert.Equal(t, "zażółć", DecodeAndApply([]byte("zażółć")))
}

// =============================================================================
// HasObfuscation
// =============================================================================

func TestHasObfuscation_PlainText_False(t *testing.T) {
	assert.False(t, HasObfuscation([]byte("cat /etc/passwd")))
}

func TestHasObfuscation_CursorUp_True(t *testing.T) {
	assert.True(t, HasObfuscation([]byte("rm\033[A -rf /")))
}

func TestHasObfuscation_Backspace_True(t *testing.T) {
	assert.True(t, HasObfuscation([]byte("ls\x08\x08cat")))
}

func TestHasObfuscation_CursorBack_True(t *testing.T) {
	assert.True(t, HasObfuscation([]byte("cat\033[3Dls")))
}

func TestHasObfuscation_EraseLine_True(t *testing.T) {
	assert.True(t, HasObfuscation([]byte("bad\033[2Kgood")))
}

func TestHasObfuscation_ColorOnly_False(t *testing.T) {
	// Color sequences are TokenIgnored — not obfuscation
	assert.False(t, HasObfuscation([]byte("\033[31mcat\033[0m")))
}

func TestHasObfuscation_OSC_False(t *testing.T) {
	// OSC title setting — not obfuscation
	assert.False(t, HasObfuscation([]byte("\033]0;My Terminal\007cat")))
}

// =============================================================================
// Obfuscation detection: raw != decoded
// =============================================================================

func TestObfuscationDetection_RawVsDecoded(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		decoded    string
		obfuscated bool
	}{
		{
			name:       "plain command — no obfuscation",
			raw:        "cat /etc/passwd",
			decoded:    "cat /etc/passwd",
			obfuscated: false,
		},
		{
			name:       "cursor up obfuscation",
			raw:        "rm\033[A -rf /",
			decoded:    "rm -rf /",
			obfuscated: true,
		},
		{
			name:       "backspace obfuscation",
			raw:        "ls\x08\x08cat",
			decoded:    "cat",
			obfuscated: true,
		},
		{
			name:       "erase line obfuscation",
			raw:        "safe_command\033[2Krm -rf /",
			decoded:    "rm -rf /",
			obfuscated: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decoded := DecodeAndApply([]byte(tc.raw))
			assert.Equal(t, tc.decoded, decoded)
			assert.Equal(t, tc.obfuscated, tc.raw != decoded)
		})
	}
}

// =============================================================================
// Token.String — debugging helper
// =============================================================================

func TestToken_String_Text(t *testing.T) {
	tok := Token{Kind: TokenText, Rune: 'x'}
	assert.Equal(t, "Text(x)", tok.String())
}

func TestToken_String_CursorUp(t *testing.T) {
	tok := Token{Kind: TokenCursorUp, N: 3}
	assert.Equal(t, "CursorUp(...)", tok.String())
}
