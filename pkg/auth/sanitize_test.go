package auth

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// disallowedRunes reports every rune in s that must never reach a terminal in a
// pre-auth prompt: C0 controls, DEL, the C1 block, and the Unicode line and
// paragraph separators. Newline is allowed only when allowNewline is set, which
// is true for a whole prompt (the instruction template is multi-line and
// trusted) and false for an individual provider-supplied value.
//
// This is written out longhand rather than calling isDisallowedInPrompt so that
// the test states the property independently of the code under test. A test that
// asks the implementation what the right answer is cannot fail.
func disallowedRunes(s string, allowNewline bool) []rune {
	var found []rune
	for _, r := range s {
		if r == '\n' && allowNewline {
			continue
		}
		switch {
		case r < 0x20, // C0, including ESC, CR, TAB and NUL
			r == 0x7f,              // DEL
			r >= 0x80 && r <= 0x9f, // C1, e.g. U+009B CSI
			r == '\u2028',          // LINE SEPARATOR
			r == '\u2029':          // PARAGRAPH SEPARATOR
			found = append(found, r)
		}
	}
	return found
}

// assertNoDisallowedRunes fails the test if s carries any rune that could move
// the cursor, hide text, or start a line where the template did not put one.
func assertNoDisallowedRunes(t *testing.T, allowNewline bool, s string) {
	t.Helper()
	// A raw 0x9B byte is invalid UTF-8, so ranging over the string reports it as
	// U+FFFD rather than as the C1 CSI it would be to a terminal reading bytes.
	// Requiring valid UTF-8 is what closes that gap.
	if !utf8.ValidString(s) {
		t.Errorf("output is not valid UTF-8, so it may still carry raw C1 bytes: %q", s)
	}
	bad := disallowedRunes(s, allowNewline)
	if len(bad) == 0 {
		return
	}
	names := make([]string, 0, len(bad))
	for _, r := range bad {
		names = append(names, fmt.Sprintf("U+%04X", r))
	}
	t.Errorf("output carries %d control rune(s) %s; a provider must not be able to draw on a pre-auth terminal.\nOutput was %q",
		len(bad), strings.Join(names, " "), s)
}

// assertMarked fails the test if the sanitizer removed something without saying
// so. Silently handing the operator a mangled URL is its own failure mode: they
// need to be able to tell tampering from a typo.
func assertMarked(t *testing.T, in, got string) {
	t.Helper()
	if !strings.Contains(got, "control character") {
		t.Errorf("sanitize(%q) = %q, want a visible marker saying something was removed", in, got)
	}
}

// cleanValues are strings a well-behaved provider really does return. The
// sanitizer must return each one byte-for-byte identical: an over-eager
// sanitizer that mangles a legitimate verification URI breaks every login on
// every host, which is a worse outcome than the injection it was written to
// stop.
var cleanValues = []string{
	"https://github.com/login/device",
	"https://github.com/login/device?user_code=WDJB-MJHT",
	"https://ghes.corp.example:8443/login/device?user_code=WDJB-MJHT&next=%2Fhome",
	"WDJB-MJHT",
	"ABCD-1234",
	"",
	"a",                                   // one rune, nothing trailing, to catch a slicing bug
	"https://sso.example/dévice",          // non-ASCII just above the C1 block
	"code ─═ ABCD",                        // box drawing, as the template itself uses
	"visit https://example/device — ABCD", // em dash
	"\u00a0leading no-break space\u00a0",  // U+00A0 sits right after C1 and must survive
}

func TestSanitizePromptValueLeavesCleanInputUnchanged(t *testing.T) {
	for _, in := range cleanValues {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			if got := SanitizePromptValue(in); got != in {
				t.Errorf("SanitizePromptValue(%q) = %q, want it returned unchanged", in, got)
			}
		})
	}
}

func TestSanitizePromptBlockLeavesCleanInputUnchanged(t *testing.T) {
	// The block form additionally has to leave newlines alone, because it is
	// applied to the pre-rendered ASCII QR code.
	multiline := []string{"line one\nline two\n", "\n\n", "█▄\n▀█\n"}
	for _, in := range append(multiline, cleanValues...) {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			if got := SanitizePromptBlock(in); got != in {
				t.Errorf("SanitizePromptBlock(%q) = %q, want it returned unchanged", in, got)
			}
		})
	}
}

func TestSanitizePromptValueRemovesControlCharacters(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantKept    string // the printable residue, before the marker
		wantRemoved int
	}{
		{
			name:        "ANSI CSI colour sequence",
			in:          "\x1b[31mWDJB-MJHT\x1b[0m",
			wantKept:    "[31mWDJB-MJHT[0m", // inert printable text once ESC is gone
			wantRemoved: 2,
		},
		{
			name:        "ANSI cursor movement and screen clear",
			in:          "WDJB\x1b[2J\x1b[H\x1b[10;1f-MJHT",
			wantKept:    "WDJB[2J[H[10;1f-MJHT",
			wantRemoved: 3,
		},
		{
			name:        "bare ESC",
			in:          "WDJB\x1b-MJHT",
			wantKept:    "WDJB-MJHT",
			wantRemoved: 1,
		},
		{
			name:        "carriage return, which overwrites the line the user just read",
			in:          "https://real.example/device\rhttps://evil.example/device",
			wantKept:    "https://real.example/devicehttps://evil.example/device",
			wantRemoved: 1,
		},
		{
			name:        "NUL",
			in:          "WDJB\x00-MJHT",
			wantKept:    "WDJB-MJHT",
			wantRemoved: 1,
		},
		{
			name:        "DEL",
			in:          "WDJB\x7f-MJHT",
			wantKept:    "WDJB-MJHT",
			wantRemoved: 1,
		},
		{
			name:        "backspace, which rewrites what is already on screen",
			in:          "WDJB\b\b\b\bXXXX",
			wantKept:    "WDJBXXXX",
			wantRemoved: 4,
		},
		{
			name:        "tab, which shifts the column the value sits in",
			in:          "WDJB\t-MJHT",
			wantKept:    "WDJB-MJHT",
			wantRemoved: 1,
		},
		{
			// U+009B is CSI. On a terminal that honours 8-bit controls it does
			// everything ESC-[ does, in one rune, and in valid UTF-8 it arrives
			// as two bytes (0xC2 0x9B) rather than as a raw 0x9B.
			name:        "C1 runes, which are U+0080-U+009F and not raw bytes",
			in:          "WDJB\u009b31m\u0085\u009f-MJHT",
			wantKept:    "WDJB31m-MJHT",
			wantRemoved: 3,
		},
		{
			name:        "newline, which a URL and a short code never legitimately contain",
			in:          "https://evil.example/device\n\nsomething else",
			wantKept:    "https://evil.example/devicesomething else",
			wantRemoved: 2,
		},
		{
			name:        "Unicode line and paragraph separators, newlines by another name",
			in:          "WDJB\u2028-MJHT\u2029",
			wantKept:    "WDJB-MJHT",
			wantRemoved: 2,
		},
		{
			// The whole point of the finding: a hostile GitHub Enterprise
			// verification_uri that clears the screen and draws its own prompt
			// on a root pre-auth terminal.
			name:        "a plausible fake password prompt",
			in:          "https://ghes.corp.example/login/device\x1b[2J\x1b[H\x1b[1;1fPassword: \x1b[8m",
			wantKept:    "https://ghes.corp.example/login/device[2J[H[1;1fPassword: [8m",
			wantRemoved: 4,
		},
		{
			name:        "only control characters leaves nothing but the marker",
			in:          "\x1b\x1b\x00",
			wantKept:    "",
			wantRemoved: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizePromptValue(tt.in)

			assertNoDisallowedRunes(t, false, got)
			assertMarked(t, tt.in, got)

			if !strings.HasPrefix(got, tt.wantKept) {
				t.Errorf("SanitizePromptValue(%q) = %q, want it to start with the printable residue %q",
					tt.in, got, tt.wantKept)
			}
			if !strings.Contains(got, fmt.Sprintf("%d", tt.wantRemoved)) {
				t.Errorf("SanitizePromptValue(%q) = %q, want the marker to report %d removed rune(s)",
					tt.in, got, tt.wantRemoved)
			}
		})
	}
}

func TestSanitizePromptBlockRemovesEverythingButNewline(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantKept string
	}{
		{
			name:     "escape sequence between lines",
			in:       "line one\n\x1b[2Jline two\n",
			wantKept: "line one\n[2Jline two\n",
		},
		{
			name:     "C1 CSI",
			in:       "block\u009b31m\n",
			wantKept: "block31m\n",
		},
		{
			name:     "carriage return is not a newline",
			in:       "line one\r\nline two",
			wantKept: "line one\nline two",
		},
		{
			name:     "Unicode line separator is not a newline either",
			in:       "line one\u2028line two",
			wantKept: "line oneline two",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizePromptBlock(tt.in)

			assertNoDisallowedRunes(t, true, got)
			assertMarked(t, tt.in, got)

			if !strings.HasPrefix(got, tt.wantKept) {
				t.Errorf("SanitizePromptBlock(%q) = %q, want it to start with %q", tt.in, got, tt.wantKept)
			}
		})
	}
}

// TestSanitizePromptBlockLeavesARealQRCodeIntact is the guard on the qrCode
// decision. GenerateQRCode's output is block-drawing runes separated by
// newlines, so the block policy has to pass it through untouched: a sanitizer
// that stripped its newlines would collapse the QR code into one unreadable
// line for every user on every login.
func TestSanitizePromptBlockLeavesARealQRCodeIntact(t *testing.T) {
	qr, err := GenerateQRCode(testDeviceURL)
	if err != nil {
		t.Fatalf("GenerateQRCode: %v", err)
	}
	if !strings.Contains(qr, "\n") {
		t.Fatal("a QR code is expected to be multi-line; this test proves nothing otherwise")
	}

	if got := SanitizePromptBlock(qr); got != qr {
		t.Errorf("SanitizePromptBlock mangled a real QR code.\nbefore (%d bytes, %d lines):\n%s\nafter (%d bytes, %d lines):\n%s",
			len(qr), strings.Count(qr, "\n"), qr, len(got), strings.Count(got, "\n"), got)
	}
}

// TestSanitizingCannotAmplify pins the reason the sanitizer removes rather than
// escapes. The module copies the instructions into a fixed 16 KB buffer and
// strncpy truncates silently, so if sanitizing could make a value longer than it
// arrived, a provider could pad its way past the end of the prompt and cut the
// trusted trailer off the bottom. Removal plus one fixed marker cannot.
func TestSanitizingCannotAmplify(t *testing.T) {
	const markerAllowance = 64 // "[!] N control character(s) removed", plus a separator

	inputs := []string{
		strings.Repeat("\x1b", 4096),
		strings.Repeat("\u009b", 4096),
		strings.Repeat("\u2028", 4096),
		strings.Repeat("\xff", 4096),
		strings.Repeat("\x1b[31m", 512),
		hostileDeviceURL,
		hostileUserCode,
	}

	for name, sanitize := range map[string]func(string) string{
		"value": SanitizePromptValue,
		"block": SanitizePromptBlock,
	} {
		for i, in := range inputs {
			t.Run(fmt.Sprintf("%s/%d", name, i), func(t *testing.T) {
				if got := sanitize(in); len(got) > len(in)+markerAllowance {
					t.Errorf("sanitizing grew %d bytes into %d; a provider must not be able to pad the prompt past the module's buffer",
						len(in), len(got))
				}
			})
		}
	}
}

// TestSanitizeDropsMalformedUTF8 pins the byte-versus-rune question. Provider
// output is not guaranteed to be valid UTF-8, and a stray high byte must not
// survive into a prompt: it is exactly how a raw 0x9B CSI would arrive.
func TestSanitizeDropsMalformedUTF8(t *testing.T) {
	in := "WDJB\xc3-MJHT\x80\xff\x9b"

	for name, sanitize := range map[string]func(string) string{
		"value": SanitizePromptValue,
		"block": SanitizePromptBlock,
	} {
		t.Run(name, func(t *testing.T) {
			got := sanitize(in)

			if !utf8.ValidString(got) {
				t.Errorf("sanitize(%q) = %q, which is not valid UTF-8", in, got)
			}
			if strings.ContainsRune(got, utf8.RuneError) {
				t.Errorf("sanitize(%q) = %q, want malformed bytes dropped rather than replaced in place", in, got)
			}
			if !strings.HasPrefix(got, "WDJB-MJHT") {
				t.Errorf("sanitize(%q) = %q, want the valid runes kept and the malformed bytes dropped", in, got)
			}
			assertMarked(t, in, got)
		})
	}
}
