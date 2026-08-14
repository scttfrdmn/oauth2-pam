package auth

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Provider-supplied strings end up on a terminal that nobody has authenticated
// to yet. The broker hands the device-flow instructions to the PAM module over
// IPC, and the module prints them with the conversation function while running
// as root, before it knows who is logging in. Neither side filters them: the C
// bridge bounds the length and nothing else.
//
// For github.com that is academic. For a configured GitHub Enterprise base_url
// it is not: that server picks verification_uri and user_code, so whoever runs
// it can put arbitrary bytes on the pre-auth terminal of every host configured
// against it. A GHES operator is already trusted to decide who gets in; being
// able to home the cursor, hide text, and draw a convincing password prompt over
// the real one is a different and much larger capability, and there is no reason
// to hand it over.
//
// Two policies, because the instruction text has two kinds of content:
//
//   - SanitizePromptValue for the untrusted values a provider chooses (the
//     verification URI, the user code). A URL and a short code are single-line
//     by definition — RFC 8628 has no notion of a multi-line verification_uri —
//     so newline is removed along with everything else. This is deliberately
//     stricter than the issue's "everything other than \n": a value that can
//     emit a newline can start a line of its own, and a line of its own is what
//     makes a fake prompt convincing. Confined to the middle of a template
//     line, injected text reads as the garbage it is.
//
//   - SanitizePromptBlock for text whose newlines are structural, which in
//     practice means the ASCII QR code. It keeps \n and removes everything else.
//
// The trusted template in qr_code.go is not sanitized at all: it is a constant
// in this repository, its newlines are the layout, and running it through a
// sanitizer would only make the layout depend on the sanitizer.
//
// Removing rather than escaping is a size decision. The module copies the
// instructions into a fixed 16 KB buffer and strncpy truncates silently, so a
// sanitizer that expanded ESC into a six-character escape would let a provider
// amplify its way past the end of the prompt and cut off the trailing template.
// Removal can only shrink. To keep removal from being silent, a value that lost
// anything carries a marker saying so — an operator debugging a URL that does
// not work needs to be able to tell tampering from a typo, and a user staring at
// a login prompt needs a reason to be suspicious of what is above it.
//
// Note what is *not* filtered: bidirectional controls, zero-width joiners and
// other confusables are left alone. They cannot move a cursor or hide a line,
// they are legitimate in real text, and a deny-list that reached for them would
// start breaking non-Latin values for no security gain.

// sanitizeNote is the marker appended to a value the sanitizer had to alter.
// It is plain ASCII so that it renders on a serial console and inside a GUI
// login dialog, not just in a UTF-8 terminal emulator.
const sanitizeNote = "[!] %d control character(s) removed"

// SanitizePromptValue makes a provider-supplied single-line value safe to print
// on a terminal. It removes every C0 control character (including newline, CR,
// tab and ESC), DEL, every C1 control (U+0080-U+009F, which is where U+009B CSI
// lives), and the Unicode line and paragraph separators, and it drops bytes that
// are not valid UTF-8. Clean input is returned unchanged; input that lost
// anything gains a visible note saying how much.
func SanitizePromptValue(s string) string {
	return sanitizeForPrompt(s, false)
}

// SanitizePromptBlock is SanitizePromptValue for pre-rendered multi-line text,
// such as the ASCII QR code from GenerateQRCode: it keeps '\n', because those
// newlines are the layout, and removes everything else SanitizePromptValue
// removes. Passing the QR code through here is defence in depth rather than a
// fix for a known path — go-qrcode's ToSmallString emits only block-drawing
// runes and newlines whatever URL it encodes — and it is safe precisely because
// keeping '\n' leaves that output untouched.
func SanitizePromptBlock(s string) string {
	return sanitizeForPrompt(s, true)
}

// isDisallowedInPrompt reports whether r must not reach a pre-auth terminal.
// Newline is handled by the caller, which knows whether it is structural.
func isDisallowedInPrompt(r rune) bool {
	switch {
	case r < 0x20: // C0: NUL, BS, TAB, LF, CR, ESC and friends
		return true
	case r == 0x7f: // DEL
		return true
	case r >= 0x80 && r <= 0x9f: // C1, e.g. U+0085 NEL and U+009B CSI
		return true
	case r == '\u2028', r == '\u2029': // LINE and PARAGRAPH SEPARATOR
		return true
	default:
		return false
	}
}

// sanitizeForPrompt walks s by rune, not by byte, because in valid UTF-8 a C1
// control is two bytes (U+009B is 0xC2 0x9B) and a byte-wise filter would miss
// it. Bytes that do not decode are dropped rather than replaced in place: a
// stray 0x9B is a raw CSI to a terminal reading bytes, and turning it into
// U+FFFD would hide the fact that the provider sent something malformed, which
// the marker is there to surface.
func sanitizeForPrompt(s string, allowNewline bool) string {
	var b strings.Builder
	removed := 0

	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		start := i
		i += size

		switch {
		case r == utf8.RuneError && size == 1: // not valid UTF-8
			removed++
		case r == '\n' && allowNewline:
			b.WriteByte('\n')
		case isDisallowedInPrompt(r):
			removed++
		default:
			// Copy the original bytes rather than re-encoding the rune, so a
			// value that needs no sanitizing is returned byte-for-byte.
			b.WriteString(s[start:i])
		}
	}

	if removed == 0 {
		return s
	}

	note := fmt.Sprintf(sanitizeNote, removed)
	out := b.String()
	if !allowNewline {
		return out + " " + note
	}
	// In block context the note belongs on a line of its own, or it would be
	// read as part of the last row of the QR code.
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out + note
}
