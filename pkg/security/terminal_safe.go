package security

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// DisallowedTerminalRune reports whether r is a control character that must not
// reach a terminal decoding UTF-8 verbatim: C0 (NUL through US, including LF, CR,
// TAB and ESC), DEL, C1 (U+0080–U+009F, where U+009B CSI lives), and the Unicode
// line and paragraph separators.
//
// This is the one policy #105 unified across the broker's prompt and its reply;
// #111 brought the audit record under it too. Both pkg/auth/sanitize.go's prompt
// filter and boundEvent's audit escaper ask this function, so "which runes are
// dangerous" is decided in exactly one place — the round-8 lesson was a reply
// filter that kept its own narrower copy of the rule and a test that could not
// notice.
//
// What the two callers DO with a dangerous rune differs, deliberately. The prompt
// removes it, because the module copies the instructions into a fixed 16 KiB
// buffer and an escape that expanded length could push the trailing template off
// the end. The audit record escapes it to a printable \uXXXX, because a record
// exists to be read back and evidence of exactly what a provider sent is the whole
// point of keeping it. Same policy on which runes are unsafe; different remedy for
// the two media.
func DisallowedTerminalRune(r rune) bool {
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

// escapeTerminalUnsafe returns s with every DisallowedTerminalRune rewritten as a
// printable \uXXXX escape, and every byte that is not valid UTF-8 as \xXX, and
// reports whether it changed anything.
//
// It is walked by rune, not by byte, because in valid UTF-8 a C1 control is two
// bytes (U+009B is 0xC2 0x9B) and a byte-wise filter would miss it — the same
// reasoning as sanitizeForPrompt. A clean string is returned byte-for-byte via the
// fast path, so a value that needs no escaping is unchanged; a hostile one is
// rendered inert without losing what it was, which is why the record escapes where
// the prompt removes.
//
// Note this is applied before json.Marshal, which then escapes the backslash — so
// a C1 lands in the file as the six ASCII characters of a JSON \u009b and
// reads back as text, never as a live CSI. encoding/json already escapes C0 and
// U+2028/U+2029, and leaves DEL and C1 raw; escaping the whole disallowed set here
// rather than only the two json misses keeps this function the single policy
// rather than a patch over json's specific gaps.
func escapeTerminalUnsafe(s string) (string, bool) {
	// Fast path: the value is clean and must come back exactly as it arrived.
	if utf8.ValidString(s) && !strings.ContainsFunc(s, DisallowedTerminalRune) {
		return s, false
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
		case DisallowedTerminalRune(r):
			fmt.Fprintf(&b, `\u%04x`, r)
			i += size
		default:
			b.WriteString(s[i : i+size])
			i += size
		}
	}
	return b.String(), true
}

// escapeAuditValue recursively neutralizes terminal-unsafe runes in a metadata
// value, whose static type is interface{} and whose real type may be a string, a
// list, or a claims map of provider-chosen names and values.
//
// It handles the concrete shapes a producer builds (broker.go) and the shapes an
// interface{} takes after a JSON round trip, and passes numbers, bools and nil
// through untouched. Map keys are escaped as well as values: a claim name is
// provider-chosen too, and audit.go marshals it as a JSON object key that lands on
// the same console.
func escapeAuditValue(v interface{}) (interface{}, bool) {
	switch t := v.(type) {
	case string:
		return escapeTerminalUnsafe(t)
	case []string:
		out := make([]string, len(t))
		changed := false
		for i, s := range t {
			e, c := escapeTerminalUnsafe(s)
			out[i], changed = e, changed || c
		}
		return out, changed
	case []interface{}:
		out := make([]interface{}, len(t))
		changed := false
		for i, e := range t {
			ev, c := escapeAuditValue(e)
			out[i], changed = ev, changed || c
		}
		return out, changed
	case map[string][]string:
		out := make(map[string][]string, len(t))
		changed := false
		for k, vs := range t {
			ek, ck := escapeTerminalUnsafe(k)
			evs, cv := escapeAuditValue(vs)
			out[ek], changed = evs.([]string), changed || ck || cv
		}
		return out, changed
	case map[string]string:
		out := make(map[string]string, len(t))
		changed := false
		for k, s := range t {
			ek, ck := escapeTerminalUnsafe(k)
			es, cs := escapeTerminalUnsafe(s)
			out[ek], changed = es, changed || ck || cs
		}
		return out, changed
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		changed := false
		for k, e := range t {
			ek, ck := escapeTerminalUnsafe(k)
			ev, cv := escapeAuditValue(e)
			out[ek], changed = ev, changed || ck || cv
		}
		return out, changed
	default:
		return v, false
	}
}
