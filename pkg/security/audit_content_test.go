package security

import (
	"bytes"
	"encoding/json"
	"strconv"
	"testing"
	"unicode/utf8"
)

// #111: the audit record was bounded in length and unfiltered in content. A
// provider-chosen string carrying U+009B CSI, or a bare DEL, reached the audit
// file — which cat, tail and grep decode verbatim — as a live escape, because
// boundEvent truncated and never filtered a rune, and encoding/json leaves DEL and
// the whole C1 range raw.
//
// This asserts on the marshalled BYTES, not on the struct, because the escaping is
// what decides what the bytes are — asserting on the struct would be #105's
// tautology, a test restating the transform it is meant to check. A control test
// below proves the same scan fires on an unbounded record, so a bounded record
// passing is a real result rather than a scan that matches nothing.

// hostileAudit is a string of runes the terminal policy forbids: NUL, ESC + a CSI
// sequence, DEL, U+009B (CSI as one C1 rune) + its own sequence, NEL (C1), the line
// and paragraph separators, and a trailing lone 0x9b byte — not valid UTF-8, and a
// raw CSI to a terminal reading bytes. Written with Go escapes only; no literal
// control byte lives in this source.
const hostileAudit = "a\x00\x1b[2Jb\x7fc\u009b2Kd\u0085e\u2028f\u2029g\x9b"

// terminalUnsafeBytes reports the byte offsets in data that a terminal decoding
// UTF-8 would act on: DEL, a raw C0 other than the whitespace a text file
// legitimately holds, a C1 control (U+0080–U+009F, i.e. 0xC2 followed by
// 0x80–0x9F), and the line/paragraph separators (U+2028/U+2029, i.e. 0xE2 0x80
// 0xA8/0xA9). C0 and the separators are things encoding/json escapes on its own;
// they are checked anyway, because the guarantee is about the bytes on disk, not
// about which layer is trusted to have produced them.
func terminalUnsafeBytes(data []byte) []string {
	var found []string
	for i := 0; i < len(data); i++ {
		switch {
		case data[i] == 0x7f:
			found = append(found, "DEL at "+strconv.Itoa(i))
		case data[i] < 0x20 && data[i] != '\n' && data[i] != '\t' && data[i] != '\r':
			found = append(found, "C0 at "+strconv.Itoa(i))
		case data[i] == 0xc2 && i+1 < len(data) && data[i+1] >= 0x80 && data[i+1] <= 0x9f:
			found = append(found, "C1 at "+strconv.Itoa(i))
		case data[i] == 0xe2 && i+2 < len(data) && data[i+1] == 0x80 &&
			(data[i+2] == 0xa8 || data[i+2] == 0xa9):
			found = append(found, "U+2028/9 at "+strconv.Itoa(i))
		}
	}
	return found
}

// fullyHostileEvent puts hostileAudit in every string the record carries: the
// scalars, a group, a plain metadata string, and inside a claims map as both a key
// and a value, so a field added later that is not escaped shows up here.
func fullyHostileEvent() AuditEvent {
	return AuditEvent{
		EventType:    "authentication_success",
		EventID:      "evt-" + hostileAudit,
		UserID:       "alice" + hostileAudit,
		Email:        "alice" + hostileAudit + "@example.com",
		SourceIP:     "10.0.0.1",
		TargetHost:   "host" + hostileAudit,
		SessionID:    "sess" + hostileAudit,
		Provider:     "acme" + hostileAudit,
		AuthMethod:   "github_device_flow",
		ErrorMessage: "provider said: " + hostileAudit,
		ErrorCode:    "X" + hostileAudit,
		Groups:       []string{"wheel" + hostileAudit, "docker"},
		Metadata: map[string]interface{}{
			"provider_login": "octocat" + hostileAudit,
			"claims": map[string][]string{
				"org" + hostileAudit: {"acme" + hostileAudit, "beta"},
			},
		},
	}
}

func TestBoundEventLeavesNoTerminalEscapeInTheMarshalledRecord(t *testing.T) {
	data, err := json.Marshal(boundEvent(fullyHostileEvent()))
	if err != nil {
		t.Fatalf("marshal bounded event: %v", err)
	}
	if bad := terminalUnsafeBytes(data); len(bad) != 0 {
		t.Errorf("bounded record still carries terminal-unsafe bytes: %v\nrecord: %s", bad, data)
	}
	if !utf8.Valid(data) {
		t.Errorf("bounded record is not valid UTF-8")
	}
	// The escape has to be reversible, not a silent drop: the CSI has to be findable
	// as text so an investigator sees what the provider sent.
	if !bytes.Contains(data, []byte(`\u009b`)) {
		t.Errorf("bounded record does not contain the escaped form \\u009b; the CSI was dropped, not escaped\nrecord: %s", data)
	}
}

// The control. If terminalUnsafeBytes cannot find the raw escapes in a record that
// was never bounded, the test above passes for the wrong reason.
func TestTheContentScanFindsEscapesInAnUnboundedRecord(t *testing.T) {
	data, err := json.Marshal(fullyHostileEvent())
	if err != nil {
		t.Fatalf("marshal raw event: %v", err)
	}
	if bad := terminalUnsafeBytes(data); len(bad) == 0 {
		t.Fatalf("the scan found nothing terminal-unsafe in a record built from raw C1 and DEL, "+
			"so it is not checking what it is meant to\nrecord: %s", data)
	}
}
