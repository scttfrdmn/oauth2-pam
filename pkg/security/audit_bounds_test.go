package security

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

// How large a record the provider gets to make the broker write — #104.
//
// The three values the broker does not choose (the provider's email and login, the
// mapper's groups, the provider's claims) are bounded on the reply and were not
// bounded on the record. Since a critical record is marshalled and fsynced on the
// login's own goroutine, and a failed write refuses the login, an unbounded record
// is not a large log line but a host that stops granting logins once its log volume
// fills.
//
// These tests measure the record, because a bound stated in constants is a claim
// about arithmetic and the thing that matters is the bytes.

// recordFor returns the bytes a sink would receive for event.
func recordFor(t *testing.T, event AuditEvent) []byte {
	t.Helper()
	sink := &capturingOutput{}
	al := loggerWithSinks(t, sink)
	if err := al.LogAuthEventErr(event); err != nil {
		t.Fatalf("LogAuthEventErr: %v", err)
	}
	if len(sink.records) != 1 {
		t.Fatalf("the sink saw %d records, want 1", len(sink.records))
	}
	return sink.records[0]
}

type capturingOutput struct {
	records [][]byte
}

func (o *capturingOutput) Write(b []byte) error {
	o.records = append(o.records, append([]byte(nil), b...))
	return nil
}

func (o *capturingOutput) Close() error { return nil }

// TestAProviderCannotChooseHowLargeAnAuditRecordIs is the regression test. The
// numbers are the ones apiGetAll and AddClaim actually permit: 2000 entries is its
// entry cap, and nothing bounds an entry's length.
func TestAProviderCannotChooseHowLargeAnAuditRecordIs(t *testing.T) {
	claims := make(map[string]interface{}, 2000)
	for i := 0; i < 2000; i++ {
		claims[fmt.Sprintf("claim_%d", i)] = strings.Repeat("x", 10*1024)
	}
	groups := make([]string, 3000)
	for i := range groups {
		groups[i] = fmt.Sprintf("group-%d-%s", i, strings.Repeat("y", 200))
	}

	record := recordFor(t, AuditEvent{
		EventType: "authentication_success",
		UserID:    "alice",
		Email:     strings.Repeat("e", 64*1024) + "@example.com",
		Groups:    groups,
		Success:   true,
		Metadata: map[string]interface{}{
			"provider_login": strings.Repeat("L", 32*1024),
			"claims":         claims,
		},
	})

	if len(record) > maxAuditRecordBytes {
		t.Errorf("the record is %d bytes, over the %d-byte cap; this is written and fsynced on the "+
			"login's goroutine, and once the volume fills every later login on the host is refused",
			len(record), maxAuditRecordBytes)
	}
	if !utf8.Valid(record) {
		t.Error("the record is not valid UTF-8; a field was cut mid-rune")
	}

	// The record has to remain the thing it exists for: an identification of the
	// access decision. A bound that dropped user_id would pass the size assertion
	// and destroy the trail.
	var got AuditEvent
	if err := json.Unmarshal(record, &got); err != nil {
		t.Fatalf("the bounded record does not parse: %v", err)
	}
	if got.UserID != "alice" {
		t.Errorf("user_id = %q, want alice: the record no longer says whose login it describes", got.UserID)
	}
	if got.EventType != "authentication_success" {
		t.Errorf("event_type = %q, want authentication_success", got.EventType)
	}
	if !got.Success {
		t.Error("success = false on a record built with Success: true")
	}
	if got.Metadata[auditTruncationKey] == nil {
		t.Error("the record lost fields and does not say so; a truncated record that reads as " +
			"complete is worse than either a complete one or a refused one")
	}
}

// TestAnOversizedGroupListIsOmittedRatherThanTruncated: the reply's rule, applied
// to the record. docs/wire-protocol.md's reason is that a truncated list is
// indistinguishable from a complete one, and whoever reads the trail to answer
// "was this user in wheel?" is exactly the client that reason is about.
func TestAnOversizedGroupListIsOmittedRatherThanTruncated(t *testing.T) {
	groups := make([]string, maxAuditGroups+1)
	for i := range groups {
		groups[i] = fmt.Sprintf("group-%d", i)
	}

	record := recordFor(t, AuditEvent{
		EventType: "authentication_success",
		UserID:    "alice",
		Groups:    groups,
	})

	var got AuditEvent
	if err := json.Unmarshal(record, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Groups) != 0 {
		t.Errorf("groups has %d of %d entries; a partial membership list reads as a complete one",
			len(got.Groups), len(groups))
	}
	note, _ := json.Marshal(got.Metadata[auditTruncationKey])
	if !strings.Contains(string(note), fmt.Sprintf("%d entries", len(groups))) {
		t.Errorf("the record does not say how many groups it dropped; note = %s", note)
	}
}

// TestAnOrdinaryEventIsRecordedByteForByte is the control, and the one that would
// catch a bound set too tight. Every field of a real authentication_success from
// broker.go has to survive verbatim — a fix that truncated ordinary emails or
// dropped ordinary group lists would destroy the trail far more thoroughly than the
// defect it was fixing.
func TestAnOrdinaryEventIsRecordedByteForByte(t *testing.T) {
	event := AuditEvent{
		EventType:  "authentication_success",
		UserID:     "alice",
		Email:      "alice@example.com",
		Groups:     []string{"wheel", "docker", "users"},
		SessionID:  "0123456789abcdef0123456789abcdef",
		Provider:   "github",
		AuthMethod: "github_device_flow",
		SourceIP:   "2001:db8::1",
		TargetHost: "login.example.edu",
		Success:    true,
		Metadata: map[string]interface{}{
			"provider_login":   "alice-gh",
			"provider_subject": "12345",
			"claims":           map[string]interface{}{"orgs": []string{"acme"}},
		},
	}

	var got AuditEvent
	if err := json.Unmarshal(recordFor(t, event), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Email != event.Email {
		t.Errorf("email = %q, want %q", got.Email, event.Email)
	}
	if strings.Join(got.Groups, ",") != strings.Join(event.Groups, ",") {
		t.Errorf("groups = %v, want %v", got.Groups, event.Groups)
	}
	if got.SessionID != event.SessionID || got.Provider != event.Provider ||
		got.AuthMethod != event.AuthMethod || got.SourceIP != event.SourceIP ||
		got.TargetHost != event.TargetHost || got.UserID != event.UserID {
		t.Errorf("a scalar field was altered on an ordinary event: %+v", got)
	}
	if got.Metadata["provider_login"] != "alice-gh" {
		t.Errorf("metadata.provider_login = %v, want alice-gh", got.Metadata["provider_login"])
	}
	if got.Metadata["claims"] == nil {
		t.Error("metadata.claims was dropped from an ordinary event")
	}
	if got.Metadata[auditTruncationKey] != nil {
		t.Errorf("an ordinary event was reported as truncated: %v", got.Metadata[auditTruncationKey])
	}
}

// TestAProducerCannotForgeTheTruncationNote. The note is what tells an investigator
// the record is incomplete, so a producer that could set it could also set it to
// something reassuring. It is a reserved key.
func TestAProducerCannotForgeTheTruncationNote(t *testing.T) {
	record := recordFor(t, AuditEvent{
		EventType: "authentication_success",
		UserID:    "alice",
		Email:     strings.Repeat("e", 8*1024),
		Metadata: map[string]interface{}{
			auditTruncationKey: "nothing was truncated, everything is fine",
		},
	})

	var got AuditEvent
	if err := json.Unmarshal(record, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	note, _ := json.Marshal(got.Metadata[auditTruncationKey])
	if strings.Contains(string(note), "everything is fine") {
		t.Errorf("a producer's own value survived under the reserved key: %s", note)
	}
	if !strings.Contains(string(note), "email") {
		t.Errorf("the note does not mention the field that was actually truncated: %s", note)
	}
}

// TestBoundingDoesNotBreakTheLandingContract: the bound runs before the
// critical/queued split, so it is upstream of everything #91 and #94 established
// about what an error means. A record that was bounded is still written, and a sink
// that refuses it must still report that honestly.
func TestBoundingDoesNotBreakTheLandingContract(t *testing.T) {
	al, err := NewAuditLoggerWithOutputs(config.AuditConfig{Enabled: true},
		&refusingOutput{err: fmt.Errorf("no space left on device")})
	if err != nil {
		t.Fatalf("NewAuditLoggerWithOutputs: %v", err)
	}
	t.Cleanup(func() { _ = al.Stop() })

	writeErr := al.LogAuthEventErr(AuditEvent{
		EventType: "authentication_success",
		UserID:    "alice",
		Email:     strings.Repeat("e", 128*1024),
		Success:   true,
	})
	if writeErr == nil {
		t.Fatal("a bounded record that no sink accepted was reported as written")
	}
	if RecordMayHaveLanded(writeErr) {
		t.Errorf("err = %v claims the record may be readable; the sink reported taking none of it",
			writeErr)
	}
}

// TestTruncationNeverSplitsARune. json.Marshal answers invalid UTF-8 by
// substituting U+FFFD, so a bound that cut mid-rune would silently edit a field
// that is recorded precisely so it can be read back verbatim.
func TestTruncationNeverSplitsARune(t *testing.T) {
	// A 3-byte rune repeated, so that a naive cut at any byte offset not divisible by
	// three lands inside one.
	for _, pad := range []int{0, 1, 2} {
		email := strings.Repeat("a", pad) + strings.Repeat("→", maxAuditStringBytes)
		record := recordFor(t, AuditEvent{
			EventType: "authentication_success",
			UserID:    "alice",
			Email:     email,
		})
		if !utf8.Valid(record) {
			t.Errorf("pad %d: the record is not valid UTF-8", pad)
		}
		var got AuditEvent
		if err := json.Unmarshal(record, &got); err != nil {
			t.Fatalf("pad %d: unmarshal: %v", pad, err)
		}
		if strings.ContainsRune(got.Email, '�') {
			t.Errorf("pad %d: the truncated email contains U+FFFD, so a rune was split and "+
				"json.Marshal replaced it", pad)
		}
	}
}
