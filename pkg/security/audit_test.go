package security

import (
	"bufio"
	"context"
	"encoding/json"
	"log/syslog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

// fileLogger returns a started AuditLogger writing to a temp file, plus a
// function that stops it and returns the events it wrote.
func fileLogger(t *testing.T, cfg config.AuditConfig) (*AuditLogger, func() []AuditEvent) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "audit.log")
	cfg.Enabled = true
	cfg.Outputs = []config.AuditOutput{{Type: "file", Path: path}}

	al, err := NewAuditLogger(cfg)
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	if err := al.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = al.Stop()
		}
	})

	return al, func() []AuditEvent {
		// Stop drains the queue, so everything logged before it is on disk.
		if err := al.Stop(); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		stopped = true
		return readEvents(t, path)
	}
}

func readEvents(t *testing.T, path string) []AuditEvent {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer func() { _ = f.Close() }()

	var events []AuditEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e AuditEvent
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("audit line is not valid JSON: %v (%q)", err, line)
		}
		events = append(events, e)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan audit log: %v", err)
	}
	return events
}

func TestFileOutputWritesJSONLines(t *testing.T) {
	al, collect := fileLogger(t, config.AuditConfig{})

	al.LogAuthEvent(AuditEvent{
		EventType: "authentication_success",
		UserID:    "alice",
		SessionID: "sess-1",
		Provider:  "github",
		Success:   true,
		Metadata:  map[string]interface{}{"github_login": "alice-gh"},
	})
	al.LogAuthEvent(AuditEvent{EventType: "session_revoked", UserID: "alice", Success: true})

	events := collect()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}

	first := events[0]
	if first.EventType != "authentication_success" || first.UserID != "alice" {
		t.Errorf("event = %+v", first)
	}
	if !first.Success {
		t.Error("Success was not preserved")
	}
	if first.Metadata["github_login"] != "alice-gh" {
		t.Errorf("Metadata = %v", first.Metadata)
	}
	// Both are filled in by the logger when the caller leaves them unset.
	if first.Timestamp.IsZero() {
		t.Error("Timestamp was not stamped")
	}
	if first.EventID == "" {
		t.Error("EventID was not assigned")
	}
}

func TestAuditFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	al, err := NewAuditLogger(config.AuditConfig{
		Enabled: true,
		Outputs: []config.AuditOutput{{Type: "file", Path: path}},
	})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = al.Stop() }()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// The trail records who logged in from where; it is not public.
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("mode = %04o, want 0600", perm)
	}
}

// TestEventAllowlistFilters is the point of audit.events: types outside the
// list are dropped, and the drop is counted rather than silent.
func TestEventAllowlistFilters(t *testing.T) {
	al, collect := fileLogger(t, config.AuditConfig{
		Events: []string{"authentication_success", "authentication_denied"},
	})

	al.LogAuthEvent(AuditEvent{EventType: "authentication_success", UserID: "alice"})
	al.LogAuthEvent(AuditEvent{EventType: "authentication_attempt", UserID: "alice"}) // filtered
	al.LogAuthEvent(AuditEvent{EventType: "authentication_denied", UserID: "bob"})
	al.LogAuthEvent(AuditEvent{EventType: "session_revoked", UserID: "alice"}) // filtered

	if got := al.FilteredEvents(); got != 2 {
		t.Errorf("FilteredEvents = %d, want 2", got)
	}

	events := collect()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	for _, e := range events {
		if e.EventType != "authentication_success" && e.EventType != "authentication_denied" {
			t.Errorf("event type %q was written despite not being allowlisted", e.EventType)
		}
	}
}

// TestEmptyAllowlistLogsEverything: an empty list must mean "no filter", not
// "discard the entire audit trail".
func TestEmptyAllowlistLogsEverything(t *testing.T) {
	al, collect := fileLogger(t, config.AuditConfig{Events: nil})

	for _, et := range config.KnownAuditEvents {
		al.LogAuthEvent(AuditEvent{EventType: et, UserID: "alice"})
	}

	if got := al.FilteredEvents(); got != 0 {
		t.Errorf("FilteredEvents = %d, want 0 with no filter configured", got)
	}
	if events := collect(); len(events) != len(config.KnownAuditEvents) {
		t.Errorf("got %d events, want all %d", len(events), len(config.KnownAuditEvents))
	}
}

func TestEveryKnownEventTypePassesTheDefaultFilter(t *testing.T) {
	filter := buildEventFilter(config.KnownAuditEvents)
	if filter == nil {
		t.Fatal("buildEventFilter returned nil for a non-empty list")
	}
	for _, et := range config.KnownAuditEvents {
		if _, ok := filter[et]; !ok {
			t.Errorf("%q is not admitted by the default filter", et)
		}
	}
}

// TestDisabledLoggerIsInert: with audit.enabled false, nothing is queued and
// Start/Stop are no-ops — importantly without touching the nil channel.
func TestDisabledLoggerIsInert(t *testing.T) {
	al, err := NewAuditLogger(config.AuditConfig{Enabled: false})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	if err := al.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	al.LogAuthEvent(AuditEvent{EventType: "authentication_success"})
	if err := al.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if got := al.DroppedEvents(); got != 0 {
		t.Errorf("DroppedEvents = %d, want 0", got)
	}
	if got := al.FilteredEvents(); got != 0 {
		t.Errorf("FilteredEvents = %d, want 0", got)
	}
}

// TestFullChannelDropsAreCounted: the queue is bounded, so under a flood the
// logger sheds events. It must count them, so an operator can tell a quiet log
// from a lost one.
func TestFullChannelDropsAreCounted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	al, err := NewAuditLogger(config.AuditConfig{
		Enabled: true,
		Outputs: []config.AuditOutput{{Type: "file", Path: path}},
	})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	// Deliberately not started: nothing drains the channel, so the queue fills
	// deterministically at its 1000-event capacity.
	defer func() { _ = al.Stop() }()

	const queued = 1005
	for i := 0; i < queued; i++ {
		al.LogAuthEvent(AuditEvent{EventType: "authentication_attempt", UserID: "alice"})
	}

	if got := al.DroppedEvents(); got != queued-1000 {
		t.Errorf("DroppedEvents = %d, want %d", got, queued-1000)
	}
}

// TestCriticalEventsAreWrittenSynchronously covers the reason
// criticalAuditEvents exists: an access decision must be on disk when
// LogAuthEvent returns, not sitting in a queue that a crash or a full channel can
// discard. The logger here is deliberately never started, so nothing drains the
// channel — anything that reaches disk did so on the calling goroutine.
func TestCriticalEventsAreWrittenSynchronously(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	al, err := NewAuditLogger(config.AuditConfig{
		Enabled: true,
		Outputs: []config.AuditOutput{{Type: "file", Path: path}},
	})
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}
	defer func() { _ = al.Stop() }()

	// Fill the queue past capacity, so a queued event would certainly be dropped.
	for i := 0; i < 1100; i++ {
		al.LogAuthEvent(AuditEvent{EventType: "authentication_attempt", UserID: "alice"})
	}
	if al.DroppedEvents() == 0 {
		t.Fatal("test premise broken: the queue did not overflow")
	}

	for eventType := range criticalAuditEvents {
		al.LogAuthEvent(AuditEvent{EventType: eventType, UserID: "alice"})
	}

	written := make(map[string]bool)
	for _, e := range readEvents(t, path) {
		written[e.EventType] = true
	}
	for eventType := range criticalAuditEvents {
		if !written[eventType] {
			t.Errorf("%s was not on disk when LogAuthEvent returned", eventType)
		}
	}
	if written["authentication_attempt"] {
		t.Error("authentication_attempt was written synchronously; it is the high-volume event the queue exists for")
	}
}

// TestCriticalEventsStillRespectTheAllowlist guards against the synchronous path
// becoming a way around audit.events.
func TestCriticalEventsStillRespectTheAllowlist(t *testing.T) {
	al, collect := fileLogger(t, config.AuditConfig{Events: []string{"authentication_attempt"}})

	al.LogAuthEvent(AuditEvent{EventType: "authentication_success", UserID: "alice"})

	if events := collect(); len(events) != 0 {
		t.Errorf("got %d events, want 0: a filtered critical event was written anyway", len(events))
	}
	if got := al.FilteredEvents(); got != 1 {
		t.Errorf("FilteredEvents = %d, want 1", got)
	}
}

func TestStopFlushesQueuedEvents(t *testing.T) {
	al, collect := fileLogger(t, config.AuditConfig{})

	for i := 0; i < 50; i++ {
		al.LogAuthEvent(AuditEvent{EventType: "authentication_attempt", UserID: "alice"})
	}

	// No sleep: Stop must drain rather than race the dispatcher.
	if events := collect(); len(events) != 50 {
		t.Errorf("got %d events after Stop, want 50; queued events were lost on shutdown", len(events))
	}
}

// An unknown type must be refused, not quietly turned into stdout. The old
// fallback meant `type: fille` produced a broker that started clean and wrote its
// audit trail to the journal instead of the configured file.
func TestUnknownOutputTypeIsRejected(t *testing.T) {
	if _, err := newAuditOutput(config.AuditOutput{Type: "carrier-pigeon"}); err == nil {
		t.Error("newAuditOutput accepted an unknown type; the audit trail would silently go to stdout")
	}

	_, err := NewAuditLogger(config.AuditConfig{
		Enabled: true,
		Outputs: []config.AuditOutput{{Type: "carrier-pigeon"}},
	})
	if err == nil {
		t.Error("NewAuditLogger accepted an unknown output type")
	}
}

// TestSyslogOutputConnects covers the part that can fail on a real host: the
// dial. It writes nothing, so a developer's auth.log does not fill with test
// records. It skips where there is no syslog daemon — a container, usually —
// rather than failing, because the absence of one is a property of the machine
// and not of this code.
func TestSyslogOutputConnects(t *testing.T) {
	out, err := newSyslogOutput(config.AuditOutput{Type: "syslog", Facility: "local7", Severity: "debug"})
	if err != nil {
		t.Skipf("no syslog daemon reachable: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestSyslogPriority(t *testing.T) {
	// Defaults: auth.info, so audit records land beside sshd's own.
	pri, err := syslogPriority("", "")
	if err != nil {
		t.Fatalf("syslogPriority: %v", err)
	}
	if want := syslog.LOG_AUTH | syslog.LOG_INFO; pri != want {
		t.Errorf("default priority = %d, want %d (auth.info)", pri, want)
	}

	pri, err = syslogPriority("LOCAL3", "Warning")
	if err != nil {
		t.Fatalf("syslogPriority: %v", err)
	}
	if want := syslog.LOG_LOCAL3 | syslog.LOG_WARNING; pri != want {
		t.Errorf("local3.warning = %d, want %d; names must be case-insensitive", pri, want)
	}

	// A typo is a startup error, not a record logged somewhere unexpected.
	if _, err := syslogPriority("athu", ""); err == nil {
		t.Error("syslogPriority accepted a misspelled facility")
	}
	if _, err := syslogPriority("", "verbose"); err == nil {
		t.Error("syslogPriority accepted an unknown severity")
	}
}

func TestFileOutputOnUnwritablePathFails(t *testing.T) {
	_, err := NewAuditLogger(config.AuditConfig{
		Enabled: true,
		Outputs: []config.AuditOutput{{Type: "file", Path: filepath.Join(t.TempDir(), "no-such-dir", "audit.log")}},
	})
	if err == nil {
		t.Error("NewAuditLogger accepted an unwritable audit path; the broker would start with no audit trail")
	}
}

func TestTimestampIsPreservedWhenSupplied(t *testing.T) {
	al, collect := fileLogger(t, config.AuditConfig{})

	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	al.LogAuthEvent(AuditEvent{EventType: "authentication_success", Timestamp: ts})

	events := collect()
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if !events[0].Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %s, want the supplied %s", events[0].Timestamp, ts)
	}
}
