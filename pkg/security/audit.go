package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

// AuditEvent represents a security audit event.
type AuditEvent struct {
	Timestamp    time.Time              `json:"timestamp"`
	EventID      string                 `json:"event_id"`
	EventType    string                 `json:"event_type"`
	UserID       string                 `json:"user_id"`
	Email        string                 `json:"email,omitempty"`
	Groups       []string               `json:"groups,omitempty"`
	SourceIP     string                 `json:"source_ip,omitempty"`
	TargetHost   string                 `json:"target_host,omitempty"`
	SessionID    string                 `json:"session_id,omitempty"`
	Provider     string                 `json:"provider,omitempty"`
	AuthMethod   string                 `json:"auth_method,omitempty"`
	Success      bool                   `json:"success"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	ErrorCode    string                 `json:"error_code,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// AuditOutput is the interface implemented by all audit output sinks.
// Write receives a pre-marshaled JSON line (no trailing newline).
type AuditOutput interface {
	Write(data []byte) error
	Close() error
}

// AuditLogger manages async audit event dispatch to one or more outputs.
type AuditLogger struct {
	config config.AuditConfig
	// enabledEvents is the audit.events allowlist. A nil map means "no filter
	// configured", which allows every event — an empty allowlist that silently
	// discarded the entire audit trail would be a trap. criticalAuditEvents are
	// exempt however it is set, for the same reason.
	enabledEvents map[string]struct{}
	outputs       []AuditOutput
	// writeMu serializes writes to the outputs. Critical events are written on the
	// caller's goroutine (see criticalAuditEvents) while the dispatcher may be
	// writing a queued one, and Stop closes the sinks underneath both.
	writeMu sync.Mutex
	// stalledOn names the write that overran auditWriteTimeout and has not come
	// back, or is nil if none has. While it is set and that write is still running,
	// writeEvent refuses immediately rather than queueing behind a mutex held by a
	// goroutine stuck in an fsync. See sinksStalled and writeEvent.
	stalledOn atomic.Pointer[writeToken]
	// testWriteTimeout overrides auditWriteTimeout. Only tests set it — a stalled
	// sink is otherwise untestable in reasonable time, since the honest version of
	// the test has to wait out the deadline.
	testWriteTimeout time.Duration
	eventChan        chan AuditEvent
	stopChan         chan struct{}
	wg               sync.WaitGroup
	droppedCount     atomic.Uint64
	filteredCount    atomic.Uint64
}

// FilteredEvents returns the number of events not written because their type
// was absent from the audit.events allowlist. No access decision is ever counted
// here; those are not filterable.
func (al *AuditLogger) FilteredEvents() uint64 {
	return al.filteredCount.Load()
}

// DroppedEvents returns the number of audit events dropped due to a full channel.
func (al *AuditLogger) DroppedEvents() uint64 {
	return al.droppedCount.Load()
}

// NewAuditLogger creates a new AuditLogger.
func NewAuditLogger(cfg config.AuditConfig) (*AuditLogger, error) {
	if !cfg.Enabled {
		return &AuditLogger{config: cfg}, nil
	}

	var outputs []AuditOutput
	for i, oc := range cfg.Outputs {
		out, err := newAuditOutput(oc)
		if err != nil {
			// Close what is already open: this error fails broker startup, and
			// nothing else holds a reference to these sinks.
			for _, o := range outputs {
				_ = o.Close()
			}
			return nil, fmt.Errorf("audit.outputs[%d]: %w", i, err)
		}
		outputs = append(outputs, out)
	}

	// Default to stdout if no outputs configured
	if len(outputs) == 0 {
		outputs = append(outputs, &stdoutOutput{})
	}

	return &AuditLogger{
		config:        cfg,
		enabledEvents: buildEventFilter(cfg.Events),
		outputs:       outputs,
		eventChan:     make(chan AuditEvent, 1000),
		stopChan:      make(chan struct{}),
	}, nil
}

// NewAuditLoggerWithOutputs creates an AuditLogger that writes to sinks the caller
// supplies, instead of to the ones audit.outputs describes. cfg still supplies the
// event allowlist; it must have Enabled set, and at least one output is required,
// because a logger with neither would discard everything in silence.
//
// It exists for the reason auth.NewBrokerWithProviders exists: the behaviour worth
// testing here is what a *caller* does when an access decision cannot be written
// down, and no audit.outputs value can express a sink that fails. Every output type
// the config can name either works, or fails when the logger is constructed and so
// never reaches a caller at all. A broker that must fail a login when the audit
// record does not land needs a sink that accepts the logger and then refuses the
// write.
func NewAuditLoggerWithOutputs(cfg config.AuditConfig, outputs ...AuditOutput) (*AuditLogger, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("audit logger with explicit outputs requires audit.enabled")
	}
	if len(outputs) == 0 {
		return nil, fmt.Errorf("at least one audit output is required")
	}
	return &AuditLogger{
		config:        cfg,
		enabledEvents: buildEventFilter(cfg.Events),
		outputs:       outputs,
		eventChan:     make(chan AuditEvent, 1000),
		stopChan:      make(chan struct{}),
	}, nil
}

// buildEventFilter turns the configured event list into a lookup set, or nil
// when no list is configured (meaning: log everything).
func buildEventFilter(events []string) map[string]struct{} {
	if len(events) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(events))
	for _, e := range events {
		set[e] = struct{}{}
	}
	return set
}

// Start starts the audit logger background dispatcher.
func (al *AuditLogger) Start(ctx context.Context) error {
	if !al.config.Enabled {
		return nil
	}
	al.wg.Add(1)
	go al.processEvents(ctx)
	return nil
}

// Stop flushes pending events and shuts down the audit logger.
func (al *AuditLogger) Stop() error {
	if !al.config.Enabled {
		return nil
	}
	close(al.stopChan)
	al.wg.Wait()
	al.writeMu.Lock()
	defer al.writeMu.Unlock()
	for _, out := range al.outputs {
		_ = out.Close()
	}
	return nil
}

// criticalAuditEvents are the events that record an access decision. They are
// written on the calling goroutine rather than queued, so they cannot be lost to
// a full channel or to the process dying with events still buffered, and they are
// not subject to the audit.events allowlist.
//
// The buffered channel is the right default for volume — a flood of attempts must
// not slow authentication down — but it is the wrong default for the handful of
// events that answer "was this login allowed, and for whom". Those are the ones
// an incident is reconstructed from, and dropping one silently means the audit
// trail is missing exactly the record that mattered.
//
// authentication_attempt is deliberately not here: it is the high-volume event,
// and it is the one the buffer exists for.
var criticalAuditEvents = map[string]struct{}{
	"authentication_success": {},
	"authentication_failed":  {},
	"authentication_denied":  {},
	"session_revoked":        {},
}

// LogAuthEvent records an audit event, reporting a failure to write a critical one
// to the log and nowhere else. It is LogAuthEventErr for callers that have nothing
// to do with the error; prefer LogAuthEventErr on any path that grants access,
// where "the decision was not recorded" is a fact the decision should turn on.
func (al *AuditLogger) LogAuthEvent(event AuditEvent) {
	if err := al.LogAuthEventErr(event); err != nil {
		log.Error().Err(err).Str("event_type", event.EventType).
			Msg("Audit record of an access decision was not written")
	}
}

// LogAuthEventErr records an audit event and returns the error from writing a
// critical one.
//
// Access decisions (criticalAuditEvents) are written synchronously and are not
// filterable. Everything else is checked against the audit.events allowlist,
// counted if it is discarded, and otherwise queued for the background dispatcher,
// where it may still be dropped if the queue is full.
//
// A returned error therefore means one thing: an event recording an access
// decision reached none of its sinks. Queued events return nil — they have not
// been written yet.
func (al *AuditLogger) LogAuthEventErr(event AuditEvent) error {
	if !al.config.Enabled {
		return nil
	}

	// The allowlist is applied after this lookup, not before it. audit.events is a
	// volume control, and a critical event is not something an operator gets to turn
	// down: with the filter first, an audit.events that omitted
	// authentication_success produced a broker that granted logins and recorded
	// nothing, with a filteredCount as the only trace. Which is the shape of a
	// deliberately blinded host as much as a misconfigured one.
	_, critical := criticalAuditEvents[event.EventType]

	if !critical && al.enabledEvents != nil {
		if _, ok := al.enabledEvents[event.EventType]; !ok {
			al.filteredCount.Add(1)
			return nil
		}
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.EventID == "" {
		event.EventID = fmt.Sprintf("audit_%d", time.Now().UnixNano())
	}

	if critical {
		return al.writeEvent(event)
	}

	select {
	case al.eventChan <- event:
	default:
		n := al.droppedCount.Add(1)
		log.Warn().Uint64("total_dropped", n).Msg("Audit event channel full, dropping event")
	}
	return nil
}

func (al *AuditLogger) processEvents(ctx context.Context) {
	defer al.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-al.stopChan:
			// Drain remaining events
			for {
				select {
				case event := <-al.eventChan:
					// Only non-critical events are ever queued, and writeEvent has
					// already logged whatever went wrong. There is no caller left here
					// to return it to.
					_ = al.writeEvent(event)
				default:
					return
				}
			}
		case event := <-al.eventChan:
			_ = al.writeEvent(event)
		}
	}
}

// WriteError is a failed audit write, and reports whether the record may
// nevertheless be sitting at a sink.
//
// The distinction is the whole point of the type (#91). A caller that refuses an
// access decision because the record could not be written needs to know which of
// two different facts it has been told. "No sink has this record" needs nothing
// further: the trail says nothing, and nothing happened. "Some sink may have this
// record" is the opposite — a reader will find an authentication_success
// byte-identical to a real grant, describing a login that was refused — and the
// caller has to correct it.
//
// Three ways the second arises, none exotic. Every sink is attempted whatever the
// earlier ones did (see writeEvent), so one broken output among several returns an
// error while the healthy ones hold the record. A write that overran its deadline
// is still running: fileOutput.Write is a write followed by an fsync, so on the
// degraded-disk case that motivated the deadline the bytes are in the file, and
// visible to anything tailing it, well before the deadline fires. And a sink can
// return an error having already taken the record — which is not an edge case but
// the shipped file sink's ordinary behaviour on a full or failing disk, because
// the fsync that reports ENOSPC, EIO, EDQUOT or an NFS commit failure runs after
// the bytes are in the file (#94).
//
// So MayHaveLanded is "may": true unless a sink positively reports that the record
// reached nothing. The asymmetry is deliberate. A spurious correction is one extra
// session_revoked saying a refused login was not recorded, which is true whether or
// not the success made it; a missing correction leaves an authentication_success
// standing for a login that was refused, which is the harm the type exists to
// prevent.
type WriteError struct {
	EventType string
	// MayHaveLanded reports that a sink may hold the record: one accepted it, one
	// failed in a way that leaves the bytes where a reader could find them, or a
	// write still in progress may yet accept it. False means the record reached
	// nothing — every sink said so, or none was attempted.
	MayHaveLanded bool
	Err           error
}

// ErrRecordNotLanded marks an error from AuditOutput.Write as one where no part of
// the record reached anywhere a reader could find it. A sink that knows this joins
// it to its own error:
//
//	return fmt.Errorf("%w: %w", err, security.ErrRecordNotLanded)
//
// Without it a failed write is assumed to have kept the record, because the sinks
// this package ships mostly do. fileOutput.Write hands the bytes to the kernel and
// then fsyncs, and every disk failure worth a deadline — a full filesystem with
// delayed allocation, a quota, an I/O error, an NFS server that accepted the write
// and not the commit — is reported by the fsync, with the record already in the
// file and already readable by anything tailing it. Reading such an error as "the
// record does not exist" is what made the #91 correction skip the case it was
// written for.
var ErrRecordNotLanded = errors.New("no part of the record reached the sink")

// recordReachedSink reports whether err from AuditOutput.Write leaves the record,
// or some of it, where a reader could find it. Anything that does not say
// otherwise is assumed to have kept it.
func recordReachedSink(err error) bool {
	return !errors.Is(err, ErrRecordNotLanded)
}

func (e *WriteError) Error() string {
	return fmt.Sprintf("write audit event %s: %v", e.EventType, e.Err)
}

func (e *WriteError) Unwrap() error { return e.Err }

// RecordMayHaveLanded reports whether err from LogAuthEventErr leaves the record
// possibly present at a sink, and so in need of correcting rather than forgetting.
// A non-WriteError — a marshal failure, or any error from elsewhere — is not
// something a sink ever saw.
func RecordMayHaveLanded(err error) bool {
	var we *WriteError
	return errors.As(err, &we) && we.MayHaveLanded
}

// writeEvent writes event to every sink and returns the first failure.
//
// It used to log a failure and return nothing, which for a critical event meant a
// full disk turned a granted login into a login recorded nowhere — the audit trail
// missing exactly the record an incident would be reconstructed from, and the
// caller unaware. The failure now travels back to LogAuthEventErr and from there to
// whoever made the access decision.
//
// Every sink is attempted whatever the earlier ones did: a broken file output must
// not cost the record on syslog as well.
//
// The write is bounded by auditWriteTimeout, because "the sink returned an error"
// and "the sink never returned" are different failures and only the first one was
// handled. A sink that stalls rather than erroring is not exotic: fileOutput.Write
// ends in an fsync, and a hard NFS mount that becomes unreachable blocks it
// indefinitely; syslogOutput.Write blocks the same way on a stream /dev/log whose
// peer has stopped reading. Without a deadline the caller waits forever, and a
// caller that waits forever never gets the error that would make it withdraw a
// grant — so an unreachable log server turned the fail-closed guarantee above into
// its exact opposite, granting logins and recording none of them (#87).
//
// The write therefore happens on its own goroutine and the deadline is enforced
// here. Nothing can abort an fsync in progress, so that goroutine is still stuck
// afterwards, holding writeMu; that is the point of the stalled flag. Once one
// write has overrun, later ones fail immediately instead of each queueing behind
// the mutex and waiting out the full timeout again — the sinks are known bad, and
// the answer callers need is the error, quickly. Whichever write eventually
// returns clears the flag, from inside writeMu so that the write clearing it is
// necessarily the one that was past the lock.
//
// Which of the two paths reports a write's outcome is decided by a compare-and-set
// on settled, so that the two cannot both act on the same write. A write that
// returns in the same moment its deadline fires used to be declared stalled after
// it had already cleared the flag — and since a refused write spawns no goroutine
// to clear it, the flag stayed set and every later record was refused for the life
// of the process. Fail-closed forever is still a broker that grants no logins.
//
// Winning settled decides who reports, and that is all it decides: it does not
// order the two stores to stalled, which is how the paragraph above described a
// bug it had only narrowed rather than closed. The state is no longer a flag at
// all — see sinksStalled for why a flag could not be made correct here.
//
// A stalled sink still blocks Stop, which takes writeMu to close the outputs. That
// is not new — a caller stuck in Sync held the same mutex before this change — and
// it is a shutdown that hangs rather than a login that is silently unrecorded.
// writeToken is one audit write's completion signal. The goroutine performing the
// write closes finished when it is back, whatever the outcome was and whoever
// reported it.
type writeToken struct{ finished chan struct{} }

// sinksStalled reports whether a write has overrun its deadline and not yet come
// back, which is the condition for refusing a record rather than queueing behind a
// mutex nobody is going to release soon.
//
// The state is a pointer to the overrunning write's own completion signal rather
// than a bool, because a bool has to be cleared by somebody and neither candidate
// can do it correctly. The deadline path cannot: the write is by definition still
// running when it gives up. The write that eventually returns cannot either, and
// this is the part two review rounds got wrong — its store and the deadline path's
// store are unordered, so it could clear the flag microseconds before the deadline
// path set it, leaving the flag set with nothing outstanding and no goroutine left
// to clear it, because a refused write spawns none. Every record after that was
// refused for the life of the process: a broker that grants no logins at all, out
// of one write that was a few microseconds late. Round five narrowed that window
// and called it closed; it took about forty runs of
// TestAWriteReturningAsItsDeadlineFiresDoesNotWedgeTheStalledFlag to reappear, and
// it reappeared on a CI runner rather than here.
//
// Asking the write itself has no such window. Recording a write that has already
// finished is harmless, because the recorded thing carries its own answer: the next
// caller looks, sees it is back, and retires it. The invariant the test states —
// with no write outstanding, nothing is stalled — holds by construction rather than
// by two stores landing in the right order.
func (al *AuditLogger) sinksStalled() bool {
	tok := al.stalledOn.Load()
	if tok == nil {
		return false
	}
	select {
	case <-tok.finished:
		// Back. Retire it, but only if nothing newer has taken its place since the
		// load — otherwise this would clear a genuinely stalled write's record.
		al.stalledOn.CompareAndSwap(tok, nil)
		return false
	default:
		return true
	}
}

func (al *AuditLogger) writeEvent(event AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		log.Error().Err(err).Str("event_type", event.EventType).Msg("Failed to marshal audit event")
		return fmt.Errorf("marshal audit event %s: %w", event.EventType, err)
	}

	if al.sinksStalled() {
		log.Error().Str("event_type", event.EventType).
			Msg("Audit sinks are not draining; refusing the record rather than waiting on them")
		return &WriteError{
			EventType: event.EventType,
			Err:       errors.New("an earlier write to the audit sinks has not returned"),
		}
	}

	done := make(chan error, 1)
	// settled decides which of the two paths below owns this write's outcome: the
	// goroutine that returns, or the deadline that gives up on it. Exactly one.
	var settled atomic.Bool
	tok := &writeToken{finished: make(chan struct{})}
	go func() {
		al.writeMu.Lock()
		defer func() {
			// The only thing this goroutine has to say about the stalled state: it is
			// back. Whether anybody had given up on it in the meantime is not its
			// business, and not asking is what removes the ordering problem — see
			// sinksStalled.
			close(tok.finished)
			settled.Store(true)
			al.writeMu.Unlock()
		}()

		var firstErr error
		// Sinks that may hold the record, which is not the same as sinks that
		// accepted it: a sink that errored after taking the bytes counts here, and
		// the shipped file sink does exactly that whenever its fsync is what failed.
		landed := 0
		for _, out := range al.outputs {
			err := out.Write(data)
			if err == nil {
				landed++
				continue
			}
			log.Error().Err(err).Str("event_type", event.EventType).Msg("Failed to write audit event")
			if firstErr == nil {
				firstErr = err
			}
			if recordReachedSink(err) {
				landed++
			}
		}
		if firstErr == nil {
			done <- nil
			return
		}
		done <- &WriteError{
			EventType:     event.EventType,
			MayHaveLanded: landed > 0,
			Err:           firstErr,
		}
	}()

	timer := time.NewTimer(al.writeTimeout())
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		if !settled.CompareAndSwap(false, true) {
			// It came back in the moment the deadline fired. Its answer is the better
			// one, and the send on done has either happened or is about to.
			return <-done
		}
		// Recording the write rather than a verdict about it. Doing this for a write
		// that has in fact just finished is harmless: the next caller asks the write
		// whether it is back, and it says yes.
		al.stalledOn.Store(tok)
		log.Error().Str("event_type", event.EventType).Dur("timeout", al.writeTimeout()).
			Msg("Audit write exceeded its deadline; treating the record as unwritten")
		return &WriteError{
			EventType: event.EventType,
			// The write is still running and nothing can abort it. fileOutput.Write has
			// already written the bytes by the time it is inside Sync, so the caller
			// must treat this record as possibly readable.
			MayHaveLanded: true,
			Err: fmt.Errorf("audit sinks did not accept the record within %s",
				al.writeTimeout()),
		}
	}
}

// auditWriteTimeout bounds one attempt to get a record in front of the sinks.
//
// Five seconds is far longer than any healthy sink needs — an fsync to a local
// disk is single-digit milliseconds, and to a responsive NFS server tens — and
// short enough that a caller holding a grant open on the answer is not waiting on
// a dead log server for a minute. It is deliberately not configurable: an operator
// who could raise it would be choosing to wait longer before finding out that
// their audit trail has stopped, and there is no good reason to want that.
const auditWriteTimeout = 5 * time.Second

// writeTimeout is the deadline writeEvent enforces. Tests override it; nothing
// else does.
func (al *AuditLogger) writeTimeout() time.Duration {
	if al.testWriteTimeout > 0 {
		return al.testWriteTimeout
	}
	return auditWriteTimeout
}

// --- output implementations ---

// newAuditOutput builds the sink cfg describes.
//
// An unrecognised type is an error. It used to fall through to stdout, so a
// misspelled type produced a broker that started cleanly and wrote its audit
// trail somewhere nobody was looking. config.Validate rejects unknown types
// before this is reached; this is the backstop for a Config built in code.
func newAuditOutput(cfg config.AuditOutput) (AuditOutput, error) {
	switch cfg.Type {
	case "file":
		return newFileOutput(cfg)
	case "syslog":
		return newSyslogOutput(cfg)
	case "stdout":
		return &stdoutOutput{}, nil
	default:
		return nil, fmt.Errorf("unsupported type %q (supported: %s)",
			cfg.Type, strings.Join(config.SupportedAuditOutputTypes, ", "))
	}
}

type stdoutOutput struct{}

// Write returns the write error rather than discarding it. stdout is the default
// sink — config.setDefaults installs it when audit.outputs is empty — so a sink
// that can never fail made the fail-closed guarantee above vacuous on the default
// configuration: under systemd stdout is a journal socket, and a full or
// unreachable journal is exactly the case the guarantee is for.
//
// A short write says which of the two failures this is, by the same argument as
// fileOutput.Write: whatever bytes the journal took, it took.
func (o *stdoutOutput) Write(data []byte) error {
	n, err := fmt.Println(string(data))
	if err == nil {
		return nil
	}
	if n == 0 {
		return fmt.Errorf("write to stdout: %w: %w", err, ErrRecordNotLanded)
	}
	return fmt.Errorf("write to stdout: %w", err)
}

func (o *stdoutOutput) Close() error { return nil }

type fileOutput struct {
	file *os.File
}

func newFileOutput(cfg config.AuditOutput) (*fileOutput, error) {
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open audit file %s: %w", cfg.Path, err)
	}
	return &fileOutput{file: f}, nil
}

// Write appends one record and fsyncs it, and says which of the two failed.
//
// The distinction is what the caller acts on (#94). Only the write failing with
// nothing written means the record does not exist. If the write took any bytes the
// record, or the start of it, is in the file and readable by anything tailing it —
// and if the write succeeded and the *fsync* failed, the whole record is there. The
// fsync is the likelier of the two to fail on the cases this sink is hardened for:
// ext4 with delayed allocation reports a full filesystem there rather than at the
// write, as do quotas, I/O errors on a degraded device, and an NFS server that
// accepted the write and not the commit.
//
// The record being unsynced does not make it unreadable. It is in the page cache,
// every reader on the host sees it, and it survives everything short of the machine
// losing power. So an unsynced record is a record, and the caller has to be told it
// is there.
func (o *fileOutput) Write(data []byte) error {
	n, err := o.file.Write(append(data, '\n'))
	if err != nil {
		if n == 0 {
			return fmt.Errorf("write audit file: %w: %w", err, ErrRecordNotLanded)
		}
		return fmt.Errorf("write audit file (%d bytes of the record were written): %w", n, err)
	}
	if err := o.file.Sync(); err != nil {
		return fmt.Errorf("sync audit file (the record is written but unsynced): %w", err)
	}
	return nil
}

func (o *fileOutput) Close() error { return o.file.Close() }
