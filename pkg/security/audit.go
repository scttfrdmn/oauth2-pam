package security

import (
	"context"
	"encoding/json"
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
	writeMu       sync.Mutex
	eventChan     chan AuditEvent
	stopChan      chan struct{}
	wg            sync.WaitGroup
	droppedCount  atomic.Uint64
	filteredCount atomic.Uint64
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
func (al *AuditLogger) writeEvent(event AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		log.Error().Err(err).Str("event_type", event.EventType).Msg("Failed to marshal audit event")
		return fmt.Errorf("marshal audit event %s: %w", event.EventType, err)
	}
	al.writeMu.Lock()
	defer al.writeMu.Unlock()
	var firstErr error
	for _, out := range al.outputs {
		if err := out.Write(data); err != nil {
			log.Error().Err(err).Str("event_type", event.EventType).Msg("Failed to write audit event")
			if firstErr == nil {
				firstErr = fmt.Errorf("write audit event %s: %w", event.EventType, err)
			}
		}
	}
	return firstErr
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

func (o *stdoutOutput) Write(data []byte) error {
	fmt.Println(string(data))
	return nil
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

func (o *fileOutput) Write(data []byte) error {
	_, err := o.file.Write(append(data, '\n'))
	if err != nil {
		return err
	}
	return o.file.Sync()
}

func (o *fileOutput) Close() error { return o.file.Close() }
