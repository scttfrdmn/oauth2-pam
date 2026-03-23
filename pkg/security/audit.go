package security

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	config       config.AuditConfig
	outputs      []AuditOutput
	eventChan    chan AuditEvent
	stopChan     chan struct{}
	wg           sync.WaitGroup
	droppedCount atomic.Uint64
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
	for _, oc := range cfg.Outputs {
		out, err := newAuditOutput(oc)
		if err != nil {
			return nil, fmt.Errorf("create audit output: %w", err)
		}
		outputs = append(outputs, out)
	}

	// Default to stdout if no outputs configured
	if len(outputs) == 0 {
		out, _ := newAuditOutput(config.AuditOutput{Type: "stdout"})
		outputs = append(outputs, out)
	}

	return &AuditLogger{
		config:    cfg,
		outputs:   outputs,
		eventChan: make(chan AuditEvent, 1000),
		stopChan:  make(chan struct{}),
	}, nil
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
	for _, out := range al.outputs {
		_ = out.Close()
	}
	return nil
}

// LogAuthEvent queues an audit event for async writing.
func (al *AuditLogger) LogAuthEvent(event AuditEvent) {
	if !al.config.Enabled {
		return
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.EventID == "" {
		event.EventID = fmt.Sprintf("audit_%d", time.Now().UnixNano())
	}

	select {
	case al.eventChan <- event:
	default:
		n := al.droppedCount.Add(1)
		log.Warn().Uint64("total_dropped", n).Msg("Audit event channel full, dropping event")
	}
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
					al.writeEvent(event)
				default:
					return
				}
			}
		case event := <-al.eventChan:
			al.writeEvent(event)
		}
	}
}

func (al *AuditLogger) writeEvent(event AuditEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Error().Err(err).Str("event_type", event.EventType).Msg("Failed to marshal audit event")
		return
	}
	for _, out := range al.outputs {
		if err := out.Write(data); err != nil {
			log.Error().Err(err).Str("event_type", event.EventType).Msg("Failed to write audit event")
		}
	}
}

// --- output implementations ---

func newAuditOutput(cfg config.AuditOutput) (AuditOutput, error) {
	switch cfg.Type {
	case "file":
		return newFileOutput(cfg)
	case "syslog":
		return &syslogOutput{cfg: cfg}, nil
	default: // "stdout" or unrecognized
		return &stdoutOutput{}, nil
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

type syslogOutput struct {
	cfg config.AuditOutput
}

func (o *syslogOutput) Write(data []byte) error {
	log.Info().
		Str("facility", o.cfg.Facility).
		RawJSON("event", data).
		Msg("audit")
	return nil
}

func (o *syslogOutput) Close() error { return nil }
