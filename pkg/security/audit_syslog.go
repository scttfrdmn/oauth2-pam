package security

import (
	"fmt"
	"log/syslog"
	"sort"
	"strings"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

// syslogTag is the ident every audit record is logged under.
const syslogTag = "oauth2-pam"

// syslogFacilities and syslogSeverities are the names audit.outputs[].facility
// and .severity accept.
//
// This is where they are defined, and pkg/config deliberately does not repeat
// them: it cannot import this package (pkg/security imports pkg/config), and a
// second copy of a table like this is how the two spellings of a name drift
// apart. A bad name is still a startup error — newAuditOutput runs while the
// broker is being built — just from here rather than from Validate.
//
// The list is the facilities that make sense for an authentication audit trail,
// not all sixteen: kern is the kernel's, syslog is the daemon's own, and mail,
// news, uucp and lpr belong to services this is not.
var syslogFacilities = map[string]syslog.Priority{
	"auth":     syslog.LOG_AUTH,
	"authpriv": syslog.LOG_AUTHPRIV,
	"daemon":   syslog.LOG_DAEMON,
	"user":     syslog.LOG_USER,
	"local0":   syslog.LOG_LOCAL0,
	"local1":   syslog.LOG_LOCAL1,
	"local2":   syslog.LOG_LOCAL2,
	"local3":   syslog.LOG_LOCAL3,
	"local4":   syslog.LOG_LOCAL4,
	"local5":   syslog.LOG_LOCAL5,
	"local6":   syslog.LOG_LOCAL6,
	"local7":   syslog.LOG_LOCAL7,
}

var syslogSeverities = map[string]syslog.Priority{
	"emerg":   syslog.LOG_EMERG,
	"alert":   syslog.LOG_ALERT,
	"crit":    syslog.LOG_CRIT,
	"err":     syslog.LOG_ERR,
	"warning": syslog.LOG_WARNING,
	"notice":  syslog.LOG_NOTICE,
	"info":    syslog.LOG_INFO,
	"debug":   syslog.LOG_DEBUG,
}

// syslogPriority resolves the configured facility and severity names, defaulting
// to auth.info.
//
// auth is the default because that is where the rest of the login record already
// is: sshd's own accept and reject lines land there, so an audit trail in the
// same stream can be read against them in one pass.
func syslogPriority(facility, severity string) (syslog.Priority, error) {
	f := syslog.LOG_AUTH
	if facility != "" {
		var ok bool
		if f, ok = syslogFacilities[strings.ToLower(facility)]; !ok {
			return 0, fmt.Errorf("unknown syslog facility %q (known: %s)", facility, sortedKeys(syslogFacilities))
		}
	}

	s := syslog.LOG_INFO
	if severity != "" {
		var ok bool
		if s, ok = syslogSeverities[strings.ToLower(severity)]; !ok {
			return 0, fmt.Errorf("unknown syslog severity %q (known: %s)", severity, sortedKeys(syslogSeverities))
		}
	}

	return f | s, nil
}

func sortedKeys(m map[string]syslog.Priority) string {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// syslogOutput writes audit records to the system logger.
//
// It really does talk to syslog now. It used to hand the record to this process's
// own zerolog logger with the facility attached as a field, which under systemd
// meant the journal and under anything else meant wherever stderr pointed —
// neither of which is what `type: syslog` with `facility: auth` says, and neither
// of which routes by facility at all.
type syslogOutput struct {
	w *syslog.Writer
}

// newSyslogOutput connects to the local syslog daemon.
//
// A failure here fails broker startup. That is the point: an operator who
// configured syslog and got no syslog should find out at start, not from an empty
// /var/log/auth.log during an incident.
func newSyslogOutput(cfg config.AuditOutput) (*syslogOutput, error) {
	pri, err := syslogPriority(cfg.Facility, cfg.Severity)
	if err != nil {
		return nil, err
	}
	w, err := syslog.New(pri, syslogTag)
	if err != nil {
		return nil, fmt.Errorf("connect to syslog: %w", err)
	}
	return &syslogOutput{w: w}, nil
}

// Write sends one record. The writer reconnects on its own if the daemon was
// restarted, so a syslog bounce costs at most the record in flight.
//
// Note that a daemon may truncate a long line — 1024 bytes is a common limit, and
// the RFC 3164 minimum is 480. An audit record with a long error message can
// reach that, so treat the file sink as the authoritative one where records must
// be complete.
func (o *syslogOutput) Write(data []byte) error {
	_, err := o.w.Write(data)
	return err
}

func (o *syslogOutput) Close() error { return o.w.Close() }
