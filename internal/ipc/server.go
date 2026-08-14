package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/pkg/auth"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

// maxRequestSize is the largest JSON body accepted from a PAM client.
//
// The read is capped at this many bytes, so a caller cannot make the broker
// allocate without bound. It is a cap on the allocation rather than a check that
// happens before any decoding: a request is a bare JSON object with no length
// prefix, so nothing on the wire announces its size in advance and the only way
// to learn a body is too big is to reach the cap while reading it. See
// handleConnection, and the note in docs/wire-protocol.md that used to claim the
// refusal came first.
const maxRequestSize = 64 * 1024 // 64 KB

// ErrorCodeRateLimited is returned when a request was refused by the rate
// limiter. It is exported because it is part of the wire contract: a client must
// treat it as a *retryable* condition, not as a decision about the user. The PAM
// module counts it against its transport-failure budget and keeps polling; a
// client that treated it as terminal would fail a login that is merely being
// asked to slow down.
const ErrorCodeRateLimited = "RATE_LIMITED"

// removeStaleSocket deletes a leftover socket from a previous run.
//
// It refuses to delete anything that is not a socket, and it is not recursive.
// This used to be os.RemoveAll, which meant a typo in server.socket_path — say a
// path under /etc/oauth2-pam, which the systemd unit granted write access to —
// destroyed a directory tree as root on the next restart.
func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat socket path %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace %s: it exists and is not a socket (mode %s)", path, info.Mode())
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale socket %s: %w", path, err)
	}
	return nil
}

// Server handles IPC communication between the PAM module and the broker.
type Server struct {
	socketPath string
	broker     *auth.Broker
	listener   net.Listener
	// rateLimiter buckets authenticate requests per calling UID; sessionLimiter
	// buckets everything else per session ID. See callerKey and sessionKey for
	// why the two cannot share a bucket.
	rateLimiter    *rateLimiter
	sessionLimiter *rateLimiter
	// newSessionLimiter charges, per calling UID, the act of naming a session ID
	// the sessionLimiter has never seen. See allowRequest and
	// maxNewSessionsPerMinute.
	newSessionLimiter *rateLimiter
	// handlerSlots bounds concurrent connection handlers. See
	// maxConcurrentHandlers.
	handlerSlots chan struct{}
	readTimeout  time.Duration
	writeTimeout time.Duration
	// evictInterval is how often stale rate-limit windows are swept. A field
	// rather than a literal so a test can watch the sweep actually happen instead
	// of asserting that a function it calls by hand does the right thing.
	evictInterval time.Duration
	stopChan      chan struct{}
	wg            sync.WaitGroup
	stopOnce      sync.Once
}

// defaultIOTimeout applies when server.read_timeout / server.write_timeout are
// unset or non-positive.
const defaultIOTimeout = 30 * time.Second

// maxConcurrentHandlers bounds how many connections are being served at once.
//
// This replaced an accept-time rate limit, which was the wrong primitive: it
// bounded resources by *failing* requests, and since every caller is sshd as
// root they all shared one bucket, so a burst of logins denied each other. A
// semaphore bounds the same resource without failing anything — excess
// connections wait in the kernel's listen backlog and are served as slots free,
// which for a login broker is the right trade.
//
// A slot is held for at most server.read_timeout + maxDispatchDuration +
// server.write_timeout, and every one of those three is a clock something in
// handleConnection actually sets. This comment used to claim the read deadline
// alone bounded a slot, which was false in the direction that matters: dispatch
// runs inside the slot, after the read, and its only clock was the 30s on the
// provider's HTTP client. 64 connections asking to authenticate against a
// provider that accepts and then stalls therefore held every slot for 30s each,
// and because acceptConnections blocks after accepting, nothing else on the host
// was served for that time — including check_session polls for logins that had
// already succeeded.
//
// Read it as a bound on hold time and not as a promise that 64 simultaneous
// stalls are painless: with the default timeouts the bound is a little over a
// minute, and the 65th connection waits for it. What the bound buys is that the
// wait ends, and that it ends at a number set here rather than at whatever the
// far end of the provider's TLS session decides.
const maxConcurrentHandlers = 64

// maxDispatchDuration bounds the work a handler does with a slot held: the
// provider round trip a verb makes, plus the broker's own bookkeeping.
//
// It is deliberately above the provider HTTP client's own 30s
// (pkg/provider/github) rather than below it. This is a backstop for a call that
// turns out to have no clock of its own — a future provider, a library default
// nobody checked — not a second and tighter provider timeout, and a dispatch cut
// off here fails a login that might have been about to succeed.
const maxDispatchDuration = 40 * time.Second

// maxSessionRequestsPerMinute bounds polls against one session ID. The module
// permits poll_interval as low as 1s, i.e. 60 requests a minute for a legitimate
// login, so this leaves 2x headroom and only catches a client that has stopped
// honouring the interval.
const maxSessionRequestsPerMinute = 120

// maxSessionLimiterKeys bounds how many session windows the session limiter will
// hold at once.
//
// It exists because the session limiter's key space is chosen by the caller: a
// request naming a session ID the broker has never issued still allocated a
// window, so any client could mint windows faster than the five-minute eviction
// sweep removed them. The better check is "refuse a session the broker does not
// have" before the limiter sees it, but the broker exports no session-existence
// lookup to ask with; until it does, the map has a ceiling instead.
//
// 8192 live windows means 8192 distinct sessions polled inside the same minute.
// A host with that many concurrent logins in flight has run out of something
// else first, and the ceiling costs well under a megabyte if it is ever reached.
const maxSessionLimiterKeys = 8192

// maxNewSessionsPerMinute bounds how many *previously unseen* session IDs one
// caller may introduce per minute.
//
// This is the charge that makes an unknown-session flood cost the caller
// something. It is deliberately not a charge on session requests in general:
// every PAM caller is sshd as root, so charging each poll to the caller is the
// host-wide login DoS that sessionKey exists to avoid. Introducing a session ID
// is different — a legitimate login does it once, when its first check_session
// arrives, so a real caller spends one or two units per login while a flood of
// invented IDs spends one per request.
//
// 600/minute is ten new logins a second sustained from a single caller, far above
// what a login node does and far below what the map ceiling cares about.
const maxNewSessionsPerMinute = 600

// defaultEvictInterval is how often stale rate-limit windows are swept.
const defaultEvictInterval = 5 * time.Minute

// ProtocolVersion is the wire contract this broker speaks. It is documented in
// docs/wire-protocol.md, which is the specification both this project and its
// sister oidc-pam are meant to implement.
//
// Version 1 is what shipped from v0.2.0 onward: the status state machine, with
// access granted only on success && status == "authorized". The field itself is
// new in v0.3.0 and optional in a request, because a v0.2.x module does not send
// it and must keep working — absent means 1. It exists so that the *next* change
// to the contract has somewhere to declare itself, rather than being inferred
// from which fields happen to be present.
const ProtocolVersion = 1

// ErrorCodeUnsupportedProtocol is returned when a request declares a
// protocol_version this broker does not implement. Part of the wire contract: a
// client must treat it as terminal, not retryable — retrying the same version
// gets the same answer. Refusing is deliberate. A client asking for semantics
// this broker does not have, served under semantics it did not ask for, is how a
// field quietly changes meaning between two implementations.
const ErrorCodeUnsupportedProtocol = "UNSUPPORTED_PROTOCOL"

// Request is a message from the PAM module.
type Request struct {
	// ProtocolVersion is the contract the client speaks. Omitted or 0 means 1.
	ProtocolVersion int `json:"protocol_version,omitempty"`

	Type       string            `json:"type"` // authenticate, check_session, refresh_session, revoke_session
	UserID     string            `json:"user_id"`
	SourceIP   string            `json:"source_ip"`
	UserAgent  string            `json:"user_agent"`
	TargetHost string            `json:"target_host"`
	LoginType  string            `json:"login_type"` // ssh, console, gui
	DeviceID   string            `json:"device_id"`
	SessionID  string            `json:"session_id"`
	Metadata   map[string]string `json:"metadata"`

	// Provider selects which configured provider to authenticate against, by
	// its providers[].name. Optional: empty means the first configured provider.
	// An older PAM module that never sends it therefore keeps working.
	Provider string `json:"provider"`
}

// StatusRevoked is the status of a successful revoke_session reply. It is not a
// session state — the session no longer exists — but every reply carries a
// status, so a client never has to special-case a missing one.
const StatusRevoked = "revoked"

// Response is a message from the broker to the PAM module.
//
// Status is the authoritative field. For the authentication verbs it is one of
// the auth.Status* values ("pending", "authorized", "denied", "expired",
// "error"); revoke_session replies "revoked". The rule a client must apply is:
//
//	access is granted only when Success is true AND Status is "authorized"
//
// and UserID is populated only in that case. In particular "pending" is never an
// authenticated user, and a status the client does not recognise is not either.
type Response struct {
	// ProtocolVersion is the contract this reply is written in. Always set, so a
	// client never has to infer it; a client reading a version it does not know
	// must not grant access on the strength of fields it may be misreading.
	ProtocolVersion int `json:"protocol_version"`

	Success          bool              `json:"success"`
	Status           string            `json:"status"`
	UserID           string            `json:"user_id"`
	Email            string            `json:"email"`
	Groups           []string          `json:"groups"`
	SessionID        string            `json:"session_id"`
	DeviceCode       string            `json:"device_code"`
	DeviceURL        string            `json:"device_url"`
	QRCode           string            `json:"qr_code"`
	ExpiresAt        time.Time         `json:"expires_at"`
	RequiresDevice   bool              `json:"requires_device"`
	RequiresApproval bool              `json:"requires_approval"`
	ErrorCode        string            `json:"error_code"`
	ErrorMessage     string            `json:"error_message"`
	Instructions     string            `json:"instructions"`
	Metadata         map[string]string `json:"metadata"`
}

// NewServer creates a new IPC server.
func NewServer(socketPath string, broker *auth.Broker, cfg *config.Config) (*Server, error) {
	rl := newRateLimiter(cfg.Security.RateLimiting.MaxRequestsPerMinute)

	readTimeout := cfg.Server.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = defaultIOTimeout
	}
	writeTimeout := cfg.Server.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = defaultIOTimeout
	}

	return &Server{
		socketPath:        socketPath,
		broker:            broker,
		rateLimiter:       rl,
		sessionLimiter:    newBoundedRateLimiter(maxSessionRequestsPerMinute, maxSessionLimiterKeys),
		newSessionLimiter: newRateLimiter(maxNewSessionsPerMinute),
		handlerSlots:      make(chan struct{}, maxConcurrentHandlers),
		readTimeout:       readTimeout,
		writeTimeout:      writeTimeout,
		evictInterval:     defaultEvictInterval,
		stopChan:          make(chan struct{}),
	}, nil
}

// Start begins accepting connections on the Unix socket.
func (s *Server) Start(ctx context.Context) error {
	if err := removeStaleSocket(s.socketPath); err != nil {
		return err
	}
	// 0750 on a root-owned directory: only root may traverse it and reach the
	// socket. See the socket mode below for who that leaves as the caller.
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0750); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.socketPath, err)
	}
	s.listener = l

	// 0660 — owner and group only, never world. Combined with the 0750 directory
	// above and the packaged unit's User=root/Group=root, that makes the broker
	// socket reachable by root and nobody else.
	//
	// Root-only is the whole trust boundary, and it is worth being blunt about
	// because a good deal rests on it: an unauthenticated caller that reaches this
	// socket can start device flows and name session IDs, so several defects in
	// the verbs behind it are rated low purely because only root can get here.
	// Nothing in this process enforces that, though — it is a property of the
	// packaging (configs/systemd/oauth2-pam-broker.service) plus the two modes
	// set here, so a change to either widens the boundary silently. The mode is
	// asserted in server_test.go for that reason.
	//
	// This is not a group-based access model, and it deliberately is not one. The
	// module runs inside sshd's pre-auth child, which is already root, so there is
	// no unprivileged service account that needs to reach the socket and no
	// oauth2-pam group to add one to. Introducing a group would mean creating it
	// in packaging and chowning both the directory and the socket, and it would
	// hand every group member the capabilities described above. If that day comes,
	// re-rate the findings that assume root-only first.
	if err := os.Chmod(s.socketPath, 0660); err != nil {
		log.Warn().Err(err).Str("socket", s.socketPath).Msg("Failed to set socket permissions")
	}

	// Say out loud whether the rate limiter can tell callers apart. Without peer
	// credentials every caller shares one bucket, which is a materially weaker
	// guarantee than the config's per-caller limit implies.
	log.Info().
		Str("socket", s.socketPath).
		Bool("peer_credentials", peerCredsSupported).
		Msg("IPC server started")
	if !peerCredsSupported {
		log.Warn().Msg("Peer credentials unavailable on this platform; all callers share one rate-limit bucket")
	}

	s.wg.Add(2)
	go s.acceptConnections(ctx)
	go s.evictRateLimitWindows(ctx)

	return nil
}

// Stop shuts down the IPC server.
func (s *Server) Stop() error {
	s.stopOnce.Do(func() {
		close(s.stopChan)
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.wg.Wait()
		if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
			log.Warn().Err(err).Str("socket", s.socketPath).Msg("Failed to remove socket file")
		}
		log.Info().Msg("IPC server stopped")
	})
	return nil
}

func (s *Server) acceptConnections(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
		}

		if ul, ok := s.listener.(*net.UnixListener); ok {
			_ = ul.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-s.stopChan:
				return
			default:
				log.Error().Err(err).Msg("Accept error")
				return
			}
		}

		// Bound concurrent handlers rather than rate-limiting the accept path.
		// Blocking here is intentional: the kernel's listen backlog holds the
		// excess and every waiting login is eventually served, where a rejection
		// would have failed it outright.
		select {
		case s.handlerSlots <- struct{}{}:
		case <-s.stopChan:
			_ = conn.Close()
			return
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// countingReader records how many bytes were actually consumed from the wire.
//
// It exists so the request-size limit can be reported as a size limit. Wrapping
// the connection in an io.LimitReader bounds the allocation but says nothing
// about why the decode failed, and the client is left to guess from "unexpected
// EOF" whether it sent bad JSON or too much of it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer func() { <-s.handlerSlots }()
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))

	// The read stops one byte past the cap: reaching that byte is how an
	// oversized request is recognised, since there is nothing to check before
	// decoding starts. counted is what turns that into an answer the caller can
	// act on — a truncated body makes the decoder report "unexpected EOF", which
	// tells a client its JSON is malformed when in fact it was too long.
	counted := &countingReader{r: io.LimitReader(conn, maxRequestSize+1)}

	var req Request
	decodeErr := json.NewDecoder(counted).Decode(&req)

	// Checked before decodeErr, and checked even when the decode succeeded: a body
	// whose closing brace lands exactly on the last byte the limiter allows parses
	// cleanly and is still over the cap. Refusing here rather than only on the
	// error path keeps the limit and the behaviour the same number.
	if counted.n > maxRequestSize {
		log.Warn().Int("bytes_read", counted.n).Int("max", maxRequestSize).
			Msg("Refusing an oversized IPC request")
		_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		s.sendError(conn, "INVALID_REQUEST",
			fmt.Sprintf("Request exceeds the %d-byte limit", maxRequestSize))
		return
	}
	if decodeErr != nil {
		log.Error().Err(decodeErr).Msg("Decode IPC request")
		_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		s.sendError(conn, "INVALID_REQUEST", "Failed to decode request")
		return
	}

	// The version check comes first and answers with its own code: "your contract
	// is not one I implement" is a different thing from "your fields are wrong",
	// and a client that cannot tell them apart cannot report anything useful.
	if req.ProtocolVersion != 0 && req.ProtocolVersion != ProtocolVersion {
		log.Warn().Int("requested", req.ProtocolVersion).Int("supported", ProtocolVersion).
			Msg("Refusing an IPC request in an unsupported protocol version")
		_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		s.sendError(conn, ErrorCodeUnsupportedProtocol,
			fmt.Sprintf("this broker speaks protocol version %d", ProtocolVersion))
		return
	}

	if err := validateRequest(&req); err != nil {
		log.Warn().Err(err).Msg("Invalid IPC request fields")
		_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		s.sendError(conn, "INVALID_REQUEST", "Invalid request fields")
		return
	}

	// Rate-limit after decoding, so the bucket can depend on what was asked for.
	if !s.allowRequest(conn, &req) {
		_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		s.sendError(conn, ErrorCodeRateLimited, "Too many requests; try again shortly")
		return
	}

	resp := dispatchWithin(maxDispatchDuration, &req, s.dispatch)

	_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	writeResponse(conn, resp)

	log.Debug().
		Str("type", req.Type).
		Str("user_id", req.UserID).
		Bool("success", resp.Success).
		Msg("IPC request handled")
}

// The byte ceilings on the strings a request may carry. Each one is also a row in
// the request table of docs/wire-protocol.md, which is what other implementations
// build against, so the two are changed together.
//
// The whole request is already capped at maxRequestSize, so these are not what
// keeps the broker from allocating without bound. What they bound is where the
// values *go*: source_ip and target_host are copied verbatim into an audit event
// (pkg/auth/broker.go), user_agent and device_id are carried into the audit
// trail, and any of them can reach a log line. Before this list existed a 64 KB
// user_agent was accepted, which is a 64 KB audit record written by whatever
// reached the socket.
//
// Every ceiling is sized so that nothing a real client sends is refused. The two
// that are not round numbers are the ones the wire contract sized for a specific
// value: 45 bytes is an IPv6 literal with a zone, 253 a DNS name.
const (
	maxUserIDLen     = 256
	maxSessionIDLen  = 128
	maxProviderLen   = 256
	maxSourceIPLen   = 45
	maxTargetHostLen = 253
	maxUserAgentLen  = 512
	maxDeviceIDLen   = 256
)

// metadata is a map, so it needs a ceiling on the map as well as on the strings
// inside it — 3000 keys were accepted before these existed, and the count is the
// half that a per-value bound does not cover.
//
// The reference client sends four entries (service, tty, pid, rhost) and a
// consumer's extension fields are audit context of the same shape, so 64 entries
// of a 128-byte key and a 1 KB value is far above anything a real client sends
// while still bounding one audit record to something a log can hold.
const (
	maxMetadataEntries  = 64
	maxMetadataKeyLen   = 128
	maxMetadataValueLen = 1024
)

// requestField is one string from a request together with the ceiling the wire
// contract puts on it: a name for the error message, the value, and the maximum.
type requestField struct {
	name  string
	value string
	max   int
}

// requestFields is every string a request carries.
//
// It is a list rather than a run of ifs because the checks used to be written by
// hand per field, and so which checks a field got depended on who added it:
// user_agent and device_id arrived with neither a length bound nor a NUL check,
// while session_id, source_ip and target_host had a length and no NUL check. A
// field added to Request now gets both by being listed here, and one that is
// missing is a visible omission in a single place —
// TestEveryRequestStringIsBounded fails if the list falls behind the struct.
//
// type and login_type are deliberately absent: both are whitelisted against a
// fixed set of values in validateRequest, which bounds them more tightly than a
// length could.
func requestFields(req *Request) []requestField {
	return []requestField{
		{"user_id", req.UserID, maxUserIDLen},
		{"session_id", req.SessionID, maxSessionIDLen},
		// A provider name is only ever compared against the configured ones, but it
		// reaches the log and the error message, so bound it like the rest.
		{"provider", req.Provider, maxProviderLen},
		// Length-bounded and deliberately not parsed. docs/wire-protocol.md
		// requires a receiver to accept a zoned IPv6 literal, which is exactly what
		// net.ParseIP refuses, so validating harder here would refuse link-local
		// logins the contract sized this field for.
		{"source_ip", req.SourceIP, maxSourceIPLen},
		{"target_host", req.TargetHost, maxTargetHostLen},
		{"user_agent", req.UserAgent, maxUserAgentLen},
		{"device_id", req.DeviceID, maxDeviceIDLen},
	}
}

// checkRequestField is the two things every request string has to satisfy.
//
// The NUL check is not cosmetic, and it is why it applies to fields nothing here
// interprets. The other end of this contract is C, where a NUL ends the string:
// "alice\x00bob" can be audited as one value and acted on as another, and
// source_ip and target_host reach an audit event unaltered. The PAM module never
// sends one, so nothing legitimate is refused — this is the last line of defence
// declining to fail open.
//
// The error names the field and its length and never its contents, because it is
// written to the broker's log. What goes back on the wire stays the generic
// INVALID_REQUEST.
func checkRequestField(f requestField) error {
	if len(f.value) > f.max {
		return fmt.Errorf("%s too long (%d bytes, max %d)", f.name, len(f.value), f.max)
	}
	if strings.ContainsRune(f.value, '\x00') {
		return fmt.Errorf("%s contains NUL byte", f.name)
	}
	return nil
}

// validateRequest checks that all fields are within expected bounds.
// Returns a non-nil error if any field is out of range.
func validateRequest(req *Request) error {
	// Whitelist request types
	switch req.Type {
	case "authenticate", "check_session", "refresh_session", "revoke_session":
		// valid
	default:
		return fmt.Errorf("unknown request type %q", req.Type)
	}

	// An authenticate request must name the account it is for. The broker's
	// authoritative check is "the mapped local user equals the requested one",
	// and an empty requested user made that comparison vacuous — the session
	// activated as whatever the identity happened to map to. The PAM module never
	// sends an empty username, so nothing legitimate is refused here; this is the
	// last line of defence declining to fail open.
	if req.Type == "authenticate" && req.UserID == "" {
		return fmt.Errorf("authenticate requires a non-empty user_id")
	}
	for _, f := range requestFields(req) {
		if err := checkRequestField(f); err != nil {
			return err
		}
	}
	if req.LoginType != "" &&
		req.LoginType != "ssh" &&
		req.LoginType != "console" &&
		req.LoginType != "gui" {
		return fmt.Errorf("invalid login_type %q", req.LoginType)
	}
	if len(req.Metadata) > maxMetadataEntries {
		return fmt.Errorf("metadata has too many entries (%d, max %d)", len(req.Metadata), maxMetadataEntries)
	}
	for k, v := range req.Metadata {
		if err := checkRequestField(requestField{"metadata key", k, maxMetadataKeyLen}); err != nil {
			return err
		}
		// The offending key is not named in the error for the same reason a value's
		// contents are not: the error is a log line, and both halves of a metadata
		// entry are chosen by the caller.
		if err := checkRequestField(requestField{"metadata value", v, maxMetadataValueLen}); err != nil {
			return err
		}
	}
	return nil
}

// allowRequest applies the rate limiter appropriate to the request type.
//
// authenticate is the expensive verb — it starts a device flow, a polling
// goroutine and a provider round trip — so it is charged to the calling UID.
// Session operations are charged to the session instead: a poll's cost belongs
// to one login, and bucketing them by caller made every login on the host share
// a single budget.
//
// The one thing a session operation is charged to its caller for is *introducing*
// a session ID the session limiter has not seen. That allocation is the only part
// of a session request whose cost outlives the request — the window survives the
// reply, and nothing here can tell an invented session ID from a real one — so it
// is charged, and charged before the window exists. Polling an established
// session stays free to the caller, which is what keeps concurrent logins from
// competing for one budget.
func (s *Server) allowRequest(conn net.Conn, req *Request) bool {
	if req.Type == "authenticate" {
		uid, known := peerUID(conn)
		if !s.rateLimiter.allow(callerKey(uid, known)) {
			log.Warn().Uint32("uid", uid).Bool("uid_known", known).
				Msg("Rate limit exceeded for authenticate")
			return false
		}
		return true
	}

	key := sessionKey(req.SessionID)
	if !s.sessionLimiter.hasLiveWindow(key) {
		uid, known := peerUID(conn)
		if !s.newSessionLimiter.allow(callerKey(uid, known)) {
			log.Warn().Uint32("uid", uid).Bool("uid_known", known).Str("type", req.Type).
				Msg("Rate limit exceeded for new session IDs from this caller")
			return false
		}
	}
	if !s.sessionLimiter.allow(key) {
		log.Warn().Str("type", req.Type).Msg("Rate limit exceeded for session operation")
		return false
	}
	return true
}

// dispatchWithin runs one dispatch under a budget, so that a handler slot cannot
// be held for as long as a provider is willing to stall. It takes the dispatch
// function rather than calling s.dispatch so the timeout can be tested without a
// broker, a socket, or a real 40 seconds.
//
// The reply comes back over a buffered channel because the goroutine outlives
// this call when the budget expires. Nothing here can cancel dispatch —
// auth.Broker.Authenticate takes no context, and the context the provider call
// uses is the broker's own — so the work is abandoned, not stopped, and it must
// not block forever handing back a reply nobody is reading.
//
// Abandoning it is the lesser of two failures, and it is worth being explicit
// about the greater one. An abandoned authenticate may still create a session the
// client never hears about, which is already what happens when the client's own
// deadline expires first; holding the slot instead means holding a share of every
// login on the host, because acceptConnections stops serving anything once all
// the slots are taken.
func dispatchWithin(budget time.Duration, req *Request, dispatch func(*Request) *Response) *Response {
	done := make(chan *Response, 1)
	go func() { done <- dispatch(req) }()

	timer := time.NewTimer(budget)
	defer timer.Stop()

	select {
	case resp := <-done:
		return resp
	case <-timer.C:
		log.Error().Str("type", req.Type).Dur("budget", budget).
			Msg("Dispatch exceeded its budget; abandoning it and releasing the handler slot")
		return &Response{
			Success:      false,
			Status:       auth.StatusError,
			ErrorCode:    verbErrorCode(req.Type),
			ErrorMessage: "The request took too long to process",
		}
	}
}

// verbErrorCode is the internal-error code for a verb.
//
// A dispatch that overran its budget is reported as that verb's own internal
// failure, which is what docs/wire-protocol.md already says these codes mean:
// "the verb's handler returned an internal error; details are in the broker's
// log, deliberately not on the wire". A new code would be a change to the
// contract and to the C module for no gain — there is nothing a client would
// usefully do differently, and all of these are terminal for the login either
// way. Which one it was stays in the log.
func verbErrorCode(reqType string) string {
	switch reqType {
	case "check_session":
		return "SESSION_CHECK_FAILED"
	case "refresh_session":
		return "SESSION_REFRESH_FAILED"
	case "revoke_session":
		return "SESSION_REVOCATION_FAILED"
	default:
		return "AUTHENTICATION_FAILED"
	}
}

func (s *Server) dispatch(req *Request) *Response {
	switch req.Type {
	case "authenticate":
		return s.handleAuthenticate(req)
	case "check_session":
		return s.handleCheckSession(req)
	case "refresh_session":
		return s.handleRefreshSession(req)
	case "revoke_session":
		return s.handleRevokeSession(req)
	default:
		// Already caught by validateRequest, but keep as a safety net.
		return &Response{
			Success:      false,
			Status:       auth.StatusError,
			ErrorCode:    "INVALID_REQUEST_TYPE",
			ErrorMessage: "Unknown request type",
		}
	}
}

func (s *Server) handleAuthenticate(req *Request) *Response {
	authReq := &auth.AuthRequest{
		UserID:     req.UserID,
		SourceIP:   req.SourceIP,
		UserAgent:  req.UserAgent,
		TargetHost: req.TargetHost,
		LoginType:  req.LoginType,
		DeviceID:   req.DeviceID,
		// req.SessionID is intentionally not forwarded — the broker generates
		// its own session IDs with crypto/rand to prevent session fixation.
		Timestamp: time.Now(),
		Metadata:  req.Metadata,
		Provider:  req.Provider,
	}

	ar, err := s.broker.Authenticate(authReq)
	if err != nil {
		log.Error().Err(err).Str("user_id", req.UserID).Msg("Authenticate error")
		return &Response{
			Success:      false,
			Status:       auth.StatusError,
			ErrorCode:    "AUTHENTICATION_FAILED",
			ErrorMessage: "Authentication failed",
		}
	}

	resp := authResponseToIPC(ar)
	if ar.RequiresDevice {
		resp.Instructions = formatInstructions(req.LoginType, ar.DeviceURL, ar.DeviceCode, ar.QRCode)
	}
	return resp
}

func (s *Server) handleCheckSession(req *Request) *Response {
	ar, err := s.broker.CheckSession(req.SessionID)
	if err != nil {
		return &Response{
			Success:      false,
			Status:       auth.StatusError,
			ErrorCode:    "SESSION_CHECK_FAILED",
			ErrorMessage: "Session check failed",
		}
	}
	return authResponseToIPC(ar)
}

func (s *Server) handleRefreshSession(req *Request) *Response {
	ar, err := s.broker.RefreshSession(req.SessionID)
	if err != nil {
		return &Response{
			Success:      false,
			Status:       auth.StatusError,
			ErrorCode:    "SESSION_REFRESH_FAILED",
			ErrorMessage: "Session refresh failed",
		}
	}
	return authResponseToIPC(ar)
}

func (s *Server) handleRevokeSession(req *Request) *Response {
	if err := s.broker.RevokeSession(req.SessionID); err != nil {
		return &Response{
			Success:      false,
			Status:       auth.StatusError,
			ErrorCode:    "SESSION_REVOCATION_FAILED",
			ErrorMessage: "Session revocation failed",
		}
	}
	// Carries a status like every other reply. It used to be the sole exception,
	// which meant any client applying the documented "Success iff Status is
	// authorized" rule saw success with no status and had to special-case it.
	return &Response{Success: true, Status: StatusRevoked}
}

func (s *Server) sendError(conn net.Conn, code, message string) {
	writeResponse(conn, &Response{
		Success:      false,
		Status:       auth.StatusError,
		ErrorCode:    code,
		ErrorMessage: message,
	})
}

// writeResponse is the only place a reply reaches the socket, so it is the only
// place that has to remember to stamp the protocol version. Every reply carries
// it, including the errors written before dispatch: a client that cannot parse a
// reply should still be able to tell whether it was talking to a broker speaking
// a contract it knows.
func writeResponse(conn net.Conn, resp *Response) {
	resp.ProtocolVersion = ProtocolVersion
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		log.Error().Err(err).Msg("Encode IPC response")
	}
}

func authResponseToIPC(ar *auth.AuthResponse) *Response {
	return &Response{
		Success:          ar.Success,
		Status:           ar.Status,
		UserID:           ar.UserID,
		Email:            ar.Email,
		Groups:           ar.Groups,
		SessionID:        ar.SessionID,
		DeviceCode:       ar.DeviceCode,
		DeviceURL:        ar.DeviceURL,
		QRCode:           ar.QRCode,
		ExpiresAt:        ar.ExpiresAt,
		RequiresDevice:   ar.RequiresDevice,
		RequiresApproval: ar.RequiresApproval,
		ErrorCode:        ar.ErrorCode,
		ErrorMessage:     ar.ErrorMessage,
		Metadata:         ar.Metadata,
	}
}

func formatInstructions(loginType, deviceURL, deviceCode, qrCode string) string {
	switch loginType {
	case "console":
		return auth.FormatConsoleInstructions(deviceURL, deviceCode, qrCode)
	case "gui":
		return auth.FormatGUIInstructions(deviceURL, deviceCode, qrCode)
	default: // ssh
		return auth.FormatDeviceInstructions(deviceURL, deviceCode, qrCode)
	}
}

// evictRateLimitWindows periodically cleans up stale rate-limit entries.
//
// Every limiter the server owns has to be swept here. This used to sweep only
// rateLimiter, whose key space is the host's UIDs and therefore tiny; the one it
// missed, sessionLimiter, is the one keyed on something a caller supplies, so it
// grew one permanent entry per session ID ever named.
func (s *Server) evictRateLimitWindows(ctx context.Context) {
	defer s.wg.Done()
	interval := s.evictInterval
	if interval <= 0 {
		interval = defaultEvictInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.evictNow()
		}
	}
}

// evictNow sweeps every rate limiter once.
func (s *Server) evictNow() {
	s.rateLimiter.evict()
	s.sessionLimiter.evict()
	s.newSessionLimiter.evict()
}
