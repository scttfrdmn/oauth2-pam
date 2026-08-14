package ipc

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oauth2-pam/pkg/auth"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

// wireBytes runs resp through writeResponse over a real connection and returns
// exactly what a client would read. The cap is a property of the bytes on the
// socket, so a test that measured a marshalled struct instead would be measuring
// something the client never sees.
func wireBytes(t *testing.T, resp *Response) []byte {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		writeResponse(server, resp)
		_ = server.Close()
	}()

	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	<-done
	return got
}

// pendingReply builds the first reply to an authenticate the way
// handleAuthenticate does, from the values a provider chose. deviceURL goes
// through the same sanitize-then-encode path as pkg/auth uses, so the QR code
// here is the real go-qrcode output for a real URL and not a stand-in.
func pendingReply(t *testing.T, deviceURL, userCode string) (*Response, string) {
	t.Helper()

	deviceURL = auth.SanitizePromptValue(deviceURL)
	userCode = auth.SanitizePromptValue(userCode)

	qr, err := auth.GenerateQRCode(deviceURL)
	if err != nil {
		qr = "" // exactly what the broker does: no QR code, still a login
	}

	ar := &auth.AuthResponse{
		Status:         auth.StatusPending,
		SessionID:      strings.Repeat("ab", 16),
		DeviceCode:     userCode,
		DeviceURL:      deviceURL,
		QRCode:         qr,
		ExpiresAt:      time.Now().Add(10 * time.Minute),
		RequiresDevice: true,
		Metadata: map[string]string{
			"provider":         "github",
			"polling_interval": "5",
			"provider_login":   "alice",
		},
	}

	resp := authResponseToIPC(ar)
	resp.Instructions = formatInstructions("ssh", ar.DeviceURL, ar.DeviceCode, ar.QRCode)
	return resp, qr
}

// TestTheQRCodeIsSerializedOnce is the wire half of the #56 regression. The art
// used to travel in the qr_code field *and* inside instructions, so the largest
// reply carried the largest field twice — and the provider chose how large that
// field was, since it is the QR encoding of its own verification_uri.
//
// It counts occurrences in the serialized reply rather than checking the two
// fields, so it also catches a third copy arriving in some field nobody has
// thought of yet.
func TestTheQRCodeIsSerializedOnce(t *testing.T) {
	resp, qr := pendingReply(t, "https://github.com/login/device", "WDJB-MJHT")
	if qr == "" {
		t.Fatal("no QR code was generated, so this test would prove nothing")
	}

	wire := string(wireBytes(t, resp))

	// Inside a JSON string the art is itself, with its newlines escaped. That is
	// the form to count, and counting it also proves the field is not empty.
	encoded := strings.ReplaceAll(qr, "\n", `\n`)
	if n := strings.Count(wire, encoded); n != 1 {
		t.Errorf("the QR code appears %d times in the reply, want exactly 1", n)
	}

	// And row by row, in case a partial copy is ever reintroduced. Rows repeat
	// inside the art — the quiet-zone rows are identical — so the assertion is
	// that the reply contains each row as often as the art does and no oftener.
	for _, row := range strings.Split(strings.TrimRight(qr, "\n"), "\n") {
		if len(row) <= 8 {
			continue
		}
		if got, want := strings.Count(wire, row), strings.Count(qr, row); got != want {
			t.Fatalf("a row of the QR code appears %d times in the reply and %d times in the art: %q",
				got, want, row)
		}
	}
}

// TestAnOverlongVerificationURICannotInflateTheReply is the other half. Every
// length here was a reply that did not fit the module's 16 KiB buffer before the
// bound in pkg/auth existed: a ~300-byte verification_uri crossed it, and a 2 KB
// one produced tens of kilobytes of block characters. The provider does not get
// to decide whether a login fits.
func TestAnOverlongVerificationURICannotInflateTheReply(t *testing.T) {
	for _, n := range []int{85, 200, 300, 512, 1029, 2029, 2300, 4096} {
		base := "https://ghes.corp.example/login/device?x="
		deviceURL := base + strings.Repeat("ab", n)[:n-len(base)]
		if len(deviceURL) != n {
			t.Fatalf("test URL is %d bytes, want %d", len(deviceURL), n)
		}

		resp, _ := pendingReply(t, deviceURL, "WDJB-MJHT")
		wire := wireBytes(t, resp)

		if len(wire) > maxResponseSize {
			t.Errorf("a %d-byte verification_uri produced a %d-byte reply, over the %d-byte cap",
				n, len(wire), maxResponseSize)
		}

		// The reply must still be a usable pending answer, not a truncated or
		// substituted one: dropping the QR code is the graceful degradation, and
		// hitting the cap instead would mean the login fails.
		var decoded Response
		if err := json.Unmarshal(wire, &decoded); err != nil {
			t.Fatalf("a %d-byte verification_uri produced an unparseable reply: %v", n, err)
		}
		if decoded.ErrorCode != "" {
			t.Errorf("a %d-byte verification_uri turned the reply into %q", n, decoded.ErrorCode)
		}
		if decoded.Status != auth.StatusPending || decoded.SessionID == "" {
			t.Errorf("a %d-byte verification_uri lost the pending session: status=%q session_id=%q",
				n, decoded.Status, decoded.SessionID)
		}
	}
}

// TestAnOversizedReplyIsReplacedRatherThanTruncated covers the cap itself, with a
// reply no provider can currently produce — because the belt has to work when the
// bounds upstream of it do not. A reply over the client's MAX_RESPONSE_SIZE is not
// a big reply, it is a login that fails with "could not parse broker response" in
// the log, so the broker says what happened instead.
func TestAnOversizedReplyIsReplacedRatherThanTruncated(t *testing.T) {
	resp, _ := pendingReply(t, "https://github.com/login/device", "WDJB-MJHT")
	resp.ErrorMessage = strings.Repeat("x", maxResponseSize)

	wire := wireBytes(t, resp)
	if len(wire) > maxResponseSize {
		t.Fatalf("an oversized reply went out at %d bytes, over the %d-byte cap", len(wire), maxResponseSize)
	}

	var decoded Response
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("the substituted reply does not parse: %v", err)
	}
	if decoded.ErrorCode != "RESPONSE_TOO_LARGE" {
		t.Errorf("error_code = %q, want RESPONSE_TOO_LARGE", decoded.ErrorCode)
	}
	if decoded.Status != auth.StatusError || decoded.Success {
		t.Errorf("substituted reply is success=%v status=%q, want false/error", decoded.Success, decoded.Status)
	}
	if decoded.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocol_version = %d, want %d; every reply carries it, this one included",
			decoded.ProtocolVersion, ProtocolVersion)
	}
	// Nothing from the oversized reply is copied forward — whatever made it
	// oversized is in one of those fields.
	if strings.Contains(string(wire), strings.Repeat("x", 64)) {
		t.Error("the substituted reply carried the oversized field forward")
	}
	if decoded.QRCode != "" || decoded.Instructions != "" || decoded.SessionID != "" {
		t.Error("the substituted reply carried fields from the reply it replaced")
	}
}

// TestARealFirstReplyIsWellUnderTheCap is the sizing claim in
// docs/wire-protocol.md, kept honest by measurement rather than by memory: the
// figure in that document was once "2–3 KiB" for a reply that was already twice
// that. If this fails, the document needs re-measuring, not the number here
// loosening.
func TestARealFirstReplyIsWellUnderTheCap(t *testing.T) {
	resp, _ := pendingReply(t, "https://github.com/login/device", "WDJB-MJHT")
	n := len(wireBytes(t, resp))

	// Half the cap. Not a tight bound — a claim about headroom, which is what the
	// document promises a client implementer.
	if n > maxResponseSize/2 {
		t.Errorf("the github.com first reply is %d bytes, over half the %d-byte cap; docs/wire-protocol.md's sizing figure needs re-measuring",
			n, maxResponseSize)
	}
	t.Logf("github.com first reply: %d bytes on the wire", n)
}

// TestAnAuthorizedReplyFitsTheCapWhateverTheProviderAndMapperSay is the #88
// regression test, and the case every test in this file used to skip: they all
// build their reply with pendingReply — the *first* reply, which carries no email,
// no groups and no provider_login. TestAnOversizedReplyIsReplacedRatherThanTruncated
// even states the assumption this closes, "with a reply no provider can currently
// produce". An authorized reply carries three fields the broker does not choose the
// length of, and nothing anywhere constructed one and measured it.
//
// The mapper rule here declares 700 groups, which pkg/mapper's own comment used to
// endorse ("a user in a thousand groups is a few tens of KB, so 1 MB is
// generous"), and the fake provider answers with a 17 KB email, which needs no
// operator mistake at all — a compromised or misconfigured GHES named by
// api_base_url is enough.
//
// What made this more than a failed login is the residue: the session stays
// authorized and active behind a RESPONSE_TOO_LARGE, counts toward
// max_concurrent_sessions, and holds a live token for token_lifetime. Ten attempts
// and the user is locked out for eight hours behind ten authorized sessions no
// client can resolve. So the assertions are both halves: the reply fits, and the
// login works.
func TestAnAuthorizedReplyFitsTheCapWhateverTheProviderAndMapperSay(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		groups := make([]string, 700)
		for i := range groups {
			groups[i] = fmt.Sprintf("research-computing-group-%03d", i)
		}
		c.Mapper.Rules[0].Groups = groups
	})
	h.fake.setEmail(strings.Repeat("a", 17000) + "@example.com")

	start := h.authenticate("alice")
	if start.Status != auth.StatusPending {
		t.Fatalf("status = %q, want pending", start.Status)
	}
	h.fake.grant()

	resp := h.waitForTerminal(start.SessionID)
	if resp.ErrorCode == "RESPONSE_TOO_LARGE" {
		t.Fatalf("check_session answered RESPONSE_TOO_LARGE: the session is authorized and holding a token, "+
			"and no client can ever resolve it (status=%q)", resp.Status)
	}
	if !resp.Success || resp.Status != auth.StatusAuthorized {
		t.Fatalf("status = %q success = %v error = %q; the login has to work",
			resp.Status, resp.Success, resp.ErrorMessage)
	}
	if resp.UserID != "alice" {
		t.Errorf("user_id = %q, want alice", resp.UserID)
	}
	if len(resp.Groups) != 0 {
		t.Errorf("got %d groups on the wire, want none: 700 does not fit", len(resp.Groups))
	}
	if resp.Metadata["groups_omitted"] != "true" {
		t.Error("metadata.groups_omitted is not set, so a client cannot tell a dropped list from no membership")
	}

	// The reply measured as bytes, against the cap itself. The socket handed back a
	// decoded object above, which cannot answer "how close was that to 16384" — and
	// a reply that fits only because writeResponse replaced it would have passed
	// every assertion so far if the status check had not been made first.
	ar, err := h.broker.CheckSession(start.SessionID)
	if err != nil {
		t.Fatalf("CheckSession: %v", err)
	}
	wire := wireBytes(t, authResponseToIPC(ar))
	if len(wire) > maxResponseSize {
		t.Errorf("the authorized reply is %d bytes, over the %d-byte cap", len(wire), maxResponseSize)
	}
	if strings.Contains(string(wire), "RESPONSE_TOO_LARGE") {
		t.Error("the authorized reply was replaced rather than sent")
	}
	// Headroom, not just a fit: the cap is a detector and the field bounds in
	// pkg/auth are the enforcement point, so an authorized reply has no business
	// approaching it.
	if len(wire) > maxResponseSize/2 {
		t.Errorf("the authorized reply is %d bytes, over half the %d-byte cap", len(wire), maxResponseSize)
	}
	t.Logf("authorized reply for a 700-group, 17 KB-email session: %d bytes on the wire", len(wire))
}
