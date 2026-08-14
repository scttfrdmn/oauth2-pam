package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
)

// unreachableProvider fails to start a device flow the way a real HTTP client
// does: with the URL it dialled and the address behind it in the error string.
// For a host configured against a GitHub Enterprise Server, that is the
// deployment's internal name and IP.
type unreachableProvider struct {
	*fakeProvider
}

const unreachableDetail = `Post "https://ghes.corp.internal:8443/login/device/code": ` +
	`dial tcp 10.1.2.3:8443: connect: connection refused`

func (u unreachableProvider) StartDeviceFlow(context.Context) (*provider.DeviceFlow, error) {
	return nil, errors.New(unreachableDetail)
}

// TestInternalErrorDetailStaysOffTheWire is broker conformance item 7 in
// docs/wire-protocol.md: "Never puts internal error detail on the wire.
// error_code is a category; the detail belongs in the broker's log."
//
// Both refusals in Authenticate used to answer with err.Error(), and
// internal/ipc copies error_message verbatim to the socket — so an unreachable
// or misconfigured Enterprise deployment put its own hostname and address into
// the reply, and a selection failure echoed back the provider name the client
// sent, unsanitized.
//
// The audience is root, so the disclosure ceiling is low. The contract is the
// point: error_message is documented as being for the log and never for a
// decision, and a client that starts finding detail there is a client that will
// start parsing it.
func TestInternalErrorDetailStaysOffTheWire(t *testing.T) {
	b := startBroker(t, brokerConfig(t), unreachableProvider{newFakeProvider("ghes")})

	t.Run("device flow failure", func(t *testing.T) {
		resp, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if resp.ErrorCode != "DEVICE_FLOW_FAILED" {
			t.Fatalf("error_code = %q, want DEVICE_FLOW_FAILED", resp.ErrorCode)
		}
		assertNoInternalDetail(t, resp.ErrorMessage,
			"ghes.corp.internal", "10.1.2.3", "8443", "connection refused", "Post")
	})

	t.Run("provider selection failure", func(t *testing.T) {
		// The requested name is the client's own bytes coming back out of a root
		// process, which is the second reason not to echo it.
		const asked = "sso.corp.internal"

		resp, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh", Provider: asked})
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if resp.ErrorCode != "NO_PROVIDER" {
			t.Fatalf("error_code = %q, want NO_PROVIDER", resp.ErrorCode)
		}
		assertNoInternalDetail(t, resp.ErrorMessage, asked)
	})
}

// assertNoInternalDetail fails if any of detail appears in the wire message, and
// also if the message is empty: a category with nothing in it would satisfy every
// other assertion while telling an operator's client nothing at all.
func assertNoInternalDetail(t *testing.T, message string, detail ...string) {
	t.Helper()
	if message == "" {
		t.Error("error_message is empty; the category still has to say something")
	}
	for _, d := range detail {
		if strings.Contains(message, d) {
			t.Errorf("error_message contains internal detail %q: %q", d, message)
		}
	}
}

// hostileProvider is a provider whose device flow returns strings laced with
// terminal escapes, as a compromised or malicious GitHub Enterprise deployment
// would: it chooses verification_uri and user_code, and every host configured
// against it prints them.
type hostileProvider struct {
	*fakeProvider
}

// The payload clears the screen, homes the cursor, draws a fake password prompt
// and turns off local echo — the shape of an attack that harvests a Unix password
// from a user who believes they are still talking to sshd.
const hostilePayload = "\x1b[2J\x1b[H\x1b[1;1fPassword: \x1b[8m"

func (h hostileProvider) StartDeviceFlow(ctx context.Context) (*provider.DeviceFlow, error) {
	df, err := h.fakeProvider.StartDeviceFlow(ctx)
	if err != nil {
		return nil, err
	}
	df.UserCode = "ABCD-1234" + hostilePayload
	df.DeviceURL = "https://ghes.corp.example/login/device" + hostilePayload
	return df, nil
}

// TestWireFieldsFromAProviderAreSanitized covers the half of #45 that sanitizing
// the prompt formatters does not reach.
//
// A reply carries device_url, device_code and qr_code as their own fields, and
// docs/wire-protocol.md describes them as "the parts, for a client that wants to
// format its own prompt" — so a consumer this project does not control is
// explicitly invited to draw them on a pre-auth terminal. Cleaning them inside
// this implementation's formatters would leave that consumer holding raw provider
// bytes. The contract has to be clean at the boundary.
//
// The escapes must not survive anywhere in the response, so this asserts the
// property on every field a client might print rather than on one of them.
func TestWireFieldsFromAProviderAreSanitized(t *testing.T) {
	fake := newFakeProvider("ghes")
	b := startBroker(t, brokerConfig(t), hostileProvider{fake})

	resp, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.Status != StatusPending {
		t.Fatalf("status = %q, want pending", resp.Status)
	}

	// Single-line values: no control characters at all, newline included. A value
	// that can emit a newline can start a line of its own, and a line of its own is
	// what makes a forged prompt convincing.
	for _, f := range []struct{ name, got string }{
		{"device_url", resp.DeviceURL},
		{"device_code", resp.DeviceCode},
	} {
		if f.got == "" {
			t.Errorf("%s is empty; sanitizing must not discard the value", f.name)
		}
		assertNoDisallowedRunes(t, false, f.got)
	}

	// qr_code and instructions are multi-line by construction, so newline is the
	// one thing they may contain.
	assertNoDisallowedRunes(t, true, resp.QRCode)

	// ESC is the character every one of these attacks needs; check for it by name
	// as well, so a future sanitizer that somehow permits it fails loudly here and
	// not only through the rune predicate it might share a bug with.
	for _, f := range []struct{ name, got string }{
		{"device_url", resp.DeviceURL},
		{"device_code", resp.DeviceCode},
		{"qr_code", resp.QRCode},
	} {
		if strings.ContainsRune(f.got, 0x1b) {
			t.Errorf("%s still contains ESC: %q", f.name, f.got)
		}
	}

	// The legitimate part of each value must survive; a sanitizer that dropped
	// everything would pass every assertion above.
	if !strings.HasPrefix(resp.DeviceCode, "ABCD-1234") {
		t.Errorf("device_code = %q, want it to still begin with the real code", resp.DeviceCode)
	}
	if !strings.HasPrefix(resp.DeviceURL, "https://ghes.corp.example/login/device") {
		t.Errorf("device_url = %q, want it to still begin with the real URL", resp.DeviceURL)
	}
}
