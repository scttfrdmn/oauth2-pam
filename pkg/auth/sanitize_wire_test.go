package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
)

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
