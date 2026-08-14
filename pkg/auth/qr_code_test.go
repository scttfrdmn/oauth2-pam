package auth

import (
	"errors"
	"strings"
	"testing"
)

const (
	testDeviceURL = "https://github.com/login/device?user_code=WDJB-MJHT"
	testUserCode  = "WDJB-MJHT"
)

func allFormatters() map[string]func(string, string, string) string {
	return map[string]func(string, string, string) string{
		"ssh":     FormatDeviceInstructions,
		"console": FormatConsoleInstructions,
		"gui":     FormatGUIInstructions,
	}
}

// TestInstructionsCarryTheCodeAndURL: without both, the user has nothing to
// act on, and the login can only time out.
func TestInstructionsCarryTheCodeAndURL(t *testing.T) {
	for name, format := range allFormatters() {
		t.Run(name, func(t *testing.T) {
			out := format(testDeviceURL, testUserCode, "")
			if !strings.Contains(out, testDeviceURL) {
				t.Errorf("the device URL is missing from:\n%s", out)
			}
			if !strings.Contains(out, testUserCode) {
				t.Errorf("the user code is missing from:\n%s", out)
			}
		})
	}
}

// TestInstructionsDoNotPromiseAutomaticCompletion is the wording contract with
// the PAM module: it shows these instructions as a prompt and waits for a
// keypress before polling. Telling the user that authorization "completes
// automatically" leaves them waiting for something that will not happen.
func TestInstructionsDoNotPromiseAutomaticCompletion(t *testing.T) {
	forbidden := []string{"automatic", "Waiting for authorization", "Waiting..."}

	for name, format := range allFormatters() {
		t.Run(name, func(t *testing.T) {
			out := format(testDeviceURL, testUserCode, "")
			for _, phrase := range forbidden {
				if strings.Contains(out, phrase) {
					t.Errorf("instructions contain %q, which contradicts the Enter keypress the module waits for:\n%s", phrase, out)
				}
			}
		})
	}
}

// TestInstructionsDoNotEmbedTheQRCode is half of the regression test for #56,
// and the half that pins where the single copy of the art lives.
//
// A reply carries the QR code in its own qr_code field. Embedding it in
// instructions as well put every byte of the largest thing in the largest reply
// on the wire twice — a doubling the provider chose the size of, since the art
// is a function of its verification_uri. The formatters still take the argument
// so the shape of the contract is unchanged; they must not write it anywhere.
func TestInstructionsDoNotEmbedTheQRCode(t *testing.T) {
	qr, err := GenerateQRCode(testDeviceURL)
	if err != nil {
		t.Fatalf("GenerateQRCode: %v", err)
	}
	if qr == "" {
		t.Fatal("GenerateQRCode returned an empty string")
	}

	for name, format := range allFormatters() {
		t.Run(name, func(t *testing.T) {
			withQR := format(testDeviceURL, testUserCode, qr)
			if withQR != format(testDeviceURL, testUserCode, "") {
				t.Error("supplying a QR code changed the instructions, so the art is serialized twice")
			}
			if strings.Contains(withQR, qr) {
				t.Errorf("the QR code was embedded in the instructions:\n%s", withQR)
			}
			// A line of the art is enough to catch a partial copy, which the
			// whole-string check above would miss.
			for _, line := range strings.Split(strings.TrimRight(qr, "\n"), "\n") {
				if len(line) > 8 && strings.Contains(withQR, line) {
					t.Errorf("a row of the QR code appears in the instructions: %q", line)
				}
			}
		})
	}
}

// TestQRCodeIsSkippedForAnOverlongURL is the other half of #56: the input to the
// encoder is a provider's verification_uri, a QR symbol grows superlinearly in
// it, and the module's reply buffer is fixed. Above the bound there must be no
// art at all — and the caller must be told why, because "the provider sent a
// 2 KB URL" and "the encoder is broken" are the same fallback and different
// things for an operator to go and look at.
func TestQRCodeIsSkippedForAnOverlongURL(t *testing.T) {
	atTheBound := testDeviceURL + strings.Repeat("a", maxQRCodeURLBytes-len(testDeviceURL))
	if len(atTheBound) != maxQRCodeURLBytes {
		t.Fatalf("test URL is %d bytes, want %d", len(atTheBound), maxQRCodeURLBytes)
	}

	if qr, err := GenerateQRCode(atTheBound); err != nil || qr == "" {
		t.Errorf("a URL of exactly %d bytes was refused: qr=%d bytes, err=%v",
			maxQRCodeURLBytes, len(qr), err)
	}

	// One byte over, and the length the issue's dangerous band is drawn around.
	for _, n := range []int{maxQRCodeURLBytes + 1, 300, 1029, 2029} {
		long := testDeviceURL + strings.Repeat("a", n-len(testDeviceURL))
		qr, err := GenerateQRCode(long)
		if qr != "" {
			t.Errorf("a %d-byte URL still produced %d bytes of QR code", n, len(qr))
		}
		if !errors.Is(err, ErrURLTooLongForQR) {
			t.Errorf("a %d-byte URL returned err = %v, want ErrURLTooLongForQR", n, err)
		}
	}
}

// TestAnOverlongVerificationURICannotInflateTheInstructions walks the same path
// the broker does — sanitize, then encode — and pins the size of what comes out.
// The 16 KiB is the module's MAX_RESPONSE_SIZE, which is the buffer the whole
// reply has to fit in, so instructions alone need to be well inside it.
func TestAnOverlongVerificationURICannotInflateTheInstructions(t *testing.T) {
	// A provider-chosen URL from the middle of the band where the QR art used to
	// cross the buffer on its own.
	hostile := "https://ghes.corp.example/login/device?x=" + strings.Repeat("ab", 1000)

	deviceURL := SanitizePromptValue(hostile)
	qr, err := GenerateQRCode(deviceURL)
	if err == nil {
		t.Fatalf("a %d-byte URL was encoded into %d bytes of QR code", len(deviceURL), len(qr))
	}

	const maxPromptSize = 16384
	for name, format := range allFormatters() {
		t.Run(name, func(t *testing.T) {
			// qr is "" here, but pass what the encoder returned rather than a
			// literal: a formatter that started embedding the argument again
			// should fail this test as well as the one above.
			out := format(deviceURL, testUserCode, qr)
			if len(out) >= maxPromptSize {
				t.Errorf("instructions are %d bytes for a %d-byte URL, which does not fit the module's %d-byte buffer",
					len(out), len(hostile), maxPromptSize)
			}
			// The URL is echoed once and the login is still usable.
			if !strings.Contains(out, testUserCode) {
				t.Error("the user code is missing, so the user has nothing to act on")
			}
		})
	}
}

// hostileDeviceURL and hostileUserCode are what a compromised or hostile
// provider can return. For github.com this cannot happen, but a configured
// GitHub Enterprise base_url chooses both verification_uri and user_code, and
// the instructions built from them are printed to the terminal by the PAM
// conversation function, as root, before authentication completes. Left
// verbatim, that is an arbitrary-draw primitive on a pre-auth terminal.
const (
	// Clear the screen, home the cursor, and draw a convincing password prompt
	// over the top of the real one.
	hostileDeviceURL = "https://ghes.corp.example/login/device" +
		"\x1b[2J\x1b[H\x1b[1;1fPassword: \x1b[8m"
	// Colour, a bare ESC, a CR to overwrite the line, a NUL, a DEL, a C1 CSI,
	// and a newline to break out of the template's line.
	hostileUserCode = "WDJB\x1b[31m\x1b\rMJHT\x00\x7f\u009b31m\x9b7m\nsudo password: "
)

// TestInstructionsSanitizeProviderStrings is the regression test for the
// finding. It asserts the property rather than an expected string, so that it
// keeps working when the template wording changes: whatever the formatters
// emit, it must carry no control character other than the newlines the trusted
// template itself writes.
func TestInstructionsSanitizeProviderStrings(t *testing.T) {
	qr, err := GenerateQRCode(testDeviceURL)
	if err != nil {
		t.Fatalf("GenerateQRCode: %v", err)
	}

	for name, format := range allFormatters() {
		t.Run(name, func(t *testing.T) {
			for _, qrCode := range []string{"", qr, "block\x1b[2J\n"} {
				out := format(hostileDeviceURL, hostileUserCode, qrCode)
				// Newline is allowed: the template is multi-line and trusted.
				assertNoDisallowedRunes(t, true, out)
			}
		})
	}
}

// TestInstructionsKeepProviderValuesOnTheirOwnLine is the reason the value
// policy is stricter than the template's. A provider that can emit a newline
// can put text at the start of a line, which is what makes a fake prompt
// convincing; a value confined to the middle of a template line cannot.
func TestInstructionsKeepProviderValuesOnTheirOwnLine(t *testing.T) {
	for name, format := range allFormatters() {
		t.Run(name, func(t *testing.T) {
			out := format(hostileDeviceURL, hostileUserCode, "")
			for i, line := range strings.Split(out, "\n") {
				for _, injected := range []string{"Password:", "sudo password:"} {
					if strings.HasPrefix(strings.TrimSpace(line), injected) {
						t.Errorf("line %d begins with the injected %q, so the provider started a line of its own:\n%s",
							i+1, injected, out)
					}
				}
			}
		})
	}
}

// TestInstructionsSayWhenTheyDroppedSomething: a sanitizer that quietly mangles
// a URL leaves the operator debugging a broken login with no clue that the
// provider sent something it should not have.
func TestInstructionsSayWhenTheyDroppedSomething(t *testing.T) {
	for name, format := range allFormatters() {
		t.Run(name, func(t *testing.T) {
			out := format(hostileDeviceURL, hostileUserCode, "")
			if !strings.Contains(out, "control character") {
				t.Errorf("the instructions do not mention that anything was removed:\n%s", out)
			}
		})
	}
}

// TestTheReplyCarriesARealQRCodeIntact is where the old formatting test moved
// to, because the property moved: the art is no longer written into instructions,
// so the qr_code field is the one place it has to arrive undamaged. It is
// block-drawing runes and newlines by construction, and running it through the
// single-line value policy would collapse it into one unreadable row for
// everybody, which is why the broker uses the block policy on it.
func TestTheReplyCarriesARealQRCodeIntact(t *testing.T) {
	b := startBroker(t, brokerConfig(t), newFakeProvider("acme"))

	resp, err := b.Authenticate(&AuthRequest{UserID: "alice", LoginType: "ssh"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	want, err := GenerateQRCode(resp.DeviceURL)
	if err != nil {
		t.Fatalf("GenerateQRCode: %v", err)
	}
	if resp.QRCode != want {
		t.Errorf("qr_code did not survive the broker byte-for-byte.\nwanted (%d lines):\n%s\ngot:\n%s",
			strings.Count(want, "\n"), want, resp.QRCode)
	}
	if strings.Contains(resp.QRCode, "control character") {
		t.Errorf("a clean QR code was reported as needing sanitizing:\n%s", resp.QRCode)
	}
}

// TestInstructionsFitTheModulePromptBuffer: the module copies the instructions
// into a fixed 16 KB field (MAX_RESPONSE_SIZE in cgo_bridge.h) and strncpy
// silently truncates anything longer — which would cut the code off the end of
// the message the user is looking at.
func TestInstructionsFitTheModulePromptBuffer(t *testing.T) {
	qr, err := GenerateQRCode(testDeviceURL)
	if err != nil {
		t.Fatalf("GenerateQRCode: %v", err)
	}

	const maxPromptSize = 16384
	for name, format := range allFormatters() {
		t.Run(name, func(t *testing.T) {
			if n := len(format(testDeviceURL, testUserCode, qr)); n >= maxPromptSize {
				t.Errorf("instructions are %d bytes, which does not fit the module's %d-byte prompt buffer", n, maxPromptSize)
			}
		})
	}
}
