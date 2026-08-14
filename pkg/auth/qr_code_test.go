package auth

import (
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

func TestQRCodeIsIncludedWhenSupplied(t *testing.T) {
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
			withoutQR := format(testDeviceURL, testUserCode, "")

			switch name {
			case "gui":
				// A GUI login manager renders a plain-text dialog; ASCII art
				// would be unreadable there, so it is deliberately omitted.
				if withQR != withoutQR {
					t.Error("the GUI format embedded the ASCII QR code")
				}
			default:
				if !strings.Contains(withQR, qr) {
					t.Error("the QR code was not embedded")
				}
				if withQR == withoutQR {
					t.Error("supplying a QR code made no difference")
				}
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

// TestFormattingLeavesARealQRCodeIntact: the ASCII QR code is block-drawing
// runes and newlines by construction, and sanitizing it as if it were a
// single-line value would collapse it into one unreadable line for everybody.
func TestFormattingLeavesARealQRCodeIntact(t *testing.T) {
	qr, err := GenerateQRCode(testDeviceURL)
	if err != nil {
		t.Fatalf("GenerateQRCode: %v", err)
	}

	for name, format := range allFormatters() {
		if name == "gui" {
			continue // deliberately omits the QR code; see the test above
		}
		t.Run(name, func(t *testing.T) {
			out := format(testDeviceURL, testUserCode, qr)
			if !strings.Contains(out, qr) {
				t.Errorf("the QR code did not survive formatting byte-for-byte.\nwanted (%d lines):\n%s\ngot:\n%s",
					strings.Count(qr, "\n"), qr, out)
			}
			if strings.Contains(out, "control character") {
				t.Errorf("a clean QR code was reported as needing sanitizing:\n%s", out)
			}
		})
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
