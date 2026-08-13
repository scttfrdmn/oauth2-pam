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
