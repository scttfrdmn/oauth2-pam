package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
)

// What this command draws on a root terminal — #102.
//
// The broker sanitizes verification_uri and user_code before they reach a pre-auth
// tty (broker.go:386, and #45 for why). This command reaches a terminal with the
// same two strings out of the same StartDeviceFlow return value, and until #102 it
// printed them with a bare %s — the only place in the tree where provider bytes
// got to a terminal unfiltered, and the terminal in question is already root.
//
// pkg/auth/sanitize_test.go tests the sanitizer. This tests the call site, which
// is the half that was missing: a test of the function cannot notice a caller that
// does not call it.

// hostileFlow is what a malicious or compromised GitHub Enterprise returns. The
// escapes are the ones that matter rather than an arbitrary sample: CSI 2J clears
// the screen, CSI H homes the cursor, and OSC 0 ; ... ST followed by CSI 21 t is
// the terminal answerback attack, which makes an xterm-family terminal type the
// attacker's text into its own input queue. Because this command never reads
// stdin, that text is left for the invoking root shell.
func hostileFlow() *provider.DeviceFlow {
	return &provider.DeviceFlow{
		DeviceCode:      "notprinted",
		UserCode:        "WDJB\x1b]0;rm -rf /\x07-MJHT",
		DeviceURL:       "https://ghes.example/login/device\x1b[2J\x1b[H[sudo] password for admin: ",
		ExpiresAt:       time.Now().Add(15 * time.Minute),
		PollingInterval: 5,
	}
}

func TestTheDeviceInstructionsCarryNoProviderChosenControlCharacters(t *testing.T) {
	var out bytes.Buffer
	printDeviceInstructions(&out, "alice", "github", hostileFlow())
	got := out.String()

	// Every rune the sanitizer's policy removes, checked here rather than trusting
	// the policy: this asserts what reaches the terminal, not what the sanitizer
	// says it does. Newline is the exception — the template's own newlines are the
	// layout, and SanitizePromptValue removes newlines from the values.
	for i, r := range got {
		switch {
		case r == '\n':
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f, r == '\u2028', r == '\u2029':
			t.Errorf("byte %d of the instructions is control character %#U; "+
				"a provider that chooses this can clear an operator's root terminal and draw a "+
				"fake sudo prompt on it", i, r)
		}
	}
	if !utf8.ValidString(got) {
		t.Error("the instructions are not valid UTF-8; a raw 0x9b is a CSI to a terminal reading bytes")
	}
}

// TestTheDeviceInstructionsStillSayWhatToDo is the control. Removing every
// character would pass the test above and leave the operator with nothing to act
// on, and the sanitizer is deliberately lossy — so pin that the parts the operator
// needs survive, and that the tampering is visible rather than silently repaired.
func TestTheDeviceInstructionsStillSayWhatToDo(t *testing.T) {
	var out bytes.Buffer
	printDeviceInstructions(&out, "alice", "github", hostileFlow())
	got := out.String()

	for _, want := range []string{
		`"alice"`,                           // who is being enrolled
		"github",                            // against what
		"https://ghes.example/login/device", // where to go, minus the escapes
		"WDJB",                              // and the code to type there
		"MJHT",
		"control character(s) removed", // and that something was taken out
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the instructions do not contain %q; operator sees:\n%s", want, got)
		}
	}
}

// TestCleanDeviceInstructionsAreUnchanged: the github.com case, which is every
// real deployment. A sanitizer that marked or mangled ordinary values would put a
// "[!]" on every enrollment and train operators to ignore it.
func TestCleanDeviceInstructionsAreUnchanged(t *testing.T) {
	var out bytes.Buffer
	printDeviceInstructions(&out, "alice", "github", &provider.DeviceFlow{
		UserCode:  "WDJB-MJHT",
		DeviceURL: "https://github.com/login/device",
		ExpiresAt: time.Now().Add(15 * time.Minute),
	})
	got := out.String()

	if !strings.Contains(got, "  Visit:      https://github.com/login/device\n") {
		t.Errorf("the URL was altered on a clean value; operator sees:\n%s", got)
	}
	if !strings.Contains(got, "  User Code:  WDJB-MJHT\n") {
		t.Errorf("the user code was altered on a clean value; operator sees:\n%s", got)
	}
	if strings.Contains(got, "[!]") {
		t.Errorf("a clean device flow was reported as tampered with; operator sees:\n%s", got)
	}
}
