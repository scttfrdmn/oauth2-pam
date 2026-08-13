package auth

import (
	"fmt"
	"strings"

	"github.com/skip2/go-qrcode"
)

// GenerateQRCode generates an ASCII-art QR code for terminal display.
func GenerateQRCode(url string) (string, error) {
	qr, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("generate QR code: %w", err)
	}
	return qr.ToSmallString(false), nil
}

// The instructions below are delivered to the user as the body of a PAM
// prompt: the module appends its own "press Enter once you have approved"
// line and then blocks on the reply before it starts polling the broker.
//
// So none of these may promise that authorization completes on its own. It
// does not — a user who approves on their phone and waits, having been told
// waiting is all that is required, sits there until the login times out.

// FormatDeviceInstructions formats the device flow prompt for SSH / generic terminal.
func FormatDeviceInstructions(deviceURL, userCode, qrCode string) string {
	var b strings.Builder

	b.WriteString("GitHub Authentication Required\n")
	b.WriteString("═══════════════════════════════════════════════════\n\n")

	if qrCode != "" {
		b.WriteString("Scan QR code with your phone:\n")
		b.WriteString(qrCode)
		b.WriteString("\n")
	}

	b.WriteString("Or visit:  ")
	b.WriteString(deviceURL)
	b.WriteString("\n\n")

	b.WriteString("Enter code: ")
	b.WriteString(userCode)
	b.WriteString("\n\n")

	b.WriteString("Approve the request in your browser, then return here.\n")
	b.WriteString("═══════════════════════════════════════════════════\n")

	return b.String()
}

// FormatConsoleInstructions formats the device flow prompt for a console login.
func FormatConsoleInstructions(deviceURL, userCode, qrCode string) string {
	var b strings.Builder

	b.WriteString("\nGitHub Authentication Required\n\n")

	if qrCode != "" {
		b.WriteString("Scan QR code:\n")
		b.WriteString(qrCode)
		b.WriteString("\n")
	}

	b.WriteString("Visit:  ")
	b.WriteString(deviceURL)
	b.WriteString("\nCode:   ")
	b.WriteString(userCode)
	b.WriteString("\n\nApprove the request, then return here.")

	return b.String()
}

// FormatGUIInstructions formats the device flow prompt for a GUI login manager.
func FormatGUIInstructions(deviceURL, userCode, qrCode string) string {
	var b strings.Builder

	b.WriteString("Authentication Required\n\n")
	b.WriteString("1. Visit: ")
	b.WriteString(deviceURL)
	b.WriteString("\n2. Enter code: ")
	b.WriteString(userCode)
	b.WriteString("\n3. Sign in with your GitHub account\n")
	b.WriteString("4. Return here and confirm to finish signing in")

	return b.String()
}
