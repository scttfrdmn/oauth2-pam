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

	b.WriteString("Waiting for authorization... (completes automatically)\n")
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
	b.WriteString("\n\nWaiting...")

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
	b.WriteString("\n3. Sign in with your GitHub account\n\n")
	b.WriteString("This dialog will close automatically once authentication is complete.")

	return b.String()
}
