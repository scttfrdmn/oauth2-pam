package auth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/skip2/go-qrcode"
)

// maxQRCodeURLBytes is the longest URL this project will draw as a QR code.
//
// The bound exists because a QR symbol grows superlinearly in what it encodes and
// what it encodes is the provider's choice. verification_uri arrives from
// whatever server providers[].base_url names, and go-qrcode turns a 300-byte one
// into about 8 KB of block characters — while the PAM module copies a reply into
// a fixed 16 KiB buffer where strncpy truncates in silence (MAX_RESPONSE_SIZE in
// cmd/pam-module/cgo_bridge.h). Without a bound on this side of the encoder, a
// configured-but-compromised GitHub Enterprise decides whether a login on any
// host pointed at it fits in the buffer at all. That is the amplification
// sanitize.go refuses to hand over for control characters — "amplify its way past
// the end of the prompt" — obtained for free and needing no control characters.
//
// 200 bytes is measured rather than guessed, against the real go-qrcode at
// Medium recovery with a lowercase URL (a real path is lowercase, which puts the
// encoder in byte mode and produces the larger symbol of the two): a 200-byte URL
// is 5610 bytes of QR art and a ~6.9 KB reply, comfortably under half the
// module's buffer and still inside it even if some future change serialized the
// art twice again. For scale, github.com's actual verification_uri is 31 bytes,
// so this is six times the value in front of us; RFC 8628 expects a URI short
// enough for a person to read off a screen and type into a phone, and nothing
// approaching 200 bytes is that.
//
// Over the bound the QR code is skipped, not the login: the instructions still
// carry the URL and the user code as text, which is what the user acts on.
const maxQRCodeURLBytes = 200

// ErrURLTooLongForQR reports a URL over maxQRCodeURLBytes. It is a sentinel
// because the two ways GenerateQRCode can fail have the same fallback and are
// different operator problems: an encoder error is a bug to chase, and this one
// says the provider sent something absurd.
var ErrURLTooLongForQR = errors.New("URL too long to encode as a QR code")

// GenerateQRCode generates an ASCII-art QR code for terminal display.
//
// The length check lives here rather than at the call site for the same reason
// the sanitizing below lives here: there is one encoder and any number of
// callers, so a bound a caller has to remember is a bound the next caller will
// not. See maxQRCodeURLBytes for the number and why it is that number.
func GenerateQRCode(url string) (string, error) {
	if len(url) > maxQRCodeURLBytes {
		return "", fmt.Errorf("%w: %d bytes, limit %d", ErrURLTooLongForQR, len(url), maxQRCodeURLBytes)
	}
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
//
// They are also printed by the module's conversation function, as root, before
// authentication completes, so every formatter below sanitizes its
// provider-supplied arguments before writing them into the template. Doing it
// here rather than at the call site in internal/ipc covers all three prompts
// however they are reached, and cannot be forgotten by a fourth. See
// sanitize.go for the policy and why it differs between a value and a block.
//
// None of them embeds the QR code, though all three still take it. A reply
// already carries the art in its own qr_code field, and writing it into
// instructions as well put every byte of it on the wire twice, in the one reply
// that is by far the largest — the provider choosing the size, and the broker
// then doubling it for nothing. Only one copy can go, and it cannot be the
// field: docs/wire-protocol.md is normative, and removing a reply field is a new
// protocol version there, which a bug fix does not get to allocate. So the
// duplicate that goes is the one inside instructions, which the spec describes
// only as "ready-to-display text" and does not fix the contents of. A client
// that wants to draw a QR code renders the qr_code field, which is what that
// field is for.
//
// The argument is kept rather than removed from the signatures so that this stays
// a change of content and not of shape: formatInstructions in internal/ipc calls
// all three positionally, and a consumer that has copied these formatters should
// see a diff it can read.

// FormatDeviceInstructions formats the device flow prompt for SSH / generic terminal.
func FormatDeviceInstructions(deviceURL, userCode, qrCode string) string {
	// qrCode is deliberately not used; see above. Nothing to sanitize as a result.
	deviceURL = SanitizePromptValue(deviceURL)
	userCode = SanitizePromptValue(userCode)

	var b strings.Builder

	b.WriteString("GitHub Authentication Required\n")
	b.WriteString("═══════════════════════════════════════════════════\n\n")

	b.WriteString("Visit:  ")
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
	// qrCode is deliberately not used; see above. Nothing to sanitize as a result.
	deviceURL = SanitizePromptValue(deviceURL)
	userCode = SanitizePromptValue(userCode)

	var b strings.Builder

	b.WriteString("\nGitHub Authentication Required\n\n")

	b.WriteString("Visit:  ")
	b.WriteString(deviceURL)
	b.WriteString("\nCode:   ")
	b.WriteString(userCode)
	b.WriteString("\n\nApprove the request, then return here.")

	return b.String()
}

// FormatGUIInstructions formats the device flow prompt for a GUI login manager.
func FormatGUIInstructions(deviceURL, userCode, qrCode string) string {
	// qrCode is deliberately not used: a GUI login dialog renders plain text and
	// ASCII art would be unreadable there. Nothing to sanitize as a result.
	deviceURL = SanitizePromptValue(deviceURL)
	userCode = SanitizePromptValue(userCode)

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
