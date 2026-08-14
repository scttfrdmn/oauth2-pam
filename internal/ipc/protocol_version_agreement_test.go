package ipc

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// The C bridge declares its own copy of the protocol version, because a #define
// cannot be imported from Go. Two copies of a constant is two chances to bump one
// and forget the other, and the failure is quiet in the worst way: the module
// refuses every reply the broker sends, so every login on the host fails with a
// "broker speaks protocol version N" line and nothing else looks wrong.
//
// This test is plain text parsing on purpose. It has no build tag and does not
// need cgo, PAM headers, or Linux, so it runs on the developer's macOS machine
// where the C half cannot even be compiled — which is precisely where the two
// constants are most likely to drift apart.
func TestCBridgeProtocolVersionAgrees(t *testing.T) {
	header := filepath.Join("..", "..", "cmd", "pam-module", "cgo_bridge.h")
	src, err := os.ReadFile(header)
	if err != nil {
		t.Fatalf("read %s: %v", header, err)
	}

	// A #define, not a comment mentioning one: anchored to the start of a line.
	re := regexp.MustCompile(`(?m)^#define[ \t]+PROTOCOL_VERSION[ \t]+(\d+)`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatalf("no `#define PROTOCOL_VERSION <n>` in %s; if the C bridge stopped "+
			"declaring a version, this test is what tells you the contract lost an end", header)
	}

	got, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("PROTOCOL_VERSION %q in %s is not a number: %v", m[1], header, err)
	}
	if got != ProtocolVersion {
		t.Errorf("PROTOCOL_VERSION is %d in %s but internal/ipc.ProtocolVersion is %d.\n"+
			"Bump both together, and update docs/wire-protocol.md: the module would "+
			"refuse every reply from this broker.", got, header, ProtocolVersion)
	}
}

// The spec is part of the contract, not commentary on it, so a version bump that
// leaves the document behind is a bug the same way a stale comment is. This only
// checks that the document exists and names the current version — it cannot check
// that the prose is right.
func TestWireProtocolSpecNamesTheCurrentVersion(t *testing.T) {
	spec := filepath.Join("..", "..", "docs", "wire-protocol.md")
	src, err := os.ReadFile(spec)
	if err != nil {
		t.Fatalf("read %s: %v", spec, err)
	}

	want := "version " + strconv.Itoa(ProtocolVersion)
	re := regexp.MustCompile(`(?i)\bversion[ \t]+` + strconv.Itoa(ProtocolVersion) + `\b`)
	if !re.Match(src) {
		t.Errorf("%s never mentions %q, but internal/ipc.ProtocolVersion is %d; "+
			"the spec is the contract two implementations share, so a version bump "+
			"has to reach it", spec, want, ProtocolVersion)
	}
}
