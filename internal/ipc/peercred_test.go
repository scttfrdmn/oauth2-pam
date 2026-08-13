package ipc

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPeerUIDOnRealUnixSocket exercises whichever peercred implementation this
// platform compiled in, against a real socket. It is the only test that can tell
// a working SO_PEERCRED/LOCAL_PEERCRED call from one that always fails and
// silently degrades to the shared bucket.
func TestPeerUIDOnRealUnixSocket(t *testing.T) {
	if !peerCredsSupported {
		t.Skipf("no peer-credential mechanism on %s", runtime.GOOS)
	}

	// Not t.TempDir(): its path includes the test name, and on macOS that pushes
	// the socket past the ~104-byte sun_path limit, which surfaces as EINVAL.
	dir, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	socket := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	type result struct {
		uid   uint32
		known bool
		err   error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			accepted <- result{err: err}
			return
		}
		defer func() { _ = conn.Close() }()
		uid, known := peerUID(conn)
		accepted <- result{uid: uid, known: known}
	}()

	client, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Close() }()

	got := <-accepted
	if got.err != nil {
		t.Fatalf("accept: %v", got.err)
	}
	if !got.known {
		t.Fatalf("peerUID could not identify the peer, but %s reports support", runtime.GOOS)
	}
	if want := uint32(os.Getuid()); got.uid != want { //nolint:gosec // a UID always fits
		t.Errorf("peerUID = %d, want %d (this process connected to itself)", got.uid, want)
	}
}

// TestPeerUIDOnNonUnixConn covers the type-assertion path. A TCP or in-memory
// connection carries no peer credentials, and peerUID must say so rather than
// return a UID the caller would treat as real.
func TestPeerUIDOnNonUnixConn(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()

	uid, known := peerUID(server)
	if known {
		t.Errorf("peerUID reported uid %d as known for a net.Pipe connection", uid)
	}
}
