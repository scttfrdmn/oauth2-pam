package main

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/oauth2-pam/internal/ipc"
)

// These cover the client conformance items in docs/wire-protocol.md that this
// tool violated: it sent no protocol_version, read a reply of any size, and
// accepted a reply written in a version it does not know. The broker's own half is
// covered in internal/ipc; what is checked here is the client's obligations,
// against a fake broker that can be made to break them.

// startFakeBroker answers each connection with whatever handle writes. It decodes
// the request first and hands it over, so a test can assert on what was sent.
func startFakeBroker(t *testing.T, handle func(conn net.Conn, req *ipc.Request)) string {
	t.Helper()

	// Under /tmp rather than t.TempDir(): sun_path caps a socket path at ~104
	// bytes and macOS TMPDIR plus a test name is already longer than that. Same
	// reasoning as internal/ipc/e2e_test.go.
	dir, err := os.MkdirTemp("/tmp", "o2p")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	sock := filepath.Join(dir, "b.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen on %s: %v", sock, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				var req ipc.Request
				if err := json.NewDecoder(io.LimitReader(conn, 64*1024)).Decode(&req); err != nil {
					return
				}
				handle(conn, &req)
			}()
		}
	}()
	return sock
}

func TestSendDeclaresProtocolVersion(t *testing.T) {
	got := make(chan ipc.Request, 1)
	sock := startFakeBroker(t, func(conn net.Conn, req *ipc.Request) {
		got <- *req
		_, _ = io.WriteString(conn, `{"protocol_version":1,"success":false,"status":"pending"}`)
	})

	c, err := newIPCClient(sock)
	if err != nil {
		t.Fatalf("newIPCClient: %v", err)
	}
	if _, err := c.send(&ipc.Request{Type: "check_session"}); err != nil {
		t.Fatalf("send: %v", err)
	}

	req := <-got
	if req.ProtocolVersion != ipc.ProtocolVersion {
		t.Errorf("request protocol_version = %d, want %d", req.ProtocolVersion, ipc.ProtocolVersion)
	}
}

func TestSendRefusesAnUnknownReplyVersion(t *testing.T) {
	sock := startFakeBroker(t, func(conn net.Conn, _ *ipc.Request) {
		_, _ = io.WriteString(conn,
			`{"protocol_version":9999,"success":true,"status":"authorized","user_id":"alice"}`)
	})

	c, err := newIPCClient(sock)
	if err != nil {
		t.Fatalf("newIPCClient: %v", err)
	}
	if _, err := c.send(&ipc.Request{Type: "check_session"}); err == nil {
		t.Fatal("send accepted a reply in protocol version 9999")
	}
}

// A broker predating the field is still answerable: absent means 1.
func TestSendAcceptsAnAbsentReplyVersion(t *testing.T) {
	sock := startFakeBroker(t, func(conn net.Conn, _ *ipc.Request) {
		_, _ = io.WriteString(conn, `{"success":false,"status":"pending"}`)
	})

	c, err := newIPCClient(sock)
	if err != nil {
		t.Fatalf("newIPCClient: %v", err)
	}
	resp, err := c.send(&ipc.Request{Type: "check_session"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Status != "pending" {
		t.Errorf("status = %q, want pending", resp.Status)
	}
}

func TestSendBoundsTheReply(t *testing.T) {
	sock := startFakeBroker(t, func(conn net.Conn, _ *ipc.Request) {
		_, _ = io.WriteString(conn, `{"protocol_version":1,"status":"pending","instructions":"`)
		_, _ = io.WriteString(conn, strings.Repeat("A", maxResponseSize*4))
		_, _ = io.WriteString(conn, `"}`)
	})

	c, err := newIPCClient(sock)
	if err != nil {
		t.Fatalf("newIPCClient: %v", err)
	}
	if _, err := c.send(&ipc.Request{Type: "check_session"}); err == nil {
		t.Fatalf("send accepted a reply of %d bytes with a %d-byte cap",
			maxResponseSize*4, maxResponseSize)
	}
}

// The pair below are one test and its control. TestAuth used to read status alone,
// so an authorized reply the broker had marked success=false was reported as a
// successful authentication.
func TestAuthRefusesAuthorizedWithoutSuccess(t *testing.T) {
	t.Parallel()

	sock := startFakeBroker(t, func(conn net.Conn, req *ipc.Request) {
		switch req.Type {
		case "authenticate":
			_, _ = io.WriteString(conn,
				`{"protocol_version":1,"success":false,"status":"pending","session_id":"s1"}`)
		default:
			_, _ = io.WriteString(conn,
				`{"protocol_version":1,"success":false,"status":"authorized","user_id":"alice"}`)
		}
	})

	c, err := newIPCClient(sock)
	if err != nil {
		t.Fatalf("newIPCClient: %v", err)
	}
	err = c.TestAuth("alice")
	if err == nil {
		t.Fatal("TestAuth reported success for an authorized reply with success=false")
	}
	if !strings.Contains(err.Error(), "success=false") {
		t.Errorf("error does not name the cause: %v", err)
	}
}

func TestAuthAcceptsAuthorizedWithSuccess(t *testing.T) {
	t.Parallel()

	sock := startFakeBroker(t, func(conn net.Conn, req *ipc.Request) {
		switch req.Type {
		case "authenticate":
			_, _ = io.WriteString(conn,
				`{"protocol_version":1,"success":false,"status":"pending","session_id":"s1"}`)
		default:
			_, _ = io.WriteString(conn,
				`{"protocol_version":1,"success":true,"status":"authorized","user_id":"alice"}`)
		}
	})

	c, err := newIPCClient(sock)
	if err != nil {
		t.Fatalf("newIPCClient: %v", err)
	}
	if err := c.TestAuth("alice"); err != nil {
		t.Fatalf("TestAuth: %v", err)
	}
}
