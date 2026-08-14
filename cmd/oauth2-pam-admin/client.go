package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/internal/ipc"
	"github.com/scttfrdmn/oauth2-pam/pkg/auth"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/mapper"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
)

// maxResponseSize bounds the reply this client will read: client conformance item
// 8 in docs/wire-protocol.md, "bounds the reply it will read instead of growing a
// buffer to fit". It is MAX_RESPONSE_SIZE from cmd/pam-module/cgo_bridge.h, so
// this tool accepts exactly what the PAM module accepts — a reply too large for
// the module is not one an operator should see reported here as fine.
const maxResponseSize = 16 * 1024

// ipcClient is a thin client for the broker IPC socket.
//
// It is this repository's reference client for the protocol the repository
// specifies, so the conformance items in docs/wire-protocol.md are cited by
// number below rather than left to be inferred.
type ipcClient struct {
	socketPath string
}

func newIPCClient(socketPath string) (*ipcClient, error) {
	return &ipcClient{socketPath: socketPath}, nil
}

func (c *ipcClient) Close() {}

func (c *ipcClient) send(req *ipc.Request) (*ipc.Response, error) {
	// Item 4: say which contract this request is written in. Omitting it worked
	// only because the broker reads an absent version as 1, and that rule exists
	// so a v0.2.x PAM module keeps working — not so this repository's own client
	// can leave the field out.
	req.ProtocolVersion = ipc.ProtocolVersion

	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial broker: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	// Item 8: read at most maxResponseSize, so a broker that answers with
	// megabytes cannot make this tool allocate them. A reply that overruns the cap
	// arrives here as a decode error naming the cap, which is the diagnosis.
	var resp ipc.Response
	if err := json.NewDecoder(io.LimitReader(conn, maxResponseSize+1)).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response (at most %d bytes): %w", maxResponseSize, err)
	}

	// Items 4 and 5: an absent version is 1, so a broker predating the field still
	// answers this tool; a version it does not know is refused rather than read
	// for fields that may no longer mean what they appear to.
	if resp.ProtocolVersion != 0 && resp.ProtocolVersion != ipc.ProtocolVersion {
		return nil, fmt.Errorf("broker replied in protocol version %d, and this client speaks %d",
			resp.ProtocolVersion, ipc.ProtocolVersion)
	}
	return &resp, nil
}

// TestAuth initiates and polls a device flow for the given username. It is the
// same two-phase protocol the PAM module implements, so it doubles as a way to
// exercise the broker end to end without an SSH login.
func (c *ipcClient) TestAuth(username string) error {
	resp, err := c.send(&ipc.Request{
		Type:      "authenticate",
		UserID:    username,
		LoginType: "ssh",
	})
	if err != nil {
		return err
	}

	// Success is deliberately not consulted here: by the broker's first conformance
	// item the reply to authenticate is always success=false, status=pending, and
	// nothing has been authenticated yet. Where success matters is the authorized
	// reply below.
	if resp.Status != auth.StatusPending {
		return fmt.Errorf("auth failed (%s): %s", resp.Status, resp.ErrorMessage)
	}

	// The broker issues its own session ID; a client-supplied one is ignored to
	// prevent session fixation, so poll with the ID it returned.
	sessionID := resp.SessionID
	if sessionID == "" {
		return fmt.Errorf("broker returned no session id")
	}

	fmt.Println(resp.Instructions)
	fmt.Printf("\nPolling for authorization (session: %s)...\n", sessionID)

	for i := 0; i < 60; i++ {
		time.Sleep(5 * time.Second)

		check, err := c.send(&ipc.Request{
			Type:      "check_session",
			SessionID: sessionID,
		})
		if err != nil {
			return err
		}

		switch check.Status {
		case auth.StatusAuthorized:
			// Item 1: authorized *and* success, both. Reading the status alone
			// reports a successful test for a reply the broker did not consider a
			// success, which is the shape of the v0.1.x bypass.
			if !check.Success {
				return fmt.Errorf("broker reported status %q with success=false: %s",
					check.Status, check.ErrorMessage)
			}
			if check.UserID != username {
				// Should never happen: the broker enforces this before
				// activating the session. Refuse anyway.
				return fmt.Errorf("broker authorized %q for a request for %q", check.UserID, username)
			}
			log.Info().
				Str("local_user", check.UserID).
				Str("email", check.Email).
				Strs("groups", check.Groups).
				Msg("Authentication successful")
			return nil
		case auth.StatusPending:
			fmt.Printf("  Waiting... (%ds elapsed)\n", (i+1)*5)
		default:
			return fmt.Errorf("authorization failed (%s): %s", check.Status, check.ErrorMessage)
		}
	}
	return fmt.Errorf("timed out waiting for authorization")
}

// ListSessions requests a session list from the broker.
// The broker does not yet expose a dedicated list endpoint; this is a placeholder.
func (c *ipcClient) ListSessions() error {
	log.Info().Msg("(Session listing requires a running broker with admin endpoint — not yet implemented)")
	return nil
}

// RevokeSession sends a revoke_session request.
func (c *ipcClient) RevokeSession(sessionID string) error {
	resp, err := c.send(&ipc.Request{
		Type:      "revoke_session",
		SessionID: sessionID,
	})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("revoke failed: %s", resp.ErrorMessage)
	}
	log.Info().Str("session_id", sessionID).Msg("Session revoked")
	return nil
}

// runTestMapping exercises the mapper chain with a synthetic identity.
func runTestMapping(cfgPath, login, org, team string) error {
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	// The broker refuses to start on a config that fails this, so a dry run that
	// reported a mapping from one would be answering a question about a
	// configuration that cannot run — and debugging that config is exactly why an
	// operator reaches for this command.
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config %s: %w", cfgPath, err)
	}

	orgs := []string{}
	if org != "" {
		orgs = append(orgs, org)
	}
	teams := []string{}
	if team != "" {
		teams = append(teams, team)
	}

	// A synthetic identity, so the type is "github" only in the sense that the
	// org/team claims are the ones a GitHub provider asserts.
	id := &provider.Identity{
		Provider: "github",
		Type:     "github",
		Login:    login,
	}
	id.AddClaim(provider.ClaimOrg, orgs...)
	id.AddClaim(provider.ClaimTeam, teams...)

	chain := mapper.New(cfg.Mapper)
	result, err := chain.Map(context.Background(), id, "") // "" = skip Tier 0 enrollment in dry-run
	if err != nil {
		// Not necessarily "no mapping": a tier may have produced one and had it
		// refused for resolving to root, a system account, or an account below
		// mapper.min_uid. The error says which, and a dry run is exactly where an
		// operator should find that out.
		log.Error().Err(err).
			Str("login", login).
			Msg("Mapping failed")
		return err
	}

	log.Info().
		Str("login", login).
		Str("local_user", result.LocalUser).
		Strs("groups", result.Groups).
		Msg("Mapping result")
	return nil
}
