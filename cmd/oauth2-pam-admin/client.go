package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/internal/ipc"
	"github.com/scttfrdmn/oauth2-pam/pkg/auth"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/mapper"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
)

// ipcClient is a thin client for the broker IPC socket.
type ipcClient struct {
	socketPath string
}

func newIPCClient(socketPath string) (*ipcClient, error) {
	return &ipcClient{socketPath: socketPath}, nil
}

func (c *ipcClient) Close() {}

func (c *ipcClient) send(req *ipc.Request) (*ipc.Response, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial broker: %w", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	var resp ipc.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
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
		log.Error().Err(err).
			Str("login", login).
			Msg("No mapping found")
		return err
	}

	log.Info().
		Str("login", login).
		Str("local_user", result.LocalUser).
		Strs("groups", result.Groups).
		Msg("Mapping result")
	return nil
}
