package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/pam-oauth2/internal/ipc"
	"github.com/scttfrdmn/pam-oauth2/pkg/config"
	"github.com/scttfrdmn/pam-oauth2/pkg/mapper"
	"github.com/scttfrdmn/pam-oauth2/pkg/provider/github"
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

// TestAuth initiates and polls a device flow for the given username.
func (c *ipcClient) TestAuth(username string) error {
	sessionID := fmt.Sprintf("admin-test-%d", time.Now().UnixNano())

	resp, err := c.send(&ipc.Request{
		Type:      "authenticate",
		UserID:    username,
		LoginType: "ssh",
		SessionID: sessionID,
	})
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("auth failed: %s", resp.ErrorMessage)
	}

	if resp.RequiresDevice {
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

			if !check.RequiresDevice && check.Success {
				log.Info().
					Str("local_user", check.UserID).
					Str("email", check.Email).
					Strs("groups", check.Groups).
					Msg("Authentication successful")
				return nil
			}

			if !check.Success {
				return fmt.Errorf("authorization failed: %s", check.ErrorMessage)
			}

			fmt.Printf("  Waiting... (%ds elapsed)\n", (i+1)*5)
		}
		return fmt.Errorf("timed out waiting for authorization")
	}

	log.Info().
		Str("local_user", resp.UserID).
		Str("email", resp.Email).
		Msg("Authentication successful (cached session)")
	return nil
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

	id := &github.Identity{
		Provider: "github",
		Login:    login,
		Orgs:     orgs,
		Teams:    teams,
	}

	chain := mapper.New(cfg.Mapper)
	result, err := chain.Map(context.Background(), id, "") // "" = skip Tier 0 enrollment in dry-run
	if err != nil {
		log.Error().Err(err).
			Str("login", login).
			Msg("No mapping found")
		return err
	}

	log.Info().
		Str("github_login", login).
		Str("local_user", result.LocalUser).
		Strs("groups", result.Groups).
		Msg("Mapping result")
	return nil
}
