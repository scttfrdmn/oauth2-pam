package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/scttfrdmn/oauth2-pam/internal/ipc"
)

var (
	version   = "dev"
	buildDate = "unknown"
	gitCommit = "unknown"
)

var (
	socketPath string
	configPath string
	verbose    bool
)

func main() {
	root := &cobra.Command{
		Use:   "oauth2-pam-admin",
		Short: "Admin CLI for the oauth2-pam authentication broker",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if verbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			} else {
				zerolog.SetGlobalLevel(zerolog.InfoLevel)
			}
			log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		},
	}

	root.PersistentFlags().StringVarP(&socketPath, "socket", "s",
		"/var/run/oauth2-pam/broker.sock", "Broker Unix socket path")
	root.PersistentFlags().StringVarP(&configPath, "config", "c",
		"/etc/oauth2-pam/broker.yaml", "Broker configuration file")
	root.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	root.AddCommand(
		newVersionCmd(),
		newStatusCmd(),
		newTestAuthCmd(),
		newListSessionsCmd(),
		newRevokeSessionCmd(),
		newTestMappingCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			log.Info().
				Str("version", version).
				Str("build_date", buildDate).
				Str("git_commit", gitCommit).
				Msg("oauth2-pam-admin")
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check whether the broker is running and reachable",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newIPCClient(socketPath)
			if err != nil {
				return err
			}
			defer client.Close()

			// Send a check_session with an empty ID; the broker will return
			// SESSION_CHECK_FAILED, which confirms it is alive and responsive.
			_, err = client.send(&ipc.Request{Type: "check_session", SessionID: ""})
			if err != nil {
				return fmt.Errorf("broker unreachable: %w", err)
			}
			log.Info().Str("socket", socketPath).Msg("Broker is reachable")
			return nil
		},
	}
}

func newTestAuthCmd() *cobra.Command {
	var username string
	cmd := &cobra.Command{
		Use:   "test-auth",
		Short: "Start a test authentication flow for a user",
		Long: `Initiate a GitHub Device Flow authentication for the given username.
Displays the device code and URL, then polls until the user completes authorization.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if username == "" {
				return cmd.Usage()
			}

			client, err := newIPCClient(socketPath)
			if err != nil {
				return err
			}
			defer client.Close()

			return client.TestAuth(username)
		},
	}
	cmd.Flags().StringVarP(&username, "user", "u", "", "Username to authenticate (required)")
	_ = cmd.MarkFlagRequired("user")
	return cmd
}

func newListSessionsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-sessions",
		Short: "List active authentication sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newIPCClient(socketPath)
			if err != nil {
				return err
			}
			defer client.Close()

			return client.ListSessions()
		},
	}
}

func newRevokeSessionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke-session <session-id>",
		Short: "Revoke an active authentication session",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := newIPCClient(socketPath)
			if err != nil {
				return err
			}
			defer client.Close()

			return client.RevokeSession(args[0])
		},
	}
}

func newTestMappingCmd() *cobra.Command {
	var githubLogin string
	var orgFlag string
	var teamFlag string

	cmd := &cobra.Command{
		Use:   "test-mapping",
		Short: "Test how a GitHub identity maps to a local Unix user",
		Long: `Evaluate the configured mapper against a synthetic GitHub identity
without performing a real OAuth2 flow. Useful for validating mapping rules.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if githubLogin == "" {
				return cmd.Usage()
			}
			return runTestMapping(configPath, githubLogin, orgFlag, teamFlag)
		},
	}
	cmd.Flags().StringVarP(&githubLogin, "login", "l", "", "GitHub login (required)")
	cmd.Flags().StringVarP(&orgFlag, "org", "o", "", "GitHub org to include in test identity")
	cmd.Flags().StringVarP(&teamFlag, "team", "t", "", "GitHub team to include (format: org/team-slug)")
	_ = cmd.MarkFlagRequired("login")
	return cmd
}
