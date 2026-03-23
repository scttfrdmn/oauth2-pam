// Command oauth2-pam-enroll links a local Unix user to a GitHub identity by
// running a Device Authorization Grant flow and writing the result to the
// enrollment file.
//
// Typical usage (run as root or via sudo):
//
//	oauth2-pam-enroll --user alice
//	oauth2-pam-enroll --user alice --remove
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/enrollment"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider/github"
)

var (
	version   = "dev"
	buildDate = "unknown"
	gitCommit = "unknown"
)

func main() {
	root := buildRootCmd()
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func buildRootCmd() *cobra.Command {
	var (
		cfgPath    string
		localUser  string
		groups     []string
		removeMode bool
		verbose    bool
	)

	cmd := &cobra.Command{
		Use:   "oauth2-pam-enroll",
		Short: "Enroll a local Unix user with a GitHub identity for oauth2-pam authentication",
		Long: `oauth2-pam-enroll links a local Unix username to a GitHub account so that
the user can authenticate via the GitHub Device Flow in future PAM sessions.

Run as root (or via sudo) since the enrollment file lives in /etc/oauth2-pam/.

Examples:
  # Enroll the current user
  sudo oauth2-pam-enroll

  # Enroll a specific user
  sudo oauth2-pam-enroll --user alice

  # Enroll with supplementary group overrides
  sudo oauth2-pam-enroll --user alice --groups users,docker

  # Remove an enrollment
  sudo oauth2-pam-enroll --user alice --remove`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				zerolog.SetGlobalLevel(zerolog.DebugLevel)
			} else {
				zerolog.SetGlobalLevel(zerolog.InfoLevel)
			}
			log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

			// Default local user: the user who invoked sudo, or the current user.
			if localUser == "" {
				localUser = callerUsername()
			}
			if localUser == "" {
				return fmt.Errorf("could not determine local username; use --user to specify one")
			}

			cfg, err := config.LoadConfig(cfgPath)
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			enrollFile := cfg.Mapper.EnrollmentFile
			if enrollFile == "" {
				enrollFile = "/etc/oauth2-pam/enrolled-users.yaml"
			}

			if removeMode {
				return runRemove(localUser, enrollFile)
			}
			return runEnroll(localUser, groups, enrollFile, cfg)
		},
	}

	cmd.Flags().StringVarP(&cfgPath, "config", "c", "/etc/oauth2-pam/broker.yaml", "Broker config file")
	cmd.Flags().StringVarP(&localUser, "user", "u", "", "Local Unix username to enroll (default: caller)")
	cmd.Flags().StringSliceVar(&groups, "groups", nil, "Supplementary Unix groups (overrides mapper defaults)")
	cmd.Flags().BoolVar(&removeMode, "remove", false, "Remove an existing enrollment")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose/debug output")

	cmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("oauth2-pam-enroll %s (commit: %s, built: %s)\n", version, gitCommit, buildDate)
		},
	})

	return cmd
}

// callerUsername returns the username of the person who invoked the tool.
// When run under sudo, SUDO_USER holds the original username; otherwise
// fall back to the effective user.
func callerUsername() string {
	if su := os.Getenv("SUDO_USER"); su != "" {
		return su
	}
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// runRemove deletes the enrollment record for localUser.
func runRemove(localUser, enrollFile string) error {
	store, err := enrollment.Load(enrollFile)
	if err != nil {
		return fmt.Errorf("load enrollment file: %w", err)
	}

	if !store.Remove(localUser) {
		return fmt.Errorf("no enrollment found for user %q", localUser)
	}

	if err := store.Save(enrollFile); err != nil {
		return fmt.Errorf("save enrollment file: %w", err)
	}

	log.Info().Str("local_user", localUser).Msg("Enrollment removed")
	return nil
}

// runEnroll runs the Device Flow, confirms the GitHub identity, and writes
// the enrollment record.
func runEnroll(localUser string, groups []string, enrollFile string, cfg *config.Config) error {
	// Verify the local Unix user exists before starting the device flow.
	if _, err := user.Lookup(localUser); err != nil {
		return fmt.Errorf("local user %q not found: %w", localUser, err)
	}

	// Verify each requested group exists.
	for _, g := range groups {
		if _, err := user.LookupGroup(g); err != nil {
			return fmt.Errorf("group %q not found: %w", g, err)
		}
	}

	if len(cfg.Providers) == 0 {
		return fmt.Errorf("no providers configured in %s", "config")
	}

	provider, err := github.New(cfg.Providers[0])
	if err != nil {
		return fmt.Errorf("create provider: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Start the Device Flow
	flow, err := provider.StartDeviceFlow(ctx)
	if err != nil {
		return fmt.Errorf("start device flow: %w", err)
	}

	fmt.Printf("\nTo enroll %q, authorize this application on GitHub:\n\n", localUser)
	fmt.Printf("  Visit:      %s\n", flow.DeviceURL)
	fmt.Printf("  User Code:  %s\n\n", flow.UserCode)
	fmt.Printf("Waiting for authorization (expires in %s)...\n", time.Until(flow.ExpiresAt).Round(time.Second))

	token, err := pollUntilAuthorized(ctx, provider, flow)
	if err != nil {
		return err
	}

	identity, err := provider.GetIdentity(ctx, token)
	if err != nil {
		return fmt.Errorf("get GitHub identity: %w", err)
	}

	// Write enrollment record
	store, err := enrollment.Load(enrollFile)
	if err != nil {
		return fmt.Errorf("load enrollment file: %w", err)
	}

	enrolledBy := callerUsername()
	if enrolledBy == "" {
		enrolledBy = "unknown"
	}

	rec := enrollment.Record{
		LocalUser:   localUser,
		GitHubLogin: identity.Login,
		EnrolledAt:  time.Now().UTC(),
		EnrolledBy:  enrolledBy,
		Groups:      groups,
	}

	if err := store.Add(rec); err != nil {
		return fmt.Errorf("add enrollment: %w", err)
	}

	if err := store.Save(enrollFile); err != nil {
		return fmt.Errorf("save enrollment file: %w", err)
	}

	log.Info().
		Str("local_user", localUser).
		Str("github_login", identity.Login).
		Str("enrollment_file", enrollFile).
		Msg("Enrollment successful")

	fmt.Printf("\nEnrolled %q → GitHub user %q\n", localUser, identity.Login)
	if len(groups) > 0 {
		fmt.Printf("Groups: %s\n", strings.Join(groups, ", "))
	}
	return nil
}

// pollUntilAuthorized polls the GitHub token endpoint until the user
// completes authorization or the device code expires.
func pollUntilAuthorized(ctx context.Context, p *github.Provider, flow *github.DeviceFlow) (*github.Token, error) {
	interval := time.Duration(flow.PollingInterval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	deadline := time.NewTimer(time.Until(flow.ExpiresAt))
	defer deadline.Stop()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("enrollment cancelled")

		case <-deadline.C:
			return nil, fmt.Errorf("device code expired; please run the command again")

		case <-ticker.C:
			token, err := p.PollDeviceAuthorization(ctx, flow.DeviceCode)
			if err == nil {
				return token, nil
			}

			switch {
			case errors.Is(err, github.ErrAuthorizationPending):
				// still waiting — keep polling
			case errors.Is(err, github.ErrSlowDown):
				interval += 5 * time.Second
				ticker.Reset(interval)
			case errors.Is(err, github.ErrExpiredToken):
				return nil, fmt.Errorf("device code expired; please run the command again")
			case errors.Is(err, github.ErrAccessDenied):
				return nil, fmt.Errorf("authorization denied on GitHub")
			default:
				return nil, fmt.Errorf("poll authorization: %w", err)
			}
		}
	}
}
