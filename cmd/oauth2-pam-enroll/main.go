// Command oauth2-pam-enroll links a local Unix user to a provider identity by
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
	"io"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/scttfrdmn/oauth2-pam/pkg/auth"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/enrollment"
	"github.com/scttfrdmn/oauth2-pam/pkg/mapper"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider/registry"
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
		cfgPath      string
		localUser    string
		providerName string
		groups       []string
		removeMode   bool
		verbose      bool
	)

	cmd := &cobra.Command{
		Use:   "oauth2-pam-enroll",
		Short: "Enroll a local Unix user with a provider identity for oauth2-pam authentication",
		Long: `oauth2-pam-enroll links a local Unix username to a provider account so that
the user can authenticate via the OAuth2 Device Flow in future PAM sessions.

Run as root (or via sudo) since the enrollment file lives in /etc/oauth2-pam/.

Examples:
  # Enroll the current user
  sudo oauth2-pam-enroll

  # Enroll a specific user
  sudo oauth2-pam-enroll --user alice

  # Enroll with supplementary group overrides
  sudo oauth2-pam-enroll --user alice --groups users,docker

  # Enroll against a specific configured provider
  sudo oauth2-pam-enroll --user alice --provider github-enterprise

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
			// The broker will not start on a config that fails this, so enrolling
			// against one would write a record for a host that cannot serve it.
			if err := cfg.Validate(); err != nil {
				return fmt.Errorf("invalid config %s: %w", cfgPath, err)
			}

			enrollFile := cfg.Mapper.EnrollmentFile
			if enrollFile == "" {
				enrollFile = "/etc/oauth2-pam/enrolled-users.yaml"
			}

			if removeMode {
				return runRemove(localUser, enrollFile)
			}
			return runEnroll(localUser, providerName, groups, enrollFile, cfg)
		},
	}

	cmd.Flags().StringVarP(&cfgPath, "config", "c", "/etc/oauth2-pam/broker.yaml", "Broker config file")
	cmd.Flags().StringVarP(&localUser, "user", "u", "", "Local Unix username to enroll (default: caller)")
	cmd.Flags().StringVar(&providerName, "provider", "", "Configured provider name to enroll against (default: the first one)")
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

// localUserGate returns the check a local username has to pass to be enrolled:
// the mapper's, taken from the mapper configuration this host will authenticate
// with, so the answer here is the answer the login will get. Because the config is
// loaded (mapper.min_uid included) the full gate applies, not just the parts that
// need no configuration.
//
// The error explains the rule rather than only refusing it, and says where the
// rule comes from — an operator who is told "no" by a tool that is not the one
// that will deny the login has no way to guess why.
func localUserGate(cfg *config.Config) enrollment.LocalUserValidator {
	chain := mapper.New(cfg.Mapper)
	return func(localUser string) error {
		if err := chain.ValidateLocalUser("enrollment", localUser); err != nil {
			return fmt.Errorf("%w\n\n"+
				"This is the same local-account gate the mapper applies to every tier at\n"+
				"login, so %q could not authenticate even once enrolled. To be enrollable a\n"+
				"local user must:\n"+
				"  - be a valid Unix name: a lowercase letter or underscore, then lowercase\n"+
				"    letters, digits, hyphens or underscores, at most 32 characters\n"+
				"  - not be root, and not be a system or service account (if a real person on\n"+
				"    this host has such a name, list it in mapper.allow_system_users; nothing\n"+
				"    exempts root)\n"+
				"  - have a UID at or above mapper.min_uid, when the account resolves here",
				err, localUser)
		}
		return nil
	}
}

// runEnroll runs the Device Flow, confirms the provider identity, and writes
// the enrollment record.
func runEnroll(localUser, providerName string, groups []string, enrollFile string, cfg *config.Config) error {
	// The mapper's own local-account gate, applied here before anything else
	// happens. mapper.Map already refuses tier 0 answers that do not pass it, so an
	// enrollment naming root, a system account, or an account below
	// mapper.min_uid can never authenticate; writing it would only turn a typo into
	// a denied login days later. Checked before the device flow so the operator is
	// not sent to a browser to authorize a record that will be rejected.
	validateLocalUser := localUserGate(cfg)
	if err := validateLocalUser(localUser); err != nil {
		return err
	}

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

	pc, err := selectProviderConfig(cfg, providerName)
	if err != nil {
		return err
	}

	prov, err := registry.New(pc)
	if err != nil {
		return fmt.Errorf("create provider: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Start the Device Flow
	flow, err := prov.StartDeviceFlow(ctx)
	if err != nil {
		return fmt.Errorf("start device flow: %w", err)
	}

	printDeviceInstructions(os.Stdout, localUser, prov.Name(), flow)

	token, err := pollUntilAuthorized(ctx, prov, flow)
	if err != nil {
		return err
	}

	identity, err := prov.GetIdentity(ctx, token)
	if err != nil {
		return fmt.Errorf("get provider identity: %w", err)
	}

	// An identity with no login is a provider error, not something to record. The
	// login is one half of what tier 0 matches on; writing an empty one produces a
	// record that matches any identity that also arrives without a login, which is a
	// wildcard for this local account. Store.Add refuses it too — this check is here
	// so the operator is told the provider was at fault rather than the record.
	if identity.Login == "" {
		return fmt.Errorf("%s returned an identity with no login, so there is nothing to enroll %q against",
			prov.Name(), localUser)
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
		LocalUser: localUser,
		Login:     identity.Login,
		// Recorded even on a single-provider host: if a second provider is added
		// later, an enrollment that names its provider cannot be claimed by a
		// same-named account at the new one.
		Provider:   prov.Name(),
		EnrolledAt: time.Now().UTC(),
		EnrolledBy: enrolledBy,
		Groups:     groups,
	}

	// The gate again, at the store: the check above is for the operator, this one
	// is what a future writer of this file inherits.
	if err := store.Add(rec, validateLocalUser); err != nil {
		return fmt.Errorf("add enrollment: %w", err)
	}

	if err := store.Save(enrollFile); err != nil {
		return fmt.Errorf("save enrollment file: %w", err)
	}

	log.Info().
		Str("local_user", localUser).
		Str("provider", prov.Name()).
		Str("login", identity.Login).
		Str("enrollment_file", enrollFile).
		Msg("Enrollment successful")

	fmt.Printf("\nEnrolled %q → %s user %q\n", localUser, prov.Name(), identity.Login)
	if len(groups) > 0 {
		fmt.Printf("Groups: %s\n", strings.Join(groups, ", "))
	}
	return nil
}

// printDeviceInstructions writes the "go here, type this" block for a started
// device flow.
//
// The two provider-chosen strings are sanitized for the same reason the broker
// sanitizes them at broker.go:386 — #102. For a configured GitHub Enterprise
// base_url it is the operator of that server who picks verification_uri and
// user_code, and printed raw they can home the cursor, clear the screen and draw
// a convincing prompt. The terminal they would draw it on here is a root shell
// that was very likely just given a sudo password, and because this command never
// reads stdin, anything typed at a fake prompt is left in the tty queue for the
// invoking shell to run.
//
// prov.Name() needs none of this: it is providers[].name out of a root-owned
// config file, not something the provider said. localUser is printed with %q and
// has already been through the mapper's name gate.
//
// A function taking an io.Writer rather than four Printf calls in runEnroll,
// because runEnroll needs a config, a real local account and a reachable provider
// to reach its first print — which is how these two lines came to be the only
// place in the tree where provider bytes reached a terminal unfiltered.
// The write errors are discarded, which errcheck exempts for Printf and not for
// Fprintf. There is nothing to do with a stdout that will not take bytes: the
// operator cannot be told, since telling them is the write that just failed, and
// failing the enrollment over it would refuse a device flow the provider has
// already started.
func printDeviceInstructions(w io.Writer, localUser, providerName string, flow *provider.DeviceFlow) {
	_, _ = fmt.Fprintf(w, "\nTo enroll %q, authorize this application at %s:\n\n", localUser, providerName)
	_, _ = fmt.Fprintf(w, "  Visit:      %s\n", auth.SanitizePromptValue(flow.DeviceURL))
	_, _ = fmt.Fprintf(w, "  User Code:  %s\n\n", auth.SanitizePromptValue(flow.UserCode))
	_, _ = fmt.Fprintf(w, "Waiting for authorization (expires in %s)...\n",
		time.Until(flow.ExpiresAt).Round(time.Second))
}

// selectProviderConfig picks the providers[] entry to enroll against: the named
// one, or the first configured. A name that is not configured is an error naming
// the ones that are, rather than a silent enrollment against the wrong provider.
func selectProviderConfig(cfg *config.Config, name string) (config.ProviderConfig, error) {
	if len(cfg.Providers) == 0 {
		return config.ProviderConfig{}, fmt.Errorf("no providers are configured")
	}
	if name == "" {
		return cfg.Providers[0], nil
	}
	names := make([]string, 0, len(cfg.Providers))
	for _, pc := range cfg.Providers {
		if strings.EqualFold(pc.Name, name) {
			return pc, nil
		}
		names = append(names, pc.Name)
	}
	return config.ProviderConfig{}, fmt.Errorf("no provider named %q is configured (configured: %s)",
		name, strings.Join(names, ", "))
}

// pollUntilAuthorized polls the provider's token endpoint until the user
// completes authorization or the device code expires.
func pollUntilAuthorized(ctx context.Context, p provider.Provider, flow *provider.DeviceFlow) (*provider.Token, error) {
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
			case errors.Is(err, provider.ErrAuthorizationPending):
				// still waiting — keep polling
			case errors.Is(err, provider.ErrSlowDown):
				interval += 5 * time.Second
				ticker.Reset(interval)
			case errors.Is(err, provider.ErrExpiredToken):
				return nil, fmt.Errorf("device code expired; please run the command again")
			case errors.Is(err, provider.ErrAccessDenied):
				return nil, fmt.Errorf("authorization was denied at the provider")
			default:
				return nil, fmt.Errorf("poll authorization: %w", err)
			}
		}
	}
}
