// Package mapper translates a provider.Identity into a local Unix user and
// group list using a three-tier chain:
//
//	Tier 1 — built-in config-file rules  (zero runtime deps)
//	Tier 2 — external script             (custom logic, no service)
//	Tier 3 — HTTP service                (LDAP gateway, identity platform, …)
//
// Tiers are tried in order; the first successful, non-empty result wins.
// If no tier produces a result, Map returns ErrNoMapping.
package mapper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/enrollment"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
)

// ErrNoMapping is returned when no tier produces a mapping for the identity.
var ErrNoMapping = fmt.Errorf("no mapping found for identity")

// ErrForbiddenLocalUser is returned when a tier resolves to a local account that
// must never be reached through this path: a system account, or one below
// mapper.min_uid.
//
// It is a decision about the identity, not an outage, so the broker reports it as
// "denied" and no later tier is consulted. A tier that answers "this identity is
// www-data" has answered; asking the next tier for a more convenient answer would
// turn a refusal into a retry.
var ErrForbiddenLocalUser = errors.New("mapping resolves to a forbidden local account")

// unixUsernameRe matches valid POSIX portable Unix usernames:
// starts with letter or underscore, up to 32 chars of [a-z0-9_-].
var unixUsernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// DefaultMinUID is the floor applied when mapper.min_uid is unset. 1000 is the
// first non-system UID on Debian, Ubuntu, RHEL 7+, and SUSE; UID_MIN in
// /etc/login.defs is 1000 on all of them.
const DefaultMinUID = 1000

// systemAccounts are local accounts a provider identity may never be mapped to,
// whatever the UID lookup says. The floor below is the real control — it is
// authoritative about the host — but it needs the account to be resolvable, and
// os/user built without cgo only reads /etc/passwd. This list is what still holds
// when the lookup comes back empty.
//
// The threat is concrete. The shipped example maps `local_user: "{{ .Login }}"`
// gated only on org membership, so before this existed, any member of the org who
// named themselves "postgres" or "www-data" — trivial on a GitHub Enterprise
// Server, and merely a matter of getting there first on github.com — logged in as
// that service account.
//
// mapper.allow_system_users overrides an entry by name, for the site that has a
// real person called "mail". Nothing overrides root; see checkLocalUser.
var systemAccounts = map[string]bool{
	// Debian/Ubuntu base
	"root": true, "daemon": true, "bin": true, "sys": true, "sync": true,
	"games": true, "man": true, "lp": true, "mail": true, "news": true,
	"uucp": true, "proxy": true, "www-data": true, "backup": true, "list": true,
	"irc": true, "gnats": true, "nobody": true, "nogroup": true,
	// RHEL/Fedora base
	"adm": true, "operator": true, "halt": true, "shutdown": true, "ftp": true,
	"games-ftp": true, "nfsnobody": true, "rpc": true, "rpcuser": true,
	// Common daemons
	"messagebus": true, "dbus": true, "sshd": true, "ntp": true, "chrony": true,
	"postfix": true, "sssd": true, "tss": true, "polkitd": true, "unbound": true,
	"nscd": true, "avahi": true, "colord": true, "saned": true, "systemd": true,
	// Service accounts that own data worth stealing
	"postgres": true, "mysql": true, "mariadb": true, "redis": true,
	"mongodb": true, "nginx": true, "apache": true, "apache2": true,
	"httpd": true, "tomcat": true, "jenkins": true, "docker": true,
	"containerd": true, "kubelet": true, "etcd": true, "elasticsearch": true,
	"grafana": true, "prometheus": true, "git": true, "gitlab": true,
	"slurm": true, "munge": true, "hdfs": true, "yarn": true, "spark": true,
	"ceph": true, "vault": true, "consul": true,
	// This project's own service account
	"oauth2-pam": true,
}

// systemAccountPrefixes catch the families that are conventionally system
// accounts and grow with every distro release: systemd-resolve,
// systemd-timesync, _apt, _ssh, and so on. A leading underscore is the
// BSD/macOS convention for a service account and Debian has adopted it too.
var systemAccountPrefixes = []string{"systemd-", "_", "nix-", "gitlab-"}

// Result is the output of a successful mapping.
type Result struct {
	// LocalUser is the Unix username
	LocalUser string `json:"local_user"`

	// Groups is the list of supplementary Unix groups to add the user to
	Groups []string `json:"groups"`
}

// Chain is the ordered mapper chain. It is safe for concurrent use.
type Chain struct {
	cfg        config.MapperConfig
	httpClient *http.Client

	// minUID is the resolved floor; allowSystem is mapper.allow_system_users as a
	// set. Resolved once here rather than per call so the defaulting rule lives in
	// one place.
	minUID      int
	allowSystem map[string]bool

	// lookupUID resolves a local account to its UID. A field so tests can present
	// a passwd database without creating real accounts; production always uses
	// os/user. Returns errUserUnknown when the account does not exist.
	lookupUID func(string) (int, error)
}

// errUserUnknown reports that a local account could not be resolved. Not exported:
// callers care whether the mapping is allowed, not how the passwd lookup went.
var errUserUnknown = errors.New("no such local user")

// New creates a new mapper Chain from the given config.
func New(cfg config.MapperConfig) *Chain {
	minUID := cfg.MinUID
	if minUID == 0 {
		minUID = DefaultMinUID
	}
	allowSystem := make(map[string]bool, len(cfg.AllowSystemUsers))
	for _, name := range cfg.AllowSystemUsers {
		allowSystem[strings.ToLower(name)] = true
	}

	return &Chain{
		cfg:         cfg,
		minUID:      minUID,
		allowSystem: allowSystem,
		lookupUID:   lookupSystemUID,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			// Disallow all redirects: the mapper endpoint is operator-configured
			// and may be untrusted; following a redirect could reach internal
			// services (SSRF via 301 → http://169.254.169.254/ etc.).
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Map resolves the authenticated identity to a local Unix user.
// requestedLocalUser is the Unix username from the PAM auth request; it is
// used by Tier 0 (enrollment) to verify a pre-enrolled (local user, provider
// login) pair.
// Pass "" to skip Tier 0 (e.g. in test-mapping dry runs).
// The context is forwarded to Tier 2 (script) and Tier 3 (HTTP) calls.
//
// Every tier's answer passes through checkLocalUser before it is returned, so no
// tier — including one added later — can produce a mapping to root, a system
// account, or an account below mapper.min_uid.
func (c *Chain) Map(ctx context.Context, id *provider.Identity, requestedLocalUser string) (*Result, error) {
	// Tier 0: enrollment file
	if c.cfg.EnrollmentEnabled && c.cfg.EnrollmentFile != "" && requestedLocalUser != "" {
		if result := mapViaEnrollment(c.cfg.EnrollmentFile, requestedLocalUser, id); result != nil {
			if err := c.checkLocalUser("tier0 (enrollment)", result.LocalUser); err != nil {
				return nil, err
			}
			log.Debug().
				Str("login", id.Login).
				Str("local_user", result.LocalUser).
				Msg("mapper tier0: enrollment matched")
			return result, nil
		}
	}

	// Tier 1: config-file rules
	if len(c.cfg.Rules) > 0 {
		result, err := mapViaRules(c.cfg.Rules, id)
		if err != nil {
			return nil, err
		}
		if result != nil {
			if err := c.checkLocalUser("tier1 (rules)", result.LocalUser); err != nil {
				return nil, err
			}
			log.Debug().
				Str("login", id.Login).
				Str("local_user", result.LocalUser).
				Msg("mapper tier1: rule matched")
			return result, nil
		}
	}

	// Tier 2: external script
	if c.cfg.ExternalScript != "" {
		timeout := c.cfg.ExternalScriptTimeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		scriptCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		result, err := mapViaScript(scriptCtx, c.cfg.ExternalScript, id)
		if err != nil {
			log.Warn().Err(err).Str("script", c.cfg.ExternalScript).Msg("mapper tier2: script error")
			// fall through to Tier 3
		} else if result != nil {
			// Not a fall-through: a forbidden target is an answer, and consulting
			// Tier 3 for a different one would turn the refusal into a retry.
			if err := c.checkLocalUser("tier2 (script)", result.LocalUser); err != nil {
				return nil, err
			}
			log.Debug().
				Str("login", id.Login).
				Str("local_user", result.LocalUser).
				Msg("mapper tier2: script matched")
			return result, nil
		}
	}

	// Tier 3: HTTP service
	if c.cfg.HTTPEndpoint != "" {
		timeout := c.cfg.HTTPTimeout
		if timeout <= 0 {
			timeout = 2 * time.Second
		}
		httpCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		result, err := mapViaHTTP(httpCtx, c.httpClient, c.cfg.HTTPEndpoint, id)
		if err != nil {
			log.Warn().Err(err).Str("endpoint", c.cfg.HTTPEndpoint).Msg("mapper tier3: http error")
			// fall through
		} else if result != nil {
			if err := c.checkLocalUser("tier3 (http)", result.LocalUser); err != nil {
				return nil, err
			}
			log.Debug().
				Str("login", id.Login).
				Str("local_user", result.LocalUser).
				Msg("mapper tier3: http matched")
			return result, nil
		}
	}

	return nil, fmt.Errorf("%w: provider=%s login=%s claims=%v",
		ErrNoMapping, id.Provider, id.Login, id.Claims)
}

// --- Tier 0: enrollment file ---

func mapViaEnrollment(path, localUser string, id *provider.Identity) *Result {
	store, err := enrollment.Load(path)
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("mapper tier0: failed to load enrollment file")
		return nil
	}
	rec := store.Find(localUser, id.Login, id.Provider)
	if rec == nil {
		return nil
	}
	if !unixUsernameRe.MatchString(rec.LocalUser) {
		log.Warn().Str("local_user", rec.LocalUser).Str("path", path).
			Msg("mapper tier0: enrollment record has invalid Unix username; skipping")
		return nil
	}
	return &Result{
		LocalUser: rec.LocalUser,
		Groups:    rec.Groups,
	}
}

// --- Tier 1: config-file rules ---

func mapViaRules(rules []config.MappingRule, id *provider.Identity) (*Result, error) {
	for _, rule := range rules {
		if !ruleMatches(rule.Match, id) {
			continue
		}

		localUser, err := expandLocalUser(rule.LocalUser, id)
		if err != nil {
			return nil, fmt.Errorf("mapper rule: expand local_user: %w", err)
		}
		if localUser == "" {
			return nil, fmt.Errorf("mapper rule: local_user resolved to empty string")
		}
		if !unixUsernameRe.MatchString(localUser) {
			return nil, fmt.Errorf("mapper rule: local_user %q is not a valid Unix username", localUser)
		}

		return &Result{
			LocalUser: localUser,
			Groups:    rule.Groups,
		}, nil
	}
	return nil, nil
}

// ruleMatches returns true if all non-empty match criteria are satisfied.
//
// The github_* keys are the GitHub spelling of neutral concepts and are kept
// working exactly as before: github_login is the identity's login, github_org
// and github_team are the "org" and "team" claims — which is what the GitHub
// adapter fills, and what any other provider asserting organizations should
// fill. A provider with a different vocabulary is matched with claims: instead,
// so the rule engine needs no change to support one.
func ruleMatches(m config.MatchCriteria, id *provider.Identity) bool {
	login := m.Login
	if login == "" {
		login = m.GitHubLogin
	}
	if login != "" && !strings.EqualFold(login, id.Login) {
		return false
	}
	if m.GitHubOrg != "" && !id.HasClaim(provider.ClaimOrg, m.GitHubOrg) {
		return false
	}
	if m.GitHubTeam != "" && !id.HasClaim(provider.ClaimTeam, m.GitHubTeam) {
		return false
	}
	// All named claims must match (AND), consistent with the rest of a rule.
	for name, want := range m.Claims {
		if want != "" && !id.HasClaim(name, want) {
			return false
		}
	}
	return true
}

// expandLocalUser replaces supported placeholder variables in tmplStr with
// values from the identity. Supports both Go-template style (for
// backwards compatibility) and brace-style placeholders:
//
//	{{ .Login }}, {{.Login}}, {login}
//	{{ .Email }}, {{.Email}}, {email}
//	{{ .Name  }}, {{.Name }}, {name}
//
// Any remaining "{{" after substitution is rejected to prevent template
// injection via provider-controlled identity fields.
func expandLocalUser(tmplStr string, id *provider.Identity) (string, error) {
	if !strings.ContainsAny(tmplStr, "{") {
		return tmplStr, nil
	}
	r := strings.NewReplacer(
		"{{ .Login }}", id.Login,
		"{{.Login}}", id.Login,
		"{login}", id.Login,
		"{{ .Email }}", id.Email,
		"{{.Email}}", id.Email,
		"{email}", id.Email,
		"{{ .Name }}", id.Name,
		"{{.Name}}", id.Name,
		"{name}", id.Name,
	)
	result := r.Replace(tmplStr)
	if strings.Contains(result, "{{") {
		return "", fmt.Errorf("local_user contains unsupported template expression: %q", tmplStr)
	}
	return result, nil
}

// --- Tier 2: external script ---

// scriptInput is the JSON sent to the external script on stdin, and posted to
// the HTTP mapping service.
//
// orgs and teams are the "org" and "team" claims, kept as their own fields
// because that is the payload the documented Tier 2/3 contract already has and
// scripts in the wild parse it. claims carries the same data plus anything else
// the provider asserted, and is where a non-GitHub provider's vocabulary shows
// up; new consumers should read it and ignore orgs/teams.
type scriptInput struct {
	Provider string              `json:"provider"`
	Type     string              `json:"type"`
	Subject  string              `json:"subject,omitempty"`
	Login    string              `json:"login"`
	Name     string              `json:"name"`
	Email    string              `json:"email"`
	Orgs     []string            `json:"orgs"`
	Teams    []string            `json:"teams"`
	Claims   map[string][]string `json:"claims"`
}

// newScriptInput builds the Tier 2/3 payload from an identity.
func newScriptInput(id *provider.Identity) scriptInput {
	orgs := id.Claim(provider.ClaimOrg)
	if orgs == nil {
		orgs = []string{}
	}
	teams := id.Claim(provider.ClaimTeam)
	if teams == nil {
		teams = []string{}
	}
	return scriptInput{
		Provider: id.Provider,
		Type:     id.Type,
		Subject:  id.Subject,
		Login:    id.Login,
		Name:     id.Name,
		Email:    id.Email,
		Orgs:     orgs,
		Teams:    teams,
		Claims:   id.Claims,
	}
}

func mapViaScript(ctx context.Context, scriptPath string, id *provider.Identity) (*Result, error) {
	inputJSON, err := json.Marshal(newScriptInput(id))
	if err != nil {
		return nil, fmt.Errorf("marshal input: %w", err)
	}

	cmd := exec.CommandContext(ctx, scriptPath)
	cmd.Stdin = bytes.NewReader(inputJSON)
	// Restrict the script's environment to prevent information leakage
	// (e.g., credentials in env vars) and reduce the attack surface.
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/nonexistent",
	}

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("script %q: %w", scriptPath, err)
	}

	return parseResult(out)
}

// --- Tier 3: HTTP service ---

func mapViaHTTP(ctx context.Context, client *http.Client, endpoint string, id *provider.Identity) (*Result, error) {
	payload, err := json.Marshal(newScriptInput(id))
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
		// Service explicitly says no mapping
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST %s: unexpected status %d", endpoint, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return parseResult(body)
}

// --- helpers ---

func parseResult(data []byte) (*Result, error) {
	var result Result
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse result: %w", err)
	}
	if result.LocalUser == "" {
		return nil, nil // treat empty local_user as no mapping
	}
	// Tier 2 and Tier 3 answers were previously checked only for emptiness, while
	// Tier 0 and Tier 1 both applied this. An external mapper is operator-supplied
	// but its *input* is provider-controlled, so a script doing the obvious
	// `jq -r .login` handed back whatever the identity said.
	if !unixUsernameRe.MatchString(result.LocalUser) {
		return nil, fmt.Errorf("local_user %q is not a valid Unix username", result.LocalUser)
	}
	return &result, nil
}

// lookupSystemUID resolves a local account through NSS (or /etc/passwd when the
// broker is built without cgo).
func lookupSystemUID(name string) (int, error) {
	u, err := user.Lookup(name)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return 0, errUserUnknown
		}
		return 0, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, fmt.Errorf("uid %q of user %q is not a number: %w", u.Uid, name, err)
	}
	return uid, nil
}

// checkLocalUser is the gate every tier's answer passes through. It refuses names
// that are not valid Unix usernames, system accounts, and accounts below the UID
// floor.
//
// The two mechanisms cover for each other. The floor is authoritative — it asks
// the host what the UID actually is — but needs the account to resolve, and a
// broker built without cgo sees only /etc/passwd, so an LDAP- or SSSD-provisioned
// user comes back unknown. The name denylist needs no lookup but cannot know about
// a site's own service accounts. An unresolvable name is therefore refused only if
// the denylist catches it: it cannot become a login regardless, because sshd
// resolves the account itself before it starts a session.
//
// root is refused unconditionally — not by name, by UID 0, and not overridable by
// allow_system_users or by lowering min_uid. A device-flow login has no channel
// binding to the SSH connection, so root here would be the weakest possible path
// to the most privilege; OpenSSH's own default (PermitRootLogin prohibit-password)
// already rules it out. Use an ordinary account and sudo.
func (c *Chain) checkLocalUser(tier, name string) error {
	if !unixUsernameRe.MatchString(name) {
		return fmt.Errorf("%w: %s produced %q, which is not a valid Unix username",
			ErrForbiddenLocalUser, tier, name)
	}

	if isSystemAccountName(name) && !c.allowSystem[name] {
		log.Warn().Str("tier", tier).Str("local_user", name).
			Msg("mapper: refusing to map an identity to a system account")
		return fmt.Errorf("%w: %s produced the system account %q "+
			"(add it to mapper.allow_system_users if that is deliberate)",
			ErrForbiddenLocalUser, tier, name)
	}

	uid, err := c.lookupUID(name)
	switch {
	case errors.Is(err, errUserUnknown):
		// Not a refusal: see the note above on NSS-backed hosts. The login cannot
		// succeed anyway, and saying so here would break every site whose users
		// live in LDAP.
		log.Warn().Str("tier", tier).Str("local_user", name).
			Msg("mapper: local account does not resolve on this host; the UID floor could not be applied")
		return nil
	case err != nil:
		// A broken passwd source is an outage, not a decision. Refuse rather than
		// skip the floor: this is the one branch where failing open would hand out
		// exactly the account the floor exists to protect.
		return fmt.Errorf("resolve local user %q: %w", name, err)
	}

	if uid == 0 {
		log.Warn().Str("tier", tier).Str("local_user", name).
			Msg("mapper: refusing to map an identity to UID 0")
		return fmt.Errorf("%w: %s produced %q, which is UID 0", ErrForbiddenLocalUser, tier, name)
	}
	if c.minUID >= 0 && uid < c.minUID {
		log.Warn().Str("tier", tier).Str("local_user", name).Int("uid", uid).Int("min_uid", c.minUID).
			Msg("mapper: refusing to map an identity to an account below the UID floor")
		return fmt.Errorf("%w: %s produced %q (uid %d), below mapper.min_uid %d",
			ErrForbiddenLocalUser, tier, name, uid, c.minUID)
	}
	return nil
}

func isSystemAccountName(name string) bool {
	if systemAccounts[name] {
		return true
	}
	for _, prefix := range systemAccountPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
