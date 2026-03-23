// Package mapper translates a provider Identity into a local Unix user and
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
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/enrollment"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider/github"
)

// ErrNoMapping is returned when no tier produces a mapping for the identity.
var ErrNoMapping = fmt.Errorf("no mapping found for identity")

// unixUsernameRe matches valid POSIX portable Unix usernames:
// starts with letter or underscore, up to 32 chars of [a-z0-9_-].
var unixUsernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

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
}

// New creates a new mapper Chain from the given config.
func New(cfg config.MapperConfig) *Chain {
	return &Chain{
		cfg: cfg,
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

// Map resolves the GitHub identity to a local Unix user.
// requestedLocalUser is the Unix username from the PAM auth request; it is
// used by Tier 0 (enrollment) to verify a pre-enrolled (local, github) pair.
// Pass "" to skip Tier 0 (e.g. in test-mapping dry runs).
// The context is forwarded to Tier 2 (script) and Tier 3 (HTTP) calls.
func (c *Chain) Map(ctx context.Context, id *github.Identity, requestedLocalUser string) (*Result, error) {
	// Tier 0: enrollment file
	if c.cfg.EnrollmentEnabled && c.cfg.EnrollmentFile != "" && requestedLocalUser != "" {
		if result := mapViaEnrollment(c.cfg.EnrollmentFile, requestedLocalUser, id.Login); result != nil {
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
			log.Debug().
				Str("login", id.Login).
				Str("local_user", result.LocalUser).
				Msg("mapper tier3: http matched")
			return result, nil
		}
	}

	return nil, fmt.Errorf("%w: login=%s orgs=%v teams=%v",
		ErrNoMapping, id.Login, id.Orgs, id.Teams)
}

// --- Tier 0: enrollment file ---

func mapViaEnrollment(path, localUser, githubLogin string) *Result {
	store, err := enrollment.Load(path)
	if err != nil {
		log.Warn().Err(err).Str("path", path).Msg("mapper tier0: failed to load enrollment file")
		return nil
	}
	rec := store.Find(localUser, githubLogin)
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

func mapViaRules(rules []config.MappingRule, id *github.Identity) (*Result, error) {
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
func ruleMatches(m config.MatchCriteria, id *github.Identity) bool {
	if m.GitHubLogin != "" && !strings.EqualFold(m.GitHubLogin, id.Login) {
		return false
	}
	if m.GitHubOrg != "" && !containsFold(id.Orgs, m.GitHubOrg) {
		return false
	}
	if m.GitHubTeam != "" && !containsFold(id.Teams, m.GitHubTeam) {
		return false
	}
	return true
}

// expandLocalUser replaces supported placeholder variables in tmplStr with
// values from the GitHub identity. Supports both Go-template style (for
// backwards compatibility) and brace-style placeholders:
//
//	{{ .Login }}, {{.Login}}, {login}
//	{{ .Email }}, {{.Email}}, {email}
//	{{ .Name  }}, {{.Name }}, {name}
//
// Any remaining "{{" after substitution is rejected to prevent template
// injection via GitHub-controlled identity fields.
func expandLocalUser(tmplStr string, id *github.Identity) (string, error) {
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

// scriptInput is the JSON sent to the external script on stdin.
type scriptInput struct {
	Provider string   `json:"provider"`
	Login    string   `json:"login"`
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Orgs     []string `json:"orgs"`
	Teams    []string `json:"teams"`
}

func mapViaScript(ctx context.Context, scriptPath string, id *github.Identity) (*Result, error) {
	input := scriptInput{
		Provider: id.Provider,
		Login:    id.Login,
		Name:     id.Name,
		Email:    id.Email,
		Orgs:     id.Orgs,
		Teams:    id.Teams,
	}

	inputJSON, err := json.Marshal(input)
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

func mapViaHTTP(ctx context.Context, client *http.Client, endpoint string, id *github.Identity) (*Result, error) {
	payload, err := json.Marshal(scriptInput{
		Provider: id.Provider,
		Login:    id.Login,
		Name:     id.Name,
		Email:    id.Email,
		Orgs:     id.Orgs,
		Teams:    id.Teams,
	})
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
	return &result, nil
}

func containsFold(slice []string, s string) bool {
	for _, v := range slice {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
