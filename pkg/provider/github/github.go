// Package github implements an OAuth2 provider adapter for GitHub.
//
// Authentication uses the OAuth2 Device Authorization Grant (RFC 8628).
// After the user authorizes, the adapter fetches the GitHub user profile,
// org membership, and team membership to build an Identity that the mapper
// can use to determine the local Unix user.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

const (
	deviceAuthEndpoint = "https://github.com/login/device/code"
	tokenEndpoint      = "https://github.com/login/oauth/access_token"
	apiBase            = "https://api.github.com"
)

// Provider is a GitHub OAuth2 provider that supports Device Flow auth.
type Provider struct {
	name       string
	cfg        config.ProviderConfig
	httpClient *http.Client
}

// DeviceFlow holds the in-progress device authorization state.
type DeviceFlow struct {
	DeviceCode      string
	UserCode        string
	DeviceURL       string
	ExpiresAt       time.Time
	PollingInterval int
}

// Identity is the authenticated GitHub identity returned after a successful
// device flow. It carries enough information for the mapper to decide the
// local Unix user.
type Identity struct {
	// Provider is always "github"
	Provider string

	// Login is the GitHub username (e.g. "scttfrdmn")
	Login string

	// Name is the display name from the GitHub profile
	Name string

	// Email is the primary email (may be empty if the user has hidden it)
	Email string

	// Orgs is the list of GitHub organization slugs the user belongs to
	Orgs []string

	// Teams is the list of teams the user belongs to, in "org/team-slug" format
	Teams []string
}

// Token wraps an OAuth2 access token.
type Token struct {
	AccessToken string
	TokenType   string
	Scope       string
	ExpiresAt   time.Time
	Fingerprint string
}

// deviceAuthResponse is the JSON response from the device authorization endpoint.
type deviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// tokenResponse is the JSON response from the token endpoint.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	// Error fields
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// gitHubUser is the response from GET /user.
type gitHubUser struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
	ID    int64  `json:"id"`
}

// gitHubOrg is one element from GET /user/orgs.
type gitHubOrg struct {
	Login string `json:"login"`
}

// gitHubTeam is one element from GET /user/teams.
type gitHubTeam struct {
	Slug         string     `json:"slug"`
	Organization gitHubOrg  `json:"organization"`
}

// New creates a new GitHub provider from the given config.
func New(cfg config.ProviderConfig) (*Provider, error) {
	if cfg.Type != "github" {
		return nil, fmt.Errorf("github provider: unexpected type %q", cfg.Type)
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("github provider: client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("github provider: client_secret is required")
	}

	return &Provider{
		name: cfg.Name,
		cfg:  cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			// Only follow redirects to GitHub-owned hosts. A redirect to any
			// other host would indicate a misconfiguration or a MITM attempt.
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				h := req.URL.Hostname()
				if h != "github.com" && !strings.HasSuffix(h, ".github.com") {
					return fmt.Errorf("redirect to non-GitHub host %q rejected", h)
				}
				return nil
			},
		},
	}, nil
}

// Name returns the provider name.
func (p *Provider) Name() string { return p.name }

// StartDeviceFlow initiates a GitHub Device Authorization Grant.
// The returned DeviceFlow contains the user code and verification URL to
// display to the user.
func (p *Provider) StartDeviceFlow(ctx context.Context) (*DeviceFlow, error) {
	data := url.Values{}
	data.Set("client_id", p.cfg.ClientID)
	data.Set("scope", "read:org read:user user:email")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceAuthEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("github device flow: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github device flow: request device code: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github device flow: unexpected status %d", resp.StatusCode)
	}

	var dar deviceAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&dar); err != nil {
		return nil, fmt.Errorf("github device flow: decode response: %w", err)
	}

	verifyURL := dar.VerificationURI
	if dar.VerificationURIComplete != "" {
		verifyURL = dar.VerificationURIComplete
	}

	interval := dar.Interval
	if interval <= 0 {
		interval = 5
	}

	df := &DeviceFlow{
		DeviceCode:      dar.DeviceCode,
		UserCode:        dar.UserCode,
		DeviceURL:       verifyURL,
		ExpiresAt:       time.Now().Add(time.Duration(dar.ExpiresIn) * time.Second),
		PollingInterval: interval,
	}

	log.Debug().
		Str("provider", p.name).
		Str("user_code", df.UserCode).
		Str("device_url", df.DeviceURL).
		Msg("GitHub device flow initiated")

	return df, nil
}

// PollDeviceAuthorization polls the GitHub token endpoint for the result of
// a device authorization. Returns the token on success, or an error.
//
// The caller should check whether the error is ErrAuthorizationPending and
// retry after PollingInterval seconds; any other error is fatal.
func (p *Provider) PollDeviceAuthorization(ctx context.Context, deviceCode string) (*Token, error) {
	data := url.Values{}
	data.Set("client_id", p.cfg.ClientID)
	data.Set("client_secret", p.cfg.ClientSecret)
	data.Set("device_code", deviceCode)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("github poll: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github poll: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("github poll: decode response: %w", err)
	}

	if tr.Error != "" {
		switch tr.Error {
		case "authorization_pending":
			return nil, ErrAuthorizationPending
		case "slow_down":
			return nil, ErrSlowDown
		case "expired_token":
			return nil, ErrExpiredToken
		case "access_denied":
			return nil, ErrAccessDenied
		default:
			return nil, fmt.Errorf("github poll: %s: %s", tr.Error, tr.ErrorDescription)
		}
	}

	if tr.AccessToken == "" {
		return nil, fmt.Errorf("github poll: no access token in response")
	}

	token := &Token{
		AccessToken: tr.AccessToken,
		TokenType:   tr.TokenType,
		Scope:       tr.Scope,
		Fingerprint: tokenDisplayLabel(tr.AccessToken),
	}

	// Fail fast if any required scope is absent. Missing scopes cause silent
	// downstream failures (e.g., /user/orgs returns [] instead of an error),
	// making the root cause very hard to diagnose.
	for _, required := range []string{"read:org", "read:user", "user:email"} {
		if !strings.Contains(token.Scope, required) {
			return nil, fmt.Errorf("github token missing required scope %q (granted: %q); "+
				"ensure the OAuth app requests the correct scopes", required, token.Scope)
		}
	}

	log.Debug().
		Str("provider", p.name).
		Str("scope", token.Scope).
		Msg("GitHub device authorization completed")

	return token, nil
}

// GetIdentity fetches the user profile, org membership, and team membership
// for the authenticated token and returns an Identity. The three API calls
// are made concurrently.
func (p *Provider) GetIdentity(ctx context.Context, token *Token) (*Identity, error) {
	// /user must succeed — it provides the login needed for all subsequent work.
	user, err := p.getUser(ctx, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("github identity: get user: %w", err)
	}

	// Fetch orgs and teams concurrently; both are non-fatal.
	var (
		orgs      []string
		teams     []string
		orgsErr   error
		teamsErr  error
		wg        sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		orgs, orgsErr = p.getUserOrgs(ctx, token.AccessToken)
	}()
	go func() {
		defer wg.Done()
		teams, teamsErr = p.getUserTeams(ctx, token.AccessToken)
	}()
	wg.Wait()

	if orgsErr != nil {
		log.Warn().Err(orgsErr).Str("login", user.Login).Msg("Failed to fetch GitHub org membership")
		orgs = []string{}
	}
	if teamsErr != nil {
		log.Warn().Err(teamsErr).Str("login", user.Login).Msg("Failed to fetch GitHub team membership")
		teams = []string{}
	}

	id := &Identity{
		Provider: "github",
		Login:    user.Login,
		Name:     user.Name,
		Email:    user.Email,
		Orgs:     orgs,
		Teams:    teams,
	}

	// Enforce provider-level access controls if configured
	if err := p.checkAccess(id); err != nil {
		return nil, err
	}

	log.Debug().
		Str("provider", p.name).
		Str("login", id.Login).
		Strs("orgs", id.Orgs).
		Strs("teams", id.Teams).
		Msg("GitHub identity resolved")

	return id, nil
}

// checkAccess enforces the provider-level allow/deny rules from config.
func (p *Provider) checkAccess(id *Identity) error {
	gh := p.cfg.GitHub

	// Explicit user allowlist bypasses org/team requirements
	for _, allowed := range gh.AllowUsers {
		if strings.EqualFold(allowed, id.Login) {
			return nil
		}
	}

	// If no org/team requirements are set and no allowlist, allow all
	if gh.RequireOrg == "" && len(gh.RequireTeams) == 0 && len(gh.AllowUsers) == 0 {
		return nil
	}

	// Check required org
	if gh.RequireOrg != "" {
		found := false
		for _, org := range id.Orgs {
			if strings.EqualFold(org, gh.RequireOrg) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("access denied: %s is not a member of GitHub org %q", id.Login, gh.RequireOrg)
		}
	}

	// Check required teams (at least one must match)
	if len(gh.RequireTeams) > 0 {
		found := false
		for _, requiredTeam := range gh.RequireTeams {
			for _, team := range id.Teams {
				if strings.EqualFold(team, requiredTeam) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return fmt.Errorf("access denied: %s is not a member of any required team", id.Login)
		}
	}

	return nil
}

// GitHub API helpers

func (p *Provider) getUser(ctx context.Context, accessToken string) (*gitHubUser, error) {
	var user gitHubUser
	if err := p.apiGet(ctx, accessToken, "/user", &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (p *Provider) getUserOrgs(ctx context.Context, accessToken string) ([]string, error) {
	var orgs []gitHubOrg
	if err := p.apiGet(ctx, accessToken, "/user/orgs", &orgs); err != nil {
		return nil, err
	}
	result := make([]string, 0, len(orgs))
	for _, o := range orgs {
		result = append(result, o.Login)
	}
	return result, nil
}

func (p *Provider) getUserTeams(ctx context.Context, accessToken string) ([]string, error) {
	var teams []gitHubTeam
	if err := p.apiGet(ctx, accessToken, "/user/teams", &teams); err != nil {
		return nil, err
	}
	result := make([]string, 0, len(teams))
	for _, t := range teams {
		result = append(result, t.Organization.Login+"/"+t.Slug)
	}
	return result, nil
}

func (p *Provider) apiGet(ctx context.Context, accessToken, path string, dest interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+path, nil)
	if err != nil {
		return fmt.Errorf("build request %s: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: unexpected status %d", path, resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}

	return nil
}

// tokenDisplayLabel returns a human-readable prefix…suffix label for audit logs.
// It is NOT cryptographic — use the SHA-256 fingerprint in TokenManager for
// collision-resistant identification.
func tokenDisplayLabel(accessToken string) string {
	if len(accessToken) < 16 {
		return accessToken
	}
	return accessToken[:8] + "..." + accessToken[len(accessToken)-8:]
}

// RevokeAccessToken revokes an OAuth2 access token via the GitHub API.
// Uses DELETE /applications/{client_id}/token with HTTP Basic auth (client
// credentials). This is a best-effort call; the caller should not fail the
// overall revocation flow if this returns an error.
func (p *Provider) RevokeAccessToken(ctx context.Context, accessToken string) error {
	type revokeRequest struct {
		AccessToken string `json:"access_token"`
	}
	body, err := json.Marshal(revokeRequest{AccessToken: accessToken})
	if err != nil {
		return fmt.Errorf("marshal revoke request: %w", err)
	}

	apiURL := fmt.Sprintf("%s/applications/%s/token", apiBase, p.cfg.ClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build revoke request: %w", err)
	}
	req.SetBasicAuth(p.cfg.ClientID, p.cfg.ClientSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("revoke token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("revoke token: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Sentinel errors returned by PollDeviceAuthorization

// ErrAuthorizationPending means the user has not yet completed authorization.
// The caller should wait PollingInterval seconds and retry.
var ErrAuthorizationPending = fmt.Errorf("authorization_pending")

// ErrSlowDown means the polling interval should be increased by 5 seconds.
var ErrSlowDown = fmt.Errorf("slow_down")

// ErrExpiredToken means the device code has expired and a new flow must be started.
var ErrExpiredToken = fmt.Errorf("expired_token")

// ErrAccessDenied means the user denied the authorization request.
var ErrAccessDenied = fmt.Errorf("access_denied")
