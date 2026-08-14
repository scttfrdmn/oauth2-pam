// Package github implements pkg/provider's Provider interface for GitHub, and
// for GitHub Enterprise Server.
//
// Authentication uses the OAuth2 Device Authorization Grant (RFC 8628). After
// the user authorizes, the adapter fetches the GitHub user profile, org
// membership, and team membership, and returns them as a provider.Identity whose
// claims are provider.ClaimOrg and provider.ClaimTeam. Everything GitHub-shaped
// stops at this package's boundary.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
)

// Endpoints locates the GitHub instance to talk to. The zero value is not
// usable; call DefaultEndpoints for github.com.
//
// This exists so the provider can be pointed at a GitHub Enterprise Server
// installation, and so tests can drive the real code path against a fake
// GitHub instead of the internet.
type Endpoints struct {
	// DeviceAuth is the device authorization endpoint (RFC 8628 §3.1).
	DeviceAuth string
	// Token is the token endpoint polled while the user authorizes.
	Token string
	// APIBase is the REST API root, with no trailing slash.
	APIBase string
}

// DefaultEndpoints returns the endpoints for github.com.
func DefaultEndpoints() Endpoints {
	return Endpoints{
		DeviceAuth: "https://github.com/login/device/code",
		Token:      "https://github.com/login/oauth/access_token",
		APIBase:    "https://api.github.com",
	}
}

// EnterpriseEndpoints derives the endpoints for a GitHub Enterprise Server
// installation rooted at baseURL (e.g. "https://github.acme.internal"), which
// serves the device and token endpoints at the same paths as github.com and the
// REST API under /api/v3.
func EnterpriseEndpoints(baseURL string) Endpoints {
	base := strings.TrimSuffix(baseURL, "/")
	return Endpoints{
		DeviceAuth: base + "/login/device/code",
		Token:      base + "/login/oauth/access_token",
		APIBase:    base + "/api/v3",
	}
}

// validate checks that every endpoint is set and parses, and returns the set of
// hostnames redirects may target.
func (e Endpoints) validate() (map[string]struct{}, error) {
	hosts := make(map[string]struct{}, 3)
	for name, raw := range map[string]string{
		"device_auth": e.DeviceAuth,
		"token":       e.Token,
		"api_base":    e.APIBase,
	} {
		if raw == "" {
			return nil, fmt.Errorf("github endpoints: %s is required", name)
		}
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("github endpoints: %s is not a valid URL: %w", name, err)
		}
		if u.Host == "" {
			return nil, fmt.Errorf("github endpoints: %s must be absolute (got %q)", name, raw)
		}
		hosts[u.Hostname()] = struct{}{}
	}
	return hosts, nil
}

// Provider is a GitHub OAuth2 provider that supports Device Flow auth. It
// implements provider.Provider.
type Provider struct {
	name       string
	cfg        config.ProviderConfig
	endpoints  Endpoints
	httpClient *http.Client
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
	Slug         string    `json:"slug"`
	Organization gitHubOrg `json:"organization"`
}

// New creates a new GitHub provider from the given config. It targets
// github.com unless the config names a GitHub Enterprise Server base_url.
func New(cfg config.ProviderConfig) (*Provider, error) {
	if cfg.GitHub.BaseURL != "" {
		return NewWithEndpoints(cfg, EnterpriseEndpoints(cfg.GitHub.BaseURL))
	}
	return NewWithEndpoints(cfg, DefaultEndpoints())
}

// NewWithEndpoints creates a GitHub provider that talks to the given endpoints.
// Use it for GitHub Enterprise Server, or in tests to target a fake GitHub.
func NewWithEndpoints(cfg config.ProviderConfig, endpoints Endpoints) (*Provider, error) {
	if cfg.Type != "github" {
		return nil, fmt.Errorf("github provider: unexpected type %q", cfg.Type)
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("github provider: client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("github provider: client_secret is required")
	}

	allowedHosts, err := endpoints.validate()
	if err != nil {
		return nil, err
	}

	return &Provider{
		name:      cfg.Name,
		cfg:       cfg,
		endpoints: endpoints,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			// Only follow redirects back to a host we were configured to talk
			// to. A redirect anywhere else indicates a misconfiguration or a
			// MITM attempt, and would leak the bearer token if followed.
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				h := req.URL.Hostname()
				if _, ok := allowedHosts[h]; !ok {
					return fmt.Errorf("redirect to unconfigured host %q rejected", h)
				}
				return nil
			},
		},
	}, nil
}

// Name returns the operator's name for this provider.
func (p *Provider) Name() string { return p.name }

// Type returns "github".
func (p *Provider) Type() string { return "github" }

// StartDeviceFlow initiates a GitHub Device Authorization Grant.
// The returned DeviceFlow contains the user code and verification URL to
// display to the user.
func (p *Provider) StartDeviceFlow(ctx context.Context) (*provider.DeviceFlow, error) {
	data := url.Values{}
	data.Set("client_id", p.cfg.ClientID)
	data.Set("scope", "read:org read:user user:email")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoints.DeviceAuth, strings.NewReader(data.Encode()))
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

	df := &provider.DeviceFlow{
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
func (p *Provider) PollDeviceAuthorization(ctx context.Context, deviceCode string) (*provider.Token, error) {
	data := url.Values{}
	data.Set("client_id", p.cfg.ClientID)
	data.Set("client_secret", p.cfg.ClientSecret)
	data.Set("device_code", deviceCode)
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoints.Token, strings.NewReader(data.Encode()))
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
			return nil, provider.ErrAuthorizationPending
		case "slow_down":
			return nil, provider.ErrSlowDown
		case "expired_token":
			return nil, provider.ErrExpiredToken
		case "access_denied":
			return nil, provider.ErrAccessDenied
		default:
			return nil, fmt.Errorf("github poll: %s: %s", tr.Error, tr.ErrorDescription)
		}
	}

	if tr.AccessToken == "" {
		return nil, fmt.Errorf("github poll: no access token in response")
	}

	token := &provider.Token{
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
func (p *Provider) GetIdentity(ctx context.Context, token *provider.Token) (*provider.Identity, error) {
	// /user must succeed — it provides the login needed for all subsequent work.
	user, err := p.getUser(ctx, token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("github identity: get user: %w", err)
	}

	// Fetch orgs and teams concurrently; both are non-fatal.
	var (
		orgs     []string
		teams    []string
		orgsErr  error
		teamsErr error
		wg       sync.WaitGroup
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

	id := &provider.Identity{
		Provider: p.name,
		Type:     p.Type(),
		// GitHub's numeric user ID survives a rename; the login does not, so an
		// audit trail should key on this.
		Subject: strconv.FormatInt(user.ID, 10),
		Login:   user.Login,
		Name:    user.Name,
		Email:   user.Email,
	}
	id.AddClaim(provider.ClaimOrg, orgs...)
	id.AddClaim(provider.ClaimTeam, teams...)

	// Enforce provider-level access controls if configured
	if err := p.checkAccess(id); err != nil {
		return nil, err
	}

	log.Debug().
		Str("provider", p.name).
		Str("login", id.Login).
		Strs("orgs", id.Claim(provider.ClaimOrg)).
		Strs("teams", id.Claim(provider.ClaimTeam)).
		Msg("GitHub identity resolved")

	return id, nil
}

// checkAccess enforces the provider-level allow/deny rules from config.
func (p *Provider) checkAccess(id *provider.Identity) error {
	gh := p.cfg.GitHub

	// Explicit user allowlist bypasses org/team requirements
	for _, allowed := range gh.AllowUsers {
		if strings.EqualFold(allowed, id.Login) {
			return nil
		}
	}

	// With no requirements of any kind configured, any authenticated identity
	// is acceptable — the mapper is then the only gate.
	if gh.RequireOrg == "" && len(gh.RequireTeams) == 0 && len(gh.AllowUsers) == 0 {
		return nil
	}

	// An allowlist on its own is a restriction, not a hint: reaching here means
	// the login was not on it, and there is no org or team requirement left for
	// it to satisfy instead.
	if gh.RequireOrg == "" && len(gh.RequireTeams) == 0 {
		return fmt.Errorf("%w: %s is not in allow_users", provider.ErrAccessForbidden, id.Login)
	}

	// Check required org
	if gh.RequireOrg != "" && !id.HasClaim(provider.ClaimOrg, gh.RequireOrg) {
		return fmt.Errorf("%w: %s is not a member of GitHub org %q",
			provider.ErrAccessForbidden, id.Login, gh.RequireOrg)
	}

	// Check required teams (at least one must match)
	if len(gh.RequireTeams) > 0 {
		found := false
		for _, requiredTeam := range gh.RequireTeams {
			if id.HasClaim(provider.ClaimTeam, requiredTeam) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: %s is not a member of any required team",
				provider.ErrAccessForbidden, id.Login)
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
	orgs, err := apiGetAll[gitHubOrg](ctx, p, accessToken, "/user/orgs")
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(orgs))
	for _, o := range orgs {
		result = append(result, o.Login)
	}
	return result, nil
}

func (p *Provider) getUserTeams(ctx context.Context, accessToken string) ([]string, error) {
	teams, err := apiGetAll[gitHubTeam](ctx, p, accessToken, "/user/teams")
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(teams))
	for _, t := range teams {
		result = append(result, t.Organization.Login+"/"+t.Slug)
	}
	return result, nil
}

const (
	// apiPageSize is GitHub's maximum per_page. The default is 30, and both
	// /user/orgs and /user/teams are lists a real user overruns — anyone in a
	// large organisation is on more than 30 teams. A truncated list is not a
	// cosmetic loss: required_orgs and required_teams are checked against it, so
	// a member whose org fell off page one was denied the login.
	apiPageSize = 100

	// maxAPIPages bounds the walk at 2,000 entries. The cursor comes from the
	// server, so a loop that only stops when it says to is a loop a broken or
	// hostile API can hold a login open in.
	maxAPIPages = 20
)

// apiGetAll fetches every page of a paginated GitHub list endpoint, following the
// Link header's rel="next" cursor.
//
// It is a function rather than a method because Go does not allow type parameters
// on methods.
func apiGetAll[T any](ctx context.Context, p *Provider, accessToken, path string) ([]T, error) {
	next := fmt.Sprintf("%s%s?per_page=%d", p.endpoints.APIBase, path, apiPageSize)

	var all []T
	for page := 1; next != ""; page++ {
		if page > maxAPIPages {
			return nil, fmt.Errorf("GET %s: more than %d pages", path, maxAPIPages)
		}

		var batch []T
		link, err := p.apiGetURL(ctx, accessToken, next, &batch)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)

		// An empty page with a next cursor is how a server could keep this loop
		// going for free; maxAPIPages is the real bound, but stopping here means
		// the common case of a server that always emits a cursor costs one extra
		// request rather than twenty.
		if len(batch) == 0 {
			break
		}

		next, err = p.nextPageURL(link)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", path, err)
		}
	}

	return all, nil
}

// nextPageURL extracts the rel="next" URL from a Link header, or "" when there is
// no next page.
//
// The URL is checked against the configured API base first. It arrives in a
// server-controlled header and the next request carries the user's access token,
// so an unchecked cursor is a way to have this process hand that token to another
// host. httpClient.CheckRedirect pins hostnames for redirects; a Link header is
// not a redirect and does not go through it.
func (p *Provider) nextPageURL(link string) (string, error) {
	raw := parseNextLink(link)
	if raw == "" {
		return "", nil
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("pagination cursor is not a valid URL: %w", err)
	}
	base, err := url.Parse(p.endpoints.APIBase)
	if err != nil {
		return "", fmt.Errorf("api_base is not a valid URL: %w", err)
	}
	if u.Scheme != base.Scheme || u.Host != base.Host {
		return "", fmt.Errorf("pagination cursor points at %q, not the configured API at %q",
			u.Scheme+"://"+u.Host, base.Scheme+"://"+base.Host)
	}

	return u.String(), nil
}

// parseNextLink returns the URL of the rel="next" entry in an RFC 8288 Link
// header value, or "" if there is none.
func parseNextLink(header string) string {
	for _, entry := range strings.Split(header, ",") {
		parts := strings.Split(entry, ";")
		if len(parts) < 2 {
			continue
		}

		target := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}

		for _, param := range parts[1:] {
			// rel=next and rel="next" are both legal.
			v := strings.TrimSpace(param)
			if !strings.HasPrefix(v, "rel=") {
				continue
			}
			if strings.Trim(strings.TrimPrefix(v, "rel="), `"'`) == "next" {
				return target[1 : len(target)-1]
			}
		}
	}
	return ""
}

func (p *Provider) apiGet(ctx context.Context, accessToken, path string, dest interface{}) error {
	_, err := p.apiGetURL(ctx, accessToken, p.endpoints.APIBase+path, dest)
	return err
}

// apiGetURL performs one authenticated GET against an absolute URL and returns
// the response's Link header.
func (p *Provider) apiGetURL(ctx context.Context, accessToken, rawURL string, dest interface{}) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("build request %s: %w", rawURL, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: unexpected status %d", rawURL, resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return "", fmt.Errorf("decode %s: %w", rawURL, err)
	}

	return resp.Header.Get("Link"), nil
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

	apiURL := fmt.Sprintf("%s/applications/%s/token", p.endpoints.APIBase, p.cfg.ClientID)
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
