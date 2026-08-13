package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

// realisticToken is long enough that tokenDisplayLabel actually elides it.
const realisticToken = "gho_16C7e42F292c6912E7710c838347Ae178B4a"

func providerConfig() config.ProviderConfig {
	return config.ProviderConfig{
		Name:         "github",
		Type:         "github",
		ClientID:     "cid",
		ClientSecret: "csecret",
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.ProviderConfig)
		wantErr string
	}{
		{"valid", func(*config.ProviderConfig) {}, ""},
		{"wrong type", func(c *config.ProviderConfig) { c.Type = "gitlab" }, "unexpected type"},
		{"no client id", func(c *config.ProviderConfig) { c.ClientID = "" }, "client_id is required"},
		{"no client secret", func(c *config.ProviderConfig) { c.ClientSecret = "" }, "client_secret is required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := providerConfig()
			tc.mutate(&cfg)

			_, err := New(cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("New = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestDefaultEndpointsAreGitHubDotCom(t *testing.T) {
	e := DefaultEndpoints()
	if e.DeviceAuth != "https://github.com/login/device/code" {
		t.Errorf("DeviceAuth = %q", e.DeviceAuth)
	}
	if e.Token != "https://github.com/login/oauth/access_token" {
		t.Errorf("Token = %q", e.Token)
	}
	if e.APIBase != "https://api.github.com" {
		t.Errorf("APIBase = %q", e.APIBase)
	}
	if _, err := e.validate(); err != nil {
		t.Errorf("the default endpoints do not validate: %v", err)
	}
}

func TestEndpointValidation(t *testing.T) {
	tests := []struct {
		name    string
		ep      Endpoints
		wantErr string
	}{
		{"zero value", Endpoints{}, "required"},
		{
			"missing api base",
			Endpoints{DeviceAuth: "https://gh.example/d", Token: "https://gh.example/t"},
			"api_base is required",
		},
		{
			"relative url",
			Endpoints{DeviceAuth: "/login/device/code", Token: "https://gh.example/t", APIBase: "https://gh.example"},
			"must be absolute",
		},
		{
			"enterprise endpoints",
			Endpoints{
				DeviceAuth: "https://github.acme.internal/login/device/code",
				Token:      "https://github.acme.internal/login/oauth/access_token",
				APIBase:    "https://github.acme.internal/api/v3",
			},
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewWithEndpoints(providerConfig(), tc.ep)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewWithEndpoints: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("NewWithEndpoints = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

// TestRedirectsToOtherHostsAreRefused: following a redirect would send the
// bearer token to whatever host the response named.
func TestRedirectsToOtherHostsAreRefused(t *testing.T) {
	var elsewhereHit atomic.Bool
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhereHit.Store(true)
		_, _ = w.Write([]byte(`{"login":"attacker"}`))
	}))
	defer elsewhere.Close()

	// Both test servers listen on 127.0.0.1, and the allowlist is keyed by
	// hostname, so the redirect has to name the same address by a different
	// name to be a genuine cross-host redirect.
	target := "http://localhost:" + strings.TrimPrefix(elsewhere.URL, "http://127.0.0.1:") + "/user"

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}))
	defer redirector.Close()

	p, err := NewWithEndpoints(providerConfig(), Endpoints{
		DeviceAuth: redirector.URL + "/login/device/code",
		Token:      redirector.URL + "/login/oauth/access_token",
		APIBase:    redirector.URL,
	})
	if err != nil {
		t.Fatalf("NewWithEndpoints: %v", err)
	}

	_, err = p.GetIdentity(context.Background(), &Token{AccessToken: "gho_x"})
	if err == nil {
		t.Fatal("GetIdentity followed a cross-host redirect")
	}
	if !strings.Contains(err.Error(), "unconfigured host") {
		t.Errorf("err = %v, want the redirect to be refused by name", err)
	}
	if elsewhereHit.Load() {
		t.Error("the bearer token was sent to a host outside the configured endpoints")
	}
}

func TestStartDeviceFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("client_id"); got != "cid" {
			t.Errorf("client_id = %q", got)
		}
		// Without these scopes the org and team lookups silently return empty.
		for _, want := range []string{"read:org", "read:user", "user:email"} {
			if !strings.Contains(r.Form.Get("scope"), want) {
				t.Errorf("scope %q does not request %q", r.Form.Get("scope"), want)
			}
		}
		// The client secret must not be sent to the device authorization
		// endpoint; RFC 8628 does not use it there.
		if r.Form.Get("client_secret") != "" {
			t.Error("client_secret was sent to the device authorization endpoint")
		}

		_, _ = w.Write([]byte(`{
			"device_code": "dev-code",
			"user_code": "WDJB-MJHT",
			"verification_uri": "https://github.com/login/device",
			"verification_uri_complete": "https://github.com/login/device?user_code=WDJB-MJHT",
			"expires_in": 900,
			"interval": 5
		}`))
	}))
	defer srv.Close()

	p := providerFor(t, srv.URL)

	df, err := p.StartDeviceFlow(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}
	if df.DeviceCode != "dev-code" || df.UserCode != "WDJB-MJHT" {
		t.Errorf("device flow = %+v", df)
	}
	// The complete URI is preferred: it pre-fills the code, so the user cannot
	// mistype it.
	if !strings.Contains(df.DeviceURL, "user_code=") {
		t.Errorf("DeviceURL = %q, want the verification_uri_complete", df.DeviceURL)
	}
	if df.PollingInterval != 5 {
		t.Errorf("PollingInterval = %d, want 5", df.PollingInterval)
	}
	if df.ExpiresAt.IsZero() {
		t.Error("ExpiresAt was not set")
	}
}

func TestStartDeviceFlowDefaultsPollingInterval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No "interval" field, as some providers omit it.
		_, _ = w.Write([]byte(`{"device_code":"d","user_code":"U","verification_uri":"https://x/","expires_in":900}`))
	}))
	defer srv.Close()

	df, err := providerFor(t, srv.URL).StartDeviceFlow(context.Background())
	if err != nil {
		t.Fatalf("StartDeviceFlow: %v", err)
	}
	if df.PollingInterval != 5 {
		t.Errorf("PollingInterval = %d, want the 5s default", df.PollingInterval)
	}
}

func TestStartDeviceFlowHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := providerFor(t, srv.URL).StartDeviceFlow(context.Background()); err == nil {
		t.Error("StartDeviceFlow accepted a 500 response")
	}
}

// TestPollErrorsMapToSentinels: the broker branches on these to decide pending
// versus denied versus expired, which become different PAM results.
func TestPollErrorsMapToSentinels(t *testing.T) {
	tests := []struct {
		code string
		want error
	}{
		{"authorization_pending", ErrAuthorizationPending},
		{"slow_down", ErrSlowDown},
		{"expired_token", ErrExpiredToken},
		{"access_denied", ErrAccessDenied},
	}

	for _, tc := range tests {
		t.Run(tc.code, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"error":"` + tc.code + `"}`))
			}))
			defer srv.Close()

			_, err := providerFor(t, srv.URL).PollDeviceAuthorization(context.Background(), "dev-code")
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestPollUnrecognizedErrorIsNotPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"error":"unsupported_grant_type","error_description":"nope"}`))
	}))
	defer srv.Close()

	_, err := providerFor(t, srv.URL).PollDeviceAuthorization(context.Background(), "dev-code")
	if err == nil {
		t.Fatal("an unrecognized error was accepted")
	}
	// It must not masquerade as pending; the broker would poll forever.
	if errors.Is(err, ErrAuthorizationPending) {
		t.Error("an unrecognized error was reported as authorization_pending")
	}
}

func TestPollSendsClientCredentialsAndDeviceCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if got := r.Form.Get("device_code"); got != "dev-code" {
			t.Errorf("device_code = %q", got)
		}
		if got := r.Form.Get("client_secret"); got != "csecret" {
			t.Errorf("client_secret = %q", got)
		}
		if got := r.Form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:device_code" {
			t.Errorf("grant_type = %q", got)
		}
		_, _ = w.Write([]byte(`{"access_token":"` + realisticToken +
			`","token_type":"bearer","scope":"read:org,read:user,user:email"}`))
	}))
	defer srv.Close()

	tok, err := providerFor(t, srv.URL).PollDeviceAuthorization(context.Background(), "dev-code")
	if err != nil {
		t.Fatalf("PollDeviceAuthorization: %v", err)
	}
	if tok.AccessToken != realisticToken {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	// The label is what reaches the logs, so it must be an elision rather than
	// the token itself.
	if tok.Fingerprint == tok.AccessToken {
		t.Error("Fingerprint is the raw token")
	}
	if strings.Contains(tok.Fingerprint, realisticToken) {
		t.Error("Fingerprint contains the raw token")
	}
}

// TestMissingScopesFailFast: without read:org, /user/orgs returns an empty list
// rather than an error, so an org requirement would silently deny everyone.
// The provider must say so instead.
func TestMissingScopesFailFast(t *testing.T) {
	for _, scope := range []string{"", "read:user,user:email", "read:org,user:email", "read:org,read:user"} {
		t.Run(scope, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"access_token":"gho_abc","token_type":"bearer","scope":"` + scope + `"}`))
			}))
			defer srv.Close()

			_, err := providerFor(t, srv.URL).PollDeviceAuthorization(context.Background(), "dev-code")
			if err == nil {
				t.Fatalf("scope %q was accepted", scope)
			}
			if !strings.Contains(err.Error(), "scope") {
				t.Errorf("err = %q, want it to name the missing scope", err)
			}
		})
	}
}

func TestPollWithoutAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token_type":"bearer","scope":"read:org,read:user,user:email"}`))
	}))
	defer srv.Close()

	if _, err := providerFor(t, srv.URL).PollDeviceAuthorization(context.Background(), "d"); err == nil {
		t.Error("a response with no access token was accepted")
	}
}

func TestGetIdentity(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer gho_abc" {
			t.Errorf("Authorization = %q", got)
		}
		_, _ = w.Write([]byte(`{"login":"alice","name":"Alice","email":"alice@example.com","id":1}`))
	})
	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"login":"acme"},{"login":"other"}]`))
	})
	mux.HandleFunc("/user/teams", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"slug":"eng","organization":{"login":"acme"}}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	id, err := providerFor(t, srv.URL).GetIdentity(context.Background(), &Token{AccessToken: "gho_abc"})
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if id.Login != "alice" || id.Email != "alice@example.com" || id.Name != "Alice" {
		t.Errorf("identity = %+v", id)
	}
	if len(id.Orgs) != 2 {
		t.Errorf("Orgs = %v, want two entries", id.Orgs)
	}
	// Teams are normalised to "org/slug", which is the form mapping rules use.
	if len(id.Teams) != 1 || id.Teams[0] != "acme/eng" {
		t.Errorf("Teams = %v, want [acme/eng]", id.Teams)
	}
}

// TestGetIdentityRequiresUserEndpoint: /user provides the login everything else
// keys off, so its failure is fatal while orgs and teams degrade to empty.
func TestGetIdentityRequiresUserEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if _, err := providerFor(t, srv.URL).GetIdentity(context.Background(), &Token{AccessToken: "gho_abc"}); err == nil {
		t.Error("GetIdentity succeeded with a failing /user call")
	}
}

func TestGetIdentityToleratesOrgAndTeamFailures(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"login":"alice"}`))
	})
	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/user/teams", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	id, err := providerFor(t, srv.URL).GetIdentity(context.Background(), &Token{AccessToken: "gho_abc"})
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	// Empty rather than nil, and definitely not a spurious membership: an org
	// requirement will now legitimately deny this identity.
	if len(id.Orgs) != 0 || len(id.Teams) != 0 {
		t.Errorf("Orgs = %v, Teams = %v, want both empty", id.Orgs, id.Teams)
	}
}

func TestCheckAccess(t *testing.T) {
	id := &Identity{Login: "alice", Orgs: []string{"acme"}, Teams: []string{"acme/eng"}}

	tests := []struct {
		name   string
		gh     config.GitHubConfig
		wantOK bool
	}{
		{"no requirements allows anyone", config.GitHubConfig{}, true},
		{"required org satisfied", config.GitHubConfig{RequireOrg: "acme"}, true},
		{"required org is case-insensitive", config.GitHubConfig{RequireOrg: "ACME"}, true},
		{"required org not satisfied", config.GitHubConfig{RequireOrg: "other"}, false},
		{"required team satisfied", config.GitHubConfig{RequireTeams: []string{"acme/eng"}}, true},
		{"any one required team is enough", config.GitHubConfig{RequireTeams: []string{"acme/ops", "acme/eng"}}, true},
		{"no required team satisfied", config.GitHubConfig{RequireTeams: []string{"acme/ops"}}, false},
		{
			"org and team are both required",
			config.GitHubConfig{RequireOrg: "acme", RequireTeams: []string{"acme/ops"}},
			false,
		},
		// The allowlist is the break-glass path for an operator who is not in
		// the org.
		{"allowlisted user bypasses org", config.GitHubConfig{RequireOrg: "other", AllowUsers: []string{"alice"}}, true},
		{"allowlist is case-insensitive", config.GitHubConfig{RequireOrg: "other", AllowUsers: []string{"ALICE"}}, true},
		{"allowlist does not admit others", config.GitHubConfig{AllowUsers: []string{"bob"}}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := providerConfig()
			cfg.GitHub = tc.gh
			p, err := New(cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			err = p.checkAccess(id)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("checkAccess = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("checkAccess = nil, want a refusal")
			}
			// The broker distinguishes a policy refusal from an outage by this
			// sentinel: one denies the login, the other reports it unavailable.
			if !errors.Is(err, ErrAccessForbidden) {
				t.Errorf("err = %v, want it to wrap ErrAccessForbidden", err)
			}
		})
	}
}

func TestRevokeAccessToken(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotUser   string
		gotPass   string
		gotToken  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotUser, gotPass, _ = r.BasicAuth()

		var body struct {
			AccessToken string `json:"access_token"`
		}
		_ = jsonDecode(r, &body)
		gotToken = body.AccessToken

		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := providerFor(t, srv.URL).RevokeAccessToken(context.Background(), "gho_abc"); err != nil {
		t.Fatalf("RevokeAccessToken: %v", err)
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", gotMethod)
	}
	if gotPath != "/applications/cid/token" {
		t.Errorf("path = %q", gotPath)
	}
	// Revocation is authenticated with the app's own credentials.
	if gotUser != "cid" || gotPass != "csecret" {
		t.Errorf("basic auth = %q:%q", gotUser, gotPass)
	}
	if gotToken != "gho_abc" {
		t.Errorf("access_token = %q", gotToken)
	}
}

func TestRevokeAccessTokenReportsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if err := providerFor(t, srv.URL).RevokeAccessToken(context.Background(), "gho_abc"); err == nil {
		t.Error("RevokeAccessToken reported success on a 404; the token may still be live")
	}
}

func TestTokenDisplayLabelDoesNotRevealTheToken(t *testing.T) {
	label := tokenDisplayLabel(realisticToken)
	if strings.Contains(label, realisticToken) {
		t.Error("the label contains the whole token")
	}
	if !strings.Contains(label, "...") {
		t.Errorf("label = %q, want an elided form", label)
	}
	// Short strings cannot be elided meaningfully; they are returned as-is.
	if got := tokenDisplayLabel("short"); got != "short" {
		t.Errorf("tokenDisplayLabel(short) = %q", got)
	}
}

// --- helpers ---

// providerFor builds a provider whose every endpoint points at one test server.
func providerFor(t *testing.T, baseURL string) *Provider {
	t.Helper()

	p, err := NewWithEndpoints(providerConfig(), Endpoints{
		DeviceAuth: baseURL + "/login/device/code",
		Token:      baseURL + "/login/oauth/access_token",
		APIBase:    baseURL,
	})
	if err != nil {
		t.Fatalf("NewWithEndpoints: %v", err)
	}
	return p
}

func jsonDecode(r *http.Request, dest interface{}) error {
	defer func() { _ = r.Body.Close() }()
	return json.NewDecoder(r.Body).Decode(dest)
}
