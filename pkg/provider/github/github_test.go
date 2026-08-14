package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
)

func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

// realisticToken has the length and shape of a real GitHub access token, so a
// fingerprint of it is being asked to hide something worth hiding.
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

// TestEnterpriseEndpoints covers the config route to a non-github.com instance:
// the device and token endpoints sit at the same paths as github.com, but the
// REST API moves to /api/v3.
func TestEnterpriseEndpoints(t *testing.T) {
	// The trailing slash is the shape an operator is most likely to paste in.
	e := EnterpriseEndpoints("https://github.acme.internal/")

	if want := "https://github.acme.internal/login/device/code"; e.DeviceAuth != want {
		t.Errorf("DeviceAuth = %q, want %q", e.DeviceAuth, want)
	}
	if want := "https://github.acme.internal/login/oauth/access_token"; e.Token != want {
		t.Errorf("Token = %q, want %q", e.Token, want)
	}
	if want := "https://github.acme.internal/api/v3"; e.APIBase != want {
		t.Errorf("APIBase = %q, want %q", e.APIBase, want)
	}
	if _, err := e.validate(); err != nil {
		t.Errorf("enterprise endpoints do not validate: %v", err)
	}
}

// TestNewHonorsBaseURL pins the wiring, not just the derivation: a base_url in
// the config has to reach the provider, or the setting is decorative.
func TestNewHonorsBaseURL(t *testing.T) {
	cfg := providerConfig()
	cfg.GitHub.BaseURL = "https://github.acme.internal"

	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if want := EnterpriseEndpoints(cfg.GitHub.BaseURL); p.endpoints != want {
		t.Errorf("endpoints = %+v, want %+v", p.endpoints, want)
	}

	onDotCom, err := New(providerConfig())
	if err != nil {
		t.Fatalf("New = %v", err)
	}
	if onDotCom.endpoints != DefaultEndpoints() {
		t.Errorf("without base_url, endpoints = %+v, want github.com", onDotCom.endpoints)
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

	_, err = p.GetIdentity(context.Background(), &provider.Token{AccessToken: "gho_x"})
	if err == nil {
		t.Fatal("GetIdentity followed a cross-host redirect")
	}
	if !strings.Contains(err.Error(), "unconfigured origin") {
		t.Errorf("err = %v, want the redirect to be refused by name", err)
	}
	if elsewhereHit.Load() {
		t.Error("the bearer token was sent to a host outside the configured endpoints")
	}
}

// TestRedirectDowngradingToHTTPIsRefused: the host is not the whole of an
// origin. net/http decides whether to keep the Authorization header by comparing
// hostnames only, so an https→http redirect back to the same host carries the
// live access token in cleartext to whoever is on the path. Pinning the hostname
// alone let that through, while nextPageURL had pinned scheme and host all along.
func TestRedirectDowngradingToHTTPIsRefused(t *testing.T) {
	var cleartextHit atomic.Bool
	cleartext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleartextHit.Store(true)
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("the access token was sent over plain http: %q", got)
		}
		_, _ = w.Write([]byte(`{"login":"attacker"}`))
	}))
	defer cleartext.Close()

	// Both servers listen on 127.0.0.1, so the scheme is the only thing that
	// differs between the configured endpoint and the redirect target — which is
	// exactly the case a hostname comparison cannot see.
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, cleartext.URL+"/user", http.StatusFound)
	}))
	defer secure.Close()

	p := providerFor(t, secure.URL)
	// The test server's certificate is signed by nothing in the trust store, so
	// borrowing its client is the only way to drive a real https→http hop.
	p.httpClient.Transport = secure.Client().Transport

	_, err := p.getUser(context.Background(), realisticToken)
	if err == nil {
		t.Fatal("getUser followed a redirect that downgraded to http")
	}
	if !strings.Contains(err.Error(), "unconfigured origin") {
		t.Errorf("err = %v, want the redirect to be refused for its origin", err)
	}
	if cleartextHit.Load() {
		t.Error("the request was replayed over cleartext http")
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

// TestDeviceCodeLifetimeIsClamped: expires_in is a number the provider chooses
// and it becomes the pending session's deadline. Taken as given, an absent field
// expired the login immediately, a value above ~9.2e9 overflowed int64
// nanoseconds into a deadline in the past, and anything in between could hold a
// session open for as long as the provider liked.
func TestDeviceCodeLifetimeIsClamped(t *testing.T) {
	tests := []struct {
		name      string
		expiresIn string
		wantAtMost,
		wantAtLeast time.Duration
	}{
		{"github's own value", "900", 15 * time.Minute, 14 * time.Minute},
		{"absent", "0", defaultDeviceCodeLifetime, defaultDeviceCodeLifetime - time.Minute},
		{"negative", "-1", defaultDeviceCodeLifetime, defaultDeviceCodeLifetime - time.Minute},
		{"a week", "604800", maxDeviceCodeLifetime, maxDeviceCodeLifetime - time.Minute},
		// Large enough that time.Duration(expires_in) * time.Second wraps.
		{"overflowing", "9223372036854", maxDeviceCodeLifetime, maxDeviceCodeLifetime - time.Minute},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"device_code":"d","user_code":"U","verification_uri":"https://x/",` +
					`"expires_in":` + tc.expiresIn + `}`))
			}))
			defer srv.Close()

			df, err := providerFor(t, srv.URL).StartDeviceFlow(context.Background())
			if err != nil {
				t.Fatalf("StartDeviceFlow: %v", err)
			}
			lifetime := time.Until(df.ExpiresAt)
			if lifetime > tc.wantAtMost || lifetime < tc.wantAtLeast {
				t.Errorf("lifetime = %s, want between %s and %s", lifetime, tc.wantAtLeast, tc.wantAtMost)
			}
		})
	}
}

// TestPollingIntervalIsClamped: the interval becomes the broker's poll ticker, so
// an interval the size of a week is a flow that never makes progress while its
// session and polling goroutine stay alive.
func TestPollingIntervalIsClamped(t *testing.T) {
	tests := []struct {
		interval string
		want     int
	}{
		{"5", 5},
		{"0", defaultPollInterval},
		{"-3", defaultPollInterval},
		{"86400", maxPollInterval},
	}

	for _, tc := range tests {
		t.Run(tc.interval, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"device_code":"d","user_code":"U","verification_uri":"https://x/",` +
					`"expires_in":900,"interval":` + tc.interval + `}`))
			}))
			defer srv.Close()

			df, err := providerFor(t, srv.URL).StartDeviceFlow(context.Background())
			if err != nil {
				t.Fatalf("StartDeviceFlow: %v", err)
			}
			if df.PollingInterval != tc.want {
				t.Errorf("PollingInterval = %d, want %d", df.PollingInterval, tc.want)
			}
		})
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
		{"authorization_pending", provider.ErrAuthorizationPending},
		{"slow_down", provider.ErrSlowDown},
		{"expired_token", provider.ErrExpiredToken},
		{"access_denied", provider.ErrAccessDenied},
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
	if errors.Is(err, provider.ErrAuthorizationPending) {
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
	// The fingerprint is what reaches the logs and the session record, so it must
	// be a digest rather than any part of the token itself.
	if tok.Fingerprint == tok.AccessToken {
		t.Error("Fingerprint is the raw token")
	}
	if want := tokenFingerprint(realisticToken); tok.Fingerprint != want {
		t.Errorf("Fingerprint = %q, want the token's digest %q", tok.Fingerprint, want)
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

	id, err := providerFor(t, srv.URL).GetIdentity(context.Background(), &provider.Token{AccessToken: "gho_abc"})
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if id.Login != "alice" || id.Email != "alice@example.com" || id.Name != "Alice" {
		t.Errorf("identity = %+v", id)
	}
	if len(id.Claim(provider.ClaimOrg)) != 2 {
		t.Errorf("org claims = %v, want two entries", id.Claim(provider.ClaimOrg))
	}
	// Teams are normalised to "org/slug", which is the form mapping rules use.
	if teams := id.Claim(provider.ClaimTeam); len(teams) != 1 || teams[0] != "acme/eng" {
		t.Errorf("team claims = %v, want [acme/eng]", teams)
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

	if _, err := providerFor(t, srv.URL).GetIdentity(context.Background(), &provider.Token{AccessToken: "gho_abc"}); err == nil {
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

	id, err := providerFor(t, srv.URL).GetIdentity(context.Background(), &provider.Token{AccessToken: "gho_abc"})
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	// Empty rather than nil, and definitely not a spurious membership: an org
	// requirement will now legitimately deny this identity.
	if len(id.Claim(provider.ClaimOrg)) != 0 || len(id.Claim(provider.ClaimTeam)) != 0 {
		t.Errorf("org = %v, team = %v, want both empty",
			id.Claim(provider.ClaimOrg), id.Claim(provider.ClaimTeam))
	}
}

// TestOrgAndTeamListsArePaginated: GitHub's default page size is 30, and a member
// of a large organisation is on more than 30 teams. required_teams is checked
// against this list, so a truncated page one denied logins that should have
// succeeded.
func TestOrgAndTeamListsArePaginated(t *testing.T) {
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"login":"alice"}`))
	})

	var orgPages, teamPages atomic.Int32
	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("per_page"); got != "100" {
			t.Errorf("per_page = %q, want 100", got)
		}
		if r.URL.Query().Get("page") == "" {
			// First page: 100 entries and a cursor, exactly as GitHub replies.
			orgPages.Add(1)
			w.Header().Set("Link", `<`+base+`/user/orgs?per_page=100&page=2>; rel="next", <`+base+`/user/orgs?per_page=100&page=2>; rel="last"`)
			_, _ = w.Write([]byte(jsonList("org-%d", 100, `{"login":"%s"}`)))
			return
		}
		orgPages.Add(1)
		_, _ = w.Write([]byte(jsonList("late-org-%d", 5, `{"login":"%s"}`)))
	})
	mux.HandleFunc("/user/teams", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "" {
			teamPages.Add(1)
			// rel=next without quotes is equally legal.
			w.Header().Set("Link", `<`+base+`/user/teams?per_page=100&page=2>; rel=next`)
			_, _ = w.Write([]byte(jsonList("team-%d", 100, `{"slug":"%s","organization":{"login":"acme"}}`)))
			return
		}
		teamPages.Add(1)
		_, _ = w.Write([]byte(jsonList("late-team-%d", 2, `{"slug":"%s","organization":{"login":"acme"}}`)))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	id, err := providerFor(t, srv.URL).GetIdentity(context.Background(), &provider.Token{AccessToken: "gho_abc"})
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}

	if got := len(id.Claim(provider.ClaimOrg)); got != 105 {
		t.Errorf("orgs = %d, want 105; the second page was dropped", got)
	}
	if got := len(id.Claim(provider.ClaimTeam)); got != 102 {
		t.Errorf("teams = %d, want 102; the second page was dropped", got)
	}
	if got := orgPages.Load(); got != 2 {
		t.Errorf("fetched %d org pages, want 2", got)
	}
	if got := teamPages.Load(); got != 2 {
		t.Errorf("fetched %d team pages, want 2", got)
	}

	// The last page has no cursor, so the walk must stop rather than keep asking.
	if teams := id.Claim(provider.ClaimTeam); teams[101] != "acme/late-team-1" {
		t.Errorf("last team = %q, want acme/late-team-1", teams[101])
	}
}

// A cursor is a server-controlled URL and the next request carries the user's
// access token, so one pointing elsewhere must not be followed. CheckRedirect
// does not cover this: a Link header is not a redirect.
func TestPaginationCursorToAnotherHostIsRefused(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the access token was sent to another host: %s %s", r.Method, r.URL.Path)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer elsewhere.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"login":"alice"}`))
	})
	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", `<`+elsewhere.URL+`/user/orgs?page=2>; rel="next"`)
		_, _ = w.Write([]byte(`[{"login":"acme"}]`))
	})
	mux.HandleFunc("/user/teams", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// GetIdentity degrades org failures to an empty list rather than failing the
	// login, so the assertion that matters is the one inside the other server's
	// handler; this checks the refusal reached that path.
	id, err := providerFor(t, srv.URL).GetIdentity(context.Background(), &provider.Token{AccessToken: "gho_abc"})
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if got := id.Claim(provider.ClaimOrg); len(got) != 0 {
		t.Errorf("orgs = %v, want empty: a rejected cursor must not leave a partial list that an org requirement is then checked against", got)
	}
}

// The cursor comes from the server, so the walk cannot rely on it ever saying
// "done" — a login must not be held open by a list that never ends.
func TestPaginationStopsAtThePageLimit(t *testing.T) {
	var requests atomic.Int32
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Link", `<`+base+`/user/orgs?per_page=100&page=99>; rel="next"`)
		_, _ = w.Write([]byte(`[{"login":"acme"}]`))
	}))
	defer srv.Close()
	base = srv.URL

	_, err := providerFor(t, srv.URL).getUserOrgs(context.Background(), "gho_abc")
	if err == nil {
		t.Fatal("getUserOrgs followed an endless cursor to completion")
	}
	if got := requests.Load(); got != maxAPIPages {
		t.Errorf("made %d requests, want %d", got, maxAPIPages)
	}
}

// An empty page with a cursor is the cheapest way to spin the loop, so it ends
// the walk rather than costing the full page budget.
func TestPaginationStopsOnAnEmptyPage(t *testing.T) {
	var requests atomic.Int32
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Link", `<`+base+`/user/orgs?per_page=100&page=2>; rel="next"`)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	base = srv.URL

	orgs, err := providerFor(t, srv.URL).getUserOrgs(context.Background(), "gho_abc")
	if err != nil {
		t.Fatalf("getUserOrgs: %v", err)
	}
	if len(orgs) != 0 {
		t.Errorf("orgs = %v, want empty", orgs)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("made %d requests, want 1", got)
	}
}

// TestPaginationStopsAtTheEntryLimit: nothing obliges a server to honour
// per_page, so the page count alone did not bound what a walk accumulated — a
// server returning thousands of tiny entries per page reached hundreds of
// thousands of retained entries inside the twenty-page budget.
func TestPaginationStopsAtTheEntryLimit(t *testing.T) {
	const perPage = 500

	var requests atomic.Int32
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Link", `<`+base+`/user/orgs?per_page=100&page=2>; rel="next"`)
		_, _ = w.Write([]byte(jsonList("org-%d", perPage, `{"login":"%s"}`)))
	}))
	defer srv.Close()
	base = srv.URL

	_, err := providerFor(t, srv.URL).getUserOrgs(context.Background(), "gho_abc")
	if err == nil {
		t.Fatal("getUserOrgs accepted an unbounded number of entries")
	}
	if !strings.Contains(err.Error(), "entries") {
		t.Errorf("err = %v, want the entry limit named", err)
	}
	// The entry bound has to bite before the page bound, or it is not the thing
	// stopping the walk.
	if got := requests.Load(); got >= maxAPIPages {
		t.Errorf("made %d requests, want fewer than the %d page budget", got, maxAPIPages)
	}
}

// TestOversizedResponsesAreRefused: a response body is buffered before anything
// knows how long it is, and every one of these bodies comes from the GitHub
// instance rather than from this host. Without a ceiling, a hostile or broken
// GHES exhausts the broker's memory and takes OAuth logins down host-wide.
func TestOversizedResponsesAreRefused(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		call  func(*Provider) error
	}{
		{"device authorization", maxAuthResponseSize, func(p *Provider) error {
			_, err := p.StartDeviceFlow(context.Background())
			return err
		}},
		{"token", maxAuthResponseSize, func(p *Provider) error {
			_, err := p.PollDeviceAuthorization(context.Background(), "dev-code")
			return err
		}},
		{"api", maxAPIResponseSize, func(p *Provider) error {
			_, err := p.getUser(context.Background(), realisticToken)
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Valid JSON, in a field the adapter ignores: the body is refused for
			// its size, not because it failed to parse.
			body := `{"padding":"` + strings.Repeat("a", tc.limit+1024) + `"}`
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()

			err := tc.call(providerFor(t, srv.URL))
			if err == nil {
				t.Fatalf("a %d byte response was accepted", len(body))
			}
			if !strings.Contains(err.Error(), "byte limit") {
				t.Errorf("err = %v, want the response refused for its size", err)
			}
		})
	}
}

// TestDecodeJSONBodyStopsReadingAtTheLimit is the "refused, not consumed" half of
// the bound: the reader here never ends, so a decoder that drained its input
// would never return at all.
func TestDecodeJSONBodyStopsReadingAtTheLimit(t *testing.T) {
	const limit = 4096

	body := &countingReader{r: io.MultiReader(strings.NewReader(`{"login":"`), endlessReader{})}
	var dest gitHubUser

	err := decodeJSONBody(body, limit, &dest)
	if err == nil {
		t.Fatal("an endless body was accepted")
	}
	if !strings.Contains(err.Error(), "byte limit") {
		t.Errorf("err = %v, want the body refused for its size", err)
	}
	// limit+1 is the whole budget: one byte past the limit is what proves the body
	// was over it.
	if body.n > limit+1 {
		t.Errorf("read %d bytes, want at most %d", body.n, limit+1)
	}
}

// A body that fits must still decode, or the bound has broken the common case.
func TestDecodeJSONBodyAcceptsABodyAtTheLimit(t *testing.T) {
	var dest gitHubUser

	body := `{"login":"alice","name":"` + strings.Repeat("n", 100) + `"}`
	if err := decodeJSONBody(strings.NewReader(body), int64(len(body)), &dest); err != nil {
		t.Fatalf("decodeJSONBody: %v", err)
	}
	if dest.Login != "alice" {
		t.Errorf("Login = %q, want alice", dest.Login)
	}
}

func TestParseNextLink(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"empty", "", ""},
		{"quoted rel", `<https://api.github.com/user/orgs?page=2>; rel="next"`, "https://api.github.com/user/orgs?page=2"},
		{"bare rel", `<https://api.github.com/user/orgs?page=2>; rel=next`, "https://api.github.com/user/orgs?page=2"},
		{
			"next among several",
			`<https://api.github.com/u?page=1>; rel="prev", <https://api.github.com/u?page=3>; rel="next", <https://api.github.com/u?page=9>; rel="last"`,
			"https://api.github.com/u?page=3",
		},
		{"last page has no next", `<https://api.github.com/u?page=1>; rel="first", <https://api.github.com/u?page=1>; rel="prev"`, ""},
		{"malformed target", `https://api.github.com/u?page=2; rel="next"`, ""},
		{"no params", `<https://api.github.com/u?page=2>`, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseNextLink(tc.header); got != tc.want {
				t.Errorf("parseNextLink(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

// jsonList builds a JSON array of n objects, each entryFmt with a name from
// nameFmt.
func jsonList(nameFmt string, n int, entryFmt string) string {
	entries := make([]string, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, fmt.Sprintf(entryFmt, fmt.Sprintf(nameFmt, i)))
	}
	return "[" + strings.Join(entries, ",") + "]"
}

func TestCheckAccess(t *testing.T) {
	id := &provider.Identity{Login: "alice"}
	id.AddClaim(provider.ClaimOrg, "acme")
	id.AddClaim(provider.ClaimTeam, "acme/eng")

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
			if !errors.Is(err, provider.ErrAccessForbidden) {
				t.Errorf("err = %v, want it to wrap provider.ErrAccessForbidden", err)
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

// TestTokenFingerprintRetainsNothingOfTheToken: the label this replaced was
// prefix…suffix, so it carried 16 bytes of a live secret into the session record
// and would have carried them into the first log line that printed it.
func TestTokenFingerprintRetainsNothingOfTheToken(t *testing.T) {
	fp := tokenFingerprint(realisticToken)

	sum := sha256.Sum256([]byte(realisticToken))
	if want := hex.EncodeToString(sum[:16]); fp != want {
		t.Errorf("fingerprint = %q, want %q", fp, want)
	}

	// Every substring of the token long enough to be useful must be absent — the
	// eight-byte head and tail of the old label above all.
	for n := 4; n <= len(realisticToken); n++ {
		if strings.Contains(fp, realisticToken[:n]) {
			t.Errorf("fingerprint contains the token's first %d bytes", n)
		}
		if strings.Contains(fp, realisticToken[len(realisticToken)-n:]) {
			t.Errorf("fingerprint contains the token's last %d bytes", n)
		}
	}

	// A short token is hashed like any other: returning it as-is, as the old
	// label did, hands over the whole secret.
	if got := tokenFingerprint("short"); got == "short" {
		t.Error("a short token was returned in the clear")
	}

	// Stable for one token and distinct between two, or it cannot identify a
	// token in an audit trail.
	if tokenFingerprint(realisticToken) != fp {
		t.Error("the fingerprint is not stable")
	}
	if tokenFingerprint(realisticToken+"x") == fp {
		t.Error("two different tokens share a fingerprint")
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

// endlessReader is a body that never ends: it always has more of a JSON string
// to hand over.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// countingReader records how much of the wrapped reader was actually consumed.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func jsonDecode(r *http.Request, dest interface{}) error {
	defer func() { _ = r.Body.Close() }()
	return json.NewDecoder(r.Body).Decode(dest)
}
