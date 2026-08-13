package mapper

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/enrollment"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider/github"
)

func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

func identity() *github.Identity {
	return &github.Identity{
		Provider: "github",
		Login:    "alice",
		Name:     "Alice Example",
		Email:    "alice@example.com",
		Orgs:     []string{"acme"},
		Teams:    []string{"acme/eng"},
	}
}

func TestRuleMatching(t *testing.T) {
	tests := []struct {
		name  string
		match config.MatchCriteria
		want  bool
	}{
		{"empty criteria matches anything", config.MatchCriteria{}, true},
		{"login match", config.MatchCriteria{GitHubLogin: "alice"}, true},
		{"login is case-insensitive", config.MatchCriteria{GitHubLogin: "ALICE"}, true},
		{"login mismatch", config.MatchCriteria{GitHubLogin: "bob"}, false},
		{"org match", config.MatchCriteria{GitHubOrg: "acme"}, true},
		{"org is case-insensitive", config.MatchCriteria{GitHubOrg: "Acme"}, true},
		{"org mismatch", config.MatchCriteria{GitHubOrg: "other"}, false},
		{"team match", config.MatchCriteria{GitHubTeam: "acme/eng"}, true},
		{"team mismatch", config.MatchCriteria{GitHubTeam: "acme/ops"}, false},
		{
			"all criteria are ANDed: one mismatch fails the rule",
			config.MatchCriteria{GitHubLogin: "alice", GitHubOrg: "acme", GitHubTeam: "acme/ops"},
			false,
		},
		{
			"all criteria satisfied",
			config.MatchCriteria{GitHubLogin: "alice", GitHubOrg: "acme", GitHubTeam: "acme/eng"},
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ruleMatches(tc.match, identity()); got != tc.want {
				t.Errorf("ruleMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFirstMatchingRuleWins(t *testing.T) {
	c := New(config.MapperConfig{Rules: []config.MappingRule{
		{Match: config.MatchCriteria{GitHubTeam: "acme/ops"}, LocalUser: "opsuser"},
		{Match: config.MatchCriteria{GitHubOrg: "acme"}, LocalUser: "orguser", Groups: []string{"devs"}},
		{Match: config.MatchCriteria{}, LocalUser: "catchall"},
	}})

	res, err := c.Map(context.Background(), identity(), "")
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if res.LocalUser != "orguser" {
		t.Errorf("LocalUser = %q, want orguser (the first matching rule)", res.LocalUser)
	}
	if len(res.Groups) != 1 || res.Groups[0] != "devs" {
		t.Errorf("Groups = %v, want [devs]", res.Groups)
	}
}

func TestNoMatchReturnsErrNoMapping(t *testing.T) {
	c := New(config.MapperConfig{Rules: []config.MappingRule{
		{Match: config.MatchCriteria{GitHubLogin: "bob"}, LocalUser: "bob"},
	}})

	_, err := c.Map(context.Background(), identity(), "")
	if !errors.Is(err, ErrNoMapping) {
		t.Errorf("err = %v, want ErrNoMapping", err)
	}
}

func TestExpandLocalUser(t *testing.T) {
	id := identity()

	tests := []struct {
		tmpl    string
		want    string
		wantErr bool
	}{
		{"static", "static", false},
		{"{{ .Login }}", "alice", false},
		{"{{.Login}}", "alice", false},
		{"{login}", "alice", false},
		{"{{ .Email }}", "alice@example.com", false},
		{"{{.Email}}", "alice@example.com", false},
		{"{email}", "alice@example.com", false},
		{"{{ .Name }}", "Alice Example", false},
		{"{{.Name}}", "Alice Example", false},
		{"{name}", "Alice Example", false},
		{"gh-{{ .Login }}", "gh-alice", false},
		// Anything left unexpanded is refused rather than passed through as a
		// literal, which would produce a nonsense username.
		{"{{ .Bad }}", "", true},
		{"{{ .Login | upper }}", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.tmpl, func(t *testing.T) {
			got, err := expandLocalUser(tc.tmpl, id)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expandLocalUser(%q) = %q, want error", tc.tmpl, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("expandLocalUser(%q): %v", tc.tmpl, err)
			}
			if got != tc.want {
				t.Errorf("expandLocalUser(%q) = %q, want %q", tc.tmpl, got, tc.want)
			}
		})
	}
}

// TestTemplateInjectionViaIdentityIsRejected covers a GitHub-controlled field
// smuggling template syntax into the expanded username. GitHub logins cannot
// actually contain braces today, but the mapper must not depend on that.
func TestTemplateInjectionViaIdentityIsRejected(t *testing.T) {
	id := identity()
	id.Login = "evil{{ .Email }}"

	if _, err := expandLocalUser("{{ .Login }}", id); err == nil {
		t.Error("template syntax injected through the GitHub login was accepted")
	}
}

// TestInvalidUnixUsernamesAreRejected: a mapping that yields something the OS
// cannot name must fail loudly rather than reach the rest of the stack.
func TestInvalidUnixUsernamesAreRejected(t *testing.T) {
	bad := []string{
		"Alice",                                 // uppercase
		"alice bob",                             // space
		"alice;rm -rf /",                        // shell metacharacters
		"../root",                               // path traversal
		"1alice",                                // leading digit
		"-alice",                                // leading hyphen
		"aliceaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // over 32 chars
		"",                                      // empty
	}

	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			c := New(config.MapperConfig{Rules: []config.MappingRule{
				{Match: config.MatchCriteria{}, LocalUser: name},
			}})
			if _, err := c.Map(context.Background(), identity(), ""); err == nil {
				t.Errorf("local_user %q was accepted as a Unix username", name)
			}
		})
	}
}

// --- Tier 0: enrollment ---

func writeEnrollment(t *testing.T, recs ...enrollment.Record) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "enrolled-users.yaml")
	store := &enrollment.Store{Enrollments: recs}
	if err := store.Save(path); err != nil {
		t.Fatalf("save enrollment: %v", err)
	}
	return path
}

func TestEnrollmentTierRunsBeforeRules(t *testing.T) {
	path := writeEnrollment(t, enrollment.Record{
		LocalUser:   "alice",
		GitHubLogin: "alice",
		Groups:      []string{"enrolled"},
	})

	c := New(config.MapperConfig{
		EnrollmentEnabled: true,
		EnrollmentFile:    path,
		Rules: []config.MappingRule{
			{Match: config.MatchCriteria{}, LocalUser: "ruleuser"},
		},
	})

	res, err := c.Map(context.Background(), identity(), "alice")
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if res.LocalUser != "alice" || len(res.Groups) != 1 || res.Groups[0] != "enrolled" {
		t.Errorf("got %+v, want the enrollment record (tier 0 must win)", res)
	}
}

func TestEnrollmentTierSkippedWithoutRequestedUser(t *testing.T) {
	path := writeEnrollment(t, enrollment.Record{LocalUser: "alice", GitHubLogin: "alice"})

	c := New(config.MapperConfig{
		EnrollmentEnabled: true,
		EnrollmentFile:    path,
		Rules: []config.MappingRule{
			{Match: config.MatchCriteria{}, LocalUser: "ruleuser"},
		},
	})

	// A dry run passes "" and must fall through to the rules.
	res, err := c.Map(context.Background(), identity(), "")
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if res.LocalUser != "ruleuser" {
		t.Errorf("LocalUser = %q, want ruleuser", res.LocalUser)
	}
}

// TestEnrollmentRequiresBothHalvesOfThePair: an enrollment for (alice, alice)
// must not authorize bob's GitHub account logging in as alice, nor alice's
// GitHub account logging in as bob.
func TestEnrollmentRequiresBothHalvesOfThePair(t *testing.T) {
	path := writeEnrollment(t, enrollment.Record{LocalUser: "alice", GitHubLogin: "alice"})
	c := New(config.MapperConfig{EnrollmentEnabled: true, EnrollmentFile: path})

	id := identity()
	id.Login = "mallory"
	if _, err := c.Map(context.Background(), id, "alice"); !errors.Is(err, ErrNoMapping) {
		t.Errorf("wrong GitHub login matched an enrollment: %v", err)
	}

	if _, err := c.Map(context.Background(), identity(), "bob"); !errors.Is(err, ErrNoMapping) {
		t.Errorf("wrong local user matched an enrollment: %v", err)
	}
}

func TestEnrollmentWithInvalidUsernameIsSkipped(t *testing.T) {
	path := writeEnrollment(t, enrollment.Record{LocalUser: "root;evil", GitHubLogin: "alice"})
	c := New(config.MapperConfig{EnrollmentEnabled: true, EnrollmentFile: path})

	if _, err := c.Map(context.Background(), identity(), "root;evil"); !errors.Is(err, ErrNoMapping) {
		t.Errorf("an enrollment record with an invalid Unix username was used: %v", err)
	}
}

func TestMissingEnrollmentFileFallsThrough(t *testing.T) {
	c := New(config.MapperConfig{
		EnrollmentEnabled: true,
		EnrollmentFile:    filepath.Join(t.TempDir(), "does-not-exist.yaml"),
		Rules: []config.MappingRule{
			{Match: config.MatchCriteria{}, LocalUser: "ruleuser"},
		},
	})

	res, err := c.Map(context.Background(), identity(), "alice")
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if res.LocalUser != "ruleuser" {
		t.Errorf("LocalUser = %q, want ruleuser", res.LocalUser)
	}
}

// --- Tier 2: external script ---

func writeScript(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts are not runnable on windows")
	}
	path := filepath.Join(t.TempDir(), "map.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return path
}

func TestScriptTier(t *testing.T) {
	script := writeScript(t, `
# Echo back a mapping derived from the identity on stdin, proving the input
# reached the script.
login=$(sed -n 's/.*"login":"\([^"]*\)".*/\1/p')
printf '{"local_user":"%s","groups":["scripted"]}' "$login"
`)

	c := New(config.MapperConfig{ExternalScript: script, ExternalScriptTimeout: 5 * time.Second})

	res, err := c.Map(context.Background(), identity(), "")
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if res.LocalUser != "alice" {
		t.Errorf("LocalUser = %q, want alice", res.LocalUser)
	}
	if len(res.Groups) != 1 || res.Groups[0] != "scripted" {
		t.Errorf("Groups = %v, want [scripted]", res.Groups)
	}
}

func TestScriptFailureFallsThroughToHTTP(t *testing.T) {
	script := writeScript(t, "exit 1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"local_user":"httpuser"}`))
	}))
	defer srv.Close()

	c := New(config.MapperConfig{ExternalScript: script, HTTPEndpoint: srv.URL})

	res, err := c.Map(context.Background(), identity(), "")
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if res.LocalUser != "httpuser" {
		t.Errorf("LocalUser = %q, want httpuser", res.LocalUser)
	}
}

func TestScriptEmptyLocalUserIsNoMapping(t *testing.T) {
	script := writeScript(t, `printf '{"local_user":""}'`)
	c := New(config.MapperConfig{ExternalScript: script})

	if _, err := c.Map(context.Background(), identity(), ""); !errors.Is(err, ErrNoMapping) {
		t.Errorf("err = %v, want ErrNoMapping", err)
	}
}

// TestScriptEnvironmentIsRestricted: the script must not inherit the broker's
// environment, which holds the OAuth client secret when configured via env.
func TestScriptEnvironmentIsRestricted(t *testing.T) {
	t.Setenv("OAUTH2_PAM_SECRET_CANARY", "leaked")

	script := writeScript(t, `
if [ -n "$OAUTH2_PAM_SECRET_CANARY" ]; then
  printf '{"local_user":"%s"}' "leaked"
else
  printf '{"local_user":"clean"}'
fi
`)

	c := New(config.MapperConfig{ExternalScript: script})
	res, err := c.Map(context.Background(), identity(), "")
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if res.LocalUser != "clean" {
		t.Error("the broker's environment was visible to the mapping script")
	}
}

// --- Tier 3: HTTP service ---

func TestHTTPTier(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantUser    string
		wantNoMatch bool
	}{
		{"200 with mapping", 200, `{"local_user":"httpuser","groups":["g1"]}`, "httpuser", false},
		{"200 with empty local_user", 200, `{"local_user":""}`, "", true},
		{"404 means no mapping", 404, "", "", true},
		{"204 means no mapping", 204, "", "", true},
		{"500 is an error, not a mapping", 500, "boom", "", true},
		{"unparseable body", 200, "not json", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, want POST", r.Method)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			c := New(config.MapperConfig{HTTPEndpoint: srv.URL, HTTPTimeout: 5 * time.Second})
			res, err := c.Map(context.Background(), identity(), "")

			if tc.wantNoMatch {
				if !errors.Is(err, ErrNoMapping) {
					t.Fatalf("err = %v, want ErrNoMapping", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Map: %v", err)
			}
			if res.LocalUser != tc.wantUser {
				t.Errorf("LocalUser = %q, want %q", res.LocalUser, tc.wantUser)
			}
		})
	}
}

// TestHTTPTierRefusesRedirects guards against SSRF: an operator-configured (and
// possibly compromised) mapping service must not be able to redirect the broker
// at a link-local metadata endpoint or another internal service.
func TestHTTPTierRefusesRedirects(t *testing.T) {
	var internalHit bool
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		internalHit = true
		_, _ = w.Write([]byte(`{"local_user":"root"}`))
	}))
	defer internal.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer redirector.Close()

	c := New(config.MapperConfig{HTTPEndpoint: redirector.URL})

	if _, err := c.Map(context.Background(), identity(), ""); !errors.Is(err, ErrNoMapping) {
		t.Errorf("err = %v, want ErrNoMapping", err)
	}
	if internalHit {
		t.Error("the mapper followed a redirect to another host (SSRF)")
	}
}

func TestHTTPTierRespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte(`{"local_user":"slow"}`))
	}))
	defer srv.Close()

	c := New(config.MapperConfig{HTTPEndpoint: srv.URL, HTTPTimeout: 50 * time.Millisecond})

	start := time.Now()
	if _, err := c.Map(context.Background(), identity(), ""); !errors.Is(err, ErrNoMapping) {
		t.Errorf("err = %v, want ErrNoMapping", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Map took %s; http_timeout was not honoured", elapsed)
	}
}

func TestNoTiersConfigured(t *testing.T) {
	c := New(config.MapperConfig{})
	if _, err := c.Map(context.Background(), identity(), "alice"); !errors.Is(err, ErrNoMapping) {
		t.Errorf("err = %v, want ErrNoMapping", err)
	}
}
