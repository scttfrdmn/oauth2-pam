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

	"encoding/json"
	"io"
	"reflect"
	"strings"

	"github.com/rs/zerolog"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/enrollment"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
)

func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

func identity() *provider.Identity {
	id := &provider.Identity{
		Provider: "github",
		Type:     "github",
		Subject:  "1001",
		Login:    "alice",
		Name:     "Alice Example",
		Email:    "alice@example.com",
	}
	id.AddClaim(provider.ClaimOrg, "acme")
	id.AddClaim(provider.ClaimTeam, "acme/eng")
	return id
}

func TestRuleMatching(t *testing.T) {
	tests := []struct {
		name  string
		match config.MatchCriteria
		want  bool
	}{
		{"empty criteria matches anything", config.MatchCriteria{}, true},
		{"login match", config.MatchCriteria{Login: "alice"}, true},
		{"login is case-insensitive", config.MatchCriteria{GitHubLogin: "ALICE"}, true},
		{"login mismatch", config.MatchCriteria{GitHubLogin: "bob"}, false},
		{"org match", config.MatchCriteria{GitHubOrg: "acme"}, true},
		{"org is case-insensitive", config.MatchCriteria{GitHubOrg: "Acme"}, true},
		{"org mismatch", config.MatchCriteria{GitHubOrg: "other"}, false},
		{"team match", config.MatchCriteria{GitHubTeam: "acme/eng"}, true},
		{"team mismatch", config.MatchCriteria{GitHubTeam: "acme/ops"}, false},
		{
			"all criteria are ANDed: one mismatch fails the rule",
			config.MatchCriteria{Login: "alice", GitHubOrg: "acme", GitHubTeam: "acme/ops"},
			false,
		},
		{
			"all criteria satisfied",
			config.MatchCriteria{Login: "alice", GitHubOrg: "acme", GitHubTeam: "acme/eng"},
			true,
		},

		// The neutral spelling: github_org and github_team are the GitHub names
		// for the "org" and "team" claims, so a rule written either way means
		// the same thing.
		{"claim org match", config.MatchCriteria{Claims: map[string]string{"org": "acme"}}, true},
		{"claim org is case-insensitive", config.MatchCriteria{Claims: map[string]string{"org": "ACME"}}, true},
		{"claim org mismatch", config.MatchCriteria{Claims: map[string]string{"org": "other"}}, false},
		{"claim team match", config.MatchCriteria{Claims: map[string]string{"team": "acme/eng"}}, true},
		{
			"claims are ANDed with each other",
			config.MatchCriteria{Claims: map[string]string{"org": "acme", "team": "acme/ops"}},
			false,
		},
		{
			"claims are ANDed with the github_* keys",
			config.MatchCriteria{GitHubOrg: "acme", Claims: map[string]string{"team": "acme/ops"}},
			false,
		},
		{
			"a claim the identity does not assert never matches",
			config.MatchCriteria{Claims: map[string]string{"group": "platform-team"}},
			false,
		},
		{
			"an empty claim value is not a requirement",
			config.MatchCriteria{Claims: map[string]string{"org": ""}},
			true,
		},
		{
			"login takes precedence over github_login",
			config.MatchCriteria{Login: "alice", GitHubLogin: "bob"},
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
		LocalUser: "alice",
		Login:     "alice",
		Groups:    []string{"enrolled"},
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
	path := writeEnrollment(t, enrollment.Record{LocalUser: "alice", Login: "alice"})

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
	path := writeEnrollment(t, enrollment.Record{LocalUser: "alice", Login: "alice"})
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
	path := writeEnrollment(t, enrollment.Record{LocalUser: "root;evil", Login: "alice"})
	c := New(config.MapperConfig{EnrollmentEnabled: true, EnrollmentFile: path})

	if _, err := c.Map(context.Background(), identity(), "root;evil"); !errors.Is(err, ErrNoMapping) {
		t.Errorf("an enrollment record with an invalid Unix username was used: %v", err)
	}
}

// --- the exported gate, for write-time callers ---

// TestValidateLocalUserRefusesWhatTheTiersRefuse pins the exported gate against
// the same cases checkLocalUser refuses for a tier: the name shape, the
// system-account denylist, root by UID, and the min_uid floor.
func TestValidateLocalUserRefusesForbiddenAccounts(t *testing.T) {
	passwd := map[string]int{"root": 0, "www-data": 33, "svc": 120, "alice": 1000}
	cfg := config.MapperConfig{}

	forbidden := []struct {
		name, why string
	}{
		{"root", "UID 0"},
		{"www-data", "a denylisted service account"},
		{"systemd-resolve", "a denylisted prefix"},
		{"svc", "below the min_uid floor"},
		{"Alice", "uppercase"},
		{"1alice", "leading digit"},
		{strings.Repeat("a", 33), "over 32 characters"},
		{"al/ice", "an embedded slash"},
		{"al\x00ice", "an embedded NUL"},
		{"", "empty"},
	}
	for _, tc := range forbidden {
		t.Run(tc.why, func(t *testing.T) {
			c := chainWithPasswd(t, cfg, passwd)
			err := c.ValidateLocalUser("enrollment", tc.name)
			if !errors.Is(err, ErrForbiddenLocalUser) {
				t.Fatalf("ValidateLocalUser(%q) error = %v, want ErrForbiddenLocalUser", tc.name, err)
			}
			if !strings.Contains(err.Error(), "enrollment") {
				t.Errorf("error = %q, want it to name the caller so the operator knows what refused", err)
			}
		})
	}

	// The control: an ordinary account above the floor is accepted.
	c := chainWithPasswd(t, cfg, passwd)
	if err := c.ValidateLocalUser("enrollment", "alice"); err != nil {
		t.Errorf("ValidateLocalUser(alice): %v", err)
	}

	// And an account that does not resolve here is accepted, deliberately: the
	// floor cannot be applied without a UID, and enrolling a user before their
	// account exists — or one who lives in LDAP on a broker built without cgo — is
	// legitimate. This mirrors login time exactly; see
	// TestUnresolvableAccountPassesTheFloorButNotTheDenylist.
	c = chainWithPasswd(t, cfg, passwd)
	if err := c.ValidateLocalUser("enrollment", "notyetcreated"); err != nil {
		t.Errorf("ValidateLocalUser refused an account that does not exist yet: %v", err)
	}
}

// TestValidateLocalUserAgreesWithMap is the reason the write-time check calls the
// mapper's gate instead of restating its rules: a name accepted at enrollment must
// be one the login path accepts, and vice versa. If the two ever drift, this fails.
func TestValidateLocalUserAgreesWithMap(t *testing.T) {
	passwd := map[string]int{"root": 0, "www-data": 33, "svc": 120, "alice": 1000, "bob": 1001}
	// "" is left out because it is not a name a login can request: Map skips tier 0
	// entirely when requestedLocalUser is empty, so there is no read-time answer to
	// compare against.
	names := []string{
		"root", "www-data", "systemd-resolve", "svc", "Alice", "1alice",
		strings.Repeat("a", 33), "alice", "bob", "notyetcreated",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			id := identityWithLogin("attacker")

			// Write-time: what the enroll path would be told.
			gate := chainWithPasswd(t, config.MapperConfig{}, passwd)
			writeErr := gate.ValidateLocalUser("enrollment", name)

			// Read-time: the same name reaching Map through tier 0.
			path := writeEnrollment(t, enrollment.Record{
				LocalUser: name,
				Login:     "attacker",
				Provider:  "github",
			})
			c := chainWithPasswd(t, config.MapperConfig{
				EnrollmentEnabled: true,
				EnrollmentFile:    path,
			}, passwd)
			_, readErr := c.Map(context.Background(), id, name)

			// Map can refuse either as forbidden or as no-mapping (an unusable name
			// is skipped by tier 0); what must agree is whether it refuses at all.
			if (writeErr != nil) != (readErr != nil) {
				t.Fatalf("local_user %q: write-time err = %v, login-time err = %v; the two gates disagree",
					name, writeErr, readErr)
			}
		})
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

// TestNeutralClaimsMapAProviderWithNoOrgs is the mapper half of the provider
// interface: an identity asserting only flat "group" claims — the shape an OIDC
// provider returns, with no orgs or teams at all — maps through a rule that
// names the claim, with no GitHub vocabulary involved.
func TestNeutralClaimsMapAProviderWithNoOrgs(t *testing.T) {
	id := &provider.Identity{
		Provider: "corp-sso",
		Type:     "oidc",
		Subject:  "8f14e45f",
		Login:    "a.example",
	}
	id.AddClaim(provider.ClaimGroup, "platform-team", "staff")

	c := New(config.MapperConfig{Rules: []config.MappingRule{
		{Match: config.MatchCriteria{Claims: map[string]string{"group": "contractors"}}, LocalUser: "restricted"},
		{Match: config.MatchCriteria{Claims: map[string]string{"group": "platform-team"}}, LocalUser: "platformuser"},
	}})

	res, err := c.Map(context.Background(), id, "")
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if res.LocalUser != "platformuser" {
		t.Errorf("LocalUser = %q, want platformuser", res.LocalUser)
	}

	// {{ .Login }} is not usable for such a provider: this login is not a valid
	// Unix username, and the mapper refuses rather than producing one that no
	// account can have. A provider whose logins are email addresses needs an
	// explicit local_user, or Tier 2/3.
	c = New(config.MapperConfig{Rules: []config.MappingRule{
		{Match: config.MatchCriteria{}, LocalUser: "{{ .Login }}"},
	}})
	if _, err := c.Map(context.Background(), id, ""); err == nil {
		t.Error("Map accepted {{ .Login }} expanding to an invalid Unix username")
	}
}

// The error for an unmapped identity has to say what the identity actually
// carried, or an operator debugging a failed login has nothing to compare their
// rules against.
func TestNoMappingErrorNamesTheProviderAndClaims(t *testing.T) {
	c := New(config.MapperConfig{Rules: []config.MappingRule{
		{Match: config.MatchCriteria{Login: "bob"}, LocalUser: "bob"},
	}})

	_, err := c.Map(context.Background(), identity(), "")
	if err == nil {
		t.Fatal("Map succeeded for an identity no rule matches")
	}
	for _, want := range []string{"github", "alice", "acme/eng"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q", err, want)
		}
	}
}

// TestTierPayloadCarriesClaimsAndKeepsOrgsAndTeams pins the Tier 2/3 contract.
// claims is the provider-neutral form a new consumer should read; orgs and teams
// stay as the GitHub-shaped view of the same data because scripts in the wild
// parse them, and dropping them would break those scripts silently.
func TestTierPayloadCarriesClaimsAndKeepsOrgsAndTeams(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"local_user":"httpuser"}`))
	}))
	defer srv.Close()

	c := New(config.MapperConfig{HTTPEndpoint: srv.URL, HTTPTimeout: 5 * time.Second})
	if _, err := c.Map(context.Background(), identity(), ""); err != nil {
		t.Fatalf("Map: %v", err)
	}

	var got struct {
		Provider string              `json:"provider"`
		Type     string              `json:"type"`
		Subject  string              `json:"subject"`
		Login    string              `json:"login"`
		Orgs     []string            `json:"orgs"`
		Teams    []string            `json:"teams"`
		Claims   map[string][]string `json:"claims"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal payload %s: %v", body, err)
	}

	if got.Provider != "github" || got.Type != "github" || got.Subject != "1001" || got.Login != "alice" {
		t.Errorf("payload identity = %+v, want provider/type github, subject 1001, login alice", got)
	}
	if len(got.Orgs) != 1 || got.Orgs[0] != "acme" {
		t.Errorf("orgs = %v, want [acme]", got.Orgs)
	}
	if len(got.Teams) != 1 || got.Teams[0] != "acme/eng" {
		t.Errorf("teams = %v, want [acme/eng]", got.Teams)
	}
	if want := []string{"acme"}; !reflect.DeepEqual(got.Claims["org"], want) {
		t.Errorf("claims.org = %v, want %v", got.Claims["org"], want)
	}
	if want := []string{"acme/eng"}; !reflect.DeepEqual(got.Claims["team"], want) {
		t.Errorf("claims.team = %v, want %v", got.Claims["team"], want)
	}
}

// An identity with no memberships must still send orgs and teams as empty
// arrays, not null: a script doing `jq -r '.orgs[]'` on null errors out, where
// on [] it produces nothing.
func TestTierPayloadUsesEmptyArraysNotNull(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	id := &provider.Identity{Provider: "corp-sso", Type: "oidc", Login: "alice"}
	c := New(config.MapperConfig{HTTPEndpoint: srv.URL, HTTPTimeout: 5 * time.Second})
	if _, err := c.Map(context.Background(), id, ""); !errors.Is(err, ErrNoMapping) {
		t.Fatalf("err = %v, want ErrNoMapping", err)
	}

	if !strings.Contains(string(body), `"orgs":[]`) || !strings.Contains(string(body), `"teams":[]`) {
		t.Errorf("payload = %s, want empty arrays for orgs and teams", body)
	}
}
