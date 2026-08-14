package mapper

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/provider"
	"go.yaml.in/yaml/v3"
)

// fakePasswd is a passwd database for tests: a real UID lookup would need real
// accounts, and the interesting cases (a user at UID 0, a service account at 33)
// cannot be created in a test.
func fakePasswd(entries map[string]int) func(string) (int, error) {
	return func(name string) (int, error) {
		uid, ok := entries[name]
		if !ok {
			return 0, errUserUnknown
		}
		return uid, nil
	}
}

func chainWithPasswd(t *testing.T, cfg config.MapperConfig, passwd map[string]int) *Chain {
	t.Helper()
	c := New(cfg)
	c.lookupUID = fakePasswd(passwd)
	return c
}

func identityWithLogin(login string) *provider.Identity {
	id := &provider.Identity{Provider: "github", Type: "github", Login: login}
	id.AddClaim(provider.ClaimOrg, "acme")
	return id
}

// TestDefaultMinUIDMatchesTheConfigDefault pins the duplicated constant.
// config.setDefaults cannot import this package (pkg/mapper imports pkg/config),
// so the 1000 there is written out by hand; this is what stops the two drifting.
func TestDefaultMinUIDMatchesTheConfigDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broker.yaml")
	body := "providers:\n  - name: gh\n    type: github\n    client_id: id\n    client_secret: s\n" +
		"mapper:\n  rules:\n    - match: {github_org: acme}\n      local_user: alice\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Mapper.MinUID != DefaultMinUID {
		t.Errorf("config default min_uid = %d, mapper.DefaultMinUID = %d; the two have drifted",
			cfg.Mapper.MinUID, DefaultMinUID)
	}
}

// TestRuleMappingToSystemAccountIsRefused is the regression test for the finding
// that started this: the shipped example maps local_user: "{{ .Login }}" gated
// only on org membership, so a member who named themselves after a service
// account got that account.
func TestRuleMappingToSystemAccountIsRefused(t *testing.T) {
	cfg := config.MapperConfig{Rules: []config.MappingRule{{
		Match:     config.MatchCriteria{GitHubOrg: "acme"},
		LocalUser: "{{ .Login }}",
	}}}
	passwd := map[string]int{"root": 0, "www-data": 33, "postgres": 26, "alice": 1000}

	for _, login := range []string{"root", "www-data", "postgres", "systemd-resolve", "_apt"} {
		t.Run(login, func(t *testing.T) {
			c := chainWithPasswd(t, cfg, passwd)
			_, err := c.Map(context.Background(), identityWithLogin(login), "")
			if !errors.Is(err, ErrForbiddenLocalUser) {
				t.Fatalf("Map(login=%q) error = %v, want ErrForbiddenLocalUser", login, err)
			}
		})
	}

	// The control: an ordinary account still maps.
	c := chainWithPasswd(t, cfg, passwd)
	result, err := c.Map(context.Background(), identityWithLogin("alice"), "")
	if err != nil {
		t.Fatalf("Map(login=alice): %v", err)
	}
	if result.LocalUser != "alice" {
		t.Errorf("local_user = %q, want alice", result.LocalUser)
	}
}

func TestUIDFloorRefusesAccountsBelowIt(t *testing.T) {
	// "svc" is not on any denylist, so only the floor can catch it.
	cfg := config.MapperConfig{Rules: []config.MappingRule{{
		Match:     config.MatchCriteria{GitHubOrg: "acme"},
		LocalUser: "{{ .Login }}",
	}}}
	passwd := map[string]int{"svc": 120, "alice": 1000, "zero": 0}

	c := chainWithPasswd(t, cfg, passwd)
	if _, err := c.Map(context.Background(), identityWithLogin("svc"), ""); !errors.Is(err, ErrForbiddenLocalUser) {
		t.Errorf("uid 120 error = %v, want ErrForbiddenLocalUser", err)
	}

	// A lowered floor admits it.
	low := cfg
	low.MinUID = 100
	c = chainWithPasswd(t, low, passwd)
	if _, err := c.Map(context.Background(), identityWithLogin("svc"), ""); err != nil {
		t.Errorf("min_uid 100 refused uid 120: %v", err)
	}

	// A negative min_uid does not turn the floor off. It used to, config.Validate
	// refuses one now, and New clamps one it is handed to DefaultMinUID — so the
	// two cannot disagree for a Config built in code, which is the only way a
	// negative value still reaches the mapper at all.
	negative := cfg
	negative.MinUID = -1
	c = chainWithPasswd(t, negative, passwd)
	if _, err := c.Map(context.Background(), identityWithLogin("svc"), ""); !errors.Is(err, ErrForbiddenLocalUser) {
		t.Errorf("min_uid -1 admitted uid 120: error = %v; a negative floor must not disable the floor", err)
	}

	// UID 0 is refused whatever the floor says and even with the name allowlisted,
	// because the name is not what is being checked.
	off := negative
	off.AllowSystemUsers = []string{"zero"}
	c = chainWithPasswd(t, off, passwd)
	_, err := c.Map(context.Background(), identityWithLogin("zero"), "")
	if !errors.Is(err, ErrForbiddenLocalUser) {
		t.Errorf("uid 0 with a negative min_uid: error = %v, want ErrForbiddenLocalUser", err)
	}
	if err != nil && !strings.Contains(err.Error(), "UID 0") {
		t.Errorf("error = %q, want it to name UID 0 as the reason", err)
	}
}

// A site whose real person is called "mail" must have a way out, or the denylist
// is an unfixable false denial.
func TestAllowSystemUsersExemptsByName(t *testing.T) {
	cfg := config.MapperConfig{
		Rules: []config.MappingRule{{
			Match:     config.MatchCriteria{GitHubOrg: "acme"},
			LocalUser: "{{ .Login }}",
		}},
		AllowSystemUsers: []string{"mail"},
	}
	// Above the floor: the exemption is from the name list, not from the floor.
	c := chainWithPasswd(t, cfg, map[string]int{"mail": 1042})

	result, err := c.Map(context.Background(), identityWithLogin("mail"), "")
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if result.LocalUser != "mail" {
		t.Errorf("local_user = %q, want mail", result.LocalUser)
	}

	// Still refused when it is a real service account below the floor.
	c = chainWithPasswd(t, cfg, map[string]int{"mail": 8})
	if _, err := c.Map(context.Background(), identityWithLogin("mail"), ""); !errors.Is(err, ErrForbiddenLocalUser) {
		t.Errorf("allow_system_users bypassed the UID floor: error = %v", err)
	}
}

// An account that does not resolve cannot be checked against the floor. Refusing
// would break every site whose users live in LDAP and whose broker is built
// without cgo, and it is not needed: sshd resolves the account itself before it
// can start a session. The name denylist still applies.
func TestUnresolvableAccountPassesTheFloorButNotTheDenylist(t *testing.T) {
	cfg := config.MapperConfig{Rules: []config.MappingRule{{
		Match:     config.MatchCriteria{GitHubOrg: "acme"},
		LocalUser: "{{ .Login }}",
	}}}
	empty := map[string]int{}

	c := chainWithPasswd(t, cfg, empty)
	if _, err := c.Map(context.Background(), identityWithLogin("ldapuser"), ""); err != nil {
		t.Errorf("an unresolvable ordinary account was refused: %v", err)
	}

	c = chainWithPasswd(t, cfg, empty)
	if _, err := c.Map(context.Background(), identityWithLogin("www-data"), ""); !errors.Is(err, ErrForbiddenLocalUser) {
		t.Errorf("an unresolvable system account was allowed: error = %v", err)
	}
}

// A broken passwd source is the one case where skipping the floor would hand out
// exactly the account it protects, so it is an error rather than a pass.
func TestPasswdLookupFailureIsNotAPass(t *testing.T) {
	cfg := config.MapperConfig{Rules: []config.MappingRule{{
		Match:     config.MatchCriteria{GitHubOrg: "acme"},
		LocalUser: "{{ .Login }}",
	}}}
	c := New(cfg)
	c.lookupUID = func(string) (int, error) { return 0, errors.New("nss: connection refused") }

	_, err := c.Map(context.Background(), identityWithLogin("alice"), "")
	if err == nil {
		t.Fatal("Map succeeded while the passwd source was failing")
	}
	if errors.Is(err, ErrForbiddenLocalUser) {
		t.Errorf("error = %v; an outage should not be reported as a decision about the user", err)
	}
}

// Every tier goes through the same gate, including the two that used to check
// only that local_user was non-empty.
func TestEveryTierIsGated(t *testing.T) {
	passwd := map[string]int{"www-data": 33, "root": 0}

	t.Run("tier0 enrollment", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "enrolled.yaml")
		// Written as raw YAML: the enrollment store's own API would be entitled to
		// reject this record, and the point is that a file edited by hand cannot
		// smuggle one past the mapper.
		body := map[string]any{"enrollments": []map[string]any{
			{"local_user": "www-data", "login": "attacker", "provider": "github"},
		}}
		out, err := yaml.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out, 0600); err != nil {
			t.Fatal(err)
		}

		c := chainWithPasswd(t, config.MapperConfig{
			EnrollmentEnabled: true,
			EnrollmentFile:    path,
		}, passwd)

		_, err = c.Map(context.Background(), identityWithLogin("attacker"), "www-data")
		if !errors.Is(err, ErrForbiddenLocalUser) {
			t.Fatalf("error = %v, want ErrForbiddenLocalUser", err)
		}
	})

	t.Run("tier2 script", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "map.sh")
		// The shape of a real script that trusts its input: echo the login back.
		body := "#!/bin/sh\nprintf '{\"local_user\":\"www-data\"}'\n"
		if err := os.WriteFile(script, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}

		c := chainWithPasswd(t, config.MapperConfig{ExternalScript: script}, passwd)
		_, err := c.Map(context.Background(), identityWithLogin("attacker"), "")
		if !errors.Is(err, ErrForbiddenLocalUser) {
			t.Fatalf("error = %v, want ErrForbiddenLocalUser", err)
		}
	})

	t.Run("tier3 http", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(w).Encode(Result{LocalUser: "root"})
		}))
		defer srv.Close()

		c := chainWithPasswd(t, config.MapperConfig{HTTPEndpoint: srv.URL}, passwd)
		_, err := c.Map(context.Background(), identityWithLogin("attacker"), "")
		if !errors.Is(err, ErrForbiddenLocalUser) {
			t.Fatalf("error = %v, want ErrForbiddenLocalUser", err)
		}
	})
}

// A refused answer is terminal: consulting the next tier for a more convenient
// one would turn a refusal into a retry.
func TestForbiddenTier2ResultDoesNotFallThroughToTier3(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "map.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '{\"local_user\":\"www-data\"}'\n"), 0700); err != nil {
		t.Fatal(err)
	}

	var tier3Called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tier3Called = true
		_ = json.NewEncoder(w).Encode(Result{LocalUser: "alice"})
	}))
	defer srv.Close()

	c := chainWithPasswd(t, config.MapperConfig{
		ExternalScript: script,
		HTTPEndpoint:   srv.URL,
	}, map[string]int{"www-data": 33, "alice": 1000})

	if _, err := c.Map(context.Background(), identityWithLogin("attacker"), ""); !errors.Is(err, ErrForbiddenLocalUser) {
		t.Fatalf("error = %v, want ErrForbiddenLocalUser", err)
	}
	if tier3Called {
		t.Error("Tier 3 was consulted after Tier 2's answer was refused")
	}
}

// Tier 2/3 answers are now shape-checked like Tier 0/1 answers. Previously only
// emptiness was checked, so a script's output went through as-is.
func TestTier2And3AnswersMustBeValidUnixUsernames(t *testing.T) {
	for _, bad := range []string{"Alice", "al ice", "../../etc/passwd", "root\n", strings.Repeat("a", 33)} {
		t.Run(bad, func(t *testing.T) {
			payload, err := json.Marshal(Result{LocalUser: bad})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseResult(payload); err == nil {
				t.Errorf("parseResult accepted local_user %q", bad)
			}
		})
	}
}
