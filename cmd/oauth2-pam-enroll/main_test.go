package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/mapper"
)

// testConfig is enough config to reach the gate: a provider so the command has
// something to enroll against, and the mapper defaults LoadConfig would have
// applied. The device flow is never started in these tests, because the gate runs
// first — which is the point of where it was put.
func testConfig() *config.Config {
	return &config.Config{
		Providers: []config.ProviderConfig{{
			Name:         "gh",
			Type:         "github",
			ClientID:     "id",
			ClientSecret: "secret",
		}},
		Mapper: config.MapperConfig{MinUID: mapper.DefaultMinUID},
	}
}

// TestEnrollRefusesForbiddenLocalUsers is the finding: oauth2-pam-enroll used to
// write a record naming root, a service account, or a name no Unix account can
// have, and the operator discovered it as a denied login. The mapper refuses such a
// mapping at tier 0 regardless; this is so the refusal arrives when the name is
// typed, before a browser round trip, and with the rule attached.
func TestEnrollRefusesForbiddenLocalUsers(t *testing.T) {
	forbidden := []struct{ name, why string }{
		{"root", "root is never mappable, by UID rather than by name"},
		{"www-data", "a denylisted service account"},
		{"systemd-resolve", "a denylisted prefix"},
		{"Alice", "uppercase is not a portable Unix name"},
		{"1alice", "leading digit"},
		{strings.Repeat("a", 33), "over 32 characters"},
		{"al/ice", "an embedded slash"},
		{"al\x00ice", "an embedded NUL"},
	}

	for _, tc := range forbidden {
		t.Run(tc.why, func(t *testing.T) {
			enrollFile := filepath.Join(t.TempDir(), "enrolled-users.yaml")

			err := runEnroll(tc.name, "", nil, enrollFile, testConfig())
			if err == nil {
				t.Fatalf("runEnroll(%q) succeeded", tc.name)
			}
			if !errors.Is(err, mapper.ErrForbiddenLocalUser) {
				t.Fatalf("error = %v, want it to wrap mapper.ErrForbiddenLocalUser", err)
			}
			// The message has to teach the rule and say where it comes from, or the
			// operator is refused by a tool that is not the one denying the login and
			// cannot tell why.
			for _, want := range []string{"same local-account gate", "login", "mapper.min_uid", "mapper.allow_system_users"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to mention %q", err, want)
				}
			}
			if _, err := os.Stat(enrollFile); !os.IsNotExist(err) {
				t.Errorf("an enrollment file was created for a refused local user (stat err = %v)", err)
			}
		})
	}
}

// Nothing exempts root — not allow_system_users, not a lowered floor. Same rule as
// at login, for the same reason: a device flow has no binding to the SSH
// connection, so root here would be the weakest path to the most privilege.
func TestEnrollRefusesRootEvenWhenAllowedByName(t *testing.T) {
	cfg := testConfig()
	cfg.Mapper.AllowSystemUsers = []string{"root"}
	cfg.Mapper.MinUID = -1

	err := runEnroll("root", "", nil, filepath.Join(t.TempDir(), "enrolled-users.yaml"), cfg)
	if !errors.Is(err, mapper.ErrForbiddenLocalUser) {
		t.Fatalf("error = %v, want ErrForbiddenLocalUser", err)
	}
	if !strings.Contains(err.Error(), "UID 0") {
		t.Errorf("error = %q, want it to name UID 0 as the reason", err)
	}
}

// The control: a permissible name gets past the gate. It then fails on the
// pre-existing existence check — the account does not exist on this machine — which
// is a different error, and is how this test tells "the gate allowed it" from "the
// gate refused it".
func TestEnrollAcceptsAnOrdinaryLocalUser(t *testing.T) {
	err := runEnroll("zzordinaryuser", "", nil, filepath.Join(t.TempDir(), "enrolled-users.yaml"), testConfig())
	if err == nil {
		t.Fatal("runEnroll reached the device flow in a unit test")
	}
	if errors.Is(err, mapper.ErrForbiddenLocalUser) {
		t.Fatalf("the gate refused an ordinary Unix username: %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %v, want the existing local-account existence check", err)
	}
}
