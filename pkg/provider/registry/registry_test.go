package registry

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

// TestRegistryMatchesSupportedTypes is the guard against the two lists drifting
// apart. config.Validate rejects any type not in SupportedProviderTypes, so a
// type registered here but missing there can never be constructed; a type listed
// there but missing here passes validation and then fails at startup.
func TestRegistryMatchesSupportedTypes(t *testing.T) {
	want := append([]string(nil), config.SupportedProviderTypes...)
	sort.Strings(want)

	if got := SupportedTypes(); !reflect.DeepEqual(got, want) {
		t.Errorf("registry types = %v, config.SupportedProviderTypes = %v; add the missing entry to both",
			got, want)
	}
}

func TestNewBuildsAKnownType(t *testing.T) {
	p, err := New(config.ProviderConfig{
		Name:         "gh",
		Type:         "github",
		ClientID:     "id",
		ClientSecret: "secret",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.Name() != "gh" {
		t.Errorf("Name = %q, want gh", p.Name())
	}
	if p.Type() != "github" {
		t.Errorf("Type = %q, want github", p.Type())
	}
}

func TestNewRejectsUnknownTypeAndNamesTheAlternatives(t *testing.T) {
	_, err := New(config.ProviderConfig{Name: "sso", Type: "gitlab", ClientID: "id", ClientSecret: "s"})
	if err == nil {
		t.Fatal("New accepted an unregistered type")
	}
	// The message has to say what is available, because "not supported" alone
	// leaves an operator guessing at the spelling.
	if !strings.Contains(err.Error(), "github") {
		t.Errorf("err = %v, want it to list the supported types", err)
	}
	if !strings.Contains(err.Error(), "sso") {
		t.Errorf("err = %v, want it to name the offending provider", err)
	}
}

func TestNewAllPreservesConfigOrder(t *testing.T) {
	cfg := &config.Config{Providers: []config.ProviderConfig{
		{Name: "enterprise", Type: "github", ClientID: "id", ClientSecret: "s", GitHub: config.GitHubConfig{BaseURL: "https://github.acme.internal"}},
		{Name: "dotcom", Type: "github", ClientID: "id", ClientSecret: "s"},
	}}

	providers, err := NewAll(cfg)
	if err != nil {
		t.Fatalf("NewAll: %v", err)
	}
	if len(providers) != 2 {
		t.Fatalf("built %d providers, want 2", len(providers))
	}
	// Order matters: the first entry is the default for a request that does not
	// name a provider, so it must be the first one the operator wrote.
	if providers[0].Name() != "enterprise" || providers[1].Name() != "dotcom" {
		t.Errorf("order = [%s %s], want [enterprise dotcom]", providers[0].Name(), providers[1].Name())
	}
}

func TestNewAllFailsOnTheFirstBadProvider(t *testing.T) {
	cfg := &config.Config{Providers: []config.ProviderConfig{
		{Name: "ok", Type: "github", ClientID: "id", ClientSecret: "s"},
		{Name: "broken", Type: "github", ClientID: "", ClientSecret: "s"},
	}}

	if _, err := NewAll(cfg); err == nil {
		t.Fatal("NewAll accepted a provider with no client_id")
	}
}
