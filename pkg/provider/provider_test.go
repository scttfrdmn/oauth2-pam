package provider

import (
	"reflect"
	"testing"
)

func TestClaimOnNilAndEmptyIdentity(t *testing.T) {
	var nilID *Identity
	if got := nilID.Claim(ClaimOrg); got != nil {
		t.Errorf("nil identity: Claim = %v, want nil", got)
	}
	if nilID.HasClaim(ClaimOrg, "acme") {
		t.Error("nil identity: HasClaim = true")
	}
	if got := nilID.ClaimNames(); got != nil {
		t.Errorf("nil identity: ClaimNames = %v, want nil", got)
	}

	// An identity with no claims at all is the common case for a provider that
	// asserts nothing beyond a username, and must not panic on the nil map.
	empty := &Identity{Login: "alice"}
	if got := empty.Claim(ClaimGroup); got != nil {
		t.Errorf("Claim = %v, want nil", got)
	}
	if empty.HasClaim(ClaimGroup, "anything") {
		t.Error("HasClaim on an identity with no claims = true")
	}
}

func TestAddClaimAppendsAndAllocates(t *testing.T) {
	id := &Identity{}
	id.AddClaim(ClaimOrg, "acme")
	id.AddClaim(ClaimOrg, "widgets", "gadgets")
	id.AddClaim(ClaimTeam, "acme/eng")

	if want := []string{"acme", "widgets", "gadgets"}; !reflect.DeepEqual(id.Claim(ClaimOrg), want) {
		t.Errorf("org = %v, want %v", id.Claim(ClaimOrg), want)
	}
	if want := []string{"acme/eng"}; !reflect.DeepEqual(id.Claim(ClaimTeam), want) {
		t.Errorf("team = %v, want %v", id.Claim(ClaimTeam), want)
	}
}

// A provider that fetches no memberships calls AddClaim with an empty slice, and
// must not thereby assert an empty claim: a rule matching `claims: {org: ""}` is
// already ignored by the mapper, but `org` appearing in ClaimNames would make a
// log line claim the provider returned something it did not.
func TestAddClaimWithNoValuesAssertsNothing(t *testing.T) {
	id := &Identity{}
	id.AddClaim(ClaimOrg)
	id.AddClaim(ClaimTeam, []string{}...)

	if names := id.ClaimNames(); len(names) != 0 {
		t.Errorf("ClaimNames = %v, want none", names)
	}
	if id.Claims != nil {
		t.Errorf("Claims = %v, want the map left unallocated", id.Claims)
	}
}

func TestHasClaimIsCaseInsensitive(t *testing.T) {
	id := &Identity{}
	id.AddClaim(ClaimOrg, "ACME")

	if !id.HasClaim(ClaimOrg, "acme") {
		t.Error(`HasClaim("org", "acme") = false for an asserted "ACME"`)
	}
	if !id.HasClaim(ClaimOrg, "AcMe") {
		t.Error("HasClaim is not case-insensitive")
	}
	if id.HasClaim(ClaimOrg, "acme-corp") {
		t.Error("HasClaim matched a different org")
	}
	// Claim *names* are keys, not values: they are compared exactly, so a
	// provider and a rule must agree on the spelling.
	if id.HasClaim("ORG", "acme") {
		t.Error("HasClaim matched a claim name in the wrong case")
	}
}

func TestClaimNamesAreSorted(t *testing.T) {
	id := &Identity{}
	id.AddClaim(ClaimTeam, "acme/eng")
	id.AddClaim(ClaimRole, "admin")
	id.AddClaim(ClaimOrg, "acme")
	id.AddClaim(ClaimGroup, "staff")

	want := []string{"group", "org", "role", "team"}
	if got := id.ClaimNames(); !reflect.DeepEqual(got, want) {
		t.Errorf("ClaimNames = %v, want %v", got, want)
	}
}
