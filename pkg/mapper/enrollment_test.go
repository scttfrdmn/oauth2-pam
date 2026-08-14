package mapper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/scttfrdmn/oauth2-pam/pkg/config"
	"github.com/scttfrdmn/oauth2-pam/pkg/enrollment"
)

// TestEnrollmentTierRefusesAnIdentityWithNoLogin: tier 0 matches (local user,
// login) case-insensitively, and EqualFold("", "") is true. So before this, a
// record whose login: key was missing answered for any identity that also arrived
// without a login, handing out its local account — a wildcard in the tier that
// outranks every other one. The record here is written as raw YAML because the
// store's own Add refuses to create it; the point is that a file edited by hand,
// or a write that stopped halfway, cannot smuggle one past the mapper.
func TestEnrollmentTierRefusesAnIdentityWithNoLogin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolled-users.yaml")
	partial := `enrollments:
  - local_user: alice
    enrolled_by: root
`
	if err := os.WriteFile(path, []byte(partial), 0600); err != nil {
		t.Fatal(err)
	}

	c := New(config.MapperConfig{EnrollmentEnabled: true, EnrollmentFile: path})

	id := identity()
	id.Login = ""
	if _, err := c.Map(context.Background(), id, "alice"); !errors.Is(err, ErrNoMapping) {
		t.Errorf("an identity with no login matched a record with no login: %v", err)
	}

	// Nor does the empty record answer for an identity that does have a login.
	if _, err := c.Map(context.Background(), identity(), "alice"); !errors.Is(err, ErrNoMapping) {
		t.Errorf("a record with no login matched login %q: %v", identity().Login, err)
	}
}

// The same identity must not reach tier 0 even when a perfectly good record for
// the local user exists: an empty login is not a credential, so it gets no answer
// from the most authoritative tier and falls through to the ones that can say no.
func TestAnIdentityWithNoLoginGetsNoEnrollmentMatch(t *testing.T) {
	path := writeEnrollment(t, enrollment.Record{LocalUser: "alice", Login: "alice"})

	c := New(config.MapperConfig{EnrollmentEnabled: true, EnrollmentFile: path})

	id := identity()
	id.Login = ""
	if _, err := c.Map(context.Background(), id, "alice"); !errors.Is(err, ErrNoMapping) {
		t.Errorf("an identity with no login was mapped by tier 0: %v", err)
	}
}
