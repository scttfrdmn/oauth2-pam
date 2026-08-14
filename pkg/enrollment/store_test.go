package enrollment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolled-users.yaml")
	enrolledAt := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	original := &Store{Enrollments: []Record{
		{LocalUser: "alice", Login: "alice-gh", EnrolledAt: enrolledAt, EnrolledBy: "root", Groups: []string{"devs", "wheel"}},
		{LocalUser: "bob", Login: "bob-gh", EnrolledAt: enrolledAt, EnrolledBy: "root"},
	}}

	if err := original.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Enrollments) != 2 {
		t.Fatalf("got %d records, want 2", len(loaded.Enrollments))
	}

	got := loaded.Enrollments[0]
	if got.LocalUser != "alice" || got.Login != "alice-gh" || got.EnrolledBy != "root" {
		t.Errorf("record = %+v", got)
	}
	if !got.EnrolledAt.Equal(enrolledAt) {
		t.Errorf("EnrolledAt = %s, want %s", got.EnrolledAt, enrolledAt)
	}
	if len(got.Groups) != 2 || got.Groups[0] != "devs" {
		t.Errorf("Groups = %v, want [devs wheel]", got.Groups)
	}
}

// TestLoadMissingFileIsEmptyNotAnError: an unenrolled system is a normal state,
// so the mapper must not error out before the other tiers get a chance.
func TestLoadMissingFileIsEmptyNotAnError(t *testing.T) {
	store, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("Load on a missing file: %v", err)
	}
	if len(store.Enrollments) != 0 {
		t.Errorf("got %d records, want 0", len(store.Enrollments))
	}
}

func TestLoadMalformedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(path, []byte("enrollments: [unterminated"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Error("Load accepted malformed YAML")
	}
}

// TestSaveIsNotWorldReadable: the file links Unix accounts to GitHub identities,
// which is exactly the information an attacker needs to target a device-flow
// phish at the right person.
func TestSaveIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolled-users.yaml")
	store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}

	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("mode = %04o, want 0600", perm)
	}
}

func TestSaveCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "dir", "enrolled-users.yaml")
	store := &Store{}

	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file was not created: %v", err)
	}
}

// TestSaveLeavesNoTempFiles: Save writes to a temp file then renames, and the
// temp file must not survive on either the success or the error path.
func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enrolled-users.yaml")
	store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}

	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".enrolled-users-") {
			t.Errorf("temp file %s was left behind", e.Name())
		}
	}
}

func TestFindRequiresBothFields(t *testing.T) {
	store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}

	if store.Find("alice", "alice-gh", "") == nil {
		t.Error("Find missed an exact match")
	}
	// Case-insensitive on both halves: Unix names are lowercase by convention
	// but GitHub logins are displayed with mixed case.
	if store.Find("ALICE", "Alice-GH", "") == nil {
		t.Error("Find is case-sensitive; it should not be")
	}
	if store.Find("alice", "mallory-gh", "") != nil {
		t.Error("Find matched the wrong GitHub login")
	}
	if store.Find("bob", "alice-gh", "") != nil {
		t.Error("Find matched the wrong local user")
	}
	if store.Find("", "", "") != nil {
		t.Error("Find matched on empty input")
	}
}

func TestFindByLocalUser(t *testing.T) {
	store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}

	rec := store.FindByLocalUser("alice")
	if rec == nil {
		t.Fatal("FindByLocalUser missed an enrolled user")
	}
	if rec.Login != "alice-gh" {
		t.Errorf("Login = %q", rec.Login)
	}
	if store.FindByLocalUser("bob") != nil {
		t.Error("FindByLocalUser matched an unenrolled user")
	}
}

// TestAddRejectsDuplicateLocalUser: silently replacing an enrollment would let
// a second GitHub account take over a Unix account.
func TestAddRejectsDuplicateLocalUser(t *testing.T) {
	store := &Store{}

	if err := store.Add(Record{LocalUser: "alice", Login: "alice-gh"}, Unvalidated); err != nil {
		t.Fatalf("first Add: %v", err)
	}

	err := store.Add(Record{LocalUser: "alice", Login: "mallory-gh"}, Unvalidated)
	if err == nil {
		t.Fatal("Add silently re-enrolled an existing local user under a different GitHub account")
	}
	if !strings.Contains(err.Error(), "already enrolled") {
		t.Errorf("err = %q, want it to say the user is already enrolled", err)
	}
	if !strings.Contains(err.Error(), "alice-gh") {
		t.Errorf("err = %q, want it to name the existing GitHub login", err)
	}
	if len(store.Enrollments) != 1 {
		t.Errorf("got %d records, want the store unchanged", len(store.Enrollments))
	}
}

func TestAddDuplicateIsCaseInsensitive(t *testing.T) {
	store := &Store{}
	if err := store.Add(Record{LocalUser: "alice", Login: "alice-gh"}, Unvalidated); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := store.Add(Record{LocalUser: "ALICE", Login: "mallory-gh"}, Unvalidated); err == nil {
		t.Error("Add accepted a duplicate that differed only in case")
	}
}

func TestRemove(t *testing.T) {
	store := &Store{Enrollments: []Record{
		{LocalUser: "alice", Login: "alice-gh"},
		{LocalUser: "bob", Login: "bob-gh"},
		{LocalUser: "carol", Login: "carol-gh"},
	}}

	if !store.Remove("bob") {
		t.Error("Remove returned false for an enrolled user")
	}
	if len(store.Enrollments) != 2 {
		t.Fatalf("got %d records, want 2", len(store.Enrollments))
	}
	if store.FindByLocalUser("bob") != nil {
		t.Error("bob is still enrolled after Remove")
	}
	// The neighbours must survive the slice splice.
	if store.FindByLocalUser("alice") == nil || store.FindByLocalUser("carol") == nil {
		t.Error("Remove dropped an unrelated record")
	}

	if store.Remove("nobody") {
		t.Error("Remove returned true for an unenrolled user")
	}
}

func TestRemoveThenAddAllowsReEnrollment(t *testing.T) {
	store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}

	if !store.Remove("alice") {
		t.Fatal("Remove failed")
	}
	if err := store.Add(Record{LocalUser: "alice", Login: "alice-new-gh"}, Unvalidated); err != nil {
		t.Fatalf("re-enrollment after Remove: %v", err)
	}
	if rec := store.FindByLocalUser("alice"); rec == nil || rec.Login != "alice-new-gh" {
		t.Errorf("record = %+v, want the new GitHub login", rec)
	}
}

// --- the write-time local-user gate ---

// forbidden is a stand-in for the real gate. pkg/mapper owns the rules and imports
// this package, so a test here cannot call them; what it can pin is that Add asks,
// that a refusal stops the record entering the store, and that the reason survives
// to the caller. The rules themselves are checked against mapper's own gate in
// pkg/mapper and in cmd/oauth2-pam-enroll.
var errForbidden = errors.New("forbidden local account")

func forbidding(names ...string) LocalUserValidator {
	deny := make(map[string]bool, len(names))
	for _, n := range names {
		deny[n] = true
	}
	return func(localUser string) error {
		if deny[localUser] {
			return fmt.Errorf("%w: %q", errForbidden, localUser)
		}
		return nil
	}
}

// TestAddAppliesTheLocalUserValidator: a record that could never authenticate must
// not be written in the first place. Before this, oauth2-pam-enroll wrote it and
// the operator found out at the denied login.
func TestAddAppliesTheLocalUserValidator(t *testing.T) {
	// The shapes the mapper's gate refuses, as a reminder of what the CLI is
	// wiring in: root, a denylisted service account, and names no Unix account can
	// have.
	bad := []string{
		"root",
		"www-data",
		"systemd-resolve",
		"Alice",
		"1alice",
		strings.Repeat("a", 33),
		"al/ice",
		"al\x00ice",
		"",
	}

	for _, name := range bad {
		t.Run(name, func(t *testing.T) {
			store := &Store{}
			err := store.Add(Record{LocalUser: name, Login: "attacker"}, forbidding(bad...))
			if err == nil {
				t.Fatalf("Add(%q) succeeded; the validator's refusal was ignored", name)
			}
			if !errors.Is(err, errForbidden) {
				t.Errorf("err = %v, want it to wrap the validator's error", err)
			}
			if len(store.Enrollments) != 0 {
				t.Errorf("got %d records, want the store unchanged after a refusal", len(store.Enrollments))
			}
		})
	}
}

// The other half: a permissible account still enrolls, and comes back off disk
// exactly as it went in.
func TestAddAValidUserStillRoundTrips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolled-users.yaml")
	enrolledAt := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	rec := Record{
		LocalUser:  "alice",
		Login:      "alice-gh",
		Provider:   "corp-github",
		EnrolledAt: enrolledAt,
		EnrolledBy: "root",
		Groups:     []string{"devs"},
	}

	store := &Store{}
	if err := store.Add(rec, forbidding("root", "www-data")); err != nil {
		t.Fatalf("Add of a permissible account: %v", err)
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.Enrollments) != 1 {
		t.Fatalf("got %d records, want 1", len(loaded.Enrollments))
	}
	got := loaded.Enrollments[0]
	if got.LocalUser != rec.LocalUser || got.Login != rec.Login || got.Provider != rec.Provider ||
		got.EnrolledBy != rec.EnrolledBy || !got.EnrolledAt.Equal(rec.EnrolledAt) ||
		len(got.Groups) != 1 || got.Groups[0] != "devs" {
		t.Errorf("record = %+v, want %+v", got, rec)
	}
}

// TestAPreExistingForbiddenRecordDoesNotBreakTheFile is the backward-compatibility
// guarantee. Files written before the write-time gate existed may name accounts it
// would refuse. Validating on Load — or on Save — would take a single unusable
// enrollment and turn it into an enrollment file nobody can read or repair, which
// is an outage in place of a UX gap. The mapper refuses such a record at login on
// its own.
func TestAPreExistingForbiddenRecordDoesNotBreakTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolled-users.yaml")
	legacy := `enrollments:
  - local_user: root
    login: mallory
    enrolled_by: root
  - local_user: BadName
    login: bob
    enrolled_by: root
  - local_user: alice
    login: alice-gh
    enrolled_by: root
`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	store, err := Load(path)
	if err != nil {
		t.Fatalf("Load of a store holding a forbidden record: %v", err)
	}
	if len(store.Enrollments) != 3 {
		t.Fatalf("got %d records, want all 3 loaded", len(store.Enrollments))
	}
	if store.FindByLocalUser("root") == nil {
		t.Error("the forbidden record was silently dropped on load; --remove could never reach it")
	}

	gate := forbidding("root", "BadName")

	// Adding somebody else is not blocked by the record already there: only the
	// new name is validated.
	if err := store.Add(Record{LocalUser: "carol", Login: "carol-gh"}, gate); err != nil {
		t.Fatalf("Add beside a pre-existing forbidden record: %v", err)
	}

	// And the file can still be written back — which is what --remove needs.
	if !store.Remove("root") {
		t.Error("Remove could not delete the forbidden record")
	}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save of a store still holding a forbidden record: %v", err)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	if reloaded.FindByLocalUser("BadName") == nil {
		t.Error("Save dropped the remaining pre-existing record")
	}
	if reloaded.FindByLocalUser("carol") == nil {
		t.Error("the newly added record did not survive the save")
	}
}

// TestConcurrentSaves checks the flock + atomic-rename path: with several
// writers racing, the file must always be complete and parseable, never a
// half-written one that would break every subsequent login.
func TestConcurrentSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolled-users.yaml")

	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			store := &Store{Enrollments: []Record{
				{LocalUser: "alice", Login: "alice-gh"},
				{LocalUser: "bob", Login: "bob-gh"},
			}}
			if err := store.Save(path); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load after concurrent saves: %v", err)
	}
	if len(loaded.Enrollments) != 2 {
		t.Errorf("got %d records, want 2 (the file was torn)", len(loaded.Enrollments))
	}
}

// TestLegacyGitHubLoginKeyIsAccepted covers upgrades: an enrollment file written
// before providers were an abstraction spells the login github_login, and those
// users must not all be locked out by an upgrade.
func TestLegacyGitHubLoginKeyIsAccepted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolled-users.yaml")
	legacy := `enrollments:
  - local_user: alice
    github_login: alice-gh
    enrolled_at: 2025-01-01T00:00:00Z
    enrolled_by: root
    groups: [devs]
`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	store, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rec := store.FindByLocalUser("alice")
	if rec == nil {
		t.Fatal("legacy record not found")
	}
	if rec.Login != "alice-gh" {
		t.Errorf("Login = %q, want alice-gh from github_login", rec.Login)
	}
	if len(rec.Groups) != 1 || rec.Groups[0] != "devs" {
		t.Errorf("Groups = %v, want [devs]", rec.Groups)
	}

	// Saving migrates the file to the current spelling, and the legacy key is
	// gone rather than written back alongside it.
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "github_login") {
		t.Errorf("saved file still contains github_login:\n%s", data)
	}
	if !strings.Contains(string(data), "login: alice-gh") {
		t.Errorf("saved file does not contain login: alice-gh:\n%s", data)
	}
}

// A file setting both spellings to different values is a hand-edit, and guessing
// which one was meant would hand the local account to one of two different
// provider identities. Refuse to load it.
func TestConflictingLoginKeysAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolled-users.yaml")
	conflicting := `enrollments:
  - local_user: alice
    login: alice
    github_login: mallory
`
	if err := os.WriteFile(path, []byte(conflicting), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted a record with two disagreeing logins")
	}

	// The same value under both keys is redundant but unambiguous, so it loads.
	agreeing := `enrollments:
  - local_user: alice
    login: alice-gh
    github_login: ALICE-GH
`
	if err := os.WriteFile(path, []byte(agreeing), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Load(path)
	if err != nil {
		t.Fatalf("Load rejected two agreeing logins: %v", err)
	}
	if rec := store.FindByLocalUser("alice"); rec == nil || rec.Login != "alice-gh" {
		t.Errorf("record = %+v, want Login alice-gh", rec)
	}
}

// TestFindIsScopedToTheProvider is the reason Record carries a provider name: on
// a host with two providers, "alice" at the one she did not enroll with must not
// inherit her local account.
func TestFindIsScopedToTheProvider(t *testing.T) {
	store := &Store{Enrollments: []Record{
		{LocalUser: "alice", Login: "alice", Provider: "corp-github"},
		{LocalUser: "bob", Login: "bob"}, // no provider: written before they were named
	}}

	if store.Find("alice", "alice", "corp-github") == nil {
		t.Error("the enrolling provider did not match")
	}
	if store.Find("alice", "alice", "public-github") != nil {
		t.Error("an enrollment for one provider matched a login at another")
	}
	if store.Find("alice", "alice", "") != nil {
		t.Error("a provider-scoped enrollment matched a request naming no provider")
	}
	// A record with no provider matches any, which is what an existing file
	// means and what a single-provider host wants.
	if store.Find("bob", "bob", "public-github") == nil {
		t.Error("an unscoped enrollment did not match a named provider")
	}
	if store.Find("bob", "bob", "") == nil {
		t.Error("an unscoped enrollment did not match an unnamed provider")
	}
}
