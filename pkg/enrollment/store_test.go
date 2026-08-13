package enrollment

import (
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
		{LocalUser: "alice", GitHubLogin: "alice-gh", EnrolledAt: enrolledAt, EnrolledBy: "root", Groups: []string{"devs", "wheel"}},
		{LocalUser: "bob", GitHubLogin: "bob-gh", EnrolledAt: enrolledAt, EnrolledBy: "root"},
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
	if got.LocalUser != "alice" || got.GitHubLogin != "alice-gh" || got.EnrolledBy != "root" {
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
	store := &Store{Enrollments: []Record{{LocalUser: "alice", GitHubLogin: "alice-gh"}}}

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
	store := &Store{Enrollments: []Record{{LocalUser: "alice", GitHubLogin: "alice-gh"}}}

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
	store := &Store{Enrollments: []Record{{LocalUser: "alice", GitHubLogin: "alice-gh"}}}

	if store.Find("alice", "alice-gh") == nil {
		t.Error("Find missed an exact match")
	}
	// Case-insensitive on both halves: Unix names are lowercase by convention
	// but GitHub logins are displayed with mixed case.
	if store.Find("ALICE", "Alice-GH") == nil {
		t.Error("Find is case-sensitive; it should not be")
	}
	if store.Find("alice", "mallory-gh") != nil {
		t.Error("Find matched the wrong GitHub login")
	}
	if store.Find("bob", "alice-gh") != nil {
		t.Error("Find matched the wrong local user")
	}
	if store.Find("", "") != nil {
		t.Error("Find matched on empty input")
	}
}

func TestFindByLocalUser(t *testing.T) {
	store := &Store{Enrollments: []Record{{LocalUser: "alice", GitHubLogin: "alice-gh"}}}

	rec := store.FindByLocalUser("alice")
	if rec == nil {
		t.Fatal("FindByLocalUser missed an enrolled user")
	}
	if rec.GitHubLogin != "alice-gh" {
		t.Errorf("GitHubLogin = %q", rec.GitHubLogin)
	}
	if store.FindByLocalUser("bob") != nil {
		t.Error("FindByLocalUser matched an unenrolled user")
	}
}

// TestAddRejectsDuplicateLocalUser: silently replacing an enrollment would let
// a second GitHub account take over a Unix account.
func TestAddRejectsDuplicateLocalUser(t *testing.T) {
	store := &Store{}

	if err := store.Add(Record{LocalUser: "alice", GitHubLogin: "alice-gh"}); err != nil {
		t.Fatalf("first Add: %v", err)
	}

	err := store.Add(Record{LocalUser: "alice", GitHubLogin: "mallory-gh"})
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
	if err := store.Add(Record{LocalUser: "alice", GitHubLogin: "alice-gh"}); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := store.Add(Record{LocalUser: "ALICE", GitHubLogin: "mallory-gh"}); err == nil {
		t.Error("Add accepted a duplicate that differed only in case")
	}
}

func TestRemove(t *testing.T) {
	store := &Store{Enrollments: []Record{
		{LocalUser: "alice", GitHubLogin: "alice-gh"},
		{LocalUser: "bob", GitHubLogin: "bob-gh"},
		{LocalUser: "carol", GitHubLogin: "carol-gh"},
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
	store := &Store{Enrollments: []Record{{LocalUser: "alice", GitHubLogin: "alice-gh"}}}

	if !store.Remove("alice") {
		t.Fatal("Remove failed")
	}
	if err := store.Add(Record{LocalUser: "alice", GitHubLogin: "alice-new-gh"}); err != nil {
		t.Fatalf("re-enrollment after Remove: %v", err)
	}
	if rec := store.FindByLocalUser("alice"); rec == nil || rec.GitHubLogin != "alice-new-gh" {
		t.Errorf("record = %+v, want the new GitHub login", rec)
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
				{LocalUser: "alice", GitHubLogin: "alice-gh"},
				{LocalUser: "bob", GitHubLogin: "bob-gh"},
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
