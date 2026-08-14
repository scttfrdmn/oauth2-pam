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

// TestLoadRefusesAWritableFile is the point of checkPerms. Tier 0 says which
// provider identity owns which local account, so any local user who can write
// this file can add a record aiming their own provider login at somebody else's
// Unix account — and the login that follows looks exactly like a legitimate one.
// Load has to refuse before it parses, not warn.
func TestLoadRefusesAWritableFile(t *testing.T) {
	for _, mode := range []os.FileMode{0620, 0602, 0660, 0666, 0777} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "enrolled-users.yaml")
			store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}
			if err := store.Save(path); err != nil {
				t.Fatalf("Save: %v", err)
			}
			// Chmod rather than a mode passed to WriteFile, which the umask can trim.
			if err := os.Chmod(path, mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			if _, err := Load(path); err == nil {
				t.Fatalf("Load accepted a mode-%04o enrollment file; anyone in its group chooses who logs in as whom", mode)
			} else if !strings.Contains(err.Error(), "chmod 600") {
				t.Errorf("err = %q, want it to say how to fix the mode", err)
			}
		})
	}
}

// The other half: group-*readable* still loads. A 0640 enrollment file is a
// disclosure worth fixing, but refusing to load it would lock every enrolled
// user off the host, and that is the worse failure of the two.
func TestLoadAcceptsAGroupReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolled-users.yaml")
	store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load of a 0644 file: %v", err)
	}
	if loaded.FindByLocalUser("alice") == nil {
		t.Error("the record did not load")
	}
}

// The symlink and directory rules — #96.
//
// The mode and owner checks stop an attacker installing an enrollment file of their
// own: what they cannot forge is root's ownership. What they leave open is the
// rollback. With write access to the directory, an earlier root-owned copy of this
// very file is theirs to put back — an operator's enrolled-users.yaml.bak alongside
// it is enough — and it restores an enrollment that was deliberately removed, or one
// that pointed a provider identity at a different local account. Every check on the
// file itself passes, because in every respect they check, it is the same file.
//
// pkg/config makes both of these checks before reading a client secret and says why
// in checkDirPerms. Tier 0 is the stronger case: a client secret decides which OAuth
// app the broker trusts, and this file decides who logs in as whom.

func TestLoadRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "enrolled-users.yaml")
	store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}
	if err := store.Save(target); err != nil {
		t.Fatalf("Save: %v", err)
	}

	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	// The premise: the target is a file Load accepts. So the refusal below is about
	// the link and nothing else.
	if _, err := Load(target); err != nil {
		t.Fatalf("Load of the target itself: %v", err)
	}

	if _, err := Load(link); err == nil {
		t.Error("Load followed a symlink; the mode and owner it checked are the target's, and " +
			"whoever owns the directory holding the link can repoint it without touching either")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("err = %q, want it to name the symlink as the problem", err)
	}
}

func TestLoadRefusesAFileInAWritableDirectory(t *testing.T) {
	for _, mode := range []os.FileMode{0770, 0707, 0777} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "oauth2-pam")
			path := filepath.Join(dir, "enrolled-users.yaml")
			store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}
			if err := store.Save(path); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatalf("chmod dir: %v", err)
			}

			if _, err := Load(path); err == nil {
				t.Fatalf("Load accepted a 0600 file in a mode-%04o directory; the file cannot be "+
					"modified there but it can be renamed away and an older copy put back", mode)
			} else if !strings.Contains(err.Error(), "chmod 750") {
				t.Errorf("err = %q, want it to say how to fix the directory", err)
			}
		})
	}
}

// A sticky directory is accepted, and this is why /tmp is safe to share: with the
// sticky bit set only the owner of a file may rename or unlink it, which is the
// whole of the attack the mode is being checked for. Without this case the rule
// would be refusing a directory that is not actually exposed.
func TestLoadAcceptsAFileInAStickyWritableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "oauth2-pam")
	path := filepath.Join(dir, "enrolled-users.yaml")
	store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}
	if err := store.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(dir, 0777|os.ModeSticky); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load from a sticky world-writable directory: %v", err)
	}
	if loaded.FindByLocalUser("alice") == nil {
		t.Error("the record did not load")
	}
}

// TestSaveRefusesAWritableDirectory: the operator finds out at enrollment time,
// with the chmod that fixes it, rather than the enrolled user finding out at login
// time when the broker refuses the file that was just written for them.
func TestSaveRefusesAWritableDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "oauth2-pam")
	if err := os.MkdirAll(dir, 0777); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}

	path := filepath.Join(dir, "enrolled-users.yaml")
	store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}

	err := store.Save(path)
	if err == nil {
		t.Fatal("Save wrote an enrollment into a world-writable directory, which Load then refuses: " +
			"the enrollment appears to have worked and the user it is for cannot log in")
	}
	if !strings.Contains(err.Error(), "chmod 750") {
		t.Errorf("err = %q, want it to say how to fix the directory", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("Save left a file behind on the path it refused")
	}
}

// Save's lock descriptor is an O_WRONLY open of a path something else may have
// just created, so it refuses a symlink for the same reason Load does — and so
// that the two cannot disagree about what the enrollment path is allowed to be.
func TestSaveRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.yaml")
	if err := os.WriteFile(target, []byte("enrollments: []\n"), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	path := filepath.Join(dir, "enrolled-users.yaml")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}

	store := &Store{Enrollments: []Record{{LocalUser: "alice", Login: "alice-gh"}}}
	if err := store.Save(path); err == nil {
		t.Fatal("Save opened a symlink at the enrollment path for writing")
	}

	// And the link is still a link: nothing was renamed over it, so the target
	// was not silently adopted as the enrollment file.
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Error("Save replaced the symlink, so a later Load would read a file the operator did not name")
	}
}

// A path that is not a regular file is not an enrollment file, whatever it
// contains.
func TestLoadRefusesANonRegularFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Error("Load accepted a directory as the enrollment file")
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

// TestARecordWithNoLoginIsNotAWildcard: matching is case-insensitive, and
// EqualFold("", "") is true, so a record whose login: key never made it to disk
// used to match every identity that arrived without one — a wildcard in the tier
// that outranks all the others. A file like this is a hand edit or a half-finished
// write, so Load still reads it (--remove has to be able to reach it); what it
// must not do is match.
func TestARecordWithNoLoginIsNotAWildcard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrolled-users.yaml")
	partial := `enrollments:
  - local_user: alice
    enrolled_by: root
`
	if err := os.WriteFile(path, []byte(partial), 0600); err != nil {
		t.Fatal(err)
	}

	store, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(store.Enrollments) != 1 {
		t.Fatalf("got %d records, want the malformed record loaded so it can be removed", len(store.Enrollments))
	}

	if rec := store.Find("alice", "", "github"); rec != nil {
		t.Errorf("a record with no login matched an identity with no login: %+v", rec)
	}
	if rec := store.Find("alice", "mallory", "github"); rec != nil {
		t.Errorf("a record with no login matched login %q: %+v", "mallory", rec)
	}
	// And it is still removable, which is the whole reason Load accepts it.
	if !store.Remove("alice") {
		t.Error("the malformed record could not be removed")
	}
}

// TestAddRequiresALogin: the store is where the wildcard record is stopped from
// being created in the first place.
func TestAddRequiresALogin(t *testing.T) {
	store := &Store{}

	err := store.Add(Record{LocalUser: "alice"}, Unvalidated)
	if err == nil {
		t.Fatal("Add accepted a record with no provider login; it would match any identity that also has none")
	}
	if !strings.Contains(err.Error(), "no provider login") {
		t.Errorf("err = %q, want it to say the login is missing", err)
	}
	if len(store.Enrollments) != 0 {
		t.Errorf("got %d records, want the store unchanged", len(store.Enrollments))
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
