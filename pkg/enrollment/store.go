// Package enrollment manages the enrolled-users file that links local Unix
// usernames to provider logins. It provides the backing store for the mapper's
// Tier 0 lookup and for the oauth2-pam-enroll CLI tool.
package enrollment

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

// Record is one entry in the enrollment file.
type Record struct {
	LocalUser string `yaml:"local_user"`

	// Login is the user's username at the provider. Files written before the
	// provider interface existed spell this key github_login; UnmarshalYAML
	// accepts it, and Save always writes login.
	Login string `yaml:"login"`

	// Provider is the configured provider name (providers[].name) this
	// enrollment is for. Empty means any provider, which is what an existing
	// file means and what a single-provider host wants; on a host with two
	// providers, leaving it empty lets a login at either one claim the local
	// account, so set it.
	Provider string `yaml:"provider,omitempty"`

	EnrolledAt time.Time `yaml:"enrolled_at"`
	EnrolledBy string    `yaml:"enrolled_by"`
	Groups     []string  `yaml:"groups,omitempty"`
}

// Store holds all enrollment records loaded from disk.
type Store struct {
	Enrollments []Record `yaml:"enrollments"`
}

// LocalUserValidator reports whether localUser is a name a *new* enrollment may
// use. Add takes one.
//
// It is a function rather than a check written out here because the authoritative
// rules — the Unix-name shape, the system-account denylist, the mapper.min_uid
// floor — belong to pkg/mapper, which imports this package. Restating them here
// would mean a second copy that can drift from the gate it is predicting, and a
// write-time rule that is looser than the login-time one is worse than no
// write-time rule at all. So the writer supplies the mapper's own gate:
// mapper.Chain.ValidateLocalUser.
type LocalUserValidator func(localUser string) error

// unvalidated is what a caller passes to Add when it has no mapper configuration
// to validate against, and therefore cannot say whether the name it is recording
// could ever authenticate. Named rather than a bare nil so that the callers making
// that choice can be found by grep. Production writers should pass the mapper's
// gate; a record that fails it is one the mapper will refuse at login.
//
// Unexported since #109. It was exported so that such callers could be grepped
// for, and the grep has stayed at zero outside this package's own tests — which is
// the outcome it was watching for, so an exported sentinel is now only an
// invitation to a first one. Passing nil to Add is identical and always was; what
// the name buys is that doing so is legible at the call site.
var unvalidated LocalUserValidator

// Load reads the enrollment file at path. If the file does not exist, an
// empty Store is returned without error.
//
// The file's mode and owner are checked before anything is parsed — see
// checkPerms. A file this process cannot trust is an error rather than an empty
// store: falling through to the later tiers would turn "somebody else can rewrite
// tier 0" into a silent change of mapping policy.
func Load(path string) (*Store, error) {
	// O_NOFOLLOW refuses a symlink in the same syscall as the open, rather than
	// leaving a window in which one could appear between a check and the read (#96).
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0) // #nosec G304 -- path comes from the broker's own root-owned config
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Store{}, nil
		}
		// O_NOFOLLOW reports a symlink as ELOOP, whose message describes a loop that
		// is not there. Say what is actually wrong.
		if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return nil, symlinkError(path)
		}
		return nil, fmt.Errorf("open enrollment file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// Stat the open descriptor, not the path: what is checked has to be the same
	// bytes that are then read, and a stat by path can be answered by one file and
	// the read served by another.
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat enrollment file %s: %w", path, err)
	}
	if err := checkPerms(path, info); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read enrollment file %s: %w", path, err)
	}
	var s Store
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse enrollment file %s: %w", path, err)
	}
	return &s, nil
}

// UnmarshalYAML reads a record, accepting github_login as a synonym for login so
// that a file written by an earlier version keeps working. There is deliberately
// no exported field for the legacy key: it is accepted on the way in and gone
// from there, so nothing downstream — and no Save — has to know it existed.
func (r *Record) UnmarshalYAML(node *yaml.Node) error {
	// A distinct type, so decoding into it does not recurse back into this
	// method.
	type record Record
	var raw struct {
		record      `yaml:",inline"`
		GitHubLogin string `yaml:"github_login"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	*r = Record(raw.record)
	if r.Login == "" {
		r.Login = raw.GitHubLogin
	} else if raw.GitHubLogin != "" && !strings.EqualFold(raw.GitHubLogin, r.Login) {
		// Both spellings present and disagreeing means a hand-edited file, and
		// guessing which one the operator meant would silently grant the local
		// account to one of two different provider identities.
		return fmt.Errorf("enrollment for %q sets both login (%q) and github_login (%q); keep only login",
			r.LocalUser, r.Login, raw.GitHubLogin)
	}
	return nil
}

// Save writes the store to path atomically using a temp file + rename, with
// an exclusive flock on the destination file to prevent concurrent writers.
//
// The directory is checked before anything is written, by the same rule Load
// applies. Writing the file first would produce an enrollment the broker then
// refuses at login, which is an outage discovered by the user it locks out; the
// operator gets the error and the chmod to fix it at enrollment time instead.
func (s *Store) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create enrollment directory: %w", err)
	}
	if err := checkDirPerms(dir); err != nil {
		return err
	}

	data, err := yaml.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal enrollment store: %w", err)
	}

	// Write to a temp file in the same directory so the rename is atomic.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".enrolled-users-*.yaml")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // clean up on any error path

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// Acquire an exclusive lock on the destination file (create if needed) to
	// serialize concurrent writers, then atomically replace it.
	//
	// O_NOFOLLOW because this is an O_WRONLY open of a path another process may have
	// just created. Nothing is ever written through this descriptor — it exists only
	// to hold the flock, and the rename below is what puts the data in place — but
	// opening a symlink for writing at all is the kind of thing that stops being
	// harmless when someone later adds a write. Load refuses a symlink here too, so
	// the two agree about what this path is allowed to be.
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|oNoFollow, 0600)
	if err != nil {
		return fmt.Errorf("open enrollment file for locking: %w", err)
	}
	defer func() { _ = lock.Close() }()

	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("lock enrollment file: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file to %s: %w", path, err)
	}
	return nil
}

// Find returns the record for the given (localUser, login) pair at the named
// provider, or nil if no matching enrollment exists. Comparisons are
// case-insensitive.
//
// A record with no provider matches any, so a file written before providers
// were named keeps working. A record that names one must be matched exactly:
// otherwise, on a host with two providers, "alice" at either of them could
// claim a local account enrolled for only one.
//
// An empty login never matches, on either side. EqualFold("", "") is true, so a
// record whose login: key is missing — a hand edit, or a write that stopped
// halfway — would otherwise be a wildcard in the most authoritative mapping tier,
// matching every identity that also arrived without one. Add refuses to create
// such a record; this is the half that covers the ones already on disk.
func (s *Store) Find(localUser, login, providerName string) *Record {
	if localUser == "" || login == "" {
		return nil
	}
	for i := range s.Enrollments {
		r := &s.Enrollments[i]
		if r.Login == "" {
			continue
		}
		if !strings.EqualFold(r.LocalUser, localUser) || !strings.EqualFold(r.Login, login) {
			continue
		}
		if r.Provider != "" && !strings.EqualFold(r.Provider, providerName) {
			continue
		}
		return r
	}
	return nil
}

// FindByLocalUser returns the enrollment record for a local user regardless of
// provider login, or nil if the user has not enrolled.
func (s *Store) FindByLocalUser(localUser string) *Record {
	for i := range s.Enrollments {
		r := &s.Enrollments[i]
		if strings.EqualFold(r.LocalUser, localUser) {
			return r
		}
	}
	return nil
}

// Add appends a new enrollment record. Returns an error if the record names no
// provider login, if a record for the same local user already exists (use Remove
// first to re-enroll), or if validate refuses rec.LocalUser.
//
// validate is applied to the new record only, and only here — never on Load or
// Save. A record already in the file, however it got there, must not stop the
// store from loading or from being written back: the mapper refuses such a record
// at login on its own, and making Load fail would turn one unusable enrollment
// into a broken enrollment file for everybody, including the operator trying to
// remove it. Pass nil (see unvalidated) if there is no configuration to validate against.
func (s *Store) Add(rec Record, validate LocalUserValidator) error {
	// A record is half of a pair, and a record with no login is half of nothing.
	// Written out it would be a record Find could only ever match against an
	// identity that also arrived with no login — which is to say a wildcard in the
	// most authoritative tier, granting rec.LocalUser to whoever produces one.
	if rec.Login == "" {
		return fmt.Errorf("enrollment for local user %q names no provider login", rec.LocalUser)
	}
	if existing := s.FindByLocalUser(rec.LocalUser); existing != nil {
		return fmt.Errorf("local user %q is already enrolled as %q; remove first",
			rec.LocalUser, existing.Login)
	}
	if validate != nil {
		if err := validate(rec.LocalUser); err != nil {
			return fmt.Errorf("local user %q may not be enrolled: %w", rec.LocalUser, err)
		}
	}
	s.Enrollments = append(s.Enrollments, rec)
	return nil
}

// Remove deletes the enrollment record for localUser. Returns true if a record
// was found and removed, false if no record existed.
func (s *Store) Remove(localUser string) bool {
	for i, r := range s.Enrollments {
		if strings.EqualFold(r.LocalUser, localUser) {
			s.Enrollments = append(s.Enrollments[:i], s.Enrollments[i+1:]...)
			return true
		}
	}
	return false
}
