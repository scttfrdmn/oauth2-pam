// Package enrollment manages the enrolled-users file that links local Unix
// usernames to GitHub logins. It provides the backing store for the mapper's
// Tier 0 lookup and for the pam-oauth2-enroll CLI tool.
package enrollment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"go.yaml.in/yaml/v3"
)

// Record is one entry in the enrollment file.
type Record struct {
	LocalUser   string    `yaml:"local_user"`
	GitHubLogin string    `yaml:"github_login"`
	EnrolledAt  time.Time `yaml:"enrolled_at"`
	EnrolledBy  string    `yaml:"enrolled_by"`
	Groups      []string  `yaml:"groups,omitempty"`
}

// Store holds all enrollment records loaded from disk.
type Store struct {
	Enrollments []Record `yaml:"enrollments"`
}

// Load reads the enrollment file at path. If the file does not exist, an
// empty Store is returned without error.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Store{}, nil
		}
		return nil, fmt.Errorf("read enrollment file %s: %w", path, err)
	}
	var s Store
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse enrollment file %s: %w", path, err)
	}
	return &s, nil
}

// Save writes the store to path atomically using a temp file + rename, with
// an exclusive flock on the destination file to prevent concurrent writers.
func (s *Store) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create enrollment directory: %w", err)
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
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
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

// Find returns the record for the given (localUser, githubLogin) pair, or nil
// if no matching enrollment exists. Comparisons are case-insensitive.
func (s *Store) Find(localUser, githubLogin string) *Record {
	for i := range s.Enrollments {
		r := &s.Enrollments[i]
		if strings.EqualFold(r.LocalUser, localUser) &&
			strings.EqualFold(r.GitHubLogin, githubLogin) {
			return r
		}
	}
	return nil
}

// FindByLocalUser returns the enrollment record for a local user regardless of
// GitHub login, or nil if the user has not enrolled.
func (s *Store) FindByLocalUser(localUser string) *Record {
	for i := range s.Enrollments {
		r := &s.Enrollments[i]
		if strings.EqualFold(r.LocalUser, localUser) {
			return r
		}
	}
	return nil
}

// Add appends a new enrollment record. Returns an error if a record for the
// same local user already exists (use Remove first to re-enroll).
func (s *Store) Add(rec Record) error {
	if existing := s.FindByLocalUser(rec.LocalUser); existing != nil {
		return fmt.Errorf("local user %q is already enrolled as GitHub user %q; remove first",
			rec.LocalUser, existing.GitHubLogin)
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
