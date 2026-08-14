package config

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SecretSource records where a provider's client secret came from. It exists for
// the startup log: an operator who has just moved a secret out of broker.yaml
// wants confirmation that the broker read it from the new place, and the value
// must never appear in a log line to give them that.
type SecretSource string

const (
	SecretSourceNone   SecretSource = ""
	SecretSourceEnv    SecretSource = "environment"
	SecretSourceFile   SecretSource = "file"
	SecretSourceInline SecretSource = "config file"
)

// secretEnvPrefix is completed with the provider name — see ClientSecretEnvVar.
const secretEnvPrefix = "OAUTH2_PAM_CLIENT_SECRET_"

// maxSecretFileSize bounds what a secret file may hold. A GitHub client secret
// is 40 characters; anything near this is a wrong path, and saying so is more
// useful than reading an arbitrary file into memory.
const maxSecretFileSize = 4096

// secretFileMask is the permission bits a file holding a secret may not have:
// any access at all for group or other. Same rule ssh applies to a private key,
// for the same reason.
const secretFileMask fs.FileMode = 0o077

// dirWriteMask is the permission bits the directory holding a secret may not
// have: write for group or other. Read is allowed — listing a directory reveals
// no secret — but write is enough to replace the file inside it.
const dirWriteMask fs.FileMode = 0o022

// ClientSecretEnvVar is the environment variable that overrides one provider's
// client secret — for a container, or a development run against a throwaway
// OAuth app.
//
// viper's AutomaticEnv cannot do this: providers is a slice, and there is no
// environment-variable spelling of providers[0].client_secret. So the variable
// is keyed by provider *name* instead of by index — renaming a provider changes
// the variable, which is the price of a name that does not move when the list is
// reordered. Characters that cannot appear in a variable name become "_", so
// distinct provider names can in principle collide; Validate rejects duplicate
// names, and a name differing only in punctuation is worth rejecting anyway.
func ClientSecretEnvVar(providerName string) string {
	var b strings.Builder
	b.WriteString(secretEnvPrefix)
	for _, r := range strings.ToUpper(providerName) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// SecretSource reports where this provider's client secret was read from. It is
// SecretSourceNone until ResolveSecrets has run.
func (p ProviderConfig) SecretSource() SecretSource { return p.clientSecretSource }

// ResolveSecrets fills in each provider's ClientSecret from whichever source is
// configured, and refuses any source another local user could read or replace.
//
// Precedence, highest first:
//
//  1. $OAUTH2_PAM_CLIENT_SECRET_<PROVIDER> (see ClientSecretEnvVar)
//  2. providers[].client_secret_file — an absolute path, or a bare name resolved
//     under $CREDENTIALS_DIRECTORY when the broker runs with systemd's
//     LoadCredential=
//  3. providers[].client_secret, inline in the config file
//
// Whatever holds the secret must have no group or other permission bits, be
// owned by root or by this process, and sit in a directory no other user can
// write to. In case 3 that means the config file itself: a secret inline in a
// world-readable broker.yaml is a secret every local user on the host already
// has, and the broker refuses to start rather than carry on as if it were
// confidential.
//
// The config file is checked in all three cases, not just the third. It used to
// be checked only when it carried an inline secret, which meant the one
// permission check broker.yaml ever got disappeared the moment an operator did
// the recommended thing and moved the secret out of it — while the file went on
// holding the token encryption key, the org and team allowlists, and the mapper
// rules that decide which provider login becomes which Unix user. Those are
// worth the same care as the client secret, and a check that only applies to the
// least hardened configuration is worse than none: it teaches that silence means
// approval.
//
// configPath is the file the config was read from. Pass "" if it was not read
// from a file — there is then nothing to check, and case 3 is rejected outright.
func (c *Config) ResolveSecrets(configPath string) error {
	if configPath != "" {
		if err := checkSecretFilePerms(configPath); err != nil {
			return fmt.Errorf("config file: %w", err)
		}
	}

	for i := range c.Providers {
		p := &c.Providers[i]
		if err := resolveProviderSecret(p, configPath); err != nil {
			return fmt.Errorf("providers[%d] (%s): %w", i, p.Name, err)
		}
	}
	return nil
}

func resolveProviderSecret(p *ProviderConfig, configPath string) error {
	if p.ClientSecret != "" && p.ClientSecretFile != "" {
		return fmt.Errorf("client_secret and client_secret_file are both set; use one, " +
			"so there is no question which one is live")
	}

	env := ClientSecretEnvVar(p.Name)
	if v, ok := os.LookupEnv(env); ok {
		secret := strings.TrimSpace(v)
		if secret == "" {
			return fmt.Errorf("$%s is set but empty; unset it to fall back to the config", env)
		}
		p.ClientSecret = secret
		p.clientSecretSource = SecretSourceEnv
		return nil
	}

	if p.ClientSecretFile != "" {
		path, err := resolveSecretPath(p.ClientSecretFile)
		if err != nil {
			return fmt.Errorf("client_secret_file: %w", err)
		}
		secret, err := readSecretFile(path)
		if err != nil {
			return fmt.Errorf("client_secret_file: %w", err)
		}
		p.ClientSecret = secret
		p.clientSecretSource = SecretSourceFile
		return nil
	}

	if p.ClientSecret != "" {
		if configPath == "" {
			return fmt.Errorf("client_secret is inline, but this config did not come from a "+
				"file, so its permissions cannot be checked; use client_secret_file or $%s", env)
		}
		// No permission check here: ResolveSecrets has already made it, for every
		// source, before reaching this branch.
		p.clientSecretSource = SecretSourceInline
		return nil
	}

	// No secret anywhere. Validate reports that, with the list of ways to supply
	// one; failing here as well would only produce a worse version of the same
	// message on configs that have other problems too.
	return nil
}

// resolveSecretPath turns a client_secret_file value into an absolute path.
//
// A relative value is a systemd credential name: with LoadCredential= or
// SetCredential=, systemd places the credential in $CREDENTIALS_DIRECTORY under
// that name, mode 0400, in a tmpfs only the unit can see. Naming the credential
// rather than a path is the point of the mechanism — the secret's location stops
// being the config's business.
func resolveSecretPath(v string) (string, error) {
	if filepath.IsAbs(v) {
		return v, nil
	}
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return "", fmt.Errorf("%q is not an absolute path and $CREDENTIALS_DIRECTORY is unset, "+
			"so there is no systemd credential by that name; give an absolute path, or add "+
			"LoadCredential=%s:/path/to/secret to the unit", v, v)
	}
	if strings.Contains(v, string(filepath.Separator)) {
		return "", fmt.Errorf("%q is a systemd credential name (relative to $CREDENTIALS_DIRECTORY) "+
			"and must not contain %q", v, string(filepath.Separator))
	}
	return filepath.Join(dir, v), nil
}

func readSecretFile(path string) (string, error) {
	// Open first, then check the open descriptor. os.Stat followed by os.ReadFile
	// resolves the name twice, and in a directory another user can write, the name
	// can be a 0600 root-owned file for the stat and their own file for the read —
	// the check and the read disagreeing is the whole of the attack. f.Stat()
	// describes the inode that was opened, so what passed the check is what is
	// read, and O_NOFOLLOW refuses a symlink in the same syscall rather than
	// leaving a window in which one could appear.
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0) // #nosec G304 -- path comes from the broker's own root-owned config
	if err != nil {
		// O_NOFOLLOW reports a symlink as ELOOP, whose message describes a loop
		// that is not there. Say what is actually wrong.
		if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&fs.ModeSymlink != 0 {
			return "", symlinkError(path)
		}
		return "", err
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if err := checkPerms(path, info); err != nil {
		return "", err
	}
	if info.Size() > maxSecretFileSize {
		return "", fmt.Errorf("%s is %d bytes, which is far larger than a client secret; "+
			"check the path", path, info.Size())
	}

	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(b))
	if secret == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	// TrimSpace has already dealt with the trailing newline every editor and
	// `echo` adds; anything left means the file holds more than the secret.
	if strings.ContainsAny(secret, "\n\r") {
		return "", fmt.Errorf("%s has more than one line; it must contain the secret and "+
			"nothing else", path)
	}
	return secret, nil
}

// checkSecretFilePerms refuses a file holding a secret that another local user
// could read or replace.
func checkSecretFilePerms(path string) error {
	// Lstat, not Stat: a symlink is then reported as itself and refused below,
	// rather than resolved to whatever it happens to point at during this call.
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return checkPerms(path, info)
}

func checkPerms(path string, info fs.FileInfo) error {
	// Reachable when info came from Lstat; never when it came from a descriptor
	// opened with O_NOFOLLOW. A symlink is refused rather than followed because
	// the mode and owner that matter would be the target's, and the target can be
	// changed — by whoever owns the directory holding the link — without touching
	// anything this check looked at.
	if info.Mode()&fs.ModeSymlink != 0 {
		return symlinkError(path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&secretFileMask != 0 {
		return fmt.Errorf("%s is readable by group or other (mode %04o); run: chmod 600 %s",
			path, perm, path)
	}
	// Ownership matters as much as the mode: a 0600 file owned by someone else is
	// a secret that user can rewrite, which makes them the one choosing the OAuth
	// app the broker authenticates against.
	if uid, ok := fileOwner(info); ok {
		if euid := os.Geteuid(); uid != 0 && uid != uint32(euid) { // #nosec G115 -- a uid fits a uid
			return fmt.Errorf("%s is owned by uid %d, which is neither root nor this process "+
				"(uid %d), so that user can replace the secret; run: chown root %s",
				path, uid, euid, path)
		}
	}
	// And the directory matters as much as the file, by the same argument: a 0600
	// root-owned file in a directory another user can write cannot be modified,
	// but it can be renamed out of the way and replaced by one with the same mode
	// and the same owner and a secret of their choosing.
	return checkDirPerms(filepath.Dir(path))
}

// checkDirPerms refuses a directory another local user could write to, and so
// could replace the file inside it.
func checkDirPerms(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	perm := info.Mode().Perm()
	// The sticky bit is the exception, and it is the reason /tmp can be shared:
	// with it set, only the owner of a file may rename or unlink it, which is
	// exactly the attack the mode is being checked for.
	if perm&dirWriteMask != 0 && info.Mode()&fs.ModeSticky == 0 {
		return fmt.Errorf("%s is writable by group or other (mode %04o), so the file in it can "+
			"be replaced whatever its own mode is; run: chmod 750 %s", dir, perm, dir)
	}
	// A directory owned by another user is writable by them whatever its mode
	// says, because they can chmod it.
	if uid, ok := fileOwner(info); ok {
		if euid := os.Geteuid(); uid != 0 && uid != uint32(euid) { // #nosec G115 -- a uid fits a uid
			return fmt.Errorf("%s is owned by uid %d, which is neither root nor this process "+
				"(uid %d), so that user can replace the file in it; run: chown root %s",
				dir, uid, euid, dir)
		}
	}
	return nil
}

func symlinkError(path string) error {
	return fmt.Errorf("%s is a symlink; name the file itself, so that the file whose "+
		"permissions are checked is the file that is read", path)
}
