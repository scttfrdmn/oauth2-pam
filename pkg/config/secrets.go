package config

import (
	"fmt"
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
// Whatever holds the secret must have no group or other permission bits and be
// owned by root or by this process. In case 3 that means the config file itself:
// a secret inline in a world-readable broker.yaml is a secret every local user
// on the host already has, and the broker refuses to start rather than carry on
// as if it were confidential.
//
// configPath is the file the config was read from. Pass "" if it was not read
// from a file — case 3 is then rejected, because there are no permissions to
// check.
func (c *Config) ResolveSecrets(configPath string) error {
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
		if err := checkSecretFilePerms(configPath); err != nil {
			return fmt.Errorf("client_secret is inline, so the config file holds a secret: %w", err)
		}
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
	info, err := os.Stat(path)
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

	b, err := os.ReadFile(path) // #nosec G304 -- path comes from the broker's own root-owned config
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
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	return checkPerms(path, info)
}

func checkPerms(path string, info fs.FileInfo) error {
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
	return nil
}
