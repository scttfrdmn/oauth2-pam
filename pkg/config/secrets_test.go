package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSecret writes a secret file with the given mode and returns its path.
func writeSecret(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	// WriteFile applies the umask, so a mode this test cares about has to be set
	// explicitly — otherwise the "group-readable is refused" cases pass for the
	// wrong reason on a host with a restrictive umask.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	return path
}

func providerWith(secret, file string) *Config {
	return &Config{Providers: []ProviderConfig{{
		Name:             "github",
		Type:             "github",
		ClientID:         "id",
		ClientSecret:     secret,
		ClientSecretFile: file,
	}}}
}

func TestClientSecretEnvVar(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"github", "OAUTH2_PAM_CLIENT_SECRET_GITHUB"},
		{"GitHub", "OAUTH2_PAM_CLIENT_SECRET_GITHUB"},
		{"github-enterprise", "OAUTH2_PAM_CLIENT_SECRET_GITHUB_ENTERPRISE"},
		{"acme.internal", "OAUTH2_PAM_CLIENT_SECRET_ACME_INTERNAL"},
	} {
		if got := ClientSecretEnvVar(tc.name); got != tc.want {
			t.Errorf("ClientSecretEnvVar(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSecretFromFile(t *testing.T) {
	dir := t.TempDir()
	path := writeSecret(t, dir, "secret", "s3cret\n", 0600)

	cfg := providerWith("", path)
	if err := cfg.ResolveSecrets(""); err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	p := cfg.Providers[0]
	// The trailing newline every editor adds must not become part of the secret;
	// it would be sent to GitHub and fail authentication with no useful message.
	if p.ClientSecret != "s3cret" {
		t.Errorf("secret = %q, want %q", p.ClientSecret, "s3cret")
	}
	if p.SecretSource() != SecretSourceFile {
		t.Errorf("source = %q, want %q", p.SecretSource(), SecretSourceFile)
	}
}

func TestSecretFileMustNotBeReadableByOthers(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0640, 0604, 0644, 0666} {
		path := writeSecret(t, dir, "secret", "s3cret", mode)
		err := providerWith("", path).ResolveSecrets("")
		if err == nil {
			t.Fatalf("mode %04o was accepted", mode)
		}
		if !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("mode %04o: error does not say how to fix it: %v", mode, err)
		}
	}
}

func TestSecretFileRejectsUnusableContents(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"empty", "", "is empty"},
		{"whitespace only", "\n\n  \n", "is empty"},
		{"two lines", "s3cret\nsomething else\n", "more than one line"},
		{"oversized", strings.Repeat("x", maxSecretFileSize+1), "far larger than a client secret"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeSecret(t, dir, "secret", tc.content, 0600)
			err := providerWith("", path).ResolveSecrets("")
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestSecretFileMissing(t *testing.T) {
	err := providerWith("", filepath.Join(t.TempDir(), "absent")).ResolveSecrets("")
	if err == nil {
		t.Fatal("a missing secret file was accepted")
	}
	// The path must be in the message: "no such file or directory" alone, from a
	// broker that failed to start, is a support ticket.
	if !strings.Contains(err.Error(), "absent") {
		t.Errorf("error does not name the path: %v", err)
	}
}

func TestSecretFileNotARegularFile(t *testing.T) {
	dir := t.TempDir()
	err := providerWith("", dir).ResolveSecrets("")
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory as client_secret_file gave: %v", err)
	}
}

// A relative client_secret_file is a systemd credential name, which is only
// meaningful when systemd has set $CREDENTIALS_DIRECTORY.
func TestSecretFromSystemdCredential(t *testing.T) {
	dir := t.TempDir()
	// 0400 root-owned in a tmpfs is what systemd itself produces; 0400 is the part
	// this check can reproduce in a test.
	writeSecret(t, dir, "github-client-secret", "from-systemd", 0400)
	t.Setenv("CREDENTIALS_DIRECTORY", dir)

	cfg := providerWith("", "github-client-secret")
	if err := cfg.ResolveSecrets(""); err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	if got := cfg.Providers[0].ClientSecret; got != "from-systemd" {
		t.Errorf("secret = %q, want %q", got, "from-systemd")
	}
}

func TestRelativeSecretFileWithoutCredentialsDirectory(t *testing.T) {
	// Setenv first, so the variable is restored after the test whatever it was;
	// then unset it, because "set but empty" and "absent" are different states
	// and this test is about the absent one.
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if err := os.Unsetenv("CREDENTIALS_DIRECTORY"); err != nil {
		t.Fatal(err)
	}

	err := providerWith("", "github-client-secret").ResolveSecrets("")
	if err == nil {
		t.Fatal("a relative path with no credentials directory was accepted")
	}
	// The message has to name the mechanism, because the fix is either an absolute
	// path or a LoadCredential= line and nothing in the config hints at that.
	if !strings.Contains(err.Error(), "LoadCredential") {
		t.Errorf("error does not mention LoadCredential: %v", err)
	}
}

func TestCredentialNameMustNotBeAPath(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", t.TempDir())
	err := providerWith("", "sub/dir/secret").ResolveSecrets("")
	if err == nil || !strings.Contains(err.Error(), "must not contain") {
		t.Fatalf("a path as a credential name gave: %v", err)
	}
}

func TestEnvironmentBeatsFileAndInline(t *testing.T) {
	dir := t.TempDir()
	path := writeSecret(t, dir, "secret", "from-file", 0600)
	t.Setenv("OAUTH2_PAM_CLIENT_SECRET_GITHUB", "from-env")

	cfg := providerWith("", path)
	if err := cfg.ResolveSecrets(""); err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	if got := cfg.Providers[0].ClientSecret; got != "from-env" {
		t.Errorf("secret = %q, want the environment's value", got)
	}
	if got := cfg.Providers[0].SecretSource(); got != SecretSourceEnv {
		t.Errorf("source = %q, want %q", got, SecretSourceEnv)
	}
}

func TestEmptyEnvironmentVariableIsAnError(t *testing.T) {
	t.Setenv("OAUTH2_PAM_CLIENT_SECRET_GITHUB", "   ")
	err := providerWith("inline", "").ResolveSecrets("")
	// Set-but-empty is a mistake, not a request to fall back: a container that
	// meant to pass a secret and passed nothing should fail loudly rather than
	// silently authenticate with whatever the image's config happens to contain.
	if err == nil || !strings.Contains(err.Error(), "set but empty") {
		t.Fatalf("empty environment variable gave: %v", err)
	}
}

func TestBothInlineAndFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := writeSecret(t, dir, "secret", "from-file", 0600)
	err := providerWith("inline", path).ResolveSecrets("")
	if err == nil || !strings.Contains(err.Error(), "use one") {
		t.Fatalf("both sources set gave: %v", err)
	}
}

func TestInlineSecretRequiresAProtectedConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeSecret(t, dir, "broker.yaml", "irrelevant contents", 0644)

	err := providerWith("inline", "").ResolveSecrets(cfgPath)
	if err == nil {
		t.Fatal("an inline secret in a world-readable config was accepted")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("error does not say how to fix it: %v", err)
	}

	if err := os.Chmod(cfgPath, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := providerWith("inline", "")
	if err := cfg.ResolveSecrets(cfgPath); err != nil {
		t.Fatalf("0600 config was refused: %v", err)
	}
	if got := cfg.Providers[0].SecretSource(); got != SecretSourceInline {
		t.Errorf("source = %q, want %q", got, SecretSourceInline)
	}
}

func TestInlineSecretWithoutAConfigFile(t *testing.T) {
	err := providerWith("inline", "").ResolveSecrets("")
	if err == nil || !strings.Contains(err.Error(), "did not come from a file") {
		t.Fatalf("inline secret with no config path gave: %v", err)
	}
}

func TestNoSecretAnywhereIsLeftToValidate(t *testing.T) {
	cfg := providerWith("", "")
	// ResolveSecrets stays quiet so Validate can produce the one message that
	// lists every way to supply a secret.
	if err := cfg.ResolveSecrets(""); err != nil {
		t.Fatalf("ResolveSecrets: %v", err)
	}
	if got := cfg.Providers[0].SecretSource(); got != SecretSourceNone {
		t.Errorf("source = %q, want empty", got)
	}
}

// LoadConfig must resolve secrets, not just parse them: the broker calls it and
// nothing else.
func TestLoadConfigResolvesSecretFile(t *testing.T) {
	dir := t.TempDir()
	secretPath := writeSecret(t, dir, "client-secret", "loaded-from-file\n", 0600)
	cfgPath := writeSecret(t, dir, "broker.yaml", `
server:
  socket_path: /tmp/test.sock
providers:
  - name: github
    type: github
    client_id: id
    client_secret_file: `+secretPath+`
mapper:
  rules:
    - match:
        github_login: alice
      local_user: alice
`, 0600)

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := cfg.Providers[0].ClientSecret; got != "loaded-from-file" {
		t.Errorf("secret = %q, want %q", got, "loaded-from-file")
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate after loading a secret from a file: %v", err)
	}
}
