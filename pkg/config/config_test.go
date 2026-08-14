package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/oauth2-pam/pkg/security/keys"
)

// validConfig is the baseline every Validate test mutates one field of.
func validConfig() *Config {
	return &Config{
		Server: ServerConfig{
			SocketPath:   "/var/run/oauth2-pam/broker.sock",
			LogLevel:     "info",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Providers: []ProviderConfig{{
			Name:         "github",
			Type:         "github",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
		}},
		Mapper: MapperConfig{
			Rules: []MappingRule{{Match: MatchCriteria{GitHubOrg: "acme"}, LocalUser: "{{ .Login }}"}},
		},
		Authentication: AuthenticationConfig{
			TokenLifetime:         8 * time.Hour,
			RefreshThreshold:      time.Hour,
			MaxConcurrentSessions: 10,
		},
		Security: SecurityConfig{
			SecureTokenStorage: true,
			MaxTokenAge:        24 * time.Hour,
			RateLimiting:       RateLimiting{MaxRequestsPerMinute: 60, MaxConcurrentAuths: 10},
		},
		Audit: AuditConfig{Enabled: true, Format: "json", Events: KnownAuditEvents},
	}
}

func TestValidateAcceptsBaseline(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("baseline config rejected: %v", err)
	}
}

func TestValidate(t *testing.T) {
	generatedKey, err := keys.Generate()
	if err != nil {
		t.Fatalf("keys.Generate: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // substring; empty means the config must be accepted
	}{
		{"no socket path", func(c *Config) { c.Server.SocketPath = "" }, "socket_path"},
		{"no providers", func(c *Config) { c.Providers = nil }, "at least one provider"},
		{"provider without name", func(c *Config) { c.Providers[0].Name = "" }, "name is required"},
		{"provider without type", func(c *Config) { c.Providers[0].Type = "" }, "type is required"},
		{"unsupported provider type", func(c *Config) { c.Providers[0].Type = "gitlab" }, "not supported"},
		{"provider without client id", func(c *Config) { c.Providers[0].ClientID = "" }, "client_id is required"},
		{"provider without client secret", func(c *Config) { c.Providers[0].ClientSecret = "" }, "a client secret is required"},

		// The client secret and the access token both travel to base_url.
		{"plaintext enterprise base url", func(c *Config) { c.Providers[0].GitHub.BaseURL = "http://github.acme.internal" }, "must use HTTPS"},
		{"https enterprise base url", func(c *Config) { c.Providers[0].GitHub.BaseURL = "https://github.acme.internal" }, ""},
		{"empty base url means github.com", func(c *Config) { c.Providers[0].GitHub.BaseURL = "" }, ""},

		{"zero token lifetime", func(c *Config) { c.Authentication.TokenLifetime = 0 }, "token_lifetime must be positive"},
		{"negative refresh threshold", func(c *Config) { c.Authentication.RefreshThreshold = -time.Second }, "refresh_threshold must be positive"},
		{"unlimited sessions is allowed", func(c *Config) { c.Authentication.MaxConcurrentSessions = 0 }, ""},
		{"negative session limit", func(c *Config) { c.Authentication.MaxConcurrentSessions = -1 }, "non-negative"},

		// A session that outlives its own access token would keep granting
		// access after the credential behind it is gone.
		{
			"token lifetime beyond max token age",
			func(c *Config) {
				c.Authentication.TokenLifetime = 48 * time.Hour
				c.Security.MaxTokenAge = 24 * time.Hour
			},
			"must not exceed",
		},
		{
			"max token age unset disables the check",
			func(c *Config) {
				c.Authentication.TokenLifetime = 48 * time.Hour
				c.Security.MaxTokenAge = 0
			},
			"",
		},

		{"negative read timeout", func(c *Config) { c.Server.ReadTimeout = -time.Second }, "read_timeout"},
		{"negative write timeout", func(c *Config) { c.Server.WriteTimeout = -time.Second }, "write_timeout"},
		{"negative concurrent auth limit", func(c *Config) { c.Security.RateLimiting.MaxConcurrentAuths = -1 }, "max_concurrent_auths"},

		// A typo in the allowlist would silently discard an entire class of
		// audit record, so it is a config error rather than a warning.
		{"unknown audit event", func(c *Config) { c.Audit.Events = []string{"authentication_sucess"} }, "unknown event type"},
		{"empty audit events is allowed", func(c *Config) { c.Audit.Events = nil }, ""},

		{"16-byte key", func(c *Config) { c.Security.TokenEncryptionKey = strings.Repeat("a", 16) }, ""},
		{"24-byte key", func(c *Config) { c.Security.TokenEncryptionKey = strings.Repeat("a", 24) }, ""},
		{"32-byte key", func(c *Config) { c.Security.TokenEncryptionKey = strings.Repeat("a", 32) }, ""},
		{"20-byte key", func(c *Config) { c.Security.TokenEncryptionKey = strings.Repeat("a", 20) }, "token_encryption_key"},
		// The generated form: base64, 44 characters. Validate must accept what
		// `oauth2-pam-admin gen-key` prints.
		{"generated base64 key", func(c *Config) { c.Security.TokenEncryptionKey = generatedKey }, ""},
		{
			"key length is unchecked when encryption is off",
			func(c *Config) {
				c.Security.SecureTokenStorage = false
				c.Security.TokenEncryptionKey = "short"
			},
			"",
		},

		// Identity data (login, email, org membership) crosses this hop.
		{"plaintext mapper endpoint", func(c *Config) { c.Mapper.HTTPEndpoint = "http://mapper.internal/map" }, "must use HTTPS"},
		{"https mapper endpoint", func(c *Config) { c.Mapper.HTTPEndpoint = "https://mapper.internal/map" }, ""},

		{"no mapper tier", func(c *Config) { c.Mapper = MapperConfig{} }, "at least one tier"},
		{"enrollment alone is a tier", func(c *Config) { c.Mapper = MapperConfig{EnrollmentEnabled: true} }, ""},
		{"script alone is a tier", func(c *Config) { c.Mapper = MapperConfig{ExternalScript: "/usr/local/bin/map"} }, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(cfg)
			err := cfg.Validate()

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Validate() = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestKnownAuditEventsAreAllValid guards the defaults against the mistake this
// list was introduced to fix: shipping an allowlist that Validate itself would
// reject, or that omits events the broker emits.
func TestKnownAuditEventsAreAllValid(t *testing.T) {
	cfg := validConfig()
	cfg.Audit.Events = KnownAuditEvents
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the default audit.events list is invalid: %v", err)
	}
	for _, e := range KnownAuditEvents {
		if !isKnownAuditEvent(e) {
			t.Errorf("%q is in KnownAuditEvents but isKnownAuditEvent says otherwise", e)
		}
	}
}

const sampleYAML = `
server:
  socket_path: /tmp/oauth2-pam-test.sock
  log_level: debug
  read_timeout: 10s

providers:
  - name: github
    type: github
    client_id: cid
    client_secret: csecret
    github:
      require_org: acme
      require_teams:
        - acme/eng
      allow_users:
        - breakglass

mapper:
  rules:
    - match:
        github_org: acme
      local_user: "{{ .Login }}"
      groups:
        - devs

authentication:
  token_lifetime: 4h

audit:
  events:
    - authentication_success
    - authentication_denied
`

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loaded config does not validate: %v", err)
	}

	if cfg.Server.SocketPath != "/tmp/oauth2-pam-test.sock" {
		t.Errorf("socket_path = %q", cfg.Server.SocketPath)
	}
	if cfg.Server.ReadTimeout != 10*time.Second {
		t.Errorf("read_timeout = %s, want 10s", cfg.Server.ReadTimeout)
	}
	// Not set in the file, so the default must survive unmarshalling.
	if cfg.Server.WriteTimeout != 30*time.Second {
		t.Errorf("write_timeout = %s, want the 30s default", cfg.Server.WriteTimeout)
	}
	if cfg.Authentication.TokenLifetime != 4*time.Hour {
		t.Errorf("token_lifetime = %s, want 4h", cfg.Authentication.TokenLifetime)
	}
	if cfg.Authentication.MaxConcurrentSessions != 10 {
		t.Errorf("max_concurrent_sessions = %d, want the default 10", cfg.Authentication.MaxConcurrentSessions)
	}
	if !cfg.Security.SecureTokenStorage {
		t.Error("secure_token_storage = false, want the default true")
	}

	if len(cfg.Providers) != 1 {
		t.Fatalf("got %d providers, want 1", len(cfg.Providers))
	}
	p := cfg.Providers[0]
	if p.GitHub.RequireOrg != "acme" {
		t.Errorf("require_org = %q", p.GitHub.RequireOrg)
	}
	if len(p.GitHub.RequireTeams) != 1 || p.GitHub.RequireTeams[0] != "acme/eng" {
		t.Errorf("require_teams = %v", p.GitHub.RequireTeams)
	}
	if len(p.GitHub.AllowUsers) != 1 || p.GitHub.AllowUsers[0] != "breakglass" {
		t.Errorf("allow_users = %v", p.GitHub.AllowUsers)
	}

	if len(cfg.Mapper.Rules) != 1 {
		t.Fatalf("got %d mapper rules, want 1", len(cfg.Mapper.Rules))
	}
	r := cfg.Mapper.Rules[0]
	if r.Match.GitHubOrg != "acme" || r.LocalUser != "{{ .Login }}" {
		t.Errorf("rule = %+v", r)
	}
	if len(r.Groups) != 1 || r.Groups[0] != "devs" {
		t.Errorf("rule groups = %v", r.Groups)
	}

	// An explicit list replaces the defaults rather than merging with them.
	if len(cfg.Audit.Events) != 2 {
		t.Errorf("audit.events = %v, want exactly the two configured events", cfg.Audit.Events)
	}
}

// TestLoadConfigMissingFile: the error must name the path. The previous code
// fell back to an environment-only config here, which could never satisfy
// Validate (providers is a slice AutomaticEnv cannot populate), so the operator
// saw a complaint about missing providers instead of the missing file.
func TestLoadConfigMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.yaml")

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig on a missing file returned no error")
	}
	if !strings.Contains(err.Error(), "config file not found") {
		t.Errorf("err = %q, want it to say the config file was not found", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("err = %q, want it to name %s", err, path)
	}
}

func TestLoadConfigMalformedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("server: [this is not a mapping"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig accepted malformed YAML")
	}
}

// TestEnvironmentOverridesScalars documents what AutomaticEnv can and cannot
// do: it overrides scalars that have defaults, and that is all.
func TestEnvironmentOverridesScalars(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("OAUTH2_PAM_SERVER.LOG_LEVEL", "warn")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Server.LogLevel != "warn" {
		t.Errorf("log_level = %q, want the environment override %q", cfg.Server.LogLevel, "warn")
	}
}

// TestShippedExampleConfigIsValid loads configs/example.yaml the way an
// operator would. It shipped with an `http://` mapper endpoint that Validate
// rejects, so the documented starting point was one the broker refused to
// start from.
func TestShippedExampleConfigIsValid(t *testing.T) {
	src := filepath.Join("..", "..", "configs", "example.yaml")
	example, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("the example config is missing: %v", err)
	}

	// Loaded from a 0600 copy, because the example carries a placeholder
	// client_secret inline and ResolveSecrets refuses to read one out of a file
	// other users can read — which every file in a git checkout is. That is not a
	// wrinkle of the test: it is what `install -m 0600` in scripts/install-release.sh
	// exists for, and this copy is the same step an operator takes.
	path := filepath.Join(t.TempDir(), "broker.yaml")
	if err := os.WriteFile(path, example, 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", path, err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the shipped example config does not validate: %v", err)
	}

	// Every audit event the example lists must be one the broker actually
	// emits; Validate enforces that, so a typo here fails above.
	if len(cfg.Audit.Events) != len(KnownAuditEvents) {
		t.Errorf("the example lists %d audit events, want all %d",
			len(cfg.Audit.Events), len(KnownAuditEvents))
	}
}
