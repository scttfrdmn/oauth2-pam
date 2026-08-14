package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
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
		Audit: AuditConfig{Enabled: true, Events: KnownAuditEvents},
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

	// A mapping script the way an operator is required to install one: absolute,
	// executable, and writable by nobody but its owner. t.TempDir is 0700 and owned
	// by whoever runs the test, so the directory half of the check passes too.
	scriptDir := t.TempDir()
	goodScript := filepath.Join(scriptDir, "map-user.sh")
	if err := os.WriteFile(goodScript, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(goodScript, 0700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // substring; empty means the config must be accepted
	}{
		{"no socket path", func(c *Config) { c.Server.SocketPath = "" }, "socket_path"},
		// Resolved against the broker's working directory, which under systemd is /,
		// while the PAM module looks at its own compiled-in absolute path.
		{"relative socket path", func(c *Config) { c.Server.SocketPath = "broker.sock" }, "absolute"},

		// The level was read by nothing until v0.4.0, so nothing rejected a value
		// either: `log_level: verbose` was accepted, ignored, and believed.
		{"misspelled log level", func(c *Config) { c.Server.LogLevel = "verbose" }, "log_level"},
		{"zerolog's trace level is not one of ours", func(c *Config) { c.Server.LogLevel = "trace" }, "log_level"},
		{"unset log level is left to the flag", func(c *Config) { c.Server.LogLevel = "" }, ""},
		{"debug log level", func(c *Config) { c.Server.LogLevel = "debug" }, ""},
		{"error log level", func(c *Config) { c.Server.LogLevel = "error" }, ""},
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
		// Only negatives were rejected, so 24h validated cleanly and made a handful
		// of idle half-written requests into a stall that outlasted the day: a
		// connection holds one of the server's bounded handler slots for as long as
		// its read deadline allows.
		{"read timeout beyond the ceiling", func(c *Config) { c.Server.ReadTimeout = 24 * time.Hour }, "read_timeout"},
		{"write timeout beyond the ceiling", func(c *Config) { c.Server.WriteTimeout = 24 * time.Hour }, "write_timeout"},
		{"read timeout at the ceiling", func(c *Config) { c.Server.ReadTimeout = maxServerTimeout }, ""},
		{"a raised but sane read timeout", func(c *Config) { c.Server.ReadTimeout = 2 * time.Minute }, ""},
		{"negative concurrent auth limit", func(c *Config) { c.Security.RateLimiting.MaxConcurrentAuths = -1 }, "max_concurrent_auths"},

		// A typo in the allowlist would silently discard an entire class of
		// audit record, so it is a config error rather than a warning.
		{"unknown audit event", func(c *Config) { c.Audit.Events = []string{"authentication_sucess"} }, "unknown event type"},
		{"empty audit events is allowed", func(c *Config) { c.Audit.Events = nil }, ""},

		// An unrecognised sink type used to fall back to stdout, so a typo moved
		// the whole audit trail without saying anything.
		{"unknown audit output type", func(c *Config) {
			c.Audit.Outputs = []AuditOutput{{Type: "webhook", Path: ""}}
		}, "not supported"},
		{"audit output without a type", func(c *Config) {
			c.Audit.Outputs = []AuditOutput{{Path: "/var/log/oauth2-pam/audit.log"}}
		}, "type is required"},
		{"file output without a path", func(c *Config) {
			c.Audit.Outputs = []AuditOutput{{Type: "file"}}
		}, "path is required"},
		{"path on a stdout output", func(c *Config) {
			c.Audit.Outputs = []AuditOutput{{Type: "stdout", Path: "/var/log/oauth2-pam/audit.log"}}
		}, "applies only to type"},
		{"facility on a file output", func(c *Config) {
			c.Audit.Outputs = []AuditOutput{{Type: "file", Path: "/tmp/a.log", Facility: "auth"}}
		}, "apply only to type"},
		// #106. The broker's working directory under systemd is /, so a relative path
		// names a file at the filesystem root — and the sink's new permission checks
		// would then be checking a directory nobody chose.
		{"relative file output path", func(c *Config) {
			c.Audit.Outputs = []AuditOutput{{Type: "file", Path: "audit.log"}}
		}, "must be an absolute path"},
		{"file output path relative to a directory", func(c *Config) {
			c.Audit.Outputs = []AuditOutput{{Type: "file", Path: "../../etc/audit.log"}}
		}, "must be an absolute path"},
		{"file output with a path", func(c *Config) {
			c.Audit.Outputs = []AuditOutput{{Type: "file", Path: "/var/log/oauth2-pam/audit.log"}}
		}, ""},
		{"syslog output with facility and severity", func(c *Config) {
			c.Audit.Outputs = []AuditOutput{{Type: "syslog", Facility: "authpriv", Severity: "notice"}}
		}, ""},
		{"no outputs is allowed", func(c *Config) { c.Audit.Outputs = nil }, ""},

		{"16-byte key", func(c *Config) { c.Security.TokenEncryptionKey = strings.Repeat("a", 16) }, ""},
		{"24-byte key", func(c *Config) { c.Security.TokenEncryptionKey = strings.Repeat("a", 24) }, ""},
		{"32-byte key", func(c *Config) { c.Security.TokenEncryptionKey = strings.Repeat("a", 32) }, ""},
		{"20-byte key", func(c *Config) { c.Security.TokenEncryptionKey = strings.Repeat("a", 20) }, "token_encryption_key"},
		// The generated form: base64, 44 characters. Validate must accept what
		// `oauth2-pam-admin gen-key` prints.
		{"generated base64 key", func(c *Config) { c.Security.TokenEncryptionKey = generatedKey }, ""},
		// A key is checked even where nothing will read it (#109). It used to be
		// exempt when storage was off, so a malformed key waited in the file for
		// whoever turned storage back on and then blamed that change.
		{
			"key length is checked even when encryption is off",
			func(c *Config) {
				c.Security.SecureTokenStorage = false
				c.Security.TokenEncryptionKey = "short"
			},
			"token_encryption_key",
		},
		{
			"no key at all is still fine when encryption is off",
			func(c *Config) { c.Security.SecureTokenStorage = false },
			"",
		},

		// Identity data (login, email, org membership) crosses this hop.
		{"plaintext mapper endpoint", func(c *Config) { c.Mapper.HTTPEndpoint = "http://mapper.internal/map" }, "must use HTTPS"},
		{"https mapper endpoint", func(c *Config) { c.Mapper.HTTPEndpoint = "https://mapper.internal/map" }, ""},

		{"no mapper tier", func(c *Config) { c.Mapper = MapperConfig{} }, "at least one tier"},
		{"enrollment alone is a tier", func(c *Config) { c.Mapper = MapperConfig{EnrollmentEnabled: true} }, ""},
		{"script alone is a tier", func(c *Config) { c.Mapper = MapperConfig{ExternalScript: goodScript} }, ""},

		// The script runs as root on every tier-2 login. http_endpoint, which
		// executes nothing, has been checked since the beginning; this one was not
		// checked at all.
		{"relative script is resolved through PATH", func(c *Config) { c.Mapper.ExternalScript = "map-user.sh" }, "absolute path"},
		{"missing script", func(c *Config) { c.Mapper.ExternalScript = filepath.Join(scriptDir, "absent.sh") }, "absent.sh"},
		{"script that is a directory", func(c *Config) { c.Mapper.ExternalScript = scriptDir }, "not a regular file"},

		// A negative floor turned the UID check off for every tier, leaving only a
		// name denylist that a broker built without cgo cannot apply on an LDAP host.
		{"negative min uid", func(c *Config) { c.Mapper.MinUID = -1 }, "must not be negative"},
		{"unset min uid means the default", func(c *Config) { c.Mapper.MinUID = 0 }, ""},
		{"a lowered floor is still a floor", func(c *Config) { c.Mapper.MinUID = 500 }, ""},
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

// TestMapperScriptMustNotBeReplaceable is the other half of #81: a path that
// executes as root on every tier-2 login, with a mode and an owner that say who
// gets to choose what it executes.
func TestMapperScriptMustNotBeReplaceable(t *testing.T) {
	// One directory per case, because some of these change the directory's mode.
	newScript := func(t *testing.T, mode os.FileMode) (dir, path string) {
		t.Helper()
		dir = filepath.Join(t.TempDir(), "lib")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		path = filepath.Join(dir, "map-user.sh")
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), mode); err != nil {
			t.Fatal(err)
		}
		// WriteFile applies the umask, so the mode this test is about has to be set
		// explicitly or the group-writable cases pass for the wrong reason.
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return dir, path
	}

	t.Run("group or other writable", func(t *testing.T) {
		for _, mode := range []os.FileMode{0770, 0707, 0777, 0766} {
			_, path := newScript(t, mode)
			cfg := validConfig()
			cfg.Mapper.ExternalScript = path
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("a %04o script was accepted", mode)
			}
			if !strings.Contains(err.Error(), "runs as root") {
				t.Errorf("mode %04o: error does not say what is at stake: %v", mode, err)
			}
		}
	})

	t.Run("not executable", func(t *testing.T) {
		_, path := newScript(t, 0600)
		cfg := validConfig()
		cfg.Mapper.ExternalScript = path
		err := cfg.Validate()
		// Left alone this is silent: exec fails, the mapper falls through, and tier 2
		// is never consulted again.
		if err == nil || !strings.Contains(err.Error(), "not executable") {
			t.Fatalf("a non-executable script gave: %v", err)
		}
	})

	t.Run("in a writable directory", func(t *testing.T) {
		dir, path := newScript(t, 0755)
		if err := os.Chmod(dir, 0777); err != nil {
			t.Fatal(err)
		}
		cfg := validConfig()
		cfg.Mapper.ExternalScript = path
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "writable by group or other") {
			t.Fatalf("a script in a 0777 directory gave: %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		_, path := newScript(t, 0755)
		link := filepath.Join(filepath.Dir(path), "map.link")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		cfg := validConfig()
		cfg.Mapper.ExternalScript = link
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "is a symlink") {
			t.Fatalf("a symlinked script gave: %v", err)
		}
	})

	t.Run("the control", func(t *testing.T) {
		_, path := newScript(t, 0755)
		cfg := validConfig()
		cfg.Mapper.ExternalScript = path
		if err := cfg.Validate(); err != nil {
			t.Errorf("a 0755 script owned by this process was refused: %v", err)
		}
	})
}

// TestSupportedLogLevelsAreZerologLevels pins the allowlist to the parser that
// applies it: cmd/broker hands server.log_level to zerolog.ParseLevel, so a level
// Validate accepts and zerolog rejects would be a broker that dies immediately
// after passing validation.
func TestSupportedLogLevelsAreZerologLevels(t *testing.T) {
	for _, l := range SupportedLogLevels {
		if _, err := zerolog.ParseLevel(l); err != nil {
			t.Errorf("SupportedLogLevels contains %q, which zerolog rejects: %v", l, err)
		}
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
	// The level the file asks for has to reach the caller: cmd/broker applies it,
	// and for three releases nothing did.
	if cfg.Server.LogLevel != "debug" {
		t.Errorf("log_level = %q, want the configured %q", cfg.Server.LogLevel, "debug")
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

// TestLoadConfigRejectsUnknownKeys is the general fix for this project's
// recurring bug: the setting that is read, ignored, and believed. A lenient
// decoder makes a removed field and a typo look identical to a correct config,
// which is how `server.audit_log` and `audit.outputs[].url` survived, and how a
// misspelled `secure_token_storage` would leave tokens in plaintext silently.
func TestLoadConfigRejectsUnknownKeys(t *testing.T) {
	// sampleYAML's audit block is last, so an extra key under audit can be
	// appended; anything else has to go inside a section that already exists,
	// because a repeated top-level key is a YAML error rather than a decode one.
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"typo at the top level", sampleYAML + "securty:\n  max_token_age: 2h\n", "securty"},
		{
			"typo in a nested key",
			strings.Replace(sampleYAML, "  log_level: debug", "  log_level: debug\n  read_timout: 10s", 1),
			"read_timout",
		},
		{
			"removed field",
			strings.Replace(sampleYAML, "  log_level: debug", "  log_level: debug\n  audit_log: /var/log/oauth2-pam/audit.log", 1),
			"audit_log",
		},
		{
			"removed audit output field",
			sampleYAML + "  outputs:\n    - type: file\n      path: /tmp/a.log\n      url: https://siem.example.com/ingest\n",
			"url",
		},
		// audit.format went the same way: parsed, defaulted to json, and read by
		// nothing, while every record was JSON regardless.
		{"removed audit format field", sampleYAML + "  format: json\n", "format"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			_, err := LoadConfig(path)
			if err == nil {
				t.Fatalf("LoadConfig accepted a config containing %q", tc.want)
			}
			// The message has to name the offending key, or an operator cannot act
			// on it.
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to name %q", err, tc.want)
			}
		})
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
