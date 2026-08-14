package config

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/scttfrdmn/oauth2-pam/pkg/security/keys"
	"github.com/spf13/viper"
)

// KnownAuditEvents lists every event type the broker emits. audit.events
// filters against this set, and Validate rejects names that are not in it:
// a typo in the allowlist would otherwise silently punch a hole in the audit
// trail.
var KnownAuditEvents = []string{
	"authentication_attempt",
	"authentication_success",
	"authentication_failed",
	"authentication_denied",
	"device_flow_failed",
	"session_revoked",
}

// SupportedProviderTypes lists the values providers[].type may take. Validate
// checks against it, so an unsupported type is a startup error naming the ones
// that exist rather than a failure halfway through building the broker.
//
// pkg/provider/registry holds the constructor for each of these, and a test
// there pins the two lists together — a provider that is registered but not
// listed here would be rejected by Validate before it could ever be built.
var SupportedProviderTypes = []string{"github"}

// SupportedAuditOutputTypes lists the values audit.outputs[].type may take.
//
// Validate checks against it because the sink constructor used to fall back to
// stdout for anything it did not recognise. `type: fille` therefore produced a
// working broker whose audit trail went to the journal instead of the file an
// administrator had configured, with nothing anywhere saying so — the failure
// mode is discovering it during an incident, when the records are wanted.
var SupportedAuditOutputTypes = []string{"stdout", "file", "syslog"}

// Config represents the complete configuration for the oauth2-pam broker
type Config struct {
	Server         ServerConfig         `mapstructure:"server"`
	Providers      []ProviderConfig     `mapstructure:"providers"`
	Mapper         MapperConfig         `mapstructure:"mapper"`
	Authentication AuthenticationConfig `mapstructure:"authentication"`
	Security       SecurityConfig       `mapstructure:"security"`
	Audit          AuditConfig          `mapstructure:"audit"`
}

// ServerConfig contains server-specific configuration.
//
// There is deliberately no audit_log field: audit destinations are configured
// under audit.outputs, and a second setting that looked like it also chose one
// but was ignored was worse than no setting at all.
type ServerConfig struct {
	SocketPath string `mapstructure:"socket_path"`
	LogLevel   string `mapstructure:"log_level"`

	// ReadTimeout bounds how long the broker waits for a complete request
	// from a connected client; WriteTimeout bounds sending the response.
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// ProviderConfig represents a single OAuth2 provider configuration.
// Currently "github" is the only supported type.
type ProviderConfig struct {
	Name     string `mapstructure:"name"`
	Type     string `mapstructure:"type"` // "github"
	ClientID string `mapstructure:"client_id"`

	// ClientSecret is the secret inline in the config file. Supplying it this way
	// is supported, but it makes broker.yaml a secret-bearing file: ResolveSecrets
	// then requires that file to have no group or other permission bits, and the
	// broker refuses to start otherwise.
	//
	// After LoadConfig this field holds the secret whatever its source was, so
	// everything downstream reads one field.
	ClientSecret string `mapstructure:"client_secret"`

	// ClientSecretFile keeps the secret out of the config: an absolute path to a
	// file containing it, or a bare systemd credential name resolved under
	// $CREDENTIALS_DIRECTORY. Mutually exclusive with ClientSecret. See
	// ResolveSecrets for the precedence and the permission rules.
	ClientSecretFile string `mapstructure:"client_secret_file"`

	// clientSecretSource records which of the three sources supplied the secret,
	// for the startup log. Unexported so that no config key can set it.
	clientSecretSource SecretSource

	// GitHub-specific access controls
	GitHub GitHubConfig `mapstructure:"github"`
}

// GitHubConfig holds GitHub-specific access control settings
type GitHubConfig struct {
	// RequireOrg, if set, requires the user to be a member of this GitHub org
	RequireOrg string `mapstructure:"require_org"`

	// RequireTeams, if set, requires membership in at least one of these teams
	// Format: "org/team-slug"
	RequireTeams []string `mapstructure:"require_teams"`

	// AllowUsers is an explicit allowlist of GitHub logins (bypasses org/team
	// checks). On its own it is still a restriction: a login that is not on the
	// list and has no org/team requirement left to satisfy is refused.
	AllowUsers []string `mapstructure:"allow_users"`

	// BaseURL points the provider at a GitHub Enterprise Server installation
	// instead of github.com — for example https://github.acme.internal. The
	// device, token, and API endpoints are derived from it. Leave empty for
	// github.com.
	BaseURL string `mapstructure:"base_url"`
}

// MapperConfig defines how a GitHub identity is mapped to a local Unix user.
// The tiers are evaluated in order; the first match wins.
//
// Tier 0 — EnrollmentFile (self-enrolled users, checked first)
// Tier 1 — Rules (built-in, zero deps)
// Tier 2 — ExternalScript (external binary, JSON stdin/stdout)
// Tier 3 — HTTPEndpoint (identity service / LDAP gateway)
type MapperConfig struct {
	// EnrollmentEnabled enables Tier 0 enrollment lookups (default false).
	EnrollmentEnabled bool `mapstructure:"enrollment_enabled"`

	// EnrollmentFile is the path to the YAML file that maps local Unix users
	// to their enrolled GitHub logins (Tier 0).
	// Default: /etc/oauth2-pam/enrolled-users.yaml
	EnrollmentFile string `mapstructure:"enrollment_file"`

	// Rules is the built-in config-file mapper (Tier 1)
	Rules []MappingRule `mapstructure:"rules"`

	// ExternalScript is the path to an external mapping script (Tier 2).
	// The script receives an Identity JSON object on stdin and must write
	// a MappingResult JSON object to stdout.
	ExternalScript string `mapstructure:"external_script"`

	// ExternalScriptTimeout is how long to wait for the script (default 5s)
	ExternalScriptTimeout time.Duration `mapstructure:"external_script_timeout"`

	// HTTPEndpoint is a URL for an HTTP mapping service (Tier 3).
	// POST with Identity JSON body; expects MappingResult JSON response.
	HTTPEndpoint string `mapstructure:"http_endpoint"`

	// HTTPTimeout is how long to wait for the HTTP service (default 2s)
	HTTPTimeout time.Duration `mapstructure:"http_timeout"`

	// MinUID is the lowest UID an identity may be mapped to (default 1000, the
	// UID_MIN of every mainstream distribution). It applies to every tier.
	//
	// A negative value disables the floor, leaving only the system-account name
	// denylist. UID 0 is refused either way.
	MinUID int `mapstructure:"min_uid"`

	// AllowSystemUsers exempts named accounts from the built-in system-account
	// denylist — for the site whose real person is called "mail". Those accounts
	// still have to satisfy MinUID, and root is never exempt.
	AllowSystemUsers []string `mapstructure:"allow_system_users"`
}

// MappingRule defines a single identity-to-user mapping rule.
// All non-empty Match fields must match (AND logic).
type MappingRule struct {
	// Match criteria — all specified fields must match
	Match MatchCriteria `mapstructure:"match"`

	// LocalUser is the Unix username to map to.
	// Supports template variable: {{ .Login }} (GitHub login)
	LocalUser string `mapstructure:"local_user"`

	// Groups are additional Unix supplementary groups to assign
	Groups []string `mapstructure:"groups"`
}

// MatchCriteria specifies what must match for a rule to apply. Every non-empty
// field must match (AND), and matching is case-insensitive throughout.
//
// The github_* keys are the GitHub spelling of provider-neutral concepts and
// keep working unchanged: github_login is the identity's login, and github_org /
// github_team are its "org" and "team" claims. login and claims are the neutral
// forms, for a provider whose vocabulary is something else — an OIDC issuer
// asserting flat groups is matched with `claims: {group: platform-team}`.
type MatchCriteria struct {
	// GitHubLogin matches a specific GitHub username. Equivalent to Login.
	GitHubLogin string `mapstructure:"github_login"`

	// GitHubOrg requires membership in this GitHub org (the "org" claim).
	GitHubOrg string `mapstructure:"github_org"`

	// GitHubTeam requires membership in this team, "org/team-slug" (the "team"
	// claim).
	GitHubTeam string `mapstructure:"github_team"`

	// Login matches the identity's username at the provider, whatever the
	// provider calls it. Takes precedence over GitHubLogin if both are set.
	Login string `mapstructure:"login"`

	// Claims requires each named claim to carry the given value. The well-known
	// names are "org", "team", "group", and "role"; a provider may assert others
	// and a rule may match them by name without any change here.
	Claims map[string]string `mapstructure:"claims"`
}

// AuthenticationConfig contains authentication session policies
type AuthenticationConfig struct {
	TokenLifetime         time.Duration `mapstructure:"token_lifetime"`
	RefreshThreshold      time.Duration `mapstructure:"refresh_threshold"`
	MaxConcurrentSessions int           `mapstructure:"max_concurrent_sessions"`

	// DeviceFlowTimeout is how long the broker will keep a device flow alive
	// waiting for the user to approve it. It must be longer than the PAM module's
	// timeout= argument, or logins fail before the user has run out of time.
	//
	// It exists because the provider's own device-code lifetime is far longer than
	// any login: github.com issues 15-minute codes, so an abandoned SSH attempt
	// used to hold a pending slot and a polling goroutine for a quarter of an
	// hour. 0 means "use the provider's expiry", which restores that behaviour.
	DeviceFlowTimeout time.Duration `mapstructure:"device_flow_timeout"`
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
	TokenEncryptionKey string        `mapstructure:"token_encryption_key"`
	SecureTokenStorage bool          `mapstructure:"secure_token_storage"`
	MaxTokenAge        time.Duration `mapstructure:"max_token_age"`
	RateLimiting       RateLimiting  `mapstructure:"rate_limiting"`
}

// RateLimiting contains rate limiting settings
type RateLimiting struct {
	MaxRequestsPerMinute int `mapstructure:"max_requests_per_minute"`
	MaxConcurrentAuths   int `mapstructure:"max_concurrent_auths"`
}

// AuditConfig contains audit logging configuration
type AuditConfig struct {
	Enabled bool          `mapstructure:"enabled"`
	Format  string        `mapstructure:"format"`
	Outputs []AuditOutput `mapstructure:"outputs"`
	Events  []string      `mapstructure:"events"`
}

// AuditOutput defines where audit logs are sent.
//
// There is deliberately no url or headers field. Both were parsed and never
// read — there has never been a webhook sink — so a config that posted audit
// records to a SIEM was accepted, ignored, and silently wrote to stdout instead.
type AuditOutput struct {
	// Type is one of SupportedAuditOutputTypes.
	Type string `mapstructure:"type"`

	// Path is the audit file, required for type "file" and meaningless for the
	// others.
	Path string `mapstructure:"path"`

	// Facility and Severity name the syslog priority to log at, for type
	// "syslog". Both are optional (auth.info by default) and meaningless for the
	// other types. The accepted names are defined in pkg/security, which owns the
	// mapping to syslog's constants; a bad one is a startup error from there
	// rather than a duplicated list here.
	Facility string `mapstructure:"facility"`
	Severity string `mapstructure:"severity"`
}

// LoadConfig loads configuration from a YAML file and resolves each provider's
// client secret.
//
// The file is required. Environment variables (OAUTH2_PAM_*) can override
// scalar values that have defaults, but they cannot stand in for the file: the
// providers list is a slice, which AutomaticEnv cannot populate, and Validate
// requires at least one provider. Client secrets are the exception and have
// their own per-provider variable — see ResolveSecrets.
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()

	setDefaults(v)

	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	v.SetEnvPrefix("OAUTH2_PAM")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		// SetConfigFile names the file explicitly, so a missing file arrives as
		// an *fs.PathError, never as viper.ConfigFileNotFoundError (which only
		// occurs when searching for a config by name across search paths).
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("config file not found: %s", configPath)
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	var config Config
	// UnmarshalExact, not Unmarshal: a key with no matching field is an error.
	//
	// This project's recurring bug has been the setting that is read, ignored, and
	// believed — server.audit_log, audit.outputs[].url, six fields in 0.2.0 — and
	// every one of them was invisible because a lenient decoder discards what it
	// does not recognise. So does a typo: `secure_token_storge: true` left tokens
	// in plaintext and said nothing. An operator who writes a key into this file
	// means it, and the only way to keep that promise is to refuse the ones that
	// cannot be kept.
	if err := v.UnmarshalExact(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Before Validate, so that a secret which is present but unreadable — or
	// readable by every user on the host — is reported as what it is rather than
	// as "client_secret is required".
	if err := config.ResolveSecrets(configPath); err != nil {
		return nil, err
	}

	return &config, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.socket_path", "/var/run/oauth2-pam/broker.sock")
	v.SetDefault("server.log_level", "info")
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")

	v.SetDefault("authentication.token_lifetime", "8h")
	v.SetDefault("authentication.refresh_threshold", "1h")
	v.SetDefault("authentication.max_concurrent_sessions", 10)
	// Longer than the module's default timeout= so the user, not the broker, is
	// the one who runs out of time; short enough that an abandoned flow releases
	// its slot in minutes rather than at the provider's 15-minute code expiry.
	v.SetDefault("authentication.device_flow_timeout", "3m")

	v.SetDefault("security.secure_token_storage", true)
	v.SetDefault("security.max_token_age", "24h")
	// Both of these are host-wide backstops, not per-user limits: every PAM caller
	// is sshd running as root, so there is no per-user signal to limit on. They are
	// sized so a busy login host never reaches them and a runaway client does.
	v.SetDefault("security.rate_limiting.max_requests_per_minute", 300)
	v.SetDefault("security.rate_limiting.max_concurrent_auths", 50)

	v.SetDefault("mapper.enrollment_file", "/etc/oauth2-pam/enrolled-users.yaml")
	v.SetDefault("mapper.external_script_timeout", "5s")
	v.SetDefault("mapper.http_timeout", "2s")
	// Mirrors mapper.DefaultMinUID, which cannot be referenced here: pkg/mapper
	// imports this package. A test in pkg/mapper pins the two together.
	v.SetDefault("mapper.min_uid", 1000)

	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.format", "json")
	v.SetDefault("audit.events", KnownAuditEvents)
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.SocketPath == "" {
		return fmt.Errorf("server.socket_path is required")
	}

	if len(c.Providers) == 0 {
		return fmt.Errorf("at least one provider must be configured")
	}

	seenNames := make(map[string]int, len(c.Providers))
	for i, p := range c.Providers {
		if p.Name == "" {
			return fmt.Errorf("providers[%d].name is required", i)
		}
		// Names identify a provider in the audit log and in the environment
		// variable that can carry its secret, so two providers sharing one are
		// ambiguous in both places.
		if first, dup := seenNames[p.Name]; dup {
			return fmt.Errorf("providers[%d].name %q is already used by providers[%d]", i, p.Name, first)
		}
		seenNames[p.Name] = i

		if p.Type == "" {
			return fmt.Errorf("providers[%d].type is required", i)
		}
		if !isSupportedProviderType(p.Type) {
			return fmt.Errorf("providers[%d].type %q is not supported (supported: %s)",
				i, p.Type, strings.Join(SupportedProviderTypes, ", "))
		}
		if p.ClientID == "" {
			return fmt.Errorf("providers[%d].client_id is required", i)
		}
		if p.ClientSecret == "" {
			return fmt.Errorf("providers[%d]: a client secret is required — set client_secret_file, "+
				"$%s, or client_secret in the config file", i, ClientSecretEnvVar(p.Name))
		}
		// The client secret and the access token both travel to this host.
		if p.GitHub.BaseURL != "" && !strings.HasPrefix(p.GitHub.BaseURL, "https://") {
			return fmt.Errorf("providers[%d].github.base_url must use HTTPS (got %q)", i, p.GitHub.BaseURL)
		}
	}

	if c.Authentication.TokenLifetime <= 0 {
		return fmt.Errorf("authentication.token_lifetime must be positive")
	}
	if c.Authentication.RefreshThreshold <= 0 {
		return fmt.Errorf("authentication.refresh_threshold must be positive")
	}
	if c.Authentication.MaxConcurrentSessions < 0 {
		return fmt.Errorf("authentication.max_concurrent_sessions must be non-negative (0 = unlimited)")
	}

	// A session cannot outlive the token it is built on.
	if c.Security.MaxTokenAge > 0 && c.Authentication.TokenLifetime > c.Security.MaxTokenAge {
		return fmt.Errorf("authentication.token_lifetime (%s) must not exceed security.max_token_age (%s)",
			c.Authentication.TokenLifetime, c.Security.MaxTokenAge)
	}

	if c.Server.ReadTimeout < 0 {
		return fmt.Errorf("server.read_timeout must not be negative")
	}
	if c.Server.WriteTimeout < 0 {
		return fmt.Errorf("server.write_timeout must not be negative")
	}
	if c.Security.RateLimiting.MaxConcurrentAuths < 0 {
		return fmt.Errorf("security.rate_limiting.max_concurrent_auths must be non-negative (0 = unlimited)")
	}

	for _, e := range c.Audit.Events {
		if !isKnownAuditEvent(e) {
			return fmt.Errorf("audit.events contains unknown event type %q (known: %s)",
				e, strings.Join(KnownAuditEvents, ", "))
		}
	}

	for i, o := range c.Audit.Outputs {
		if o.Type == "" {
			return fmt.Errorf("audit.outputs[%d].type is required (one of: %s)",
				i, strings.Join(SupportedAuditOutputTypes, ", "))
		}
		if !isSupportedAuditOutputType(o.Type) {
			return fmt.Errorf("audit.outputs[%d].type %q is not supported (supported: %s)",
				i, o.Type, strings.Join(SupportedAuditOutputTypes, ", "))
		}
		// A field set on the wrong sink type is an error rather than something
		// ignored, because every way of ignoring it ends with an audit trail
		// somewhere other than where it was configured to go.
		if o.Type == "file" && o.Path == "" {
			return fmt.Errorf("audit.outputs[%d].path is required for type \"file\"", i)
		}
		if o.Type != "file" && o.Path != "" {
			return fmt.Errorf("audit.outputs[%d].path applies only to type \"file\", not %q", i, o.Type)
		}
		if o.Type != "syslog" && (o.Facility != "" || o.Severity != "") {
			return fmt.Errorf("audit.outputs[%d]: facility and severity apply only to type \"syslog\", not %q", i, o.Type)
		}
	}

	// What counts as a valid key is defined once, in pkg/security/keys, so this
	// check and the one at cipher construction cannot drift apart.
	if c.Security.SecureTokenStorage && c.Security.TokenEncryptionKey != "" {
		if err := keys.Validate(c.Security.TokenEncryptionKey); err != nil {
			return fmt.Errorf("security.token_encryption_key %w", err)
		}
	}

	// No check on MinUID == 0: it means "unset, use the default", so that a Config
	// built in code rather than loaded from a file gets the floor rather than an
	// error. Disabling the floor is a negative value, which is deliberately harder
	// to type by accident.
	for i, name := range c.Mapper.AllowSystemUsers {
		if strings.EqualFold(name, "root") {
			return fmt.Errorf("mapper.allow_system_users[%d]: root cannot be allowed", i)
		}
	}

	// Require HTTPS for the mapper HTTP endpoint to protect identity data in transit.
	if c.Mapper.HTTPEndpoint != "" && !strings.HasPrefix(c.Mapper.HTTPEndpoint, "https://") {
		return fmt.Errorf("mapper.http_endpoint must use HTTPS (got %q)", c.Mapper.HTTPEndpoint)
	}

	// Validate mapper has at least one tier configured
	hasTier := c.Mapper.EnrollmentEnabled ||
		len(c.Mapper.Rules) > 0 ||
		c.Mapper.ExternalScript != "" ||
		c.Mapper.HTTPEndpoint != ""
	if !hasTier {
		return fmt.Errorf("mapper: at least one tier (enrollment_enabled, rules, external_script, or http_endpoint) must be configured")
	}

	return nil
}

func isSupportedProviderType(t string) bool {
	for _, s := range SupportedProviderTypes {
		if s == t {
			return true
		}
	}
	return false
}

func isSupportedAuditOutputType(t string) bool {
	for _, s := range SupportedAuditOutputTypes {
		if s == t {
			return true
		}
	}
	return false
}

func isKnownAuditEvent(name string) bool {
	for _, k := range KnownAuditEvents {
		if k == name {
			return true
		}
	}
	return false
}
