package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config represents the complete configuration for the pam-oauth2 broker
type Config struct {
	Server         ServerConfig         `mapstructure:"server"`
	Providers      []ProviderConfig     `mapstructure:"providers"`
	Mapper         MapperConfig         `mapstructure:"mapper"`
	Authentication AuthenticationConfig `mapstructure:"authentication"`
	Security       SecurityConfig       `mapstructure:"security"`
	Audit          AuditConfig          `mapstructure:"audit"`
}

// ServerConfig contains server-specific configuration
type ServerConfig struct {
	SocketPath   string        `mapstructure:"socket_path"`
	LogLevel     string        `mapstructure:"log_level"`
	AuditLog     string        `mapstructure:"audit_log"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

// ProviderConfig represents a single OAuth2 provider configuration.
// Currently "github" is the only supported type.
type ProviderConfig struct {
	Name         string `mapstructure:"name"`
	Type         string `mapstructure:"type"`          // "github"
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`

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

	// AllowUsers is an explicit allowlist of GitHub logins (bypasses org/team checks)
	AllowUsers []string `mapstructure:"allow_users"`
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
	// Default: /etc/pam-oauth2/enrolled-users.yaml
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

// MatchCriteria specifies what must match for a rule to apply
type MatchCriteria struct {
	// GitHubLogin matches a specific GitHub username
	GitHubLogin string `mapstructure:"github_login"`

	// GitHubOrg requires membership in this GitHub org
	GitHubOrg string `mapstructure:"github_org"`

	// GitHubTeam requires membership in this team (format: "org/team-slug")
	GitHubTeam string `mapstructure:"github_team"`
}

// AuthenticationConfig contains authentication session policies
type AuthenticationConfig struct {
	TokenLifetime         time.Duration `mapstructure:"token_lifetime"`
	RefreshThreshold      time.Duration `mapstructure:"refresh_threshold"`
	MaxConcurrentSessions int           `mapstructure:"max_concurrent_sessions"`
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
	Enabled  bool          `mapstructure:"enabled"`
	Format   string        `mapstructure:"format"`
	Outputs  []AuditOutput `mapstructure:"outputs"`
	Events   []string      `mapstructure:"events"`
}

// AuditOutput defines where audit logs are sent
type AuditOutput struct {
	Type     string            `mapstructure:"type"` // "file", "stdout", "syslog"
	Path     string            `mapstructure:"path"`
	URL      string            `mapstructure:"url"`
	Headers  map[string]string `mapstructure:"headers"`
	Facility string            `mapstructure:"facility"`
	Severity string            `mapstructure:"severity"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()

	setDefaults(v)

	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	v.SetEnvPrefix("PAM_OAUTH2")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return loadFromEnvironment(v)
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// loadFromEnvironment builds a minimal config from environment variables
func loadFromEnvironment(v *viper.Viper) (*Config, error) {
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config from environment: %w", err)
	}
	return &config, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("server.socket_path", "/var/run/pam-oauth2/broker.sock")
	v.SetDefault("server.log_level", "info")
	v.SetDefault("server.audit_log", "/var/log/pam-oauth2/audit.log")
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")

	v.SetDefault("authentication.token_lifetime", "8h")
	v.SetDefault("authentication.refresh_threshold", "1h")
	v.SetDefault("authentication.max_concurrent_sessions", 10)

	v.SetDefault("security.secure_token_storage", true)
	v.SetDefault("security.max_token_age", "24h")
	v.SetDefault("security.rate_limiting.max_requests_per_minute", 60)
	v.SetDefault("security.rate_limiting.max_concurrent_auths", 10)

	v.SetDefault("mapper.enrollment_file", "/etc/pam-oauth2/enrolled-users.yaml")
	v.SetDefault("mapper.external_script_timeout", "5s")
	v.SetDefault("mapper.http_timeout", "2s")

	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.format", "json")
	v.SetDefault("audit.events", []string{
		"authentication_attempt",
		"authentication_success",
		"authentication_failure",
		"session_revoked",
	})
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Server.SocketPath == "" {
		return fmt.Errorf("server.socket_path is required")
	}

	if len(c.Providers) == 0 {
		return fmt.Errorf("at least one provider must be configured")
	}

	for i, p := range c.Providers {
		if p.Name == "" {
			return fmt.Errorf("providers[%d].name is required", i)
		}
		if p.Type == "" {
			return fmt.Errorf("providers[%d].type is required", i)
		}
		if p.Type != "github" {
			return fmt.Errorf("providers[%d].type %q is not supported (only \"github\")", i, p.Type)
		}
		if p.ClientID == "" {
			return fmt.Errorf("providers[%d].client_id is required", i)
		}
		if p.ClientSecret == "" {
			return fmt.Errorf("providers[%d].client_secret is required", i)
		}
	}

	if c.Authentication.TokenLifetime <= 0 {
		return fmt.Errorf("authentication.token_lifetime must be positive")
	}
	if c.Authentication.RefreshThreshold <= 0 {
		return fmt.Errorf("authentication.refresh_threshold must be positive")
	}
	if c.Authentication.MaxConcurrentSessions <= 0 {
		return fmt.Errorf("authentication.max_concurrent_sessions must be positive")
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
