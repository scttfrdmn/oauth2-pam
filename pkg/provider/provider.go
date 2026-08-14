// Package provider defines what oauth2-pam needs from an OAuth2 identity
// provider, and the provider-neutral types that flow out of one.
//
// Everything downstream of a provider — the mapper, the broker, the audit log —
// works in terms of these types and never in terms of a particular provider's
// package. Adding a provider means implementing Provider and registering it in
// pkg/provider/registry; nothing in pkg/auth or pkg/mapper should have to change.
//
// The authentication mechanism is fixed: the OAuth2 Device Authorization Grant
// (RFC 8628). That is not an oversight. A PAM module authenticating an ssh login
// has no browser to redirect and no loopback port to receive a code on, so the
// device flow is the only grant type that fits, and an interface generic over
// grant types would have exactly one implementation of each of the others.
package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Provider is one configured OAuth2 provider. Implementations must be safe for
// concurrent use: the broker calls them from a polling goroutine per device flow.
type Provider interface {
	// Name is the operator's name for this provider, from providers[].name. It
	// appears in the audit log and in the session, and is how a request selects
	// a provider.
	Name() string

	// Type is the implementation's kind, from providers[].type — "github". Two
	// providers of the same type with different names are ordinary (github.com
	// and an Enterprise Server, say).
	Type() string

	// StartDeviceFlow requests a device code and the URL the user must visit.
	StartDeviceFlow(ctx context.Context) (*DeviceFlow, error)

	// PollDeviceAuthorization asks whether the user has finished authorizing.
	// While they have not, it must return ErrAuthorizationPending; the other
	// sentinel errors below carry the remaining RFC 8628 outcomes. Anything
	// else is treated as an operational failure.
	PollDeviceAuthorization(ctx context.Context, deviceCode string) (*Token, error)

	// GetIdentity resolves the token into an Identity, and applies whatever
	// provider-level access controls the config specifies (org membership, an
	// allowlist). A refusal by those controls must wrap ErrAccessForbidden, so
	// the broker can tell a decision about the user apart from an outage.
	GetIdentity(ctx context.Context, token *Token) (*Identity, error)

	// RevokeAccessToken invalidates the token at the provider. Best-effort: the
	// broker logs a failure and continues discarding its own copy.
	RevokeAccessToken(ctx context.Context, accessToken string) error
}

// DeviceFlow is an in-progress device authorization.
type DeviceFlow struct {
	// DeviceCode identifies the flow when polling. It is a secret — it is what
	// the poll exchanges for a token — and must not be shown to the user or
	// logged.
	DeviceCode string

	// UserCode is the short code the user types at DeviceURL (e.g. "ABCD-1234").
	UserCode string

	// DeviceURL is where the user goes to enter UserCode. It may already
	// embed the code (RFC 8628's verification_uri_complete).
	DeviceURL string

	// ExpiresAt is when the device code stops being redeemable.
	ExpiresAt time.Time

	// PollingInterval is the provider's requested seconds between polls.
	PollingInterval int
}

// Token is an OAuth2 access token.
type Token struct {
	AccessToken string
	TokenType   string
	Scope       string
	ExpiresAt   time.Time

	// Fingerprint identifies this token in logs and audit records without
	// containing any of it: the hex encoding of the first 16 bytes of the token's
	// SHA-256 digest. An implementation must produce exactly that, because
	// TokenManager fingerprints the stored token the same way and an audit trail
	// lines a session up with its token by comparing the two.
	//
	// It replaced a prefix…suffix elision of the token itself, which put 16 bytes
	// of the live secret in a field labelled "for audit logs". Nothing here may
	// carry any part of AccessToken.
	Fingerprint string
}

// Identity is an authenticated identity, in provider-neutral terms. It carries
// what the mapper needs to decide a local Unix user.
type Identity struct {
	// Provider is the configured provider name that authenticated this identity.
	Provider string

	// Type is that provider's type ("github").
	Type string

	// Subject is the provider's own stable identifier for the account, when it
	// has one that outlives a rename — GitHub's numeric user ID, an OIDC `sub`.
	// Login can be changed by the user; Subject is what an audit trail should
	// key on. It may be empty if the provider offers nothing stable.
	Subject string

	// Login is the provider's username for the account: a GitHub login, an
	// OIDC preferred_username. This is what mapper rules match and what
	// {{ .Login }} expands to.
	Login string

	// Name is the display name, and Email the primary email address. Either may
	// be empty — plenty of providers let a user hide both.
	Name  string
	Email string

	// Claims is the provider's membership vocabulary: named, multi-valued
	// assertions about the account. The names are the provider's own, with the
	// well-known ones below spelled consistently so a mapper rule written for
	// one provider means the same thing for another. GitHub fills ClaimOrg and
	// ClaimTeam; an OIDC provider would fill ClaimGroup.
	//
	// Keeping memberships in a map rather than in provider-specific fields is
	// what lets the rule engine work for a provider it has never heard of: a
	// rule matches claims by name, so a new provider's vocabulary needs no
	// change to the mapper.
	Claims map[string][]string
}

// Well-known claim names. A provider is free to assert others — the mapper
// matches whatever name a rule asks for — but these have agreed meanings, so
// use them rather than a synonym.
const (
	// ClaimOrg is an organization/tenant the account belongs to, as a slug:
	// GitHub orgs, GitLab top-level groups.
	ClaimOrg = "org"

	// ClaimTeam is a team within an organization, qualified as "org/team".
	ClaimTeam = "team"

	// ClaimGroup is a flat group membership with no org above it — the shape
	// most OIDC and SAML providers assert.
	ClaimGroup = "group"

	// ClaimRole is a role or entitlement name.
	ClaimRole = "role"
)

// Claim returns the values asserted for name, or nil.
func (id *Identity) Claim(name string) []string {
	if id == nil || id.Claims == nil {
		return nil
	}
	return id.Claims[name]
}

// HasClaim reports whether name was asserted with value, compared
// case-insensitively — provider group and org names are not case-sensitive in
// practice, and a config that differs only in case is a typo rather than a
// different group.
func (id *Identity) HasClaim(name, value string) bool {
	for _, v := range id.Claim(name) {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

// AddClaim appends value to the named claim, allocating the map if needed. It is
// a convenience for provider implementations building an Identity.
func (id *Identity) AddClaim(name string, values ...string) {
	if len(values) == 0 {
		return
	}
	if id.Claims == nil {
		id.Claims = make(map[string][]string, 2)
	}
	id.Claims[name] = append(id.Claims[name], values...)
}

// ClaimNames returns the asserted claim names in sorted order, for log lines and
// error messages that need to say what the identity actually carried.
func (id *Identity) ClaimNames() []string {
	if id == nil || len(id.Claims) == 0 {
		return nil
	}
	names := make([]string, 0, len(id.Claims))
	for name := range id.Claims {
		names = append(names, name)
	}
	// Sorted so a log line or test expectation is stable across map iterations.
	sort.Strings(names)
	return names
}

// Sentinel errors from PollDeviceAuthorization. These are the RFC 8628 §3.5
// token-endpoint outcomes; an implementation must map its provider's wire errors
// onto them, because the broker's poll loop branches on them to decide between
// retrying, backing off, and failing the login.

// ErrAuthorizationPending means the user has not finished authorizing yet. The
// caller should wait PollingInterval and poll again.
var ErrAuthorizationPending = fmt.Errorf("authorization_pending")

// ErrSlowDown means the caller is polling too fast and must add five seconds to
// its interval.
var ErrSlowDown = fmt.Errorf("slow_down")

// ErrExpiredToken means the device code is no longer redeemable; the flow has to
// be started again.
var ErrExpiredToken = fmt.Errorf("expired_token")

// ErrAccessDenied means the user actively declined at the provider. Terminal,
// and a decision rather than a failure.
var ErrAccessDenied = fmt.Errorf("access_denied")

// ErrAccessForbidden means the identity authenticated but does not satisfy the
// provider-level access controls in the config (org, team, allowlist).
// GetIdentity failures wrapping it are denials; anything else is an outage.
var ErrAccessForbidden = fmt.Errorf("access denied")
