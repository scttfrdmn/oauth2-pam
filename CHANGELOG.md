# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-03-22

### Security

- **C bridge**: `receive_auth_response` now loops `recv()` until EOF instead of a single
  call, preventing partial-read failures on large device-flow responses (QR code + instructions)
- **C bridge**: `validate_socket_path` rejects paths longer than 103 bytes, preventing silent
  truncation in `strncpy` that could redirect connections to an unintended socket
- **Broker**: GitHub access tokens are now revoked at GitHub before the local session is
  removed; previously revoked sessions left live tokens indefinitely
- **Broker**: `pollDeviceAuthorization` checks session existence immediately before
  `setSession`, preventing a race that could resurrect a session revoked during device flow
- **Broker**: fatal errors in the identity-fetch and mapping retry loops now `return`
  immediately instead of `goto nextPoll`, eliminating a goroutine that survived one extra
  polling tick after session removal
- **Broker**: `getSession` returns a deep copy of Groups and Metadata, preventing
  callers from mutating live session state through the returned snapshot
- **Broker**: server-side session IDs generated with `crypto/rand`; client-supplied
  `session_id` is ignored to prevent session fixation
- **Broker**: per-user concurrent session limit enforced before starting a new device flow
- **IPC server**: `TargetHost` field bounded to 253 bytes (RFC 1035 max); metadata values
  checked for NUL bytes consistent with the existing `user_id` NUL check
- **IPC server**: per-UID sliding-window rate limiter using `SO_PEERCRED` on Linux
- **IPC server**: request body limited to 64 KB via `io.LimitReader` before JSON decode
- **IPC server**: all `Metadata` fields changed from `map[string]interface{}` to
  `map[string]string`, eliminating arbitrarily nested JSON bomb vectors
- **Token manager**: `GetToken` unexported; `GetDecryptedAccessToken` is the only public
  accessor, preventing callers from inadvertently reading encrypted bytes as plaintext
- **Token manager**: `StoredToken.Metadata` migrated to `map[string]string`
- **GitHub provider**: missing OAuth2 scope is now a fatal error instead of a silent warning,
  surfacing the root cause instead of producing a confusing `ErrNoMapping`
- **GitHub provider**: HTTP client now rejects redirects to non-GitHub hosts, preventing SSRF
  via a redirect in a compromised GitHub API response
- **Mapper HTTP client**: redirects disabled entirely (`ErrUseLastResponse`); a malicious
  identity-mapping service could otherwise redirect to internal services (SSRF)
- **Mapper HTTP client**: absolute 5-second timeout added as a defense-in-depth backstop
- **Mapper**: expanded local username validated against POSIX portable username regexp after
  template substitution in both the rules tier and the enrollment tier
- **Config**: `max_concurrent_sessions: 0` now accepted as "unlimited" (was incorrectly
  rejected); `token_encryption_key` length validated (must be 16, 24, or 32 bytes);
  `http_endpoint` required to use HTTPS
- **Enrollment store**: directory created with permissions `0750` instead of `0755`
- **Audit logger**: dropped-event counter incremented atomically with count in warning log

### Changed

- Project renamed from `pam-oauth2` to `oauth2-pam`; module path, binary names, socket
  paths, config paths, and systemd unit updated throughout

## [0.1.0] - 2026-03-22

### Added

- GitHub OAuth2 Device Authorization Grant (RFC 8628) flow via `oauth2_pam.so`
- Broker daemon (`oauth2-pam-broker`) — Unix socket IPC server that manages
  device flows, session state, token storage (AES-GCM encrypted in-memory),
  and audit logging
- Three-tier identity mapper chain: Tier 0 (enrollment file), Tier 1 (YAML
  config rules with Go template support), Tier 2 (external script, JSON
  stdin/stdout), Tier 3 (HTTP identity service)
- Self-enrollment CLI (`oauth2-pam-enroll`) — links a local Unix user to a
  GitHub identity by completing a Device Flow; result persisted to
  `/etc/oauth2-pam/enrolled-users.yaml` with atomic write and `flock`
- Admin CLI (`oauth2-pam-admin`) — `status`, `test-auth`, `list-sessions`,
  `revoke-session`, and `test-mapping` commands
- GitHub provider: fetches user profile, org membership, and team membership
  concurrently after device authorization; enforces `require_org`,
  `require_teams`, and `allow_users` access controls
- Structured JSON audit logging with file, stdout, and syslog output sinks
- systemd service unit with `ProtectSystem=strict` hardening
- Example configuration (`configs/example.yaml`) documenting all options

[0.1.1]: https://github.com/scttfrdmn/oauth2-pam/releases/tag/v0.1.1
[0.1.0]: https://github.com/scttfrdmn/oauth2-pam/releases/tag/v0.1.0
