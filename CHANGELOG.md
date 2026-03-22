# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-22

### Added

- GitHub OAuth2 Device Authorization Grant (RFC 8628) flow via `pam_oauth2.so`
- Broker daemon (`pam-oauth2-broker`) — Unix socket IPC server that manages
  device flows, session state, token storage (AES-GCM encrypted in-memory),
  and audit logging
- Three-tier identity mapper chain: Tier 0 (enrollment file), Tier 1 (YAML
  config rules with Go template support), Tier 2 (external script, JSON
  stdin/stdout), Tier 3 (HTTP identity service)
- Self-enrollment CLI (`pam-oauth2-enroll`) — links a local Unix user to a
  GitHub identity by completing a Device Flow; result persisted to
  `/etc/pam-oauth2/enrolled-users.yaml` with atomic write and `flock`
- Admin CLI (`pam-oauth2-admin`) — `status`, `test-auth`, `list-sessions`,
  `revoke-session`, and `test-mapping` commands
- GitHub provider: fetches user profile, org membership, and team membership
  concurrently after device authorization; enforces `require_org`,
  `require_teams`, and `allow_users` access controls
- Structured JSON audit logging with file, stdout, and syslog output sinks
- systemd service unit with `ProtectSystem=strict` hardening
- Example configuration (`configs/example.yaml`) documenting all options

[0.1.0]: https://github.com/scttfrdmn/pam-oauth2/releases/tag/v0.1.0
