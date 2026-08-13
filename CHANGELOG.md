# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-13

Authentication did not work in 0.1.x, and the way it failed was unsafe. Two
defects compounded, and this release fixes both. **Upgrade before putting
`oauth2_pam.so` into a working PAM stack.**

### Security

- **Fixed an authentication bypass.** `Broker.Authenticate` reported a
  *started* device flow as `Success: true` (with `RequiresDevice: true`), and
  the C module checked `success` first and returned `PAM_SUCCESS` — before the
  user had visited GitHub at all. With the README's recommended
  `auth sufficient oauth2_pam.so`, that was an unauthenticated login as any
  username the client asked for. Starting a device flow is now
  `Success: false, Status: pending`, and the module treats anything other than
  `authorized` as a failure. `internal/ipc/e2e_test.go` pins this.

  The bypass was not reachable in a shipped build, because of the next item —
  PAM could not load the module at all. It became reachable the moment the
  build was fixed, so the two are fixed together.
- **The mapped `local_user` is now enforced against the requested login name.**
  It was computed, audited, and discarded. An identity that maps to `alice`
  can no longer authorize a login as `bob`: the broker denies it server-side
  (authoritative, so an old client cannot skip the check) and the module
  re-checks `user_id` before returning `PAM_SUCCESS`.
- **`github.allow_users` on its own no longer admits everyone.** With an
  allowlist and no `require_org`/`require_teams`, a non-matching login fell
  through every check to `return nil`, so the allowlist was inert and any
  authenticated GitHub account satisfied provider policy.
- **`audit.events` is now a real allowlist**, and unknown names in it are a
  startup error. The default list previously named `authentication_failure`,
  which the broker never emits, and omitted `authentication_denied` and
  `device_flow_failed` — so activating the filter as it stood would have
  dropped exactly the denial records an operator needs.
- The GitHub HTTP client pins redirects to the configured hostnames instead of
  matching a `*.github.com` suffix.

### Added

- Explicit session state machine: `pending`, `authorized`, `denied`,
  `expired`, `error`, carried through the IPC `status` field. The invariant
  `Success == true` iff `Status == authorized` is documented at the constants
  and asserted by a test.
- Terminal statuses persist for a short grace period, so a polling client
  learns *why* a login failed instead of watching the session vanish.
- `github.Endpoints` and `NewWithEndpoints` — point the adapter at a GitHub
  Enterprise Server installation, or at a fake GitHub in tests.
- `auth.NewBrokerWithProviders` for injecting pre-built providers.
- PAM module arguments `poll_interval=N` (1–60, default 5) and `timeout=N`
  (10–900, default 300).
- A test suite, where there was none: unit tests across every package plus an
  end-to-end test that drives a real broker behind a real IPC server over a
  real Unix socket with only GitHub faked.

### Fixed

- **`oauth2_pam.so` was built with no `pam_sm_*` entry points at all.** Every
  entry point lived in `pkg/pam/cgo_bridge.c`, and nothing imported `pkg/pam`,
  so cgo never compiled it — PAM would refuse to load the result. The C bridge
  now lives in `cmd/pam-module/` where it is actually built, and `make build`
  is verified with `nm -D --defined-only`.
- The module now completes the protocol: it displays the device instructions
  and polls `check_session` until a terminal status. Previously the
  `requires_device` branch was unreachable, so the QR code and instructions
  were never shown and `check_session` was never sent.
- Abandoned device flows no longer count toward `max_concurrent_sessions`.
  Three failed logins used to lock a user out until their sessions expired.
  Pending flows are separately bounded per user (oldest evicted).
- Six config fields were parsed and then ignored. `server.read_timeout` and
  `server.write_timeout` now replace the hardcoded 30s IPC deadlines,
  `security.max_token_age` is validated against `token_lifetime`,
  `security.rate_limiting.max_concurrent_auths` caps pending device flows, and
  `audit.events` filters. `server.audit_log` is removed — it never did
  anything and `audit.outputs[].path` supersedes it.
- A missing config file now says so, instead of falling through to an
  unreachable environment-variable path that could never satisfy `Validate`.
- `go build ./...` works on macOS again, so the project can be developed
  outside Linux.
- Instruction text no longer tells the user authorization "completes
  automatically" while the module waits on an Enter keypress.
- `configs/example.yaml` validates. Its `http_endpoint` used `http://`, which
  `Validate` rejects, so the documented starting point was one the broker
  refused to start from. A test now loads it.
- `RuntimeDirectoryMode` in the systemd unit is `0750`, matching the `0750`
  directory and `0660` socket the broker creates.

### Changed

- **Breaking (IPC):** responses carry a `status` field, and `success` is no
  longer set for a pending device flow. Clients must switch on `status`.
  `oauth2-pam-admin` does.
- **Breaking:** `pkg/pam` is deleted. Its Go wrapper was dead code, and its
  `IsSocketPathValid` accepted 107-byte paths where the C caps at 103.
- Removed `TokenManager.getToken` (unused) and the stale `test-integration`
  Makefile target, which ran a `test/integration/` directory that has never
  existed.
- README documents the real two-phase flow, the mapped-user rule, the module
  arguments, `KbdInteractiveAuthentication`, and a Limitations section.

### Known limitations

- Supplementary `groups` from the mapper are still not applied to the session
  (#12); a provider interface (#13) and non-cleartext `client_secret` loading
  (#14) remain open.
- A full `sshd` login against real GitHub is not covered by the test suite.
  The broker half of the two-phase protocol is tested end to end; the C client
  half is verified by review and by compiling in a Linux container.

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

[0.2.0]: https://github.com/scttfrdmn/oauth2-pam/releases/tag/v0.2.0
[0.1.1]: https://github.com/scttfrdmn/oauth2-pam/releases/tag/v0.1.1
[0.1.0]: https://github.com/scttfrdmn/oauth2-pam/releases/tag/v0.1.0
