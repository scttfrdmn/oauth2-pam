# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The client secret can be kept out of the config file.** Each provider's
  secret now comes from one of three sources, highest precedence first:
  `$OAUTH2_PAM_CLIENT_SECRET_<PROVIDER>`, the new `client_secret_file` (an
  absolute path, or a bare [systemd credential](https://systemd.io/CREDENTIALS/)
  name resolved under `$CREDENTIALS_DIRECTORY`, which is the recommended form and
  is what `LoadCredential=` in the shipped unit sets up), or `client_secret`
  inline as before. Setting both `client_secret` and `client_secret_file` is a
  startup error rather than a precedence puzzle, and an environment variable that
  is set but empty is an error too — a container that meant to pass a secret and
  passed nothing should fail loudly rather than fall back to whatever the image's
  config contains. The broker logs which source each provider's secret came from,
  never the secret. The container harness now feeds the broker through
  `client_secret_file`, so the file path is covered end to end.
  ([#14](https://github.com/scttfrdmn/oauth2-pam/issues/14))

- **A provider interface, and a provider-neutral identity.** `pkg/provider`
  defines what the broker needs from an OAuth2 provider (`Provider`) and the
  types that flow out of one (`Identity`, `Token`, `DeviceFlow`, the RFC 8628
  sentinel errors). The broker, the mapper, the session, and the audit trail now
  work only in those terms; `pkg/provider/github` is one implementation behind
  the interface, and `pkg/provider/registry` maps `providers[].type` to it, so a
  new provider means an implementation plus one line in the registry. A second,
  non-GitHub implementation in `pkg/auth`'s tests drives a full login end to end,
  which is what makes the abstraction more than a rename.

  Memberships are carried as named multi-valued **claims** rather than
  provider-specific fields, so a mapper rule can match a provider the mapper has
  never heard of. GitHub asserts `org` and `team`; an OIDC provider would assert
  `group`. Mapper rules gained `login` and `claims:` as the neutral spelling of
  `github_login` / `github_org` / `github_team`, all of which keep working
  unchanged, and the Tier 2/3 payload gained `type`, `subject`, and `claims`
  alongside the existing `orgs` and `teams`.
  ([#13](https://github.com/scttfrdmn/oauth2-pam/issues/13))

- **Per-request provider selection.** With several providers configured, an
  `authenticate` request may name one (`provider` in the IPC request, `provider=`
  on the `pam.d` line, `--provider` for `oauth2-pam-enroll`). Omitting it selects
  the first configured provider, so an older PAM module that never sends the field
  keeps working. A name that is not configured is refused with `NO_PROVIDER`
  rather than falling back to the default: a client that asked for one identity
  source and silently got another would be authenticated against something nobody
  chose. ([#13](https://github.com/scttfrdmn/oauth2-pam/issues/13))

- **Security scanning in CI** (`.github/workflows/security.yml`): CodeQL with
  `security-extended`, gosec with SARIF upload, govulncheck, dependency review on
  pull requests, and OpenSSF Scorecard, plus a weekly schedule. CodeQL installs
  the PAM headers so the Go half of `cmd/pam-module` is actually analyzed rather
  than silently skipped; the bridge's C is not analyzed by any scanner, because
  CodeQL runs with `languages: go`. `SECURITY.md` has the table of what runs when
  and what blocks a merge. ([#18](https://github.com/scttfrdmn/oauth2-pam/issues/18))
- **A release workflow** (`.github/workflows/release.yml`) and
  `scripts/release.sh`. Tags build amd64 and arm64 on native runners and publish
  `.tar.gz` + `.sha256` archives containing the module, the three binaries,
  `configs/`, and an installer. Three gates run before anything is published: the
  tag must agree with the README version badge and the CHANGELOG, the whole of
  `ci.yml` must pass on the tagged commit (called as a reusable workflow, so it
  cannot drift from what a pull request runs), and the built `.so` must export all
  six `pam_sm_*` entry points.
  ([#19](https://github.com/scttfrdmn/oauth2-pam/issues/19))
- `SECURITY.md`, issue and pull-request templates, and `CODEOWNERS`. The security
  policy records what is verified and what is not — including that no login
  against real github.com has ever been exercised by the test suite.
  ([#21](https://github.com/scttfrdmn/oauth2-pam/issues/21))
- `.github/dependabot.yml` for Go modules, actions, and the harness base images.
  ([#20](https://github.com/scttfrdmn/oauth2-pam/issues/20))
- `make verify-linux`: the full vet/test/lint sweep in a container, so the cgo
  packages are covered from a Mac instead of only in CI.
  ([#25](https://github.com/scttfrdmn/oauth2-pam/issues/25))
- `oauth2-pam-admin gen-key` generates a `token_encryption_key`, and the new
  `pkg/security/keys` package holds the key rules — generation, validation and
  decoding — in one place that both `config.Validate` and cipher construction
  call. Nothing previously shipped a way to produce a valid key, which is how
  memorable passphrases end up in a 256-bit slot. `token_encryption_key` now also
  accepts the base64 form `gen-key` prints (44 characters); 16, 24, or 32 raw
  characters still work. `scripts/install-release.sh` generates a key when it
  writes a fresh config. ([#24](https://github.com/scttfrdmn/oauth2-pam/issues/24))
- `peerUID` implementations for darwin and freebsd, plus a stub for everything
  else, so the broker's rate limiter no longer attributes every unidentifiable
  peer to UID 0 — root's real UID. Unknown peers now share a sentinel bucket that
  cannot collide with a real UID, and the broker logs whether peer credentials are
  available at all. ([#23](https://github.com/scttfrdmn/oauth2-pam/issues/23))

- **A UID floor and a system-account denylist on every mapper tier.** Nothing —
  not a rule, not an external script, not an HTTP identity service — can now
  resolve an identity to root, to a system account by name (`www-data`,
  `postgres`, `nobody`, `systemd-*`, anything starting with `_`, …), or to an
  account below `mapper.min_uid` (new, default 1000, the UID_MIN of every
  mainstream distribution; a negative value disables the floor).

  There was no such check before, and the shipped example maps
  `local_user: "{{ .Login }}"` gated only on org membership — so any member of the
  org who renamed themselves after a service account logged in as it. Trivial on a
  GitHub Enterprise Server; a matter of getting there first on github.com.

  UID 0 is refused unconditionally: not by name, by UID, and neither
  `mapper.min_uid` nor the new `mapper.allow_system_users` exemption list can
  permit it. A device flow has no cryptographic binding to the SSH connection it
  authorises, and OpenSSH's own default (`PermitRootLogin prohibit-password`)
  already rules this out.

  The floor and the denylist cover for each other: the floor is authoritative but
  needs the account to resolve, and a broker built without cgo reads only
  `/etc/passwd`, so on an LDAP/SSSD host only the denylist applies. An account
  that does not resolve at all is allowed past the floor with a warning rather
  than refused, because it cannot become a login anyway — sshd resolves the
  account itself before it starts a session — and refusing would break every
  NSS-backed site.

- Tier 2 and Tier 3 answers are now checked against the Unix-username rules that
  Tier 0 and Tier 1 already applied; previously they were only checked for
  emptiness, so a script doing the obvious `jq -r .login` handed back whatever the
  provider identity claimed. A refused answer also ends the login rather than
  falling through to the next tier: a tier that says "this identity is www-data"
  has answered, and asking the next one for something more convenient would turn a
  refusal into a retry.

- **C unit tests for the PAM module bridge** (`test/cbridge`, `make
  test-cbridge`), compiled with `-Werror -Wall -Wextra -Wconversion`. `go test`
  cannot see this code — it is C, and on macOS `cmd/pam-module` is not compiled at
  all — and the container harness, which does drive it, cannot make the broker
  misbehave in a specific way. These provoke the boundaries directly over a
  `socketpair`: a reply exactly the size of the read buffer, a reply one byte
  over, a broker that accepts a connection and then goes silent, a broker that
  hangs up mid-request, and the exact fields the `authenticate` request puts on
  the wire. Every case was verified to fail against the unfixed code. A skipped
  case counts as a failure, so the one test that needs root cannot quietly stop
  running in CI.

- **Mutation checks on both C test suites, as CI jobs**
  (`make test-cbridge-mutations`, `make test-integration-mutations`). A green suite
  proves the code does what the tests say; it does not prove the tests would notice
  if it stopped, and a regression test that cannot fail is worse than none because
  it reads as protection. `test/cbridge/mutations.sh` reintroduces each of the six
  fixed bridge defects in a copy of the tree and requires the C unit tests to fail;
  `test/integration/mutations.sh` rebuilds the module with the v0.1.x
  authentication bypass in place and requires the container harness to refuse the
  login. Both report an unmatched pattern or a failed build as inconclusive rather
  than counting it as a pass, and neither touches the working tree. `SECURITY.md`
  previously described the harness as mutation-verified with nothing in the
  repository to back it; this is what that sentence now points at.

### Fixed

Four defects found by a security review that reproduced each one against a
running broker rather than reasoning about the code. Every one now has a
regression test in `pkg/auth/broker_limits_test.go` or
`internal/ipc/server_test.go`.

- **Polling one login could deny logins host-wide.** `check_session` polls were
  charged to the calling UID's rate-limit bucket, and every PAM caller is sshd
  running as root — so all logins on the host shared one window. Measured: with
  the limit at 4/minute, the fourth poll of a *single* login came back
  `RATE_LIMITED` and killed it; at the shipped default of 60, about five
  concurrent logins throttled each other and roughly 60 ssh connections in a
  minute denied interactive login for everyone. Polls are now bucketed per
  session (120/minute, twice what the lowest permitted `poll_interval` needs) and
  only `authenticate` is charged per caller. The accept path no longer
  rate-limits at all: concurrency is bounded by a 64-slot semaphore, so excess
  connections wait in the kernel's listen backlog and are served rather than
  refused. `RATE_LIMITED` is also now documented as a *retryable* wire
  condition — a client that treats it as terminal fails a login that is merely
  being asked to slow down.

- **`max_concurrent_auths` was unreachable from a single account.** The global cap
  was consulted after per-user eviction, and eviction holds one username's
  pending count at three — so the global count never climbed. Measured: a cap of
  10 accepted 30 requests, and the broker's goroutine count went from 7 to 40.
  The cap is now checked first.

- **An expired session could come back as authorized.** The poll loop wrote a
  whole snapshot of the session back on completion, which overwrote whatever had
  happened in the meantime. Measured: `check_session` at t+4s returned `expired`,
  and at t+10s the same session returned `authorized` — a live 8-hour session
  holding a real provider token, attached to no login. Activation is now a
  compare-and-set under one lock that refuses unless the entry is still the same
  pending session, and a terminal status is never rewritten: the answer a client
  has already been given is final.

  Evicted, revoked, and failed flows now also cancel their polling goroutine.
  Previously an evicted flow kept polling the provider until the device code
  expired — up to 15 minutes of untracked traffic against the app's rate limit,
  invisible to the pending-flow cap because the session was already gone.

- **`authenticate` with an empty `user_id` authenticated somebody.** The
  "mapped local user equals the requested one" guard was skipped when the
  requested user was empty, so the session activated as whatever the identity
  mapped to. Measured: `user_id: ""` returned `authorized` with
  `user_id: "alice"`. The comparison is now unconditional in the broker, and the
  IPC layer refuses the request outright — either alone would have been a single
  point of failure.

- **The device-flow poll loop measured its deadline with the wall clock.** An NTP
  or `hwclock` step could extend a login window past `timeout=` or abandon a user
  mid-approval — most likely on a freshly booted host, which is exactly where the
  first ssh login happens. It now uses `CLOCK_MONOTONIC`. The loop also slept with
  `sleep()`, which returns early on any signal and discards the remainder, so a
  `SIGWINCH` from a terminal resize shortened the interval and polled GitHub
  faster than configured; it now finishes the interval with `nanosleep`.
  ([#22](https://github.com/scttfrdmn/oauth2-pam/issues/22))

Six more in the C bridge, each with a regression test in `test/cbridge`:

- **A wedged broker hung the login instead of failing it.** The module's socket had
  no deadline of its own, so a broker that accepted the connection and then never
  answered — deadlocked, or stopped between `accept()` and `write()` — left the
  module blocked in `recv()` indefinitely. `timeout=` could not help: it is only
  consulted between polls. The login hung until sshd's `LoginGraceTime` killed the
  whole session. Every connection now carries `SO_RCVTIMEO`/`SO_SNDTIMEO`: 35s for
  the `authenticate` round trip, which waits on the broker's provider call (whose
  own HTTP timeout is 30s), and 10s for a `check_session` poll, which never leaves
  the host. `SO_SNDTIMEO` also bounds `connect()`, so a full listen backlog no
  longer blocks forever either.

- **A broker restart mid-login killed the ssh connection.** `send()` was called
  without `MSG_NOSIGNAL`, so writing to a socket whose peer had closed raised
  SIGPIPE — and its default disposition terminates the process, which here is
  sshd's pre-auth child. The connection dropped instead of the module failing. A
  PAM module cannot fix this with a signal handler; the disposition belongs to the
  host application. Suppressing it per call is the only correct scope. `send_json`
  also now loops on a short write rather than reporting failure while leaving the
  broker parsing a truncated request.

- **A complete response exactly 16383 bytes long was rejected as too large.** The
  read loop stopped when the buffer was full, which was indistinguishable from
  "there is more to come". The buffer is now one byte larger than the largest
  response accepted, and the ambiguous case is resolved by asking: one more read
  distinguishes a clean close from a truncated response. Anything genuinely
  oversized is still refused rather than truncated — a truncated JSON object is not
  a parse error, it is a document that might still parse into something with a
  plausible `status` field.

- **`socket=/run/oauth2-pam/broker.sock` was refused as unsafe.** Only the
  `/var/run` spelling was accepted, though `/var/run` is a symlink to `/run` on
  every systemd host and `/run/oauth2-pam` is exactly what `RuntimeDirectory=` in
  the shipped unit creates. Both prefixes are now accepted; the trailing slash in
  each is what still keeps a path under an attacker-created
  `/run/oauth2-pam-evil/` out.

- **The audit trail recorded the wrong host and no source at all.** The module sent
  `PAM_RHOST` as `target_host` and never sent `source_ip`, so every record named
  the *client* as the host being logged into and left blank the one field an
  investigator reads to answer "where did this login come from". `source_ip` now
  carries the client address and `target_host` this host's name. `source_ip` takes
  `PAM_RHOST` only when it parses as an IP literal — with `UseDNS yes` it is a
  name, and a fully qualified one can exceed the 45 bytes the broker allows, which
  would make it reject the whole request and fail the login — so the unabridged
  value always travels in `metadata.rhost` as well. Relatedly, an absent
  `PAM_RHOST` is now reported as empty rather than as `localhost`: a console login
  has no remote host, and substituting one put a fabricated origin in the record.
  **Anything parsing these audit fields needs updating.**

- **A throttled poll failed the login.** `RATE_LIMITED` arrives as
  `status: "error"`, and the module never read `error_code`, so the broker asking
  it to slow down was indistinguishable from the broker being broken — the exact
  case `internal/ipc.ErrorCodeRateLimited` documents as retryable. A rate-limited
  `check_session` now backs off geometrically (capped at 60s) and keeps polling
  until the login's own deadline, without spending the transport-failure budget:
  three tries at the normal interval would be over in fifteen seconds, well inside
  the limiter's one-minute window, and the login would have died for a condition
  that clears on its own. At `authenticate` time neither `RATE_LIMITED` nor
  `AUTH_LIMIT_REACHED` is retried — the window is a fixed minute and the
  concurrency cap is held by other logins for as long as their flows live, so a
  retry would just spend the user's remaining time to fail again — but both are now
  logged as the capacity conditions they are rather than as a broker error.

And four more in the broker's own defaults:

- **Access tokens were held in plaintext under the shipped configuration.**
  `secure_token_storage` defaults to true, but encryption was skipped unless a
  `token_encryption_key` was also set — and nothing shipped one, including
  `configs/example.yaml`. So an administrator who followed the example got exactly
  what the setting promised to prevent: live GitHub credentials in a root process's
  heap, readable from a core dump or a swapped page. With no key configured the
  broker now generates one from `crypto/rand` for the life of the process. A key
  that dies with the process costs nothing here, because tokens never outlive it
  either — there is no ciphertext left to decrypt. It is not as good as a
  configured key (the key sits in the same heap as the ciphertext), and it is
  vastly better than plaintext. `secure_token_storage: false` is now the only way
  to get plaintext, and it logs a warning.

- **A misspelled audit output type silently redirected the audit trail.**
  `newAuditOutput` fell through to stdout for anything it did not recognise, so
  `type: fille` produced a broker that started cleanly and wrote its records to
  the journal instead of the file that was configured — discovered, at the
  earliest, during an incident. `audit.outputs[].type` is now validated against
  `stdout`, `file`, and `syslog`, `path` is required for `file` and rejected on the
  others, and `facility`/`severity` are rejected on anything but `syslog`. A field
  set on the wrong sink is an error rather than something ignored.

- **Org and team membership was truncated at 30 entries.** `/user/orgs` and
  `/user/teams` were fetched without `per_page` and without following the `Link`
  cursor, so only GitHub's first default-sized page arrived. `require_org` and
  `require_team` are checked against that list, so a member of a large
  organisation — anyone on more than 30 teams — could be denied a login they were
  entitled to. Both endpoints now request 100 per page and follow `rel="next"` to
  the end, bounded at 20 pages. A cursor pointing at a different host is refused:
  it arrives in a server-controlled header, the next request carries the user's
  access token, and `CheckRedirect` does not see it because a `Link` header is not
  a redirect.

- **The broker unit had write access to its own configuration.**
  `ReadWritePaths=/etc/oauth2-pam` let a root process that parses
  network-sourced identity data rewrite `broker.yaml` and the enrollment file that
  decides which provider login becomes which Unix user. The broker only reads
  both; `oauth2-pam-enroll` is what writes the enrollment file, and it is run by
  an administrator, not by this unit. Removed, leaving `ProtectSystem=strict` to
  keep `/etc` read-only.

### Changed

- **`audit.outputs[].type: syslog` now writes to syslog.** It used to hand the
  record to the broker's own logger with the configured facility attached as a
  JSON field, which under systemd meant the journal and elsewhere meant wherever
  stderr pointed — not what `type: syslog` with `facility: auth` says, and not
  routed by facility at all. It now opens the local syslog socket at startup, so a
  host with no syslog daemon fails to start rather than quietly logging elsewhere.
  `facility` accepts `auth`, `authpriv`, `daemon`, `user`, and `local0`–`local7`;
  `severity` accepts the eight RFC 5424 names; the default is `auth.info`, beside
  sshd's own records. Note that a syslog daemon may truncate a long line, so keep
  the `file` sink where records must be complete.

- **An unknown key in `broker.yaml` is now a startup error.** The config was
  decoded leniently, so a key with no matching field was discarded in silence —
  which is how `server.audit_log` and `audit.outputs[].url` came to look like
  working settings, and how a misspelled `secure_token_storge: false` would leave
  tokens in plaintext without a word. The error names the offending key. Anything
  removed in 0.2.0 or 0.3.0 and still present in a config file now has to come
  out, which is the point: those keys have not done anything for a release
  already.

- **`audit.outputs[].url` and `.headers` are gone.** Both were parsed and never
  read — there has never been a webhook sink — so a config that appeared to post
  audit records to a SIEM was accepted and wrote to stdout instead. With strict
  decoding above, they are now refused by name rather than ignored, which is the
  only version of this that tells an operator the truth. Anything relying on them
  was already not working.

- **`authentication.device_flow_timeout` (new, default `3m`)** bounds how long the
  broker waits for a user to approve a device flow. Previously the bound was the
  provider's own device-code lifetime — 15 minutes at github.com — so an
  abandoned ssh attempt held one of `max_concurrent_auths` slots and a polling
  goroutine for a quarter of an hour. Set it to `0` to restore the old behaviour.
  It must stay *above* the module's `timeout=`, or the broker gives up while the
  user is still being told to wait.

- **The PAM module's `timeout=` default drops from 300s to 90s.** sshd's
  `LoginGraceTime` is 120s by default and disconnects first, so a 300s deadline
  could never elapse: the module's timeout branch was unreachable and a user who
  ran out of time saw an abrupt disconnect rather than a message. The README now
  documents all three deadlines and which order they have to be in.

- **The rate-limiting defaults are raised: `max_requests_per_minute` 60 → 300 and
  `max_concurrent_auths` 10 → 50.** Both are host-wide backstops against a
  runaway client, not per-user limits — every PAM caller is sshd as root, so there
  is no per-user signal to limit on. Sized tightly they do not slow an attacker
  down, they deny logins. `configs/example.yaml` now says so where the settings
  are, and points at sshd's `MaxStartups` as the control that actually bounds
  concurrent pre-auth connections.

- **`server.socket_path` is no longer removed recursively at startup.** It was
  `os.RemoveAll`, running as root, on an operator-supplied path — with the shipped
  unit granting `ReadWritePaths=/etc/oauth2-pam`, a typo in that setting destroyed
  a directory tree on the next restart. Startup now refuses to replace anything
  that is not a socket.

- **`configs/example.yaml` no longer ships a rule granting `sudo`.** It had
  `groups: [users, sudo]` on the org-admins rule, commented "Org admins get
  sudo" — while `groups` is not applied to the login at all
  ([#12](https://github.com/scttfrdmn/oauth2-pam/issues/12)). It promised
  privilege it did not grant, and would have granted it the day the field starts
  working. Both the example and the README now say plainly that `groups` grants
  nothing today, and the example explains what
  `local_user: "{{ .Login }}"` delegates before showing it.

- **`revoke_session` replies carry a `status` (`"revoked"`)** like every other
  reply. It was the sole exception, so a client applying the documented "granted
  only when `success` is true *and* `status` is `authorized`" rule had to
  special-case a missing field.

- **Enrollment records name the provider they were created against**, and the
  login is now spelled `login` rather than `github_login`. On a host with two
  providers, an account with the same login at the one a user did *not* enroll
  with can no longer claim their enrollment. Existing files keep working: the
  legacy `github_login` key is accepted on read and migrated on the next write,
  and a record with no `provider` matches any provider — which is what such a
  record has always meant and what a single-provider host wants. Re-enroll
  (`--remove`, then enroll) to scope those records. A file setting both `login`
  and `github_login` to different values is refused rather than guessed at.
  ([#13](https://github.com/scttfrdmn/oauth2-pam/issues/13))
- The `provider_login` key replaces `github_login` in session metadata and in the
  audit event for a successful login, and the success event now also records the
  provider's stable `provider_subject` (GitHub's numeric user ID) alongside the
  full `claims` map — a login can be renamed, a subject cannot, so an audit trail
  keyed on the login can be made to point at the wrong account.
  ([#13](https://github.com/scttfrdmn/oauth2-pam/issues/13))
- The poll loop now recognizes the RFC 8628 sentinel errors with `errors.Is`
  rather than equality, so a provider implementation may wrap them with context.
  Previously a wrapped `authorization_pending` would have failed a login that was
  merely still waiting for the user.
  ([#13](https://github.com/scttfrdmn/oauth2-pam/issues/13))
- **A file holding a client secret must not be readable by other users, and the
  broker refuses to start otherwise.** This applies to `client_secret_file` and,
  when the secret is inline, to `broker.yaml` itself: no group or other permission
  bits, owned by root or by the broker's own uid. The error names the file and the
  `chmod 600` / `chown root` that fixes it. **This is a breaking change for anyone
  running with a world-readable config that carries an inline `client_secret`** —
  which was the documented setup before this release, so it is a likely upgrade
  step. `scripts/install-release.sh` and `make install-dev` install the config
  `0600` root-owned (and no longer overwrite one that already exists);
  the reasoning is that a secret in a world-readable file is a secret every local
  user on the host already has, and a 0600 file owned by *another* user is a secret
  that user can replace — which would let them choose the OAuth app the broker
  authenticates against. ([#14](https://github.com/scttfrdmn/oauth2-pam/issues/14))
- Two providers may no longer share a `name`. The name identifies a provider in
  the audit log and in the environment variable that can carry its secret, so a
  duplicate is ambiguous in both places.
  ([#14](https://github.com/scttfrdmn/oauth2-pam/issues/14))
- GitHub Actions are pinned to full commit SHAs rather than floating tags.
  ([#20](https://github.com/scttfrdmn/oauth2-pam/issues/20))
- **A tag now runs the whole test suite before anything is published.**
  `release.yml` calls `ci.yml` as a reusable workflow — Linux build/vet/`test -race`,
  macOS build, lint, the C bridge tests, both mutation checks, and the container
  harness — between the version check and the build. Previously the only gates were
  the version agreement and the `nm` entry-point check, so a tag pushed from a
  commit that never passed CI would publish.
- **The documented assurances now match what CI does.** Corrected: `SECURITY.md`
  called the container harness mutation-verified with no script in the repository
  (now there is one, and it runs in CI); it listed five scanners as running "on
  every push and pull request" when dependency review is pull-requests-only,
  Scorecard skips pull requests, gosec is `continue-on-error` and advisory, and a
  push to a topic branch runs nothing at all — there is now a table of what runs
  when and what blocks a merge; and the claim that installing PAM headers makes
  CodeQL analyze `cmd/pam-module` is narrowed to the Go half of it, because
  `languages: go` puts none of the bridge's C in a CodeQL database. `CONTRIBUTING.md`
  said "CI runs all of it on every push and pull request" with the same
  topic-branch inaccuracy. None of these changed what the CI does; they were
  descriptions of a stronger position than the project held.
- Audit events that record an access decision — `authentication_success`,
  `authentication_failed`, `authentication_denied`, `session_revoked` — are
  written synchronously instead of queued, so a crash or a full queue cannot
  discard the record of who was let in. The high-volume `authentication_attempt`
  is still buffered. ([#24](https://github.com/scttfrdmn/oauth2-pam/issues/24))
- Key and token plaintext copies are zeroized once they are no longer needed, and
  `Encryption.Destroy` drops the cipher. Both are documented as narrowing a window
  rather than erasing a secret — Go offers no way to do the latter.
  ([#24](https://github.com/scttfrdmn/oauth2-pam/issues/24))
- **The minimum Go version is now 1.25** (from 1.24). Go backports security fixes
  to the two newest majors only, so 1.24 is end-of-life: with `go 1.24.0` in
  go.mod, CI's `GOTOOLCHAIN=local` build used a toolchain with 33 standard-library
  advisories reachable from this code, and no 1.24.x pin could ever clear them.
  govulncheck reports zero under 1.25. The pin is the language version rather than
  a patch release, so any 1.25.x toolchain satisfies it.

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
- `providers[].github.base_url` — the config route to a GitHub Enterprise Server
  installation. Endpoints are derived from it (REST API at `/api/v3`) and it must
  be HTTPS, since both the client secret and the access token travel there.
- `auth.NewBrokerWithProviders` for injecting pre-built providers.
- PAM module arguments `poll_interval=N` (1–60, default 5) and `timeout=N`
  (10–900, default 300).
- A test suite, where there was none: unit tests across every package plus an
  end-to-end test that drives a real broker behind a real IPC server over a
  real Unix socket with only GitHub faked.
- A container integration harness (`make test-integration`) covering the half of
  the protocol Go tests cannot reach. Two containers — one running `sshd` with
  `oauth2_pam.so` in `/etc/pam.d/sshd`, one running the broker — with logins
  driven over a real ssh connection and only GitHub faked. Six cases, including
  the two that matter most: an unapproved device flow must be refused at the
  deadline, and a mapping that does not match the requested account must be
  refused. Needs Docker and nothing else. Verified by mutation: reintroducing the
  0.1.x "pending means success" logic makes the first of those cases fail.

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
- Removed `TokenManager.getToken` (unused). The `test-integration` Makefile
  target used to run a `test/integration/` directory that had never existed; it
  now runs the container harness that lives there.
- README documents the real two-phase flow, the mapped-user rule, the module
  arguments, `KbdInteractiveAuthentication`, and a Limitations section.

### Known limitations

- Supplementary `groups` from the mapper are still not applied to the session
  (#12); a provider interface (#13) and non-cleartext `client_secret` loading
  (#14) remain open.
- A login against *real* GitHub is not covered by the test suite. Both halves of
  the protocol are now exercised end to end — the broker by `internal/ipc`, the
  module by a real `sshd` in the container harness — but github.com itself is
  faked in both, so an incompatibility with GitHub's live device-flow behaviour
  would not be caught.

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
