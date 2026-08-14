# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

A third adversarial review round, on a tree that had already survived two. It found
27 things, which is the argument for keeping the rounds going rather than declaring
the code reviewed: three of them were fail-**open** reads of the field that decides a
login, and none of the three were reachable by the previous rounds' methods.

**Upgrade notes.** `broker.yaml` must be mode 0600 regardless of where the client
secret lives — the check used to apply only when the secret was inline, which left
the file holding the token-encryption key unchecked in every deployment that did the
right thing with its secret. A deployment relying on the old behaviour will refuse to
start until it is chmodded; the error names the file and the command. A negative
`mapper.min_uid` is also now rejected rather than silently disabling the UID floor.

### Fixed

- **`"success":"false"` read as true in the C module.** `json_object_get_boolean`
  coerces: any non-empty string and any non-zero number is true. So the one field the
  module consults to decide whether a login succeeded accepted a *string* `"false"`
  as a grant. The field is now type-checked against `json_type_boolean` strictly, and
  anything else is a parse failure rather than a value. The careful version of this
  read was already sitting four lines below it, on `poll_interval` — which is the
  useful lesson: the same file got it right where the stakes were lower.
  ([#60](https://github.com/scttfrdmn/oauth2-pam/issues/60))

- **A per-syscall receive timeout is not a per-message one.** `SO_RCVTIMEO` bounds
  each `recv()`, so a broker drip-feeding one byte at a time reset the clock on every
  byte and could hold a login open far past the deadline the module believed it had
  set. The budget is now read off the socket once and decremented across the whole
  transfer, so it bounds the message.
  ([#57](https://github.com/scttfrdmn/oauth2-pam/issues/57))

- **The device-flow poll had no deadline.** It ran on a cancel-only context, so
  nothing but the client hanging up ended it.
  ([#55](https://github.com/scttfrdmn/oauth2-pam/issues/55))

- **An expired session could still be activated.** The compare-and-swap that
  activates a session tested its status and creation time but never `ExpiresAt` — so
  it succeeded on an already-expired session, and the mutation that followed rewrote
  the expiry into the future. Expiry is now part of the CAS.
  ([#55](https://github.com/scttfrdmn/oauth2-pam/issues/55))

- **The concurrent-session cap could be overshot by any number of simultaneous
  logins.** Sessions were counted under a read lock, the lock released, and the new
  session inserted afterwards — so N calls arriving together all read the same count
  and all inserted. Counting and insertion now happen under one write lock, via a
  placeholder reservation.
  ([#59](https://github.com/scttfrdmn/oauth2-pam/issues/59))

- **A deadline-aborted provider call was retried as transient.**
  `context.DeadlineExceeded` satisfies `net.Error`, so the classifier that decides
  what is worth retrying could not tell "the network is flaky" from "we ran out of
  time", and retried the second as if it were the first.
  ([#79](https://github.com/scttfrdmn/oauth2-pam/issues/79))

- **The QR code was on the wire twice, and a long provider URL overflowed the
  client's buffer.** The art was serialized inside `instructions` and again in
  `qr_code`, which made the real github.com baseline 4.9 KB rather than the "2–3 KiB"
  this project had documented — and a 300-byte `verification_uri` reached 17.6 KB,
  past the module's 16 KiB `MAX_RESPONSE_SIZE`, where `strncpy` truncates in silence
  and the client is left with an object it cannot parse. The art is now serialized
  once, the URL it is drawn from is bounded at 200 bytes, and the broker holds itself
  to the same 16 KiB cap it expects of a client, substituting `RESPONSE_TOO_LARGE`
  rather than writing a reply that cannot be read. Worth recording that the size
  ceiling depends on the *encoder's mode*: an uppercase-and-digits URL gets
  alphanumeric mode with a much larger capacity, so a 3 KB URL still encodes, and a
  byte-mode-only reading of the limits understates the dangerous band by a kilobyte.
  ([#56](https://github.com/scttfrdmn/oauth2-pam/issues/56))

- **Checking a path is not checking the bytes read from it.** Secret loading did
  `os.Stat` and then `os.ReadFile` — two resolutions of the same name, with a window
  between them. It now opens with `O_NOFOLLOW` and stats the *file descriptor*, so the
  permissions checked belong to the bytes returned.
  ([#58](https://github.com/scttfrdmn/oauth2-pam/issues/58))

- **A file-mode check is defeated by a writable directory.** Anyone who can write the
  containing directory can rename a compliant file out and a hostile one in, whatever
  the mode on the original. The directory is now checked too, with the sticky-bit case
  exempted and the reason stated where the exemption is made.
  ([#58](https://github.com/scttfrdmn/oauth2-pam/issues/58))

- **Two of three secret sources skipped the config-file permission check.** Only the
  inline branch checked `broker.yaml` itself, so a deployment that moved its client
  secret into a file or the environment — the recommended practice — lost the check on
  the file that still holds the token-encryption key. It is now unconditional.
  ([#58](https://github.com/scttfrdmn/oauth2-pam/issues/58))

- **An empty GitHub `login` was a wildcard.** An enrollment lookup for `""` matched,
  which is the wrong answer to a malformed API response. Refused in `Store.Find`,
  `Store.Add`, the mapper, the enroll CLI, and — the place the empty value actually
  enters the system — the GitHub adapter's `getUser`.
  ([#80](https://github.com/scttfrdmn/oauth2-pam/issues/80))

- **A failed audit write on the grant path now fails the login.** There is exactly one
  place in the broker where a session becomes usable for a login, and the
  `authentication_success` record written there was discarding its error — so a full
  disk produced an authenticated session with no trail of it, which is the outcome an
  audit log exists to prevent. That site now uses `LogAuthEventErr` and, if the write
  fails, withdraws the activation it had just made: the token is revoked, the session
  is marked terminally errored, and the polling client is told the login failed. The
  five sites recording a denial, a failure or an attempt deliberately still discard —
  a lost refusal record is a gap in the trail, not an unlogged access — and each now
  says so in a comment, because the distinction is the whole point.
  ([#69](https://github.com/scttfrdmn/oauth2-pam/issues/69))

- **`session_revoked` claimed success for a user it could not name.** Revoking a
  *pending* session emitted `Success: true` with an empty `UserID`, which reads as
  "someone's session was revoked successfully" with nothing to correlate it to. A
  pending session has no authenticated user, so the record now says that: success is
  false, the reason states no local user was ever established, the status that was
  revoked and the account the client *asked* for are in metadata — the latter in
  metadata rather than `UserID` precisely because the client chose it and the broker
  never confirmed it. An authorized session still records the real user.
  ([#69](https://github.com/scttfrdmn/oauth2-pam/issues/69))

- **The two capacity refusals disagreed about what they were.** `SESSION_LIMIT_REACHED`
  arrived as `status: "denied"` and `AUTH_LIMIT_REACHED` as `status: "error"`, and the
  specification supported both readings. They are now both `error`. A capacity refusal
  is a statement about the broker's load, not a judgement about the identity: the user
  was not denied, the broker declined to try. This is not cosmetic — the C module maps
  `denied` to `PAM_AUTH_ERR` and `error` to `PAM_AUTHINFO_UNAVAIL`, so under the old
  behaviour a host that was merely full told PAM the credentials were bad.
  ([#84](https://github.com/scttfrdmn/oauth2-pam/issues/84))

- **The `audit.events` allowlist filtered before the critical-event check.** The
  events that exist specifically to be undroppable were dropped by any allowlist that
  did not happen to name them. The critical check now runs first.
  ([#69](https://github.com/scttfrdmn/oauth2-pam/issues/69))

- **`CheckRedirect` compared only the hostname**, while the pagination code in the
  same package pinned scheme, host and port. Both now pin `scheme://hostname`, so a
  redirect cannot downgrade the transport.
  ([#63](https://github.com/scttfrdmn/oauth2-pam/issues/63))

- **Nothing bounded a provider's pagination.** `per_page` is a request, not a
  guarantee, and no code checked that a server honoured it — so 20 pages inside a 1 MB
  per-response limit was hundreds of thousands of retained org and team entries. The
  bound is now on entries, not pages.
  ([#62](https://github.com/scttfrdmn/oauth2-pam/issues/62))

- **`user_agent` and `device_id` were unbounded and unvalidated,** and `metadata` was
  checked for NUL bytes and nothing else. Every request field now goes through one
  table with an explicit limit, so adding a field without bounding it takes a
  deliberate omission rather than an oversight.
  ([#67](https://github.com/scttfrdmn/oauth2-pam/issues/67))

- **An over-cap request body was reported as "unexpected EOF",** which tells a client
  its serialization is broken when the actual problem is size — and a client told that
  will not go looking at how much it sent.
  ([#67](https://github.com/scttfrdmn/oauth2-pam/issues/67))

- **A git tag interpolated into a `run:` block is shell injection.** Release workflow
  steps built commands with `${{ steps.vars.outputs.* }}` derived from the pushed tag;
  those values now arrive via `env:` and are quoted.
  ([#70](https://github.com/scttfrdmn/oauth2-pam/issues/70))

- **The installer passed the generated token-encryption key in argv,** where
  `/proc/<pid>/cmdline` is world-readable for the life of the process — so every local
  account could read the key of a broker being installed. It is now fed to
  `sed -i -f -` over a pipe.
  ([#77](https://github.com/scttfrdmn/oauth2-pam/issues/77))

- **The symbol check in the installer matched a substring,** so it could report
  entry points present that were not, and it silently skipped itself when `nm` was
  absent. One shared `scripts/verify-pam-symbols.sh` now does it per symbol, and four
  divergent copies of that loop are gone.
  ([#76](https://github.com/scttfrdmn/oauth2-pam/issues/76))

- **The admin client reported a pending device flow as a successful test.** `TestAuth`
  switched on the wrong field; it now requires the `check_session` result to have
  actually succeeded, and it sends and checks `protocol_version` like every other
  client of this contract.
  ([#83](https://github.com/scttfrdmn/oauth2-pam/issues/83))

- **The integration harness could not start the broker after the permission fix.**
  Its `broker.yaml` was `COPY`ed and landed 0644, so all 11 cases failed at "the
  broker never created its socket". Found by running the harness against the collapsed
  tree — no single remediation branch could have seen it. The fix is a `chmod` in
  `Dockerfile.broker`, which is exactly what an operator now has to do, and that is
  the point of having a harness.

### Changed

- **The PAM module is plain C. The Go runtime is no longer loaded into `sshd`.** It was
  built with `go build -buildmode=c-shared`, which links the entire Go runtime into
  every process that loads the module — and the runtime installs its own signal
  handlers over the ones its host process had already set, so the thing being
  reconfigured was `sshd`'s signal handling. The module has no Go logic to justify any
  of that: all of its behaviour was already in `cgo_bridge_linux.c`, and the two Go
  files were a shim to make cgo compile it. They are deleted, the module is built by a
  direct `cc -shared -fPIC` invocation, and the shipped object went from **1.2 MB to
  73 KB**. Verified same-host, before and after: every mitigation is intact
  (`BIND_NOW`, `GNU_RELRO`, `__stack_chk_fail` and the `_chk` fortify symbols), all six
  `pam_sm_*` entry points are exported, and there are now zero Go runtime symbols in
  the object. Two dynamic flags did change and neither is a lost mitigation — `SYMBOLIC`
  had nothing left to do once everything but the entry points is `static`, and
  `NODELETE` existed only because the Go runtime cannot be unloaded, so losing it means
  PAM can `dlclose` the module again, which is correct.
  ([#65](https://github.com/scttfrdmn/oauth2-pam/issues/65))

- **CodeQL analyses the C.** It could not before: the bridge was compiled by cgo, and
  the scanner ran with `languages: go`, so the most security-sensitive code in the
  repository was the only code no scanner read. The plain `cc` line made a `c-cpp`
  database possible, and there is now one with a real build command. Note the two
  earlier changelog entries describing CodeQL as covering "the Go half of
  `cmd/pam-module`" are left as written — they were accurate for the releases they
  describe, and there is no Go half any more.
  ([#38](https://github.com/scttfrdmn/oauth2-pam/issues/38))

- **The C module is compiled with hardening flags**: stack protector, RELRO with
  `BIND_NOW`, and `_FORTIFY_SOURCE=2`. Level 2 rather than 3 deliberately — 3 needs
  gcc 12 with glibc 2.35, and on older enterprise distributions `features.h` emits a
  `#warning` that `-Werror` turns into a failed build. `-fcf-protection` is omitted
  for the same class of reason: it is x86-only and breaks the aarch64 build. Verified
  empirically on both architectures: `readelf` reports `SYMBOLIC BIND_NOW`, a
  `GNU_RELRO` segment and `__stack_chk_fail` after the change, and neither RELRO nor
  any `_chk` symbol before it.
  ([#64](https://github.com/scttfrdmn/oauth2-pam/issues/64))

- **`Token.Fingerprint` is a real fingerprint** — `hex(sha256(token)[:16])` — rather
  than an elided slice of the token itself. A prefix of a credential in a log is a
  prefix of a credential.
  ([#82](https://github.com/scttfrdmn/oauth2-pam/issues/82))

- **A zoned IPv6 literal is handled rather than rejected.** `fe80::1%eth0` fits the
  field's 45-byte bound and is the one address shape a well-meaning validator breaks,
  because `inet_pton` and `net.ParseIP` both fail on the zone. The zone is now split
  off and validated separately.
  ([#61](https://github.com/scttfrdmn/oauth2-pam/issues/61))

- **`log-level` and `audit.format` were parsed and ignored.** `log-level` is now
  honoured and validated against the levels that exist; `audit.format` is deleted
  rather than kept as a field that does nothing. `server.*_timeout` is capped at five
  minutes, since a longer one cannot help a login that lives inside sshd's
  `LoginGraceTime`.
  ([#72](https://github.com/scttfrdmn/oauth2-pam/issues/72),
  [#73](https://github.com/scttfrdmn/oauth2-pam/issues/73))

- **The UID floor can no longer be switched off.** A negative `mapper.min_uid` used to
  disable it, documented as a feature. It is now a startup error, and the floor check
  itself is unconditional rather than guarded on the value being non-negative — the
  guard was the actual mechanism, and rejecting the config while leaving the guard in
  place would have fixed only the paths that load config from a file. A `Config` built
  in code with a negative value clamps to the default, with a warning.
  ([#81](https://github.com/scttfrdmn/oauth2-pam/issues/81))

- **`error_message` no longer carries provider-chosen text to the client.** Provider
  strings reaching a prompt that root draws before authentication is the defect class
  this project already fixed once; the same rule now applies to the error field.
  ([#74](https://github.com/scttfrdmn/oauth2-pam/issues/74))

- **The specification's claim that an over-size request is "refused before it is
  decoded" was corrected rather than implemented.** No implementation of this framing
  can honour it, and none did: a request is a bare JSON object with no length prefix,
  so nothing announces its size in advance and a receiver learns a body is too long
  only by reaching the cap while reading it. What the cap guarantees is the
  allocation, not the ordering — and version 1 now says which of the two failed,
  because a body truncated at the cap looks to a parser like malformed input.
  ([#67](https://github.com/scttfrdmn/oauth2-pam/issues/67))

### Added

- **`pam_sm_acct_mgmt` does something.** It returned `PAM_SUCCESS` unconditionally, so
  a session revoked after login, an enrollment deleted, or an org membership lost was
  not caught at the account stage — the stage that exists to ask "is this account still
  allowed?". It now sends `check_session` and maps the answer: authorized *and* naming
  the same user → success; any terminal status, including `SESSION_NOT_FOUND` → denied,
  because "I have no record of this session" must not be a pass; a transport failure or
  an unparseable reply → `PAM_AUTHINFO_UNAVAIL`. With **no** stored session it answers
  `PAM_IGNORE`, not success: the module is being asked about a login it did not
  authenticate, and approving an account it knows nothing about is fail-open in exactly
  the stacked configuration a real deployment is most likely to have.

  The session id reaches the account stage through `pam_set_data`, stored only after the
  username check passes. That handoff cannot be unit-tested — `pam_set_data` refuses to
  run outside a service module — so the integration harness's account stage is now the
  real module rather than `pam_permit.so`, which makes every passing login there proof
  that the handoff works, and a new case covers the no-session path. The
  `PAM_IGNORE` → `PAM_SUCCESS` mutation is checked by the harness, since nothing in the
  C suite could catch it.
  ([#75](https://github.com/scttfrdmn/oauth2-pam/issues/75))

- **The QR code renders again.** Removing the duplicated art from `instructions` (see
  #56 above) left the module rendering the one field the art was no longer in, so for a
  short window on `main` no QR appeared at a login prompt at all. The module now reads
  the `qr_code` field, bounding what it copies like every other field it parses, and an
  absent or over-long one renders cleanly as no QR rather than as an empty caption.
  ([#56](https://github.com/scttfrdmn/oauth2-pam/issues/56))

- **`AuditLogger.LogAuthEventErr`**, so a path that is about to grant access can fail
  the login when the audit record cannot be written. An unlogged successful
  authentication is the outcome an audit log exists to prevent.
  ([#69](https://github.com/scttfrdmn/oauth2-pam/issues/69))

- **A mutation-tested C suite.** `test/cbridge` went from 147 checks and 8 transport
  and audit-field mutations to **226 checks and 25 mutations, all caught**. The one
  worth naming is `authorized_for` → `return 1`, which makes the module accept any user
  the broker authorized for anyone else — and which was green in every suite this
  project had before this round. A mutation check only covers what its tests actually
  call, which is why the count matters less than what the new ones reach. A hung run is
  now a failure rather than a hang.
  ([#57](https://github.com/scttfrdmn/oauth2-pam/issues/57))

- **`make verify-linux` compiles the C again.** It never invoked a compiler directly —
  it relied on `go build ./...` pulling the bridge in through cgo. With the module no
  longer a Go package, a Go-only sweep would have gone green without touching the C at
  all, which is the failure mode where a verification target stops verifying and
  nothing announces it. The target now builds the module and runs the C suite
  explicitly.

## [0.3.0] - 2026-08-14

0.2.0 made authentication work. This release is about being able to trust it:
repeated adversarial review, of the design and of the security of the
implementation, and the findings each round produced — plus the contract the whole
thing rests on, written down.

The protocol between broker and module is now a **specified, versioned contract**
that this repository owns ([`docs/wire-protocol.md`](docs/wire-protocol.md),
version 1), with `protocol_version` on the wire in both directions and a
conformance checklist whose every item is something an implementation in this
family has actually got wrong. Two of the defects fixed here were exploitable as
shipped, and they need different things from an attacker. `refresh_session`
extended sessions that had already expired and answered `authorized` — reachable
only by something that can reach the broker socket, which in this project's
packaging means root, a boundary this release also stops merely implying and starts
stating. The other needs no local access at all: the provider chose the strings a
root process drew on a terminal before anyone had authenticated, so a compromised
GitHub Enterprise deployment could draw a fake password prompt on every host
configured against it.

**Upgrade notes.** An unknown key in `broker.yaml` is now a startup error rather
than a silently ignored line, so a config with a typo that used to "work" will
refuse to start — deliberately, because six fields in 0.2.0 were parsed and
ignored. `audit.outputs[].url` and `.headers` are gone. The documented PAM stack
changes to `auth required` after the distribution's own module, the module's
`timeout=` default drops from 300s to 90s to fit inside sshd's `LoginGraceTime`,
and the minimum Go version is 1.25.

### Added

- **Version 1 says what an absent `source_ip` means, and that a zoned IPv6
  literal must be accepted.** Both were silences, and both cost a sister project a
  real bug: a broker enforcing "private networks only" read `net.ParseIP("")` as
  "not private" and refused *every* login on the host, reporting an unknown origin
  as a public one. The spec now states that an absent value is `unknown`, a third
  answer, and that `unknown` never satisfies a network requirement — while leaving
  the resolution (deny, or an audited waiver) to the broker, since that is policy.
  It also requires a receiver to accept `fe80::1%eth0`: it is inside the 45-byte
  bound the field always had, and it is the one address shape a well-meaning
  validator breaks, because `net.ParseIP` and `inet_pton` both fail on a zone. This
  implementation length-bounds `source_ip` and parses nothing, so it already
  conformed; `TestValidateRequest` now pins that. And `metadata.rhost` may be a
  resolved hostname — which is what makes the address-only rule on `source_ip`
  affordable, and is why nothing may read it for an authorization decision.
  ([#52](https://github.com/scttfrdmn/oauth2-pam/issues/52))
- **`RESPONSE_TOO_LARGE` is a registered `error_code`.** `oidc-pam` sends it, and
  by version 1's own rule an error code a second implementation reads is contract
  rather than local dialect. It is terminal, and it buys a client the difference
  between "the broker sent something I could not parse" and "the broker had
  something to say and it did not fit". Whether a broker is *obliged* to substitute
  it — rather than writing an oversized reply and leaving the client to refuse —
  is deliberately left open; that is a requirement this broker does not yet meet,
  and both the spec and [#48](https://github.com/scttfrdmn/oauth2-pam/issues/48)
  say so rather than implying a guarantee.
- **The wire contract is written down and versioned.**
  [`docs/wire-protocol.md`](docs/wire-protocol.md) specifies the broker↔module
  protocol as a contract rather than as a description of one implementation, and
  every request and reply now carries `protocol_version`. Version 1 is what
  v0.2.0 shipped — the status state machine, access only on `success && status ==
  "authorized"` — so the field is additive and **optional in a request**: absent
  or `0` means 1, and a v0.2.x module keeps working against a v0.3.0 broker. A
  broker refuses a version it does not implement with the new
  `UNSUPPORTED_PROTOCOL` code and does no work; a module refuses a *reply* whose
  version it does not know rather than reading `"authorized"` under a contract it
  does not implement. Every reply carries the version, including the errors
  written before the request is dispatched, so a client that cannot parse a reply
  can still tell what it was talking to.

  The spec covers what the version number is *for*: which changes are additive
  (a new field, a new error code) and which need a new version (a new `status`, a
  changed meaning, a removed field). It also states the two things a client must
  get right and neither field name reveals — that `RATE_LIMITED` means "slow
  down" and what to do about it differs between the poll phase and the
  authenticate phase, and that an unrecognised `status` must fail closed — plus
  the deliberate non-features (no channel binding, no broker authentication, no
  session reuse) with the issues tracking them.

  This exists because this project and its sister
  [oidc-pam](https://github.com/scttfrdmn/oidc-pam) independently shipped the
  same authentication bypass — a `pending` device flow reported as a success —
  and the shared root cause was that neither had written down what `success`
  meant. The C bridge's `PROTOCOL_VERSION`, `internal/ipc.ProtocolVersion`, and
  the spec cross-reference each other, and the version rules are covered from
  both ends: `TestProtocolVersionIsOnEveryReply` and
  `TestUnsupportedProtocolVersionIsRefused` in Go, `test_protocol_version()` in
  the C suite, and two new mutations in `test/cbridge/mutations.sh` — including a
  version check that accepts everything, which is the failure mode that would
  look like nothing was wrong.
  ([#17](https://github.com/scttfrdmn/oauth2-pam/issues/17))

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

- **`refresh_session` extended expired sessions and re-inserted revoked ones.**
  `RefreshSession` had no expiry check at all — `time.Until` of a past instant is
  simply negative, so an expired session fell through to the extend branch and
  came back `success: true`, `status: "authorized"`, with the mapped `user_id` and
  a fresh hour on it. `check_session` has always refused that, so the two verbs
  disagreed and a client could route around its own expiry by choosing which one
  to send. An expired session is now removed and answered `SESSION_EXPIRED`, the
  same as `check_session`.

  The extension also wrote a whole snapshot back into the session map with no
  compare-and-set, so a `revoke_session` or a cleanup pass that deleted the
  session between the read and the write was silently undone — resurrecting a
  session whose token had already been destroyed at the provider, with no poller
  and nothing left to clean it up before its brand-new expiry. Measured: 1 of 200
  unassisted attempts, and `-race` reports nothing, because every access is
  correctly locked and the wrong value is written. Extension now goes through a
  compare-and-set shaped like the one that guards activation: it takes the lock,
  re-reads the live entry, and refuses unless it is still the same authorized
  session. A refresh also re-checks that the session's token still resolves, which
  catches the same fact independently. Both proofs are in-tree —
  `TestRefreshRefusesExpiredAuthorizedSession`,
  `TestExtendSessionRefusesUnlessStillTheSameAuthorizedSession` and
  `TestRefreshDoesNotResurrectRevokedSession` in
  `pkg/auth/refresh_test.go`, plus `TestRefreshRefusesExpiredSessionOnTheWire`
  over a real socket — and each one was checked against the unfixed code.

  No in-tree client sends `refresh_session`: the PAM module sends only
  `authenticate` and `check_session`, so this was not a live privilege escalation.
  It was a latent authorization defect in a verb
  [docs/wire-protocol.md](docs/wire-protocol.md) makes normative for other
  implementations, which is why the spec now states both refusals.
  ([#41](https://github.com/scttfrdmn/oauth2-pam/issues/41))

- **`security.max_token_age` was validated and never enforced.** It was parsed,
  defaulted to 24h, documented in `configs/example.yaml`, and read in exactly one
  place: a startup check that `token_lifetime` does not exceed it. Nothing ever
  compared a session's age against it, so an operator reading it as a hard cap on
  how old a session may get had a lint rule on their config file. Measured with
  the ceiling at 2s: fifty consecutive refreshes all succeeded, and the session's
  `expires_at` ended an hour past a `created_at` that never moved. A session past
  the ceiling is now revoked rather than extended — in the refresh path and in the
  periodic session sweep, since nothing calls `refresh_session` on most sessions
  and a ceiling enforced only there would not be one. Measured from `CreatedAt`,
  which no extension moves; `0` still means unset. The boundary is asserted in
  both directions so the comparison cannot be quietly inverted.
  ([#43](https://github.com/scttfrdmn/oauth2-pam/issues/43))

- **A provider could draw on the pre-authentication terminal.** A device flow's
  `verification_uri` and `user_code` are chosen by the provider, travel over IPC,
  and are printed to the tty by a root process before anyone has authenticated —
  unfiltered. For `github.com` that is theoretical; for a configured Enterprise
  `base_url` it is not, because that server picks what every host configured
  against it draws on screen. A payload of `ESC[2J ESC[H` and a fake `Password:`
  prompt is enough to harvest a Unix password from a user who believes they are
  still talking to `sshd`.

  Provider-supplied strings are now stripped of C0, DEL, C1 (including U+009B,
  where CSI hides in UTF-8) and U+2028/9 as they enter a response, and an altered
  value is marked so the operator can see something was removed rather than
  silently receiving a mangled URL. Stripping rather than escaping is deliberate:
  the module copies `instructions` into a fixed 16 KiB buffer that truncates
  silently, so an escaping filter — up to 6× expansion — would let a provider pad
  the prompt until the trusted trailer fell off the end. `TestSanitizingCannotAmplify`
  pins that. Sanitizing happens at the point the values enter an `AuthResponse`,
  not in the prompt formatters, because `device_url` and `device_code` also go on
  the wire as their own fields that
  [docs/wire-protocol.md](docs/wire-protocol.md) offers to "a client that wants to
  format its own prompt" — cleaning only this implementation's formatters would
  have left a consumer holding raw bytes. Bidi and zero-width characters are
  deliberately not filtered: they cannot move a cursor, and denying them would
  break legitimate non-Latin text.
  ([#45](https://github.com/scttfrdmn/oauth2-pam/issues/45))

- **The session rate limiter grew without bound, and session requests cost an
  unknown caller nothing.** The five-minute eviction sweep cleaned only the
  per-UID limiter — the one whose key space is the host's own UIDs, and therefore
  tiny. The one it missed is keyed on the `session_id` in the request, which a
  caller chooses: `allow` allocates a window on first sight of any key and never
  required the session to exist, so 3000 requests naming 3000 invented sessions
  left 3000 permanent windows, none of them refused, at roughly 14k requests a
  second. The sweep now reaches every limiter, and *introducing* a previously
  unseen session ID is charged to the calling UID — introducing one is the only
  part of a session request whose cost outlives the reply. Polling an established
  session stays free to the caller, which is what keeps the fix for the host-wide
  polling DoS above intact. A key ceiling backstops both.
  ([#42](https://github.com/scttfrdmn/oauth2-pam/issues/42))

### Changed

- **Mapper `groups` stay advisory, and are no longer advisory *quietly*.** The
  broker computes supplementary groups, records them in the session and the audit
  trail, and sends them to the PAM module, which discards them — nothing here
  calls `setgroups(2)`, so `groups: [sudo]` has never granted sudo. That was
  documented and unverified; it is now measured from both ends.
  `internal/ipc/e2e_test.go` asserts the groups reach the wire, and the container
  case `mapped_groups_not_applied` drives a real `ssh` login and asserts `id -Gn`
  in the resulting session does not contain them — with the group present in
  `/etc/group` and the broker's own mapping checked first, so the negative cannot
  pass because the group was missing or was never mapped. `mapper.New` now logs a
  warning at startup naming any groups a rule declares, so a config relying on
  them says so in the log rather than doing nothing in silence. Applying them
  needs a guard against a mapper granting `wheel` or `docker`, which is tracked
  separately. ([#12](https://github.com/scttfrdmn/oauth2-pam/issues/12),
  [#39](https://github.com/scttfrdmn/oauth2-pam/issues/39))

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

- **The documented PAM stack is now `auth required` after the distribution's own
  auth stack, not `auth sufficient` before it.** With `sufficient`, this module
  succeeding ends the auth phase, so any bug in the C, the broker, or the mapper is
  the entire authentication decision — v0.1.x is the worked example, where a
  started device flow returned `PAM_SUCCESS` and that one line turned it into an
  unauthenticated login as any username. The recommended arrangement makes GitHub a
  second factor; for hosts where GitHub really is meant to be the only factor, it
  is still `required` with nothing else in the auth stack, because `sufficient`
  stops the stack being read and a line added below it later silently stops
  running. Also new: a break-glass checklist (an
  authorized key stays usable because sshd runs no PAM auth stack for `publickey`),
  Debian and RHEL forms of the stanza, and why changing RHEL's `substack` to
  `include` silently removes the second factor.

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
- **`oauth2-pam-enroll` refuses a local account the mapper would refuse anyway.**
  Enrollment is tier 0 of the mapping chain and its answer has always passed the
  same gate as every other tier, so a record naming `root` or a system account
  failed closed at login — this was never a bypass. It was a bad error at a bad
  time: the operator learned of it as a denied login rather than as a refusal when
  they typed the name. The check now runs *before* the device flow, so nobody
  authorizes in a browser for a name that cannot work. `pkg/enrollment` cannot
  import `pkg/mapper` (the dependency runs the other way), so the rules are
  injected rather than copied — a copy could drift from the mapper's silently — and
  `Add` takes the validator as a **required** parameter with a named `Unvalidated`
  sentinel, so a future caller has to choose to skip the gate rather than default
  into it. A store that already contains a forbidden record still loads and can
  still be repaired; validating on load would turn one unusable enrollment into an
  unrepairable file. ([#46](https://github.com/scttfrdmn/oauth2-pam/issues/46))
- **The socket's trust boundary is stated instead of implied.** `internal/ipc`
  described a group-based access model — "root-owned, group oauth2-pam", "must run
  as a member of the oauth2-pam group" — that nothing implements: there is no
  `os.Chown` in the repository, no packaging artifact creates the group, and the
  unit runs `User=root`/`Group=root`. Reality was *safer* than the comment, which
  is what made it worth fixing: a reader following the comment would have created
  the group and widened the boundary without the ownership work that model needs.
  The comments, the systemd unit and `docs/wire-protocol.md` now say what is true —
  the broker socket is reachable by root and nobody else, the PAM module qualifies
  because it runs inside `sshd`'s pre-auth child, and several accepted risks in this
  project are accepted *only* because that caller can only be root. Anyone who
  changes that has to re-rate those findings first, and the note says so.
  `TestSocketPermissions` now asserts the containing directory as well as the
  socket. ([#44](https://github.com/scttfrdmn/oauth2-pam/issues/44))
- **Spec correction:** `refresh_session` never exchanged an OAuth2 refresh token,
  and no implementation ever did; earlier revisions of `docs/wire-protocol.md` said
  it did. It moves the broker's own `expires_at`, with no provider round trip.

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
