# Security Policy

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| 0.2.x | yes | |
| 0.1.x | **no** | Contains an authentication bypass. Do not deploy. |

v0.1.0 and v0.1.1 shipped a PAM module that returned `PAM_SUCCESS` as soon as a
device flow started, before anyone had approved anything. With the `auth
sufficient` line those releases documented, that is an unauthenticated login as
any requested username. The same releases also built the module without any
`pam_sm_*` entry points, so PAM could not load it — the bypass was unreachable in
practice, by accident rather than by design. Both are fixed in v0.2.0. If you are
running v0.1.x, upgrade; do not treat the missing entry points as mitigation.

## Reporting a vulnerability

**Do not open a public issue.** Use
[GitHub Security Advisories](https://github.com/scttfrdmn/oauth2-pam/security/advisories/new),
which keeps the report private until there is a fix to release.

Useful to include, roughly in order of how much they help:

- what an attacker gains, and what they need to start with (local account?
  network access to the broker socket? a GitHub account in the org?)
- the smallest sequence of steps that demonstrates it
- the affected versions, and the config that reproduces it — the PAM stanza and
  the broker YAML with secrets removed
- what `authpriv` logged, if the module was running with `debug`

You will get an acknowledgement within 3 days and an assessment within 7. Fixes
for anything that grants unauthorized access are released as soon as they are
tested, not on a schedule. You will be credited in the advisory unless you would
rather not be.

## Operational warnings

**Keep a second way in.** A PAM misconfiguration locks you out of your own host,
and this module depends on a running broker, a reachable GitHub, and a user with
their phone. Before changing `/etc/pam.d/sshd`, open a second root session and
leave it open, and keep a key-based or console path available.

**`auth sufficient` is a decision, not a default.** With `sufficient`, this
module succeeding ends the auth phase — so any bug in it is the whole
authentication decision. `required` alongside another factor is the conservative
arrangement.

**The config file holds the client secret in cleartext.** Keep
`/etc/oauth2-pam/broker.yaml` `0600` and root-owned. See
[#14](https://github.com/scttfrdmn/oauth2-pam/issues/14).

**Anything that can reach the broker socket can start device flows.** The socket
is `0660` in a `0750` directory for that reason. Do not widen it to debug a
problem.

## What is verified, and what is not

This is pre-1.0 software with no third-party audit. Concretely, as of v0.2.0:

- The broker half of the protocol is covered end to end by
  `internal/ipc/e2e_test.go`, against a fake GitHub, including the assertion
  that a started device flow is not an authentication.
- The client half — `oauth2_pam.so` inside a real PAM stack, driven by real
  `sshd` over a real ssh connection — is covered by the container harness in
  `test/integration/`. That suite was mutation-verified: reintroducing the v0.1.x
  bypass in the C makes it fail.
- **A login against real github.com has never been verified by the test suite.**
  Everything above fakes the provider.
- Tokens are held encrypted in memory (AES-256-GCM) and never written to disk,
  when `secure_token_storage` is on and a key is set. They remain in process
  memory in plaintext form transiently, and are not protected against an
  attacker who can read the broker's memory or its core dumps.

## Security scanning

CodeQL, gosec, govulncheck, dependency review, and OpenSSF Scorecard run on every
push and pull request, plus weekly — see `.github/workflows/security.yml`. The
`nm` entry-point check in `make build` and in the container harness build is not a
scanner but belongs in the same list: it is what stops a release shipping a
module PAM cannot load.
