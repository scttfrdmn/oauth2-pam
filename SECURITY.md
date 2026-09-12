# Security Policy

## Supported versions

The newest minor release, and only that one. There are no maintenance branches and
nothing is backported: a fix lands on `main` and ships in the next release, so
"supported" here means "upgrade to the current release".

| Version | Supported | Notes |
|---|---|---|
| 0.3.x | yes | the current release |
| anything earlier | **no** | No fix is backported. v0.1.x additionally contains an authentication bypass — do not deploy it, see below. |

The row above is rewritten by `scripts/release.sh`, because a hand-maintained
version claim is one that spends a release cycle wrong: v0.3.0 shipped while this
table still said the newest supported version was 0.2.x.

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
leave it open, and keep a key-based or console path available — sshd does not run
the PAM auth stack for `publickey` at all, which makes an authorized key the most
reliable break-glass here. The README's
[Before you edit the PAM stack](README.md#before-you-edit-the-pam-stack) is the
longer version.

**`auth sufficient` is a decision, not a default, and this project no longer
recommends it.** With `sufficient`, this module succeeding *ends* the auth phase,
so any bug in it — in the C, the broker, or the mapper — is the entire
authentication decision. v0.1.x is what that costs. The documented arrangement is
`auth required` after the distribution's own auth stack, making GitHub a second
factor. If GitHub really is meant to be the only factor, it is still `required`,
with nothing else in the auth stack: `sufficient` stops the stack being read on
success, so a line added below it later silently stops running.

**The config file may hold the client secret in cleartext.** Since v0.3.0 it does
not have to: `client_secret_file` takes a systemd credential or a 0600 file. Where
the secret is inline, `/etc/oauth2-pam/broker.yaml` must be `0600` and owned by
root or the broker's uid, and the broker refuses to start otherwise.

**Anything that can reach the broker socket can start device flows.** The socket
is `0660` in a `0750` directory for that reason. Do not widen it to debug a
problem.

## What is verified, and what is not

This is pre-1.0 software with no third-party audit. Concretely, as of v0.3.0:

- The broker half of the protocol is covered end to end by
  `internal/ipc/e2e_test.go`, against a fake GitHub, including the assertion
  that a started device flow is not an authentication.
- The client half — `oauth2_pam.so` inside a real PAM stack, driven by real
  `sshd` over a real ssh connection — is covered by the container harness in
  `test/integration/`.
- **Both suites are mutation-checked in CI, by scripts you can run yourself.**
  `test/integration/mutations.sh` rebuilds the module twice — once with the v0.1.x
  bypass reintroduced, once with the account stage failing open — and requires the
  harness to refuse the login both times; `test/cbridge/mutations.sh` reintroduces
  each of 25 C bridge defects in turn, one per run, and requires the C unit tests
  to fail. Both run in CI on every push to `main` and every pull request — the
  harness one as its own job (`integration-mutations`), the C bridge one as a step
  in the `linux` job, alongside the suite it mutates — so "these tests would catch
  it" is a check rather than a claim.
- **A login against real github.com has never been verified by the test suite.**
  Everything above fakes the provider.
- Tokens are held encrypted in memory (AES-GCM) and never written to disk. The
  cipher is AES-256 for a generated key or a base64 32-byte one, and AES-128 or
  AES-192 if a raw 16- or 24-byte `token_encryption_key` is configured — those
  lengths are accepted for compatibility with 0.1.x configs, and this document said
  256 unconditionally until
  [#109](https://github.com/scttfrdmn/oauth2-pam/issues/109).
  With no `token_encryption_key` configured the broker generates one for the
  process, so the shipped default is encryption rather than plaintext; that key
  lives in the same heap as the ciphertext, so it defends against a core dump or
  a page that reached swap, not against an attacker who can read the broker's
  live memory. `secure_token_storage: false` is the only way to get plaintext.
  Tokens are in plaintext transiently in either case, and the provider and
  `net/http` have already made copies that nothing here can reach.

## Security scanning

`.github/workflows/security.yml`. Not all of it runs on everything, and the
differences matter if you are relying on one of them:

| Tool | When | A finding fails the run? |
|---|---|---|
| CodeQL (`security-extended,security-and-quality`, Go **and** C) | pushes to `main`, every PR, weekly | **no** — alerts go to the Security tab; the job passes |
| govulncheck | pushes to `main`, every PR, weekly | yes |
| gosec | pushes to `main`, every PR, weekly | **no** — `continue-on-error`; findings go to the Security tab for triage |
| Dependency review | pull requests only | yes, at `moderate` |
| OpenSSF Scorecard | pushes to `main`, weekly — not on PRs | no, it is a posture report |

CodeQL analyzes the C as well as the Go: the job is a `go` + `c-cpp` matrix, and
because a C database needs a real compile, the `c-cpp` leg installs the PAM and
json-c headers and runs `make build-pam` under the extractor — the same command CI
and `release.yml` use, so what is analyzed is what ships. On top of that,
`cmd/pam-module/cgo_bridge_linux.c` is covered by `test/cbridge`, compiled
`-Werror -Wall -Wextra -Wconversion` and mutation-checked as described above. This
document said no scanner analyzed the C at all until
[#109](https://github.com/scttfrdmn/oauth2-pam/issues/109).

Three gaps worth stating plainly rather than leaving to be inferred:

- **Only two of those tools can fail a run, and CodeQL is not one of them.** The
  `analyze` step has no `fail-on` and there is no CodeQL config setting a threshold,
  so a new alert appears in the Security tab and the job is green. `govulncheck`
  exits non-zero and `dependency-review` is set to `fail-on-severity: moderate`;
  those two are the ones where "fails the run" is backed by something in the file.
  This table claimed CodeQL failed the run until
  [#109](https://github.com/scttfrdmn/oauth2-pam/issues/109), which is the wrong
  direction for a document whose purpose is saying what is actually checked.
- **A push to a topic branch runs nothing.** Both workflows are `push` on `main`
  plus `pull_request`; the scans reach a branch when it opens a pull request, not
  while it is being pushed to.
- **`main` has no branch protection, so a failing run does not by itself stop a
  merge or a push.** "Fails the run" above means exactly that and no more. The
  place a check is unconditionally binding is a release: `release.yml` runs the
  whole of `ci.yml` on the tagged commit and publishes nothing if it fails.

The `nm` entry-point check is not a scanner but belongs in the same list: it is
what stops a release shipping a module PAM cannot load. It is one script,
`scripts/verify-pam-symbols.sh`, run by `make build`, by the release workflow, and
by the installer in the release archive before it copies anything — per symbol,
and a host without `nm` fails it rather than skipping it.
