# Container integration harness

`go test ./...` covers the broker's half of the two-phase protocol. It cannot
cover the other half: `oauth2_pam.so` is a Linux-PAM module, and the only honest
way to test it is to put it in a real PAM stack and log in.

This harness does that. Two containers, one per side:

| Container | What is real | What it does |
|---|---|---|
| `client` | `sshd`, `oauth2_pam.so`, `/etc/pam.d/sshd` | receives `ssh alice@127.0.0.1`, runs the module |
| `broker` | `oauth2-pam-broker` | serves the Unix socket the module connects to |

plus `fakegithub`, a stand-in for github.com. It is the *only* fake: the login
goes through a real ssh client, a real sshd, a real PAM conversation, the real
module, a real Unix socket, and the real broker.

```
ssh ──▶ sshd ──▶ pam_sm_authenticate ──socket──▶ broker ──https──▶ fakegithub
        └── client container ───────┘            └── broker container ──┘
```

## Running it

```sh
make test-integration                       # build, run every case, tear down
KEEP=1 test/integration/run-tests.sh        # leave the stack up afterwards
test/integration/run-tests.sh denied_by_github mapped_user_mismatch
```

Docker with the compose plugin is the only requirement. No GitHub OAuth app, no
credentials, no network access, and nobody has to approve anything on a phone.

The same `docker-compose.yml` runs unchanged on a Linux EC2 instance if the
containers ever need checking against a non-Docker kernel — that is the whole
difference, so it is not worth paying for by default.

## Whether `never_authorized` can fail

```sh
make test-integration-mutations              # a few minutes; CI runs it as its own job
```

The harness's most valuable assertion is a negative one — a device flow nobody
approved is not a login — and a negative assertion is exactly the kind that can
rot into passing for the wrong reason. `mutations.sh` reintroduces the v0.1.x
bypass (`status: pending` → `PAM_SUCCESS`, before the prompt) in a copy of the
tree under `$TMPDIR`, rebuilds the module, and requires `never_authorized` and
`denied_by_github` to **fail**:

```
==> running the harness with the bypass in place: never_authorized denied_by_github
    FAIL  never_authorized
    FAIL  denied_by_github
caught — the harness refuses the login the v0.1.x module would have granted
```

It insists on seeing those per-case verdicts, so a stack that failed to build is
reported as inconclusive rather than counted as the bypass being caught. There is
no baseline run: `make test-integration` is the baseline and CI runs it anyway.
Do not run it while a healthy stack is up — they share the `oauth2-pam-harness-*`
image tags. `test/cbridge/mutations.sh` does the same job for the six C bridge
defects.

## The cases

| Case | Asserts |
|---|---|
| `authorized_after_prompt` | approval *while the module is blocked on the prompt* logs alice in; the prompt carried the user code and verification URL |
| `never_authorized` | a started-but-unapproved flow is refused at the deadline — **the regression gate for the 0.1.x authentication bypass** |
| `denied_by_github` | a denial fails promptly rather than waiting out the deadline |
| `mapped_user_mismatch` | GitHub says alice, the request is for bob: refused |
| `mapped_user_match` | bob logs in when the mapping yields bob, so the case above fails for the right reason |
| `system_account_name_refused` | a mapping to `postgres` is refused by the system-account denylist, even though that account is above the UID floor and perfectly usable |
| `below_uid_floor_refused` | a mapping to `pgsvc` (UID 400) is refused by `mapper.min_uid` alone; it is on no denylist |
| `named_provider` | `provider=fakegithub` on the `pam.d` line reaches the broker and is accepted, behaving exactly like omitting it |
| `unknown_provider_refused` | `provider=nope` is refused immediately, with no prompt and no device flow started, rather than falling back to the default |
| `broker_down` | an unreachable broker fails closed, immediately, and sshd survives |

## How a login is driven without a human

The module delivers its instructions as a `PAM_PROMPT_ECHO_OFF` prompt and blocks
on the reply. `SSH_ASKPASS=/opt/tests/askpass.sh` with
`SSH_ASKPASS_REQUIRE=force` makes the ssh client hand that prompt to a script
instead of a terminal. `askpass.sh` logs the prompt (so a case can assert what
reached the user), optionally approves at the fake GitHub, and replies with an
empty line — the equivalent of pressing Enter.

Approving from inside `askpass.sh` matters: it happens strictly after the prompt
appears, so a passing `authorized_after_prompt` cannot be explained by the broker
having been told in advance.

## Fake GitHub control API

Plain HTTP on `fakegithub:8080`, so a case needs nothing but `curl`:

| Endpoint | Effect |
|---|---|
| `/control/authorize` | the next token poll returns an access token |
| `/control/deny` | the next token poll returns `access_denied` |
| `/control/expire` | the next token poll returns `expired_token` |
| `/control/login?login=X` | `/api/v3/user` reports login `X` |
| `/control/reset` | back to pending, login `alice`, counters zeroed |
| `/control/state` | JSON: `outcome`, `login`, `org`, `polls`, `revoked` |

The GitHub API surface itself is HTTPS on `fakegithub:8443` with a self-signed
certificate generated at image-build time and installed into the trust store —
the broker refuses a plain-`http` `github.base_url`, and pointing it at a stub
uses the same `base_url` setting that targets a GitHub Enterprise Server.

`polls` is what separates "waited and was told to keep waiting" from "the flow
never started", which is why `never_authorized` checks it.

## Notes

- The client's PAM stack contains **only** `oauth2_pam.so` — no
  `@include common-auth`. A fallback to `pam_unix` would let a case pass for the
  wrong reason. Every test account has `*` as its password hash for the same
  reason.
- The test accounts are created **in both containers, with the same UIDs**. The
  mapper's UID floor asks the broker host's passwd database what a mapped name
  resolves to; in production the broker and the login share a host by
  construction, but the harness splits them, so without the duplicate accounts
  the floor would silently never apply and `below_uid_floor_refused` would pass
  for the wrong reason.
- `Dockerfile.client` fails the build if the compiled `.so` is missing any
  `pam_sm_*` entry point. That defect shipped in 0.1.1 and is silent at build
  time.
- `timeout=20 poll_interval=1` in `/etc/pam.d/sshd` keeps `never_authorized`
  down to about twenty seconds; production defaults are 90 and 5.
- The two `provider=` cases rewrite the `oauth2_pam.so` line in
  `/etc/pam.d/sshd` and restore it before asserting. `sshd` re-reads that file
  for every session, so nothing needs restarting.
