# oauth2-pam

[![CI](https://github.com/scttfrdmn/oauth2-pam/actions/workflows/ci.yml/badge.svg)](https://github.com/scttfrdmn/oauth2-pam/actions/workflows/ci.yml)
[![Security](https://github.com/scttfrdmn/oauth2-pam/actions/workflows/security.yml/badge.svg)](https://github.com/scttfrdmn/oauth2-pam/actions/workflows/security.yml)
[![version](https://img.shields.io/badge/version-0.3.0-blue)](https://github.com/scttfrdmn/oauth2-pam/releases)

A Linux PAM module that authenticates users via OAuth2 Device Flow, with GitHub as the primary provider. Users authenticate by visiting a URL on their phone and approving the request — no passwords, no SSH key distribution.

## How it works

```
       ┌─ phase 1: start ──────────────────────────────────────────┐
ssh    │  oauth2_pam.so ──"authenticate"──> broker ──> GitHub      │
user@  │                 <── status=pending, code+URL, session_id  │
host   └───────────────────────────────────────────────────────────┘
       ┌─ shown to the user, who approves on their phone ──────────┐
       │  "Visit github.com/login/device — enter WDJB-MJHT"        │
       │  "Press Enter once you have approved the request:"        │
       └───────────────────────────────────────────────────────────┘
       ┌─ phase 2: poll ───────────────────────────────────────────┐
       │  oauth2_pam.so ──"check_session"──> broker ──> GitHub     │
       │                 <── status=pending  (repeat)              │
       │                 <── status=authorized, user_id            │
       │                     └─ user_id == login name? PAM_SUCCESS │
       └───────────────────────────────────────────────────────────┘
```

1. User runs `ssh alice@host`.
2. The PAM module sends `authenticate` to the broker over a Unix socket.
3. The broker starts a GitHub Device Flow and replies `status: pending` with a user code, a verification URL, an ASCII QR code, and a server-generated `session_id`. **This is not a success** — nothing has been authenticated yet.
4. The module shows the code as a PAM prompt and waits for the user to press Enter. (A prompt, not `PAM_TEXT_INFO`: OpenSSH buffers informational messages and may not flush them until authentication returns, which would show the code only after the login had already failed.)
5. The user approves on their phone or browser.
6. The module polls `check_session` every `poll_interval` seconds until the broker reports a terminal status, or `timeout` seconds elapse.
7. On the first successful poll the broker fetches the GitHub identity, enforces the org/team/allowlist rules, runs the mapper, and checks the mapped `local_user` against the name being logged in as. Only then does it return `status: authorized` with `user_id`.
8. The module verifies `user_id` equals the requested username and returns `PAM_SUCCESS`.

**The mapped `local_user` must equal the login name.** If `alice` on GitHub maps to local user `alice` but the login attempt is for `bob`, the broker denies it — it does not switch the account. This is enforced server-side in the broker, so an old or modified client cannot skip it, and re-checked client-side in the module. Log in as the account you map to.

The comparison is unconditional: an `authenticate` request that names no account at all is refused rather than activated as whatever the identity maps to.

**This project owns the broker↔module protocol**, specified in **[docs/wire-protocol.md](docs/wire-protocol.md)**. Other projects in the family — its sister [oidc-pam](https://github.com/scttfrdmn/oidc-pam) — consume that spec rather than maintaining a parallel copy of it: version numbers are allocated here, the reference implementation lives in the same repository as the document, and a protocol change starts as an issue here. The spec exists because both projects independently shipped the same authentication bypass by never writing down what `success` meant, and two peers with two copies of the contract would only have slowed down the next one.

Every request and reply carries a `protocol_version`, so the next change has somewhere to declare itself. Version 1 is the behaviour v0.2.0 shipped; the field naming it is new in v0.3.0 and is optional in a request, so a v0.2.x module keeps working against a v0.3.0 broker. If you are writing another client or another broker, the spec's **Conformance** section is the checklist.

## Requirements

- Go 1.25+ for the broker and the CLIs (1.24 is end-of-life and no longer receives security backports)
- A C compiler for the PAM module — it is plain C and needs no Go at all
- Linux with PAM (`libpam0g-dev`)
- `libjson-c-dev`
- A GitHub OAuth App with Device Flow enabled

The PAM module is Linux-only. `go build ./...` and the test suite work on macOS for development; `make build-pam` requires Linux.

The module is built by a direct `cc -shared -fPIC` invocation rather than with `go build -buildmode=c-shared`, which is what it used to be. The Go build linked the entire Go runtime into every process that loads the module — including `sshd`, where it also installed the runtime's signal handlers over the ones sshd had set. The module has no Go logic to justify that, so it no longer pays for it: the object went from 1.2 MB to 73 KB, and `sshd` keeps its own signal handling ([#65](https://github.com/scttfrdmn/oauth2-pam/issues/65)).

## Quick Start

### 1. Create a GitHub OAuth App

Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**:
- Application name: `oauth2-pam`
- Homepage URL: `https://github.com/scttfrdmn/oauth2-pam`
- **Enable device flow** (checkbox in the app settings)
- No callback URL needed for Device Flow

Copy the **Client ID** and generate a **Client Secret**.

### 2. Get the software

Either a published release archive — which carries a checksum, an installer, and a
`.so` built on a native runner for its architecture — or a source build.

**From a release archive:**

```bash
VERSION=v0.3.0
ARCH=amd64        # or arm64
BASE=https://github.com/scttfrdmn/oauth2-pam/releases/download/$VERSION
curl -fLO "$BASE/oauth2-pam-$VERSION-linux-$ARCH.tar.gz"
curl -fLO "$BASE/oauth2-pam-$VERSION-linux-$ARCH.tar.gz.sha256"

sha256sum -c "oauth2-pam-$VERSION-linux-$ARCH.tar.gz.sha256"
tar xzf "oauth2-pam-$VERSION-linux-$ARCH.tar.gz"
```

Run the `sha256sum -c` before unpacking, and stop if it fails. What it proves is
that the download arrived intact; it is not a signature, and the checksum comes
from the same place as the tarball, so it says nothing about who built either.
Signing and provenance are [#40](https://github.com/scttfrdmn/oauth2-pam/issues/40).

**From source:**

```bash
git clone https://github.com/scttfrdmn/oauth2-pam
cd oauth2-pam
make build
```

`make build` checks with `nm` that the module it just built exports all six
`pam_sm_*` entry points, and fails if `nm` is not there to ask — v0.1.1 shipped a
module with none of them and nothing noticed for a month.

### 3. Install

**From the unpacked archive:**

```bash
cd "oauth2-pam-$VERSION-linux-$ARCH"
sudo ./install.sh
```

It re-checks the archive's `sha256` if the tarball is still next to the directory,
re-checks the module's entry points, asks the package manager where this
distribution keeps its PAM modules rather than assuming, and writes
`/etc/oauth2-pam/broker.yaml` from the example with a generated
`token_encryption_key`. It does not touch `/etc/pam.d` — that is step 6, and it is
the step that can lock you out.

**From a source build:**

```bash
sudo make install
```

This installs:
- `oauth2_pam.so` into this distribution's PAM module directory, worked out by
  `scripts/pam-module-dir.sh`. It is `/lib64/security` on RHEL and
  `/usr/lib/<triplet>/security` on Debian/Ubuntu multiarch, and a module in the
  wrong one is a module PAM silently never loads. Where `dpkg` exists the script
  asks it (`dpkg -L libpam-modules`, and wherever that says `pam_permit.so` lives
  is where a module goes), which covers the multiarch case that cannot be guessed.
  Everywhere else it falls back to the first of `/lib64/security`,
  `/lib/security`, `/usr/lib64/security`, `/usr/lib/security` that exists — a
  guess, and the right one on the RPM distributions, but a guess. If your host
  keeps them somewhere else, say so: `PAMDIR=/path make install`, which the script
  takes as given and does not second-guess.
- `/usr/local/bin/oauth2-pam-broker`
- `/usr/local/bin/oauth2-pam-admin`
- `/usr/local/bin/oauth2-pam-enroll`
- `/etc/systemd/system/oauth2-pam-broker.service`

Unlike `install.sh`, it does not write a config: that is the next step.

### 4. Configure

The release installer has already done this — skip to editing the file. From a
source build:

```bash
sudo install -d -m 0750 -o root -g root /etc/oauth2-pam
sudo install -m 0600 -o root -g root configs/example.yaml /etc/oauth2-pam/broker.yaml
sudo $EDITOR /etc/oauth2-pam/broker.yaml
```

The directory is created explicitly, and `0750`. The broker checks the mode and owner
of the file that holds the secret **and of the directory around it**, because a
directory another user can write is a config file that user can *replace* — which
would let them choose the OAuth app this host authenticates against. A directory that
is writable by group or other (without the sticky bit) or owned by neither root nor
the broker is a startup error, not a warning. This paragraph said nothing checked the
directory until [#109](https://github.com/scttfrdmn/oauth2-pam/issues/109); the check
has been there since #96, so an operator following the old text got a broker that
refused to start for a reason they had been told was not checked.

Minimal config:

```yaml
providers:
  - name: github
    type: github
    client_id: "Iv1.xxxxxxxxxxxx"
    client_secret: "your-secret"
    github:
      require_org: your-org

mapper:
  rules:
    - match:
        github_org: your-org
      local_user: "{{ .Login }}"
      groups: [users]
```

A key the broker does not recognise is a startup error naming that key, so a typo
fails loudly instead of leaving the default in place. If a config from an earlier
version stops loading, the setting it names was being ignored already.

#### Where the client secret comes from

Three sources, highest precedence first:

| Source | Form |
| --- | --- |
| Environment | `OAUTH2_PAM_CLIENT_SECRET_<PROVIDER>` — the provider name uppercased, with anything outside `A-Z0-9` replaced by `_` |
| File | `client_secret_file:` — an absolute path, or a bare [systemd credential](https://systemd.io/CREDENTIALS/) name resolved under `$CREDENTIALS_DIRECTORY` |
| Config file | `client_secret:` inline, as above |

`broker.yaml` and any file holding the secret must have no group or other
permission bits and be owned by root or by the broker's own uid. The broker
refuses to start otherwise, naming the file and the `chmod`/`chown` that fixes
it: a secret in a world-readable config is a secret every local user on the host
already has, and a 0600 file owned by another user is a secret that user can
*replace*, which would let them choose the OAuth app the broker authenticates
against.

`broker.yaml` is checked in all three cases, not only when it carries an inline
secret. It used to be checked only in that case, so the one permission check the
config file ever got disappeared the moment an operator did the recommended thing
and moved the secret into a credential — while the file went on holding the token
encryption key, the org and team allowlists, and the mapping rules that decide
which provider login becomes which Unix user.

Under systemd the recommended form is a credential, which keeps the secret's
location out of the config entirely:

```ini
# /etc/systemd/system/oauth2-pam-broker.service.d/secret.conf
[Service]
LoadCredential=github-client-secret:/etc/oauth2-pam/github.secret
```

```yaml
providers:
  - name: github
    client_secret_file: github-client-secret   # a name, not a path
```

systemd reads the file as root before the unit's sandboxing applies and stages
it mode 0400 in a tmpfs only this unit can see. Setting `client_secret` and
`client_secret_file` both is a startup error rather than a precedence puzzle,
and an environment variable that is set but empty is an error too — a container
that meant to pass a secret and passed nothing should fail loudly instead of
falling back to whatever the image's config contains.

At startup the broker logs which source each provider's secret came from, never
the secret:

```
{"level":"info","provider":"github","client_secret_from":"file","message":"Provider configured"}
```

The config holds the client secret in cleartext, so keep it `0600` and root-owned.

For GitHub Enterprise Server, add `base_url: https://github.acme.internal` under
`github:`. The device, token, and API endpoints are derived from it (the REST API
at `/api/v3`), and it must be HTTPS — the client secret and the access token both
travel to that host.

### 5. Start the broker

```bash
sudo systemctl enable --now oauth2-pam-broker
```

### 6. Configure PAM (SSH)

**Open a second root session first and leave it open.** Everything in this section can lock you out of the host, and the recovery is a console, not another ssh attempt. Read [Before you edit the PAM stack](#before-you-edit-the-pam-stack) below.

Add the module to `/etc/pam.d/sshd` **after** the distribution's own auth stack, as a *second* factor:

```
# Debian/Ubuntu: common-auth is the password factor
@include common-auth
auth    required  oauth2_pam.so socket=/var/run/oauth2-pam/broker.sock
account required  oauth2_pam.so socket=/var/run/oauth2-pam/broker.sock
```

```
# RHEL/Fedora/Amazon Linux: same idea, one line later
auth       substack     password-auth
auth       required     oauth2_pam.so socket=/var/run/oauth2-pam/broker.sock
account    required     oauth2_pam.so socket=/var/run/oauth2-pam/broker.sock
```

**The `account` line is not optional decoration.** It re-checks the session between the auth stage's approval and the shell, and it is the only thing that catches a session revoked or expired in that window — a race that is narrow but is the one an operator running `oauth2-pam-admin revoke-session` is trying to win. Without the line the module's `pam_sm_acct_mgmt` never runs, and a control that exists and is tested in CI is inert on the host. It is safe to add to any stack: for a login this module did not authenticate — a key-based login, another service — it answers `PAM_IGNORE` and leaves the decision to the rest of the stack, so it cannot approve an account it knows nothing about and cannot deny one either. Note that Linux-PAM turns an account stack of *nothing but* `PAM_IGNORE` into a denial, so if this is the only `account` line, keep a `pam_unix.so`/`@include common-account` alongside it.

The password stack runs first and this module runs second, and the login needs both: a correct password *and* an approved GitHub device authorization. `required` is the whole point of the arrangement: with `sufficient`, this module succeeding *ends* the auth phase, which makes any bug in it — in the C, in the broker, in the mapper — the entire authentication decision. v0.1.x is the worked example: it returned `PAM_SUCCESS` the moment a device flow started, and the `auth sufficient` line the README recommended at the time turned that into an unauthenticated login as any username.

In `/etc/ssh/sshd_config`:

```
KbdInteractiveAuthentication yes
UsePAM yes
```

(On OpenSSH before 8.7 the option is the now-deprecated `ChallengeResponseAuthentication yes`.) Then `sudo sshd -t` to check the config parses, and restart sshd.

One difference between the two stacks, worth knowing before you read the broker log: Debian's `common-auth` ends in a `requisite`, which terminates the whole stack, so a wrong password never reaches this module. A RHEL `substack` terminates only *itself*, so a wrong password still starts a device flow that nobody will approve — the login fails either way, but the broker log will show a pending flow and an `authentication_attempt` for it.

**Do not "fix" that by changing `substack` to `include`.** It looks like the same thing with tidier short-circuiting, and it removes the second factor: `password-auth` authenticates with `auth sufficient pam_unix.so`, and under `include` that success ends the *entire* auth stack, so the line below it never runs. `substack` is what confines it. Whatever you change here, test it — a correct password with the phone left face-down must still be refused.

#### If you want GitHub to be the only factor

Some hosts genuinely want that — a bastion whose whole purpose is "prove you are in the org". It is a defensible choice; make it deliberately rather than by reaching for `sufficient` because it appears first in every PAM tutorial. Still `required`, with nothing else in the auth stack:

```
auth    required  oauth2_pam.so socket=/var/run/oauth2-pam/broker.sock
# and nothing else in the auth stack: no @include common-auth, no substack password-auth

account required  oauth2_pam.so socket=/var/run/oauth2-pam/broker.sock
@include common-account   # RHEL: account include password-auth
```

Keep the distribution's account stack even here, and this is the one place the `account` line can bite: sshd runs the account stage for `publickey` logins too, even though it skips the auth stack for them. This module answers `PAM_IGNORE` for a login it did not authenticate, and Linux-PAM turns an account stack of nothing but `PAM_IGNORE` into `PAM_PERM_DENIED` — so `account required oauth2_pam.so` *on its own* denies exactly the key-based break-glass path the rest of this section tells you to keep.

With nothing following it, `required` and `sufficient` behave identically today. The difference is what happens next year. `sufficient` means "if I succeed, stop reading the stack", so the day a distribution upgrade or a colleague adds a line below this one, that line silently stops running — and on failure `sufficient` falls *through* to whatever follows, which is how a password prompt you thought you had removed comes back. `required` can only fail the stack, never end it early, so it composes safely with whatever arrives later. This is the arrangement the container harness runs, which is why `never_authorized` means what it says.

If you take this path, keep an ssh key working for at least one account (below) — you are now one broker outage away from no interactive logins at all. And note `pam_deny.so` is not the way to close the stack: it always fails, so `auth required pam_deny.so` after this line denies every login, successful device flow or not.

#### Before you edit the PAM stack

A PAM misconfiguration is not a failed login, it is a locked host, and this module adds three more ways to get there: a stopped broker, an unreachable GitHub, and a user without their phone. The module fails closed by design, which is correct and is also exactly what locks you out.

- **Keep a second root session open** for the whole edit, and test with a *third* connection. Never close the session that still works until a new one has succeeded.
- **Keep a key-based path in.** sshd does not run the PAM auth stack for `publickey` authentication at all, so an authorized key stays usable no matter what the auth stack says — that is the most reliable break-glass here. Do not set `AuthenticationMethods publickey,keyboard-interactive` on your own account until you have tested the interactive path from somewhere else.
- **Know your out-of-band console** before you need it: a cloud provider's serial or VNC console, IPMI, or physical access. If the only way in is ssh, there is no recovery from a bad `/etc/pam.d/sshd`.
- **`sudo sshd -t`** catches an `sshd_config` mistake; nothing validates `/etc/pam.d/sshd`, so a typo in a module name is discovered at the next login attempt.
- **A stopped broker denies every login through this module** (immediately, not after a timeout). That is deliberate — an unreachable broker must not become an allowed login — so `systemctl status oauth2-pam-broker` belongs in whatever you check before rebooting.

### Module arguments

| Argument | Default | Meaning |
|---|---|---|
| `socket=PATH` | `/var/run/oauth2-pam/broker.sock` | Broker socket. Must be under `/run/oauth2-pam/` or `/var/run/oauth2-pam/` — the same directory under both names — and at most 103 bytes. |
| `provider=NAME` | the broker's default | Which configured provider (`providers[].name`) to authenticate against. Omit it and the broker uses the first one configured; a name it does not have is refused rather than substituted. |
| `poll_interval=N` | 5 (1–60) | Seconds between `check_session` calls. The broker's requested interval wins when it supplies one. |
| `timeout=N` | 90 (10–900) | Seconds to wait for the user to approve before giving up. |
| `debug` | off | Log at `LOG_DEBUG` to syslog `authpriv`. |

The local Unix account must already exist — this module authenticates, it does not create users.

#### `timeout=` has two other deadlines around it

Three limits bound one login, and only the smallest one is ever reached:

- **`LoginGraceTime`** in `sshd_config`, default **120s**. sshd disconnects when it elapses, whatever PAM is doing. Raising `timeout=` above it does not give the user longer — it just means the module's own deadline never fires, and the user gets an abrupt disconnect instead of a message saying authentication timed out. Raise both together or neither.
- **`timeout=`** here, default 90s, chosen to sit under that grace period with room for the final poll and the PAM conversation.
- **`authentication.device_flow_timeout`** in the broker, default **3m**. This one must be the *largest*, or the broker abandons the flow while the user is still being told to wait. It is what releases a `max_concurrent_auths` slot when someone closes the terminal without approving.

Approving on a phone takes longer than people expect. If you raise `timeout=`, raise `LoginGraceTime` to match and keep `device_flow_timeout` above both.

## Identity Mapper

The mapper resolves a GitHub identity to a local Unix user via a four-tier chain. The first tier to return a non-empty `local_user` wins; at least one tier must be configured.

| Tier | Config key | Description |
|------|-----------|-------------|
| 0 | `mapper.enrollment_enabled` (plus `mapper.enrollment_file`) | Self-enrolled users (`oauth2-pam-enroll`) |
| 1 | `mapper.rules` | Built-in YAML rules, zero deps |
| 2 | `mapper.external_script` | External binary (JSON stdin/stdout) |
| 3 | `mapper.http_endpoint` | HTTPS service (LDAP gateway, etc.) |

Tier 0 needs both keys, and `mapper.enrollment_enabled: true` is the one that
switches it on — a path alone does nothing. This table named only the path until
[#107](https://github.com/scttfrdmn/oauth2-pam/issues/107), which was wrong twice
over: a config with just `mapper.enrollment_file` does not satisfy "at least one
tier", so the broker refuses to start, and adding a rule to get past that leaves
tier 0 never consulted — so every enrolled user is silently ignored while
`oauth2-pam-enroll` appears to work.

```yaml
mapper:
  enrollment_enabled: true
  enrollment_file: /etc/oauth2-pam/enrolled-users.yaml   # this is the default
```

The file is read fresh on every login, so enrolling somebody takes effect without a
restart. It must be a regular file, not a symlink, owned by root, and neither it nor
its directory may be writable by group or other — tier 0 decides which provider
identity owns which local account, so whoever can write it chooses who logs in as
whom. `oauth2-pam-enroll` writes it 0600. A file that fails those checks yields no
tier-0 answer at all: the login falls through to the later tiers with a warning in
the broker's log, rather than an untrusted file being honoured.

### Which local accounts can be mapped to

Every tier's answer passes the same gate, so no rule, script, or identity service can produce a mapping that gets past it:

| Check | Default | Setting |
|---|---|---|
| Must be a valid POSIX username | always | — |
| Not a system account by name (`root`, `www-data`, `postgres`, `nobody`, `systemd-*`, anything starting with `_`, …) | always | exempt one with `mapper.allow_system_users` |
| UID at or above the floor | 1000 | `mapper.min_uid` — lower it, but it cannot be switched off |
| **Never UID 0** | always | not overridable |

The two mechanisms cover for each other. The floor is authoritative — it asks the host what the UID is — but it needs the account to resolve, and a broker built without cgo reads only `/etc/passwd`, so on an LDAP/SSSD host it cannot be applied. The name denylist needs no lookup. An account that does not resolve at all is allowed past the floor with a warning, because it cannot become a login anyway: sshd resolves the account itself before it starts a session.

This matters because `local_user: "{{ .Login }}"` gated only on org membership delegates the choice of local username to whoever can create or rename an account in that org. Without a floor, a member who renamed themselves `postgres` logged in as `postgres`.

There is no setting that removes the floor. A negative `mapper.min_uid` used to disable it and is now a startup error: a site with real people below UID 1000 sets `min_uid` to the lowest UID it means to allow, and a site whose real person is named after a service account names them in `mapper.allow_system_users`, which exempts a name from the denylist and not from the floor. Those two cover the cases that motivated the switch, and neither of them requires a host to run with no floor at all.

Root is refused by UID, not by name, and neither setting can permit it: a device flow has no cryptographic binding to the SSH connection it authorises, which makes it the weakest route to the most privilege. OpenSSH's own default `PermitRootLogin prohibit-password` already rules it out. Use an ordinary account and `sudo`.

### Rule matching

```yaml
mapper:
  rules:
    # Match by org
    - match:
        github_org: my-org
      local_user: "{{ .Login }}"

    # Match specific user
    - match:
        github_login: octocat
      local_user: octocat
```

All `match` fields within a rule are ANDed, and matching is case-insensitive. `local_user` substitutes three values, each in three spellings: `{{ .Login }}`, `{{.Login}}` or `{login}` (the provider username), and the same forms for `.Email` and `.Name`. Nothing else is substituted. A leftover `{{` after substitution is rejected outright, which is what stops a provider-controlled field turning into a template; a leftover single-brace form like `{bogus}` is left as literal text and then fails the POSIX-username check, so it is refused too, one step later. The result must be a valid POSIX username or the mapping is refused. A provider whose logins are email addresses therefore cannot use `{{ .Login }}`; give those rules an explicit `local_user`, or map in Tier 2/3.

`github_org` and `github_team` are the GitHub spelling of provider-neutral **claims**, and a rule can name claims directly instead:

```yaml
    # Equivalent to github_org: my-org
    - match:
        claims:
          org: my-org
      local_user: "{{ .Login }}"

    # A provider asserting flat groups rather than orgs and teams
    - match:
        claims:
          group: platform-team
      local_user: platformuser
```

| Match key | Means |
|---|---|
| `github_login`, `github_org`, `github_team` | The GitHub spelling; unchanged and still supported |
| `login` | The identity's username at the provider. Same as `github_login`, and wins if both are set |
| `claims: {name: value}` | The named claim must carry that value. GitHub asserts `org` and `team`; other providers assert e.g. `group` or `role`. Every named claim must match |

`groups` is **advisory**: the broker records it in the session and the audit trail and sends it to the PAM module, which discards it. Nothing here calls `setgroups(2)`, so `groups: [sudo]` grants no sudo. Manage group membership with the usual system tools.

That is measured, not asserted. `internal/ipc/e2e_test.go` checks the groups reach the wire, and the container case `mapped_groups_not_applied` logs in over real `ssh` and checks `id -Gn` in the resulting session does not contain them; the broker's own mapping is checked first so the negative cannot pass vacuously. `mapper.New` also logs a warning at startup naming any groups a rule declares, so a config relying on them is not silently ignored. Applying them needs a guard against a mapper handing out `wheel` or `docker` — see [#39](https://github.com/scttfrdmn/oauth2-pam/issues/39).

### External script (Tier 2)

```bash
#!/bin/bash
# /usr/local/lib/oauth2-pam/map-user.sh
# Receives Identity JSON on stdin, writes Result JSON to stdout

INPUT=$(cat)
LOGIN=$(echo "$INPUT" | jq -r .login)

# Example: look up in a local database
LOCAL_USER=$(sqlite3 /etc/oauth2-pam/users.db \
  "SELECT local_user FROM mappings WHERE github_login='$LOGIN'")

if [ -n "$LOCAL_USER" ]; then
  echo "{\"local_user\": \"$LOCAL_USER\", \"groups\": [\"users\"]}"
fi
```

The script runs with a scrubbed environment (`PATH` and `HOME` only) and is killed at `external_script_timeout`.

Its `local_user` is validated the same way a rule's is — a valid POSIX username, not a system account, at or above `mapper.min_uid`. The example above is worth reading as a warning as well as a template: its input is provider-controlled, and a shorter version that echoed `.login` straight back would hand over whatever the identity claimed. A refused answer ends the login; the chain does not fall through to Tier 3 looking for a more agreeable one.

### HTTP service (Tier 3)

POST body:
```json
{"provider":"github","type":"github","subject":"1","login":"octocat","email":"",
 "orgs":["my-org"],"teams":["my-org/engineers"],
 "claims":{"org":["my-org"],"team":["my-org/engineers"]}}
```

`claims` is the provider-neutral form and is the one to read for a script or service meant to work with more than one provider; `orgs` and `teams` are retained as the GitHub-shaped view of the same data, so an existing script keeps working. `subject` is the provider's stable identifier for the account, which survives a rename where `login` does not.

Expected response:
```json
{"local_user":"octocat","groups":["users","engineers"]}
```

Return `404` or `204` to indicate no mapping (falls through to the next tier). The endpoint must be `https://`, and redirects are refused outright — a mapping service that could redirect the broker would be an SSRF vector into your network.

## Admin CLI

```bash
# Generate a token_encryption_key (base64, 32 bytes from the OS CSPRNG)
oauth2-pam-admin gen-key

# Check broker status
oauth2-pam-admin status

# Test a full authentication flow
oauth2-pam-admin test-auth --user octocat

# Test mapping without a real OAuth flow
oauth2-pam-admin test-mapping --login octocat --org my-org --team my-org/engineers

# Revoke a session
oauth2-pam-admin revoke-session <session-id>
```

## Development

```bash
make test              # Go suite
make test-cbridge      # C unit tests for the PAM module bridge
make test-integration  # container harness: real sshd + PAM vs a real broker
```

The end-to-end tests in `internal/ipc` drive a real broker behind a real IPC server over a real Unix socket, with only GitHub itself faked, and they pin the contract that a started device flow is *not* an authentication.

`make test-integration` covers the other half of the protocol, which Go tests cannot reach: two containers, one running `sshd` with `oauth2_pam.so` in `/etc/pam.d/sshd` and one running the broker, with logins driven over a real ssh connection. It needs Docker and nothing else — no OAuth app, no credentials, no network. See [test/integration/README.md](test/integration/README.md) for the cases and how a device-flow prompt is answered without a human.

`make test-cbridge` covers what neither can: the boundaries. The harness drives the C, but it cannot make the broker misbehave in a specific way, so a reply exactly the size of the read buffer, a broker that accepts a connection and then goes silent, and a broker that hangs up mid-request are all tested directly over a `socketpair`. See [test/cbridge/README.md](test/cbridge/README.md).

```bash
make test-cbridge-mutations      # put each fixed bridge defect back; the C tests must fail
make test-integration-mutations  # put the v0.1.x bypass back; the harness must refuse the login
```

Those two are the check on the checks, and CI runs both on every push to `main` and
every pull request — the harness mutation check as its own job, the C bridge one as a
step in the Linux job, next to the suite it mutates. A green suite proves the code
does what the tests say; it does not prove the tests would notice if it stopped — so
each of 25 C bridge defects is reintroduced in turn in a copy of the tree, along with
the v0.1.x authentication bypass and an account stage that fails open, and the suite
is required to fail each time. A mutation that survives means that regression test is
decoration.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how work is tracked (labels, milestones, the roadmap board), what to run before pushing, and the two invariants that are easy to break.

## Project Structure

```
oauth2-pam/
├── cmd/
│   ├── broker/              # Broker daemon (oauth2-pam-broker)
│   ├── pam-module/          # PAM shared library (oauth2_pam.so) — plain C, no Go
│   ├── oauth2-pam-admin/    # Admin CLI
│   └── oauth2-pam-enroll/   # Self-enrollment CLI
├── internal/
│   └── ipc/                 # Unix socket IPC server
├── docs/
│   └── wire-protocol.md     # The broker↔module contract, version 1
├── test/
│   ├── cbridge/             # C unit tests for the PAM module bridge
│   └── integration/         # Container harness (sshd + PAM vs broker)
├── pkg/
│   ├── auth/                # Broker, session state machine, token manager
│   ├── config/              # Configuration schema and loader
│   ├── enrollment/          # Enrollment file store
│   ├── mapper/              # Four-tier identity mapper
│   ├── provider/            # Provider interface + neutral Identity/Token
│   │   ├── github/          # GitHub OAuth2 + Device Flow adapter
│   │   └── registry/        # providers[].type → implementation
│   └── security/            # Encryption, audit logging
└── configs/
    ├── example.yaml
    └── systemd/
```

## Security notes

- The documented PAM stack makes this module a **second factor** (`auth required`, after the distribution's own auth stack), not the whole authentication decision. `auth sufficient` hands the decision to one module; v0.1.x is what that costs when the module is wrong. [Configure PAM (SSH)](#6-configure-pam-ssh) has both arrangements and the break-glass checklist.
- Tokens are held encrypted in memory (AES-GCM) and never written to disk. Set `token_encryption_key` with `oauth2-pam-admin gen-key` rather than typing one: 32 typeable characters cannot carry 256 bits. A generated (base64, 32-byte) key gives AES-256; a raw 16- or 24-byte key, still accepted for 0.1.x configs, gives AES-128 or AES-192. With no key configured the broker generates one for the process instead of storing tokens in the clear — an unrecoverable key is no loss for data that never outlives the process, and it means the default is not plaintext. `secure_token_storage: false` opts out.
- Audit records go to `file`, `stdout`, or `syslog`; anything else is a startup error. An unrecognised type used to become `stdout`, so a typo moved the whole trail somewhere nobody was watching.
- The broker socket is `0660` in a `0750` directory. The PAM module runs as root and so can reach it; other local users cannot, which matters because anything that can talk to the socket can start device flows.
- The broker rate-limits per calling UID and caps request bodies at 64 KB. The UID comes from the socket's peer credentials (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS/FreeBSD); if a platform cannot supply them the broker logs `peer_credentials=false` at startup and every caller shares one window, rather than all being recorded as root.
- The client secret can be kept out of the config entirely — a systemd credential, a file, or an environment variable ([above](#where-the-client-secret-comes-from)). Whichever file holds it must be 0600 and owned by root or the broker's uid, and `broker.yaml` is checked the same way whether or not the secret is inline; the broker refuses to start rather than treat a world-readable secret — or a world-readable set of mapping rules — as confidential.
- Session IDs are generated by the broker with `crypto/rand`; a client-supplied `session_id` on an `authenticate` request is ignored.
- Org and team membership is checked server-side in the broker, before mapping.
- Enrollment records name the provider they were created against, so on a host with two providers an account with the same login at the other one cannot claim an enrollment. Records written before v0.3.0 name no provider and match any; re-enroll to scope them.
- The enrollment file is the most authoritative mapping tier, so it is read under nearly the same rules as the client secret: not writable by group or other, owned by root or the broker's uid, not a symlink, and in a directory no other local user can write. The one difference is read access, and it is deliberate — a secret must be 0600 or tighter, while a 0640 enrollment file loads. It is still a disclosure, since it says which local account belongs to which provider identity, which is what aiming a device-flow phish at the right person needs; refusing it would lock every enrolled user out of a host whose operator had chmodded it 0640, and that outage is the worse answer. Write is the one that is refused, because write is the whole of tier 0's authority. The directory matters because the file's own mode cannot be forged but its *name* can be reused — with write access to `/etc/oauth2-pam` an attacker cannot alter the file, but they can rename it away and put an earlier root-owned copy back, reinstating an enrollment that was deliberately removed. `oauth2-pam-enroll` applies the directory rule when it writes, so the operator hears about it then rather than the enrolled user hearing about it at the login that fails.
- Authentication events go to the audit log; `audit.events` filters which types are recorded, and an unknown type in that list is a config error rather than a silently ignored one. The four events that record an access decision (`authentication_success`, `authentication_failed`, `authentication_denied`, `session_revoked`) are exempt from that filter and are written synchronously, so they survive a crash, cannot be dropped by a full queue, and cannot be configured away. That leaves `authentication_attempt` — the high-volume one the buffer exists for — and `device_flow_failed` as the two types `audit.events` can actually drop. A dropped event is counted, not silent.
- A login whose `authentication_success` record cannot be written is refused rather than granted unrecorded, and that promise is bounded by a five-second deadline on the audit write: a sink that stalls — an `fsync` on an unreachable hard NFS mount, a `/dev/log` whose peer has stopped reading — is treated by the broker as a sink that refused, since a broker waiting forever for an answer never acts on it. The record is written before the session is activated, so no login exists that the trail does not already name. The converse needs saying too, because it is where that fail-closed answer costs something: a write that failed can still have left the record at a sink — every sink is attempted whatever the earlier ones did, a write that overran its deadline is still running with the bytes already in the file, and the file sink itself writes before it `fsync`s, so a full or failing disk reports the failure with the whole record already in the file and readable by anything tailing it — so the trail can name a login that did not happen. Where that is possible the broker follows the success with a `session_revoked` recording that the authentication did not take effect, which is the same correction a grant withdrawn between the record and the activation gets. That correction is best effort by nature: if the sinks have stopped draining it is refused for the same reason the record was, and the broker says so at `error` rather than leaving the impression it succeeded. The practical consequence for an operator is that an audit sink which stops draining stops logins on that host; the alternative is a host that keeps letting people in and recording none of it.

## Limitations

- **GitHub is the only provider shipped.** The broker, mapper, and audit trail work in provider-neutral terms (`pkg/provider`), and a new provider means implementing that interface and adding one line to `pkg/provider/registry` — but GitHub, including GitHub Enterprise Server via `github.base_url`, is the only implementation in the tree today.
- **The local Unix account must already exist**, and the mapping must resolve to the account being logged into.
- **Supplementary `groups` from the mapper are not applied** to the session. The broker sends them, the module discards them, and the container harness asserts as much on every run; the broker warns at startup if a rule declares any ([#39](https://github.com/scttfrdmn/oauth2-pam/issues/39)).
- **The login requires an interactive terminal**, because the user has to acknowledge the prompt. `scp`, `rsync`, and non-interactive `ssh` cannot complete this flow; keep a key-based or password path available for automation.
- **Nothing revokes the GitHub token automatically.** A session ending — by logout, by its own expiry, by the `max_token_age` ceiling, or by the broker restarting — ends it locally and leaves the access token live at GitHub until GitHub's own expiry. Only `oauth2-pam-admin revoke-session` reaches the provider, and only while the session is still inside its `token_lifetime`: past that the encrypted token record is gone and there is nothing left to present. Set a short token lifetime on the OAuth app if that matters to you, and treat a leaked token as something to revoke in GitHub's own settings ([#95](https://github.com/scttfrdmn/oauth2-pam/issues/95)).
- **No test talks to real GitHub.** Every layer below that is exercised in CI on every pull request and every push to `main`: the broker end to end against a fake GitHub (`internal/ipc`), the C bridge's own boundaries (`test/cbridge`), real `ssh` logins through a real `sshd` with `oauth2_pam.so` in its PAM stack against a real broker (`test/integration`), and mutation checks that require both C suites to fail when the defects they guard are put back. What none of them prove is behaviour against the live device endpoint — its actual `slow_down` and rate-limit responses, and a real interactive terminal — so treat a first deployment as the thing that verifies that.

## License

MIT
