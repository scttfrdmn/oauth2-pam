# oauth2-pam

[![CI](https://github.com/scttfrdmn/oauth2-pam/actions/workflows/ci.yml/badge.svg)](https://github.com/scttfrdmn/oauth2-pam/actions/workflows/ci.yml)
[![Security](https://github.com/scttfrdmn/oauth2-pam/actions/workflows/security.yml/badge.svg)](https://github.com/scttfrdmn/oauth2-pam/actions/workflows/security.yml)
[![version](https://img.shields.io/badge/version-0.2.0-blue)](https://github.com/scttfrdmn/oauth2-pam/releases)

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

## Requirements

- Go 1.25+ (1.24 is end-of-life and no longer receives security backports)
- Linux with PAM (`libpam0g-dev`)
- `libjson-c-dev`
- A GitHub OAuth App with Device Flow enabled

The PAM module is Linux-only. `go build ./...` and the test suite work on macOS for development; `make build-pam` requires Linux.

## Quick Start

### 1. Create a GitHub OAuth App

Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**:
- Application name: `oauth2-pam`
- Homepage URL: `https://github.com/scttfrdmn/oauth2-pam`
- **Enable device flow** (checkbox in the app settings)
- No callback URL needed for Device Flow

Copy the **Client ID** and generate a **Client Secret**.

### 2. Build

```bash
git clone https://github.com/scttfrdmn/oauth2-pam
cd oauth2-pam
make build
```

### 3. Install

```bash
sudo make install
```

This installs:
- `/lib/security/oauth2_pam.so`
- `/usr/local/bin/oauth2-pam-broker`
- `/usr/local/bin/oauth2-pam-admin`
- `/usr/local/bin/oauth2-pam-enroll`
- `/etc/systemd/system/oauth2-pam-broker.service`

### 4. Configure

```bash
sudo install -m 0600 -o root -g root configs/example.yaml /etc/oauth2-pam/broker.yaml
sudo $EDITOR /etc/oauth2-pam/broker.yaml
```

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

#### Where the client secret comes from

Three sources, highest precedence first:

| Source | Form |
| --- | --- |
| Environment | `OAUTH2_PAM_CLIENT_SECRET_<PROVIDER>` — the provider name uppercased, with anything outside `A-Z0-9` replaced by `_` |
| File | `client_secret_file:` — an absolute path, or a bare [systemd credential](https://systemd.io/CREDENTIALS/) name resolved under `$CREDENTIALS_DIRECTORY` |
| Config file | `client_secret:` inline, as above |

Whichever file holds the secret — the secret file, or `broker.yaml` itself when
the secret is inline — must have no group or other permission bits and be owned
by root or by the broker's own uid. The broker refuses to start otherwise,
naming the file and the `chmod`/`chown` that fixes it: a secret in a
world-readable config is a secret every local user on the host already has, and
a 0600 file owned by another user is a secret that user can *replace*, which
would let them choose the OAuth app the broker authenticates against.

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

Edit `/etc/pam.d/sshd`:

```
# Add before @include common-auth
auth sufficient oauth2_pam.so socket=/var/run/oauth2-pam/broker.sock
```

In `/etc/ssh/sshd_config`:

```
KbdInteractiveAuthentication yes
UsePAM yes
```

(On OpenSSH before 8.7 the option is the now-deprecated `ChallengeResponseAuthentication yes`.) Restart sshd.

### Module arguments

| Argument | Default | Meaning |
|---|---|---|
| `socket=PATH` | `/var/run/oauth2-pam/broker.sock` | Broker socket. Must be under `/var/run/oauth2-pam/` and at most 103 bytes. |
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
| 0 | `mapper.enrollment_file` | Self-enrolled users (`oauth2-pam-enroll`) |
| 1 | `mapper.rules` | Built-in YAML rules, zero deps |
| 2 | `mapper.external_script` | External binary (JSON stdin/stdout) |
| 3 | `mapper.http_endpoint` | HTTPS service (LDAP gateway, etc.) |

### Which local accounts can be mapped to

Every tier's answer passes the same gate, so no rule, script, or identity service can produce a mapping that gets past it:

| Check | Default | Setting |
|---|---|---|
| Must be a valid POSIX username | always | — |
| Not a system account by name (`root`, `www-data`, `postgres`, `nobody`, `systemd-*`, anything starting with `_`, …) | always | exempt one with `mapper.allow_system_users` |
| UID at or above the floor | 1000 | `mapper.min_uid` (negative disables) |
| **Never UID 0** | always | not overridable |

The two mechanisms cover for each other. The floor is authoritative — it asks the host what the UID is — but it needs the account to resolve, and a broker built without cgo reads only `/etc/passwd`, so on an LDAP/SSSD host it cannot be applied. The name denylist needs no lookup. An account that does not resolve at all is allowed past the floor with a warning, because it cannot become a login anyway: sshd resolves the account itself before it starts a session.

This matters because `local_user: "{{ .Login }}"` gated only on org membership delegates the choice of local username to whoever can create or rename an account in that org. Without a floor, a member who renamed themselves `postgres` logged in as `postgres`.

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

All `match` fields within a rule are ANDed, and matching is case-insensitive. `local_user` supports `{{ .Login }}` (the provider username), `{{ .Email }}`, and `{{ .Name }}`; nothing else — an unknown field or a pipeline is rejected rather than expanded. The result must be a valid POSIX username or the mapping is refused. A provider whose logins are email addresses therefore cannot use `{{ .Login }}`; give those rules an explicit `local_user`, or map in Tier 2/3.

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

`groups` is **advisory today**: the broker records it in the session and the audit trail, but the PAM module does not apply supplementary groups to the login. Manage group membership with the usual system tools. See [#12](https://github.com/scttfrdmn/oauth2-pam/issues/12).

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
make test-integration  # container harness: real sshd + PAM vs a real broker
```

The end-to-end tests in `internal/ipc` drive a real broker behind a real IPC server over a real Unix socket, with only GitHub itself faked, and they pin the contract that a started device flow is *not* an authentication.

`make test-integration` covers the other half of the protocol, which Go tests cannot reach: two containers, one running `sshd` with `oauth2_pam.so` in `/etc/pam.d/sshd` and one running the broker, with logins driven over a real ssh connection. It needs Docker and nothing else — no OAuth app, no credentials, no network. See [test/integration/README.md](test/integration/README.md) for the cases and how a device-flow prompt is answered without a human.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how work is tracked (labels, milestones, the roadmap board), what to run before pushing, and the two invariants that are easy to break.

## Project Structure

```
oauth2-pam/
├── cmd/
│   ├── broker/              # Broker daemon (oauth2-pam-broker)
│   ├── pam-module/          # PAM shared library (oauth2_pam.so) + C bridge
│   ├── oauth2-pam-admin/    # Admin CLI
│   └── oauth2-pam-enroll/   # Self-enrollment CLI
├── internal/
│   └── ipc/                 # Unix socket IPC server
├── test/
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

- Tokens are held encrypted in memory (AES-256-GCM) when `secure_token_storage: true` and a `token_encryption_key` is set. They are never written to disk. Generate the key with `oauth2-pam-admin gen-key` rather than typing one: 32 typeable characters cannot carry 256 bits.
- The broker socket is `0660` in a `0750` directory. The PAM module runs as root and so can reach it; other local users cannot, which matters because anything that can talk to the socket can start device flows.
- The broker rate-limits per calling UID and caps request bodies at 64 KB. The UID comes from the socket's peer credentials (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED` on macOS/FreeBSD); if a platform cannot supply them the broker logs `peer_credentials=false` at startup and every caller shares one window, rather than all being recorded as root.
- The client secret can be kept out of the config entirely — a systemd credential, a file, or an environment variable ([above](#where-the-client-secret-comes-from)). Whichever file holds it must be 0600 and owned by root or the broker's uid, including `broker.yaml` itself when the secret is inline; the broker refuses to start rather than treat a world-readable secret as confidential.
- Session IDs are generated by the broker with `crypto/rand`; a client-supplied `session_id` on an `authenticate` request is ignored.
- Org and team membership is checked server-side in the broker, before mapping.
- Enrollment records name the provider they were created against, so on a host with two providers an account with the same login at the other one cannot claim an enrollment. Records written before v0.3.0 name no provider and match any; re-enroll to scope them.
- Authentication events go to the audit log; `audit.events` filters which types are recorded, and an unknown type in that list is a config error rather than a silently ignored one. Events that record an access decision (`authentication_success`, `authentication_failed`, `authentication_denied`, `session_revoked`) are written synchronously, so they survive a crash and cannot be dropped by a full queue; the high-volume `authentication_attempt` is buffered and may be.

## Limitations

- **GitHub is the only provider shipped.** The broker, mapper, and audit trail work in provider-neutral terms (`pkg/provider`), and a new provider means implementing that interface and adding one line to `pkg/provider/registry` — but GitHub, including GitHub Enterprise Server via `github.base_url`, is the only implementation in the tree today.
- **The local Unix account must already exist**, and the mapping must resolve to the account being logged into.
- **Supplementary `groups` from the mapper are not applied** to the session ([#12](https://github.com/scttfrdmn/oauth2-pam/issues/12)).
- **The login requires an interactive terminal**, because the user has to acknowledge the prompt. `scp`, `rsync`, and non-interactive `ssh` cannot complete this flow; keep a key-based or password path available for automation.
- **A full `sshd` login against real GitHub has not been verified by the test suite**; the broker half of the protocol is covered end to end, the C client half is not.

## License

MIT
