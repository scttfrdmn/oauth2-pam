# oauth2-pam

[![CI](https://github.com/scttfrdmn/oauth2-pam/actions/workflows/ci.yml/badge.svg)](https://github.com/scttfrdmn/oauth2-pam/actions/workflows/ci.yml)

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

## Requirements

- Go 1.24+
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
sudo cp configs/example.yaml /etc/oauth2-pam/broker.yaml
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
| `poll_interval=N` | 5 (1–60) | Seconds between `check_session` calls. The broker's requested interval wins when it supplies one. |
| `timeout=N` | 300 (10–900) | Seconds to wait for the user to approve before giving up. |
| `debug` | off | Log at `LOG_DEBUG` to syslog `authpriv`. |

The local Unix account must already exist — this module authenticates, it does not create users.

## Identity Mapper

The mapper resolves a GitHub identity to a local Unix user via a four-tier chain. The first tier to return a non-empty `local_user` wins; at least one tier must be configured.

| Tier | Config key | Description |
|------|-----------|-------------|
| 0 | `mapper.enrollment_file` | Self-enrolled users (`oauth2-pam-enroll`) |
| 1 | `mapper.rules` | Built-in YAML rules, zero deps |
| 2 | `mapper.external_script` | External binary (JSON stdin/stdout) |
| 3 | `mapper.http_endpoint` | HTTPS service (LDAP gateway, etc.) |

### Rule matching

```yaml
mapper:
  rules:
    # Match by org + team → sudo
    - match:
        github_org: my-org
        github_team: my-org/admins
      local_user: "{{ .Login }}"
      groups: [users, sudo]

    # Match by org only
    - match:
        github_org: my-org
      local_user: "{{ .Login }}"
      groups: [users]

    # Match specific user
    - match:
        github_login: octocat
      local_user: octocat
      groups: [users]
```

All `match` fields within a rule are ANDed, and matching is case-insensitive. `local_user` supports `{{ .Login }}` (GitHub username), `{{ .Email }}`, and `{{ .Name }}`; nothing else — an unknown field or a pipeline is rejected rather than expanded. The result must be a valid POSIX username or the mapping is refused.

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

### HTTP service (Tier 3)

POST body:
```json
{"provider":"github","login":"octocat","email":"","orgs":["my-org"],"teams":["my-org/engineers"]}
```

Expected response:
```json
{"local_user":"octocat","groups":["users","engineers"]}
```

Return `404` or `204` to indicate no mapping (falls through to the next tier). The endpoint must be `https://`, and redirects are refused outright — a mapping service that could redirect the broker would be an SSRF vector into your network.

## Admin CLI

```bash
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
│   ├── provider/
│   │   └── github/          # GitHub OAuth2 + Device Flow adapter
│   └── security/            # Encryption, audit logging
└── configs/
    ├── example.yaml
    └── systemd/
```

## Security notes

- Tokens are held encrypted in memory (AES-256-GCM) when `secure_token_storage: true` and a `token_encryption_key` is set. They are never written to disk.
- The broker socket is `0660` in a `0750` directory. The PAM module runs as root and so can reach it; other local users cannot, which matters because anything that can talk to the socket can start device flows.
- The broker rate-limits per calling UID (`SO_PEERCRED`) and caps request bodies at 64 KB.
- Session IDs are generated by the broker with `crypto/rand`; a client-supplied `session_id` on an `authenticate` request is ignored.
- Org and team membership is checked server-side in the broker, before mapping.
- Authentication events go to the audit log; `audit.events` filters which types are recorded, and an unknown type in that list is a config error rather than a silently ignored one.

## Limitations

- **GitHub only.** The provider adapter is GitHub-specific ([#13](https://github.com/scttfrdmn/oauth2-pam/issues/13) tracks extracting an interface). `NewWithEndpoints` does point the adapter at a GitHub Enterprise Server installation.
- **The local Unix account must already exist**, and the mapping must resolve to the account being logged into.
- **Supplementary `groups` from the mapper are not applied** to the session ([#12](https://github.com/scttfrdmn/oauth2-pam/issues/12)).
- **`client_secret` lives in the config file** in cleartext ([#14](https://github.com/scttfrdmn/oauth2-pam/issues/14)).
- **The login requires an interactive terminal**, because the user has to acknowledge the prompt. `scp`, `rsync`, and non-interactive `ssh` cannot complete this flow; keep a key-based or password path available for automation.
- **A full `sshd` login against real GitHub has not been verified by the test suite**; the broker half of the protocol is covered end to end, the C client half is not.

## License

MIT
