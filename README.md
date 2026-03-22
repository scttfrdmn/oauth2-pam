# pam-oauth2

A Linux PAM module that authenticates users via OAuth2 Device Flow, with GitHub as the primary provider. Users authenticate by visiting a URL on their phone and approving the request — no passwords, no SSH key distribution.

## How it works

```
SSH login → pam_oauth2.so → Unix socket → broker daemon
                                              │
                                    GitHub Device Flow (RFC 8628)
                                              │
                                    GET /user + /orgs + /teams
                                              │
                                         Mapper chain
                                              │
                                    local Unix username → PAM_SUCCESS
```

1. User runs `ssh user@host`
2. PAM module calls the broker over a Unix socket
3. Broker starts a GitHub Device Flow and returns a user code + URL
4. User sees: `Visit github.com/login/device — enter: ABCD-1234`
5. User approves on their phone/browser
6. Broker fetches GitHub identity, evaluates access controls, runs the mapper
7. PAM returns success with the local Unix username

## Requirements

- Go 1.24+
- Linux with PAM (`libpam-dev`)
- `libjson-c-dev`
- A GitHub OAuth App with Device Flow enabled

## Quick Start

### 1. Create a GitHub OAuth App

Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**:
- Application name: `pam-oauth2`
- Homepage URL: `https://github.com/scttfrdmn/pam-oauth2`
- **Enable device flow** (checkbox in the app settings)
- No callback URL needed for Device Flow

Copy the **Client ID** and generate a **Client Secret**.

### 2. Build

```bash
git clone https://github.com/scttfrdmn/pam-oauth2
cd pam-oauth2
make build
```

### 3. Install

```bash
sudo make install
```

This installs:
- `/lib/security/pam_oauth2.so`
- `/usr/local/bin/pam-oauth2-broker`
- `/usr/local/bin/pam-oauth2-admin`
- `/etc/systemd/system/pam-oauth2-broker.service`

### 4. Configure

```bash
sudo cp configs/example.yaml /etc/pam-oauth2/broker.yaml
sudo $EDITOR /etc/pam-oauth2/broker.yaml
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

### 5. Start the broker

```bash
sudo systemctl enable --now pam-oauth2-broker
```

### 6. Configure PAM (SSH)

Edit `/etc/pam.d/sshd`:

```
# Add before @include common-auth
auth sufficient pam_oauth2.so socket=/var/run/pam-oauth2/broker.sock
```

Enable `ChallengeResponseAuthentication yes` in `/etc/ssh/sshd_config` and restart sshd.

## Identity Mapper

The mapper resolves a GitHub identity to a local Unix user via a three-tier chain:

| Tier | Config key | Description |
|------|-----------|-------------|
| 1 | `mapper.rules` | Built-in YAML rules, zero deps |
| 2 | `mapper.external_script` | External binary (JSON stdin/stdout) |
| 3 | `mapper.http_endpoint` | HTTP service (LDAP gateway, etc.) |

First tier to return a non-empty `local_user` wins.

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

`local_user` supports `{{ .Login }}` (GitHub username), `{{ .Email }}`, `{{ .Name }}`.

### External script (Tier 2)

```bash
#!/bin/bash
# /usr/local/lib/pam-oauth2/map-user.sh
# Receives Identity JSON on stdin, writes Result JSON to stdout

INPUT=$(cat)
LOGIN=$(echo "$INPUT" | jq -r .login)

# Example: look up in a local database
LOCAL_USER=$(sqlite3 /etc/pam-oauth2/users.db \
  "SELECT local_user FROM mappings WHERE github_login='$LOGIN'")

if [ -n "$LOCAL_USER" ]; then
  echo "{\"local_user\": \"$LOCAL_USER\", \"groups\": [\"users\"]}"
fi
```

### HTTP service (Tier 3)

POST body:
```json
{"provider":"github","login":"octocat","email":"","orgs":["my-org"],"teams":["my-org/engineers"]}
```

Expected response:
```json
{"local_user":"octocat","groups":["users","engineers"]}
```

Return `404` or `204` to indicate no mapping (falls through to next tier).

## Admin CLI

```bash
# Check broker status
pam-oauth2-admin status

# Test a full authentication flow
pam-oauth2-admin test-auth --user octocat

# Test mapping without a real OAuth flow
pam-oauth2-admin test-mapping --login octocat --org my-org --team my-org/engineers

# Revoke a session
pam-oauth2-admin revoke-session <session-id>
```

## Project Structure

```
pam-oauth2/
├── cmd/
│   ├── broker/              # Broker daemon (pam-oauth2-broker)
│   ├── pam-module/          # PAM shared library (pam_oauth2.so)
│   └── pam-oauth2-admin/    # Admin CLI
├── internal/
│   └── ipc/                 # Unix socket IPC server
├── pkg/
│   ├── auth/                # Broker, session, token manager
│   ├── config/              # Configuration schema and loader
│   ├── mapper/              # Three-tier identity mapper
│   ├── pam/                 # CGo PAM bridge
│   ├── provider/
│   │   └── github/          # GitHub OAuth2 + Device Flow adapter
│   └── security/            # Encryption, audit logging
└── configs/
    ├── example.yaml
    └── systemd/
```

## Security notes

- Tokens are stored encrypted in memory (AES-256-GCM) when `secure_token_storage: true`
- The broker socket is `0666` by default so the PAM module (running as root) can reach it; tighten to `0600` if you pin to a specific user
- All authentication events are written to the audit log
- The broker validates GitHub org/team membership server-side before mapping

## License

MIT
