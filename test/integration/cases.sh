#!/bin/bash
# Integration cases, run inside the client container: cases.sh <case-name>.
#
# Each case drives a real ssh login against the real sshd in this container,
# whose PAM stack contains nothing but oauth2_pam.so, against a real broker in
# another container. Only GitHub is fake, and the case tells it what to do.
#
# Exits 0 if the case passes, 1 if it fails.

set -uo pipefail

CONTROL_URL="${CONTROL_URL:-http://fakegithub:8080}"
PROMPT_LOG=/tmp/prompt.log
SSH_LOG=/tmp/ssh.log

# What the fake GitHub hands out; a case asserts these reach the ssh client.
USER_CODE="WDJB-MJHT"
VERIFY_URL="https://fakegithub/login/device"

LOGIN_RC=0
ELAPSED=0

log()  { printf '    %s\n' "$*"; }
fail() { printf '    FAIL: %s\n' "$*"; FAILED=1; }

control() { curl -fsS "$CONTROL_URL/control/$1" >/dev/null; }
polls()   { curl -fsS "$CONTROL_URL/control/state" | jq -r '.polls'; }

# attempt_login runs one ssh login as $1 and records its exit status and
# duration. AUTHORIZE_ON_PROMPT is passed through to askpass.sh, which is what
# makes approval happen *after* the prompt rather than before the flow starts.
attempt_login() {
    local user="$1" start end
    : >"$PROMPT_LOG"
    : >"$SSH_LOG"

    start=$(date +%s)
    timeout 120 env \
        SSH_ASKPASS=/opt/tests/askpass.sh \
        SSH_ASKPASS_REQUIRE=force \
        PROMPT_LOG="$PROMPT_LOG" \
        CONTROL_URL="$CONTROL_URL" \
        AUTHORIZE_ON_PROMPT="${AUTHORIZE_ON_PROMPT:-0}" \
        ssh -n \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o PreferredAuthentications=keyboard-interactive \
            -o PubkeyAuthentication=no \
            -o NumberOfPasswordPrompts=1 \
            -o ConnectTimeout=10 \
            "${user}@127.0.0.1" 'echo LOGIN_OK:$(id -un)' >"$SSH_LOG" 2>&1
    LOGIN_RC=$?
    end=$(date +%s)
    ELAPSED=$((end - start))

    log "ssh exit=${LOGIN_RC} elapsed=${ELAPSED}s"
    sed 's/^/      ssh| /' "$SSH_LOG"
}

expect_login_ok() {
    local want="$1"
    if [ "$LOGIN_RC" -ne 0 ]; then
        fail "expected the login to succeed, ssh exited ${LOGIN_RC}"
        return
    fi
    grep -q "LOGIN_OK:${want}" "$SSH_LOG" || fail "expected a shell as ${want}"
}

expect_login_refused() {
    if [ "$LOGIN_RC" -eq 0 ]; then
        fail "expected the login to be refused, ssh exited 0"
    fi
    if grep -q 'LOGIN_OK' "$SSH_LOG"; then
        fail "a command ran on the remote host — the login was not refused"
    fi
}

expect_prompt_contains() {
    grep -qF "$1" "$PROMPT_LOG" || fail "the prompt did not contain $(printf '%q' "$1")"
}

expect_prompted() {
    [ -s "$PROMPT_LOG" ] || fail "the module never prompted, so it never reached the poll phase"
}

expect_not_prompted() {
    [ ! -s "$PROMPT_LOG" ] || fail "the module prompted even though no device flow was started"
}

# set_module_args rewrites the oauth2_pam.so arguments in the sshd PAM stack, so
# a case can exercise an argument the shipped stack does not use. sshd re-reads
# /etc/pam.d/sshd for every session, so no restart is needed. Every case that
# calls this must call restore_module_args before asserting, so a failure does
# not leak a modified stack into the next case.
PAM_SSHD=/etc/pam.d/sshd
PAM_SSHD_BACKUP=/tmp/pam-sshd.orig

set_module_args() {
    cp "$PAM_SSHD" "$PAM_SSHD_BACKUP"
    sed -i "s|^auth  *required  *oauth2_pam.so.*|auth     required   oauth2_pam.so $*|" "$PAM_SSHD"
    log "pam stack: $(grep '^auth.*oauth2_pam.so' "$PAM_SSHD")"
}

restore_module_args() {
    [ -f "$PAM_SSHD_BACKUP" ] && mv "$PAM_SSHD_BACKUP" "$PAM_SSHD"
}

# ---------------------------------------------------------------- cases

# The happy path. Approval happens while the module is blocked on the prompt, so
# a success here cannot be explained by the broker having been told in advance.
case_authorized_after_prompt() {
    control reset
    AUTHORIZE_ON_PROMPT=1 attempt_login alice
    expect_login_ok alice
    expect_prompted
    expect_prompt_contains "$USER_CODE"
    expect_prompt_contains "$VERIFY_URL"
}

# The regression gate for the 0.1.x authentication bypass: a device flow that is
# started but never approved must not let anyone in. The old module returned
# PAM_SUCCESS here, before the user had visited GitHub at all.
case_never_authorized() {
    control reset
    AUTHORIZE_ON_PROMPT=0 attempt_login alice
    expect_login_refused
    expect_prompted

    # It has to have *waited*, not failed early for some unrelated reason: the
    # module's timeout= is 20s, and the broker polled GitHub more than once.
    if [ "$ELAPSED" -lt 10 ]; then
        fail "refused after only ${ELAPSED}s — that is not the authorization deadline"
    fi
    local n
    n=$(polls)
    log "fake GitHub saw ${n} token polls"
    if [ "${n:-0}" -lt 2 ]; then
        fail "expected repeated polling while pending, saw ${n}"
    fi
}

# The user pressed "deny" at GitHub. This must fail without waiting out the
# deadline, which is what distinguishes a decision from a timeout.
case_denied_by_github() {
    control reset
    control deny
    AUTHORIZE_ON_PROMPT=0 attempt_login alice
    expect_login_refused
    expect_prompted
    if [ "$ELAPSED" -ge 18 ]; then
        fail "took ${ELAPSED}s — a denial should not wait for the deadline"
    fi
}

# The mapped local_user must equal the account being logged into. GitHub says
# alice, the mapping yields alice, and the request is for bob: refuse.
case_mapped_user_mismatch() {
    control reset
    AUTHORIZE_ON_PROMPT=1 attempt_login bob
    expect_login_refused
    expect_prompted
}

# The companion to the case above: bob is a perfectly good account, and fails
# only because of the mismatch. Without this, case_mapped_user_mismatch would
# also pass if bob could never log in for an unrelated reason.
case_mapped_user_match() {
    control reset
    curl -fsS "$CONTROL_URL/control/login?login=bob" >/dev/null
    AUTHORIZE_ON_PROMPT=1 attempt_login bob
    expect_login_ok bob
}

# The mapper refuses to resolve an identity to a system account by name. postgres
# here is a perfectly ordinary account at UID 1500 — above the floor, with a real
# shell — so the only thing refusing it is the denylist. The identity claims the
# login "postgres", which is the actual attack: on a host mapping
# local_user: "{{ .Login }}" gated only on org membership, a member who renames
# themselves after a service account would otherwise get it.
case_system_account_name_refused() {
    control reset
    curl -fsS "$CONTROL_URL/control/login?login=postgres" >/dev/null
    AUTHORIZE_ON_PROMPT=1 attempt_login postgres
    expect_login_refused
    # It got as far as a device flow and a real approval: the refusal is the
    # mapping decision, not an earlier failure.
    expect_prompted
}

# The companion restriction, isolated: pgsvc is not on any denylist and fails only
# for being below mapper.min_uid (400 < 1000). Together with the case above, and
# with alice at 1001 succeeding, this pins each mechanism separately.
case_below_uid_floor_refused() {
    control reset
    curl -fsS "$CONTROL_URL/control/login?login=pgsvc" >/dev/null
    AUTHORIZE_ON_PROMPT=1 attempt_login pgsvc
    expect_login_refused
    expect_prompted
}

# provider= names which configured provider to authenticate against. The harness
# broker configures exactly one, "fakegithub", so naming it must behave exactly
# like omitting it: what this proves is that the name travels from the pam.d line
# through the IPC request and is accepted, not that it changes the outcome.
case_named_provider() {
    control reset
    set_module_args "socket=/var/run/oauth2-pam/broker.sock provider=fakegithub poll_interval=1 timeout=20 debug"
    AUTHORIZE_ON_PROMPT=1 attempt_login alice
    restore_module_args
    expect_login_ok alice
    expect_prompted
}

# A provider the broker does not have must be refused rather than silently
# replaced by the default — the alternative is authenticating against an identity
# source nobody chose. It must also be refused before any device flow starts, so
# there is nothing to prompt for and nothing for the fake GitHub to see.
case_unknown_provider_refused() {
    control reset
    set_module_args "socket=/var/run/oauth2-pam/broker.sock provider=nope poll_interval=1 timeout=20 debug"
    AUTHORIZE_ON_PROMPT=1 attempt_login alice
    restore_module_args
    expect_login_refused
    expect_not_prompted
    if [ "$ELAPSED" -ge 18 ]; then
        fail "took ${ELAPSED}s — an unconfigured provider should be refused immediately"
    fi
    local n
    n=$(polls)
    if [ "${n:-0}" -ne 0 ]; then
        fail "the fake GitHub saw ${n} token polls; no device flow should have started"
    fi
}

# The broker is stopped by the driver before this runs. The module must fail
# closed, quickly, and sshd must survive it.
case_broker_down() {
    AUTHORIZE_ON_PROMPT=0 attempt_login alice
    expect_login_refused
    expect_not_prompted
    if [ "$ELAPSED" -ge 18 ]; then
        fail "took ${ELAPSED}s — an unreachable broker should fail immediately"
    fi
    pgrep -x sshd >/dev/null || fail "sshd is gone: it did not survive the failed login"
}

# ---------------------------------------------------------------- runner

main() {
    local name="${1:-}"
    if [ -z "$name" ]; then
        echo "usage: cases.sh <case-name>" >&2
        exit 2
    fi
    if ! declare -F "case_${name}" >/dev/null; then
        echo "unknown case: ${name}" >&2
        exit 2
    fi

    FAILED=0
    "case_${name}"
    if [ "$FAILED" -ne 0 ]; then
        printf '    -- %s FAILED\n' "$name"
        exit 1
    fi
    printf '    -- %s passed\n' "$name"
}

main "$@"
