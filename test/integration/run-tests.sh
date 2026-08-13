#!/usr/bin/env bash
# Host-side driver for the container integration harness. Run it from anywhere:
#
#   test/integration/run-tests.sh          build, run every case, tear down
#   KEEP=1 test/integration/run-tests.sh   leave the stack up for poking at
#   test/integration/run-tests.sh denied_by_github [...]   run named cases only
#
# Requires Docker with the compose plugin. Everything else — sshd, PAM, the
# broker, a stand-in GitHub — lives in the containers.

set -uo pipefail

cd "$(dirname "$0")" || exit 1
COMPOSE=(docker compose -f docker-compose.yml)

# case_broker_down needs the broker stopped, so it is run last and separately.
DEFAULT_CASES=(
    authorized_after_prompt
    never_authorized
    denied_by_github
    mapped_user_mismatch
    mapped_user_match
)

say() { printf '\n==> %s\n' "$*"; }

cleanup() {
    local rc=$?
    if [ "${KEEP:-0}" = "1" ]; then
        say "KEEP=1, leaving the stack up (test/integration/run-tests.sh, then: ${COMPOSE[*]} down -v)"
    else
        say "tearing down"
        "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1
    fi
    exit "$rc"
}

# Dump both sides' logs when something fails; a PAM failure is usually only
# explicable from the broker log and the module's syslog output together.
dump_logs() {
    say "broker log"
    "${COMPOSE[@]}" logs --no-color --tail 80 broker
    say "fake GitHub log"
    "${COMPOSE[@]}" logs --no-color --tail 40 fakegithub
    say "sshd log"
    "${COMPOSE[@]}" logs --no-color --tail 40 client
}

run_case() {
    local name="$1"
    say "case: ${name}"
    if "${COMPOSE[@]}" exec -T client /opt/tests/cases.sh "$name"; then
        PASSED+=("$name")
    else
        FAILED+=("$name")
        dump_logs
    fi
}

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "the docker compose plugin is required" >&2; exit 1; }

trap cleanup EXIT INT TERM

say "building images"
"${COMPOSE[@]}" build || exit 1

say "starting the stack"
"${COMPOSE[@]}" up -d || exit 1

# The client cannot authenticate anything until the broker has bound its socket
# in the shared volume.
say "waiting for the broker socket"
for _ in $(seq 1 60); do
    if "${COMPOSE[@]}" exec -T client test -S /var/run/oauth2-pam/broker.sock 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
if [ "${ready:-0}" != 1 ]; then
    echo "the broker never created its socket" >&2
    dump_logs
    exit 1
fi

PASSED=()
FAILED=()

if [ "$#" -gt 0 ]; then
    for name in "$@"; do
        if [ "$name" = "broker_down" ]; then
            "${COMPOSE[@]}" stop broker >/dev/null
            run_case broker_down
            "${COMPOSE[@]}" start broker >/dev/null
        else
            run_case "$name"
        fi
    done
else
    for name in "${DEFAULT_CASES[@]}"; do
        run_case "$name"
    done

    # Last, because it takes the server side away.
    say "stopping the broker for the failure-mode case"
    "${COMPOSE[@]}" stop broker >/dev/null
    run_case broker_down
fi

say "summary"
for name in "${PASSED[@]:-}"; do [ -n "$name" ] && printf '    pass  %s\n' "$name"; done
for name in "${FAILED[@]:-}"; do [ -n "$name" ] && printf '    FAIL  %s\n' "$name"; done

if [ "${#FAILED[@]}" -gt 0 ]; then
    printf '\n%d of %d cases failed\n' "${#FAILED[@]}" "$(( ${#PASSED[@]} + ${#FAILED[@]} ))"
    exit 1
fi
printf '\nall %d cases passed\n' "${#PASSED[@]}"
