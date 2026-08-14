#!/usr/bin/env bash
# Mutation check for the C bridge tests.
#
#   test/cbridge/mutations.sh            native on Linux, in a container elsewhere
#   NATIVE=1 test/cbridge/mutations.sh   never use Docker (what CI does)
#
# A passing test suite proves the code does what the tests say. It does not prove
# the tests would notice if the code stopped doing it — and a regression test that
# cannot fail is worse than none, because it reads as protection.
#
# So each case here reintroduces one of the six defects test/cbridge/README.md
# lists, and asserts the suite *fails*. A mutation that goes uncaught means the
# test meant to pin that defect down is not pinning anything.
#
# Mutations are applied to a copy of the source under $TMPDIR. Nothing in the
# repository is touched, so an interrupted run leaves no half-mutated file behind.

# The mutations are perl, single-quoted so that $1 and $n reach perl rather than
# being expanded by the shell. That is what SC2016 warns about, and it is the point.
# shellcheck disable=SC2016

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

if [ "${NATIVE:-0}" != "1" ] && [ "$(uname -s)" != "Linux" ]; then
    command -v docker >/dev/null || {
        echo "the C tests need Linux-PAM headers: install Docker, or run this on Linux" >&2
        exit 1
    }
    echo "not Linux — running the mutation check in a container"
    exec docker run --rm -v "$PWD":/src -w /src debian:bookworm-slim bash -c '
        set -e
        apt-get update -qq >/dev/null
        apt-get install -y -qq --no-install-recommends \
            gcc libc6-dev libpam0g-dev libjson-c-dev perl >/dev/null
        NATIVE=1 test/cbridge/mutations.sh
    '
fi

CFLAGS=(-std=c11 -D_GNU_SOURCE -Wall -Wextra -Wconversion -Werror -g -O1)
LDLIBS=(-lpam -ljson-c)

WORK=$(mktemp -d "${TMPDIR:-/tmp}/cbridge-mutations.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

BRIDGE=cmd/pam-module/cgo_bridge_linux.c
mkdir -p "$WORK/cmd/pam-module" "$WORK/test/cbridge"
cp cmd/pam-module/cgo_bridge.h "$WORK/cmd/pam-module/"
cp test/cbridge/cbridge_test.c "$WORK/test/cbridge/"

failures=0

# run <name> <fail|pass> [perl-expression]
#
# "fail" is a mutation the suite must catch; "pass" is the unmutated baseline.
# The expression must set $n to the number of edits it made: a substitution that
# matched nothing would leave the source unmutated and the case vacuous, which is
# reported as a setup failure rather than a pass.
run() {
    local name=$1 expect=$2 expr=${3:-}

    cp "$BRIDGE" "$WORK/$BRIDGE"

    if [ -n "$expr" ]; then
        local edits
        perl -0777 -pe "$expr; END { print STDERR \$n }" \
             "$WORK/$BRIDGE" > "$WORK/mutated.c" 2>"$WORK/edits"
        mv "$WORK/mutated.c" "$WORK/$BRIDGE"
        edits=$(cat "$WORK/edits")
        if [ "${edits:-0}" -eq 0 ]; then
            echo "SETUP    $name — the mutation matched nothing; the source has moved"
            failures=$((failures + 1))
            return
        fi
    fi

    if ! gcc "${CFLAGS[@]}" -o "$WORK/cbridge_test" "$WORK/test/cbridge/cbridge_test.c" \
         "${LDLIBS[@]}" 2>"$WORK/build.log"; then
        # A mutation that will not compile is not evidence about the tests.
        echo "SETUP    $name — the mutated source does not compile"
        sed 's/^/    /' "$WORK/build.log" | head -10
        failures=$((failures + 1))
        return
    fi

    "$WORK/cbridge_test" >"$WORK/out" 2>&1
    local status=$?

    case "$expect" in
    pass)
        if [ "$status" -eq 0 ]; then
            echo "ok       $name"
        else
            echo "BROKEN   $name — the unmutated suite fails, exit $status"
            sed 's/^/    /' "$WORK/out" | tail -10
            failures=$((failures + 1))
        fi
        ;;
    fail)
        if [ "$status" -ne 0 ]; then
            # 141 is 128+13: the process was killed by SIGPIPE rather than
            # failing a check, which is the whole point of that case.
            local how="exit $status"
            [ "$status" -eq 141 ] && how="killed by SIGPIPE"
            echo "caught   $name ($how)"
            # Which assertion caught it, so an uninformative mutation is visible.
            grep 'FAIL ' "$WORK/out" | head -3 | sed 's/^ */           /'
        else
            echo "MISSED   $name — the suite passed with the defect reintroduced"
            failures=$((failures + 1))
        fi
        ;;
    esac
}

echo "==> baseline"
run "unmutated suite passes" pass

echo
echo "==> mutations, each of which must be caught"

# The SIGPIPE kill. Without MSG_NOSIGNAL, send() to a closed peer raises SIGPIPE,
# whose default disposition terminates the process — in production, sshd's
# pre-auth child. The test binary is killed rather than failing a check.
run "send() without MSG_NOSIGNAL" fail \
    '$n = s/(send\(sock, req_str \+ total, req_len - total,) MSG_NOSIGNAL/$1 0/g'

# The receive off-by-one: treating a full buffer as "too large" rejects a
# response that is exactly at the limit and complete.
run "a full buffer means too large" fail \
    '$n = s/(    filled = 1;\n)/$1    return -1;\n/g'

# The missing socket deadline. A zero SO_RCVTIMEO/SO_SNDTIMEO is no timeout at
# all, which is what the module had: a wedged broker held the login until sshd
# gave up on it. (`* 0` rather than deleting the call, so -Wunused-parameter does
# not turn the mutation into a compile error.)
run "no I/O timeout on the socket" fail \
    '$n = s/tv\.tv_sec  = seconds;/tv.tv_sec  = seconds * 0;/g'

# source_ip taking PAM_RHOST verbatim. Under `UseDNS yes` that is a hostname, and
# a long FQDN overruns the 45 bytes the broker allows — which makes it reject the
# whole request and fail the login.
run "source_ip takes any rhost" fail \
    '$n = s/(inet_pton\(AF_INET, rhost, v4\)) != 1 && (inet_pton\(AF_INET6, rhost, v6\)) != 1/$1 == 99 && $2 == 99/g'

# target_host taking the client's name: the original defect, where every audit
# record named the client as the host being logged into.
run "target_host takes rhost" fail \
    '$n = s/json_object_new_string\(target_host\)/json_object_new_string(rhost ? rhost : "")/g'

# source_ip left out of the request entirely, as the module used to send it: the
# field an investigator reads first, blank.
run "source_ip omitted from the request" fail \
    '$n = s/^.*json_object_object_add\(req, "source_ip".*\n//mg'

# A version check that accepts everything. This is the mutation that matters most
# for the wire contract: the reply still parses, so nothing looks wrong — the
# module simply reads "authorized" under a contract it does not implement.
run "any protocol version is acceptable" fail \
    '$n = s/return r->protocol_version == 0 \|\| r->protocol_version == PROTOCOL_VERSION;/return 1;/g'

# The request stops declaring its version, which is how the module would become
# invisible to a broker that starts enforcing one.
run "protocol_version omitted from requests" fail \
    '$n = s/^.*json_object_object_add\(req, "protocol_version".*\n//mg'

echo
if [ "$failures" -ne 0 ]; then
    echo "$failures case(s) failed — a regression test is not protecting what it claims to"
    exit 1
fi
echo "every mutation was caught"
