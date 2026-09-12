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
# So each case here reintroduces one of the defects test/cbridge/README.md lists,
# and asserts the suite *fails*. A mutation that goes uncaught means the test meant
# to pin that defect down is not pinning anything.
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
mutations=0

# DOCUMENTED_MUTATIONS is the number README.md and SECURITY.md say this script
# reintroduces. Both said six for three releases while the real number grew to 25
# (#109), because nothing connected the prose to the script. The count is asserted at
# the end of the run: adding a case fails here until the two documents are updated,
# which is the only mechanism that keeps a number in prose honest.
DOCUMENTED_MUTATIONS=25

# run <name> <fail|pass> [perl-expression]
#
# "fail" is a mutation the suite must catch; "pass" is the unmutated baseline.
# The expression must set $n to the number of edits it made: a substitution that
# matched nothing would leave the source unmutated and the case vacuous, which is
# reported as a setup failure rather than a pass.
run() {
    local name=$1 expect=$2 expr=${3:-}

    [ "$expect" = "fail" ] && mutations=$((mutations + 1))

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

    # Capped, because the failure mode of a timeout defect is a suite that blocks
    # rather than one that fails: a mutation that removes a deadline can leave a
    # test waiting on a peer that will never speak, and without this the run wedges
    # instead of reporting. The honest suite finishes in a few seconds.
    timeout 120 "$WORK/cbridge_test" >"$WORK/out" 2>&1
    local status=$?

    if [ "$status" -eq 124 ]; then
        # Neither caught nor missed: the suite never answered, so this case is
        # evidence about nothing. Reported as a failure so it cannot pass as one.
        echo "HUNG     $name — the suite did not finish within 120s"
        failures=$((failures + 1))
        return
    fi

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

# The reply bounded per recv() again rather than as a whole. transfer_deadline
# failing means no budget to enforce, which is the state the module was in: a peer
# sending one byte just inside every SO_RCVTIMEO holds the login open per byte.
run "no deadline on the whole reply, only on each recv()" fail \
    '$n = s/(static int transfer_deadline\(int sock, int optname, struct timespec \*deadline\) \{\n)/$1    return -1;\n/g'

# Mutating apply_remaining to hand back *more* time than is left is deliberately
# not a case here: every version of it leaves a huge SO_RCVTIMEO on the socket, so
# the silent-peer test blocks instead of failing and the run hangs rather than
# reporting. The timeout wrapper in run() turns that into a HUNG failure rather
# than a wedged CI job, but a mutation that can only hang is evidence about the
# harness, not about the tests.

# source_ip taking PAM_RHOST verbatim. Under `UseDNS yes` that is a hostname, and
# a long FQDN overruns the 45 bytes the broker allows — which makes it reject the
# whole request and fail the login.
run "source_ip takes any rhost" fail \
    '$n = s/(inet_pton\(AF_INET, addr, v4\)) != 1 && (inet_pton\(AF_INET6, addr, v6\)) != 1/$1 == 99 && $2 == 99/g'

# The zone never split off, which is the bare-inet_pton behaviour: a link-local
# login is audited as origin-unknown, and docs/wire-protocol.md conformance item 8
# names the address it happens to.
run "source_ip validated without splitting the %zone" fail \
    "\$n = s/zone = strchr\\(rhost, '%'\\);/zone = NULL;/g"

# The zone taken on trust. inet_pton never sees it, so this is the only thing
# vetting the part of the value after the '%'.
run "the IPv6 zone is not validated" fail \
    '$n = s/(static int valid_zone_id\(const char \*s\) \{\n)/$1    return 1;\n/g'

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

# success read with json-c's coercing accessor. Any non-empty string and any
# non-zero number read as true, so "success":"false" would grant the login — a
# fail-open read of a conjunct authorized_for depends on.
run "success read with type coercion" fail \
    '$n = s/json_object_get_type\(success_obj\) != json_type_boolean/0/g'

# The grant decision itself, which until v0.4.0 no case here pointed at: both of
# the mutations below were green in every suite this repository has, which is what
# an authorization bypass looks like on the way in.
#
# authorized_for stops deciding anything. This is the client half of the two
# independent checks docs/wire-protocol.md specifies — delete it and the module
# acts on whatever a broker says "authorized" about, for whatever account.
run "authorized_for accepts every reply" fail \
    '$n = s/(static int authorized_for\(const struct broker_response \*r, const char \*username\) \{\n)/$1    return 1;\n/g'

# And the specific comparison inside it: the broker authorized somebody, but not
# the account this login is for.
run "authorized_for ignores which user was authorized" fail \
    '$n = s/if \(strcmp\(r->user_id, username\) != 0\) \{/if (0) {/g'

# terminal_status_to_pam stops mapping, so denied, expired and error all read as
# a successful login — the fail-open direction of the same decision.
run "every terminal status is a successful login" fail \
    '$n = s/(static int terminal_status_to_pam\(const struct broker_response \*r, const char \*username\) \{\n)/$1    return PAM_SUCCESS;\n/g'

# Only the unrecognized-status branch fails open. A status this module has never
# heard of is the one a future broker reaches first, and "unrecognized" is where
# "nothing wrong" is easiest to write by accident.
run "an unknown broker status grants the login" fail \
    '$n = s/(    log_pam_message\(LOG_ERR, "Unknown broker status .*\n.*\n)    return PAM_AUTH_ERR;/$1    return PAM_SUCCESS;/g'

# The "error" status losing its own branch, so RATE_LIMITED, AUTH_LIMIT_REACHED and
# SESSION_LIMIT_REACHED all fall through to the unknown-status branch and report
# PAM_AUTH_ERR. Not a fail-open, which is why a suite asserting only "no terminal
# status is a login" would call it equivalent — it is a host that is busy, or a user
# who is already logged in as often as the operator allows, told that their
# credential was wrong.
run "a capacity refusal is reported as a bad credential" fail \
    '$n = s/if \(strcmp\(r->status, STATUS_ERROR\) == 0\) \{/if (0) {/'

# The account stage (issue #75). Its whole reason to exist is that authorization can
# be withdrawn after authentication succeeded, so every mutation below is a version
# of the stage this module shipped before: one that answers "fine, decided earlier".
#
# A login this module did not authenticate answering PAM_SUCCESS instead of
# PAM_IGNORE. This is the fail-open shape of the stage, and it is worse than it
# looks: `account required oauth2_pam.so` in a stack would then approve every
# account on the host, including logins that never went near a device flow.
run "a login with no session of ours is approved" fail \
    '$n = s/        return PAM_IGNORE;/        return PAM_SUCCESS;/g'

# The mapping stops mapping: denied, expired, a revoked session and a status from
# a contract this module does not implement all become a valid login.
run "every account status is a valid login" fail \
    '$n = s/(static int account_status_to_pam\(const struct broker_response \*r, const char \*username\) \{\n)/$1    return PAM_SUCCESS;\n/g'

# The username verification dropped from the account path — the auth-stage bypass
# one stage later. The broker's session is genuinely authorized; it just belongs to
# somebody else. This is what reusing authorized_for is for, and this mutation is
# what proves the reuse is load-bearing rather than decorative.
run "the account stage ignores which user the session belongs to" fail \
    '$n = s/if \(authorized_for\(r, username\)\) \{/if (1) {/g'

# A refusal reported as PAM_AUTH_ERR rather than PAM_PERM_DENIED. Both are
# failures, so a suite that only asserted "not success" would call this equivalent
# — it is not: PAM_AUTH_ERR tells sshd the credential was wrong, and sshd's answer
# to that is to offer the user another attempt at a session that has been revoked.
run "the account stage reports a revoked session as a bad password" fail \
    '$n = s/return PAM_PERM_DENIED;/return PAM_AUTH_ERR;/g'

# A broker that cannot be reached at the account stage treated as a pass. Nothing
# answered, so there is nothing to be reassured by.
run "an unverifiable session is approved" fail \
    '$n = s/(Could not re-check the session.*?)return PAM_AUTHINFO_UNAVAIL;/$1return PAM_SUCCESS;/s'

# The QR code at the login prompt. Since the #56 fix the art travels in its own
# wire field, and these are the two ways it stops reaching the screen.
#
# The field never read, which is the regression itself: the module renders
# instructions alone and the QR code silently disappears from every login. The key
# is renamed rather than the call deleted, because deleting it leaves
# copy_json_block defined and uncalled, and -Werror turns that into a compile error
# instead of a mutation.
run "the qr_code field is never read" fail \
    '$n = s/copy_json_block\(root, "qr_code"/copy_json_block(root, "not_a_field"/g'

# The caption emitted whether or not there is art under it. A dangling "Scan QR
# code with your phone:" above the Enter prompt is worse than saying nothing: the
# user waits for a code that is not coming.
run "the QR caption is printed with no art under it" fail \
    "\$n = s/if \\(r->qr_code\\[0\\] != '\\\\0'\\) \\{/if (1) {/g"

# The module's own bound on the art turned into a truncating copy. Half a QR symbol
# is not scannable, and a partial box reads as a rendering bug rather than as "no QR
# code here" — which is a case the prompt already handles correctly.
run "oversized QR art is truncated rather than dropped" fail \
    '$n = s/(if \(len >= dst_size\) \{).*?return;/$1 len = dst_size - 1; memcpy(dst, val, len); dst[len] = 0; return;/s'

echo
if [ "$mutations" -ne "$DOCUMENTED_MUTATIONS" ]; then
    echo "this script reintroduces $mutations defects; README.md and SECURITY.md say" \
         "$DOCUMENTED_MUTATIONS. Update both, and DOCUMENTED_MUTATIONS above, so the" \
         "documented count is the real one (#109)."
    failures=$((failures + 1))
fi
if [ "$failures" -ne 0 ]; then
    echo "$failures case(s) failed — a regression test is not protecting what it claims to"
    exit 1
fi
echo "every mutation was caught ($mutations of them)"
