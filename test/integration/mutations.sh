#!/usr/bin/env bash
# Mutation check for the container harness: does it still catch the defects it
# exists to catch?
#
#   test/integration/mutations.sh
#
# The harness is the only thing in this repository that exercises the module's PAM
# entry points — real sshd, real PAM stack, real broker over a real socket. Its most
# important claims are negative: a device flow nobody approved must not be a login,
# and an account the module knows nothing about must not be approved. Negative
# assertions are exactly the kind that rot into passing for the wrong reason, so this
# reintroduces each defect and insists the harness notices.
#
# Both mutations live in code no unit test can reach. The first is inside
# pam_sm_authenticate; the second is behind pam_get_data, which refuses to run
# outside a service module — so the C suite can test the decision function but not
# the storage path feeding it. That gap is why this file exists.
#
# Cost: one image rebuild per mutation plus a few cases, a few minutes each. There is
# no baseline run here — `make test-integration` is the baseline, and CI runs it in a
# separate job on every push, so repeating it would double the cost for no new
# information.
#
# Each mutation is applied to a fresh copy of the tree under $TMPDIR; the working
# tree is never modified. Do not run this while a healthy harness stack is up: they
# share the `oauth2-pam-harness-*` image tags.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

FAILURES=0

# run_mutation <description> <mutate-fn> <case>...
#
# mutate-fn is called with the path to the copied tree and must exit non-zero if its
# edit matched nothing — a mutation that silently fails to apply would report a
# "caught" that proves nothing.
run_mutation() {
    local desc="$1" mutate="$2"; shift 2
    local cases=("$@")

    local work
    work=$(mktemp -d "${TMPDIR:-/tmp}/integration-mutations.XXXXXX") || return 1

    echo
    echo "===================================================================="
    echo "==> mutation: $desc"
    echo "==> copying the tree to $work"
    tar --exclude=./.git --exclude=./bin -cf - . | tar -xf - -C "$work" || {
        rm -rf "$work"; return 1
    }

    if ! "$mutate" "$work"; then
        echo "SETUP FAILED: the mutation matched nothing; the code it targets has moved" >&2
        rm -rf "$work"
        FAILURES=$((FAILURES + 1))
        return 1
    fi

    echo "==> running the harness with the defect in place: ${cases[*]}"
    echo "    (failures below are the point; a pass is the problem)"
    "$work/test/integration/run-tests.sh" "${cases[@]}" >"$work/out" 2>&1
    local status=$?

    echo
    if [ "$status" -eq 0 ]; then
        echo "MISSED — the harness passed with the defect reintroduced."
        echo "None of ${cases[*]} is pinning this down."
        echo "Full output:"
        sed 's/^/    /' "$work/out"
        rm -rf "$work"
        FAILURES=$((FAILURES + 1))
        return 1
    fi

    # Which cases failed, so a harness that broke for an unrelated reason (a build
    # error, say) is not mistaken for one that caught the mutation.
    if grep -qE '^ +FAIL  ' "$work/out"; then
        grep -E '^ +(pass|FAIL)  ' "$work/out"
        echo
        echo "caught — $desc"
    else
        echo "the harness exited $status without reporting case results — check that it"
        echo "failed because of the mutation and not because the stack would not build:"
        tail -30 "$work/out" | sed 's/^/    /'
        rm -rf "$work"
        FAILURES=$((FAILURES + 1))
        return 1
    fi

    rm -rf "$work"
}

# ------------------------------------------------------------------ mutation 1

# v0.1.0 and v0.1.1 returned PAM_SUCCESS as soon as the broker said the device flow
# had started, before the user had approved anything. With the `auth sufficient` line
# those releases documented, that is an unauthenticated login as any requested
# username. Inserted at the point phase 1 hands off to phase 2, so the mutated module
# never prompts, never polls, and never learns whether the user approved.
mutate_auth_bypass() {
    local bridge="$1/cmd/pam-module/cgo_bridge_linux.c"
    local n
    n=$(perl -0777 -i -pe '
        $n = s{(    /\* A started device flow is never an authenticated user)}
              {    if (strcmp(r->status, STATUS_PENDING) == 0) \{\n        free(r);\n        return PAM_SUCCESS;\n    \}\n\n$1};
        END { print STDERR $n }
    ' "$bridge" 2>&1 >/dev/null)
    [ "$n" = "1" ]
}

# ------------------------------------------------------------------ mutation 2

# pam_sm_acct_mgmt answers PAM_IGNORE when it has no stored session id — it is being
# asked about a login it did not authenticate, and "not my business" is the only
# honest answer. PAM_SUCCESS there is fail-open, and fail-open in the stacked
# configuration a real deployment is most likely to have: oauth2_pam.so doing account
# management alongside a different factor for auth.
#
# This is the mutation the C suite cannot catch. The decision function is unit-tested,
# but whether the id was ever *stored* depends on pam_set_data/pam_get_data, which
# only work inside a service module.
mutate_acct_fail_open() {
    local bridge="$1/cmd/pam-module/cgo_bridge_linux.c"
    local n
    n=$(perl -0777 -i -pe '
        $n = s{\n(        )return PAM_IGNORE;}{\n$1return PAM_SUCCESS;};
        END { print STDERR $n }
    ' "$bridge" 2>&1 >/dev/null)
    [ "$n" = "1" ]
}

# ------------------------------------------------------------------ run

run_mutation "the harness refuses the login the v0.1.x module would have granted" \
    mutate_auth_bypass never_authorized denied_by_github

run_mutation "the harness refuses an account the module cannot vouch for" \
    mutate_acct_fail_open account_stage_ignores_a_login_it_did_not_authenticate

echo
echo "===================================================================="
if [ "$FAILURES" -ne 0 ]; then
    echo "$FAILURES mutation(s) were MISSED by the harness"
    exit 1
fi
echo "every mutation was caught"
