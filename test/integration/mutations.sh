#!/usr/bin/env bash
# Mutation check for the container harness: does it still catch the v0.1.x auth
# bypass?
#
#   test/integration/mutations.sh
#
# The harness is the only thing in this repository that exercises
# pam_sm_authenticate — real sshd, real PAM stack, real broker over a real socket.
# Its most important claim is negative: a device flow that nobody ever approves
# must not be a login. A negative assertion is exactly the kind that can rot into
# passing for the wrong reason, so this reintroduces the v0.1.x defect and insists
# the harness notices.
#
# The defect: v0.1.0 and v0.1.1 returned PAM_SUCCESS as soon as the broker said
# the device flow had started, before the user had approved anything. With the
# `auth sufficient` line those releases documented, that is an unauthenticated
# login as any requested username.
#
# Cost: one image rebuild plus two cases, a few minutes. There is no baseline run
# here — `make test-integration` is the baseline, and CI runs it in a separate job
# on every push, so repeating it would double the cost for no new information.
#
# The mutation is applied to a copy of the tree under $TMPDIR; the working tree is
# never modified. Do not run this while a healthy harness stack is up: the two
# share the `oauth2-pam-harness-*` image tags.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/integration-mutations.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

echo "==> copying the tree to $WORK"
tar --exclude=./.git --exclude=./bin -cf - . | tar -xf - -C "$WORK" || exit 1

BRIDGE="$WORK/cmd/pam-module/cgo_bridge_linux.c"

# Insert the v0.1.x behaviour at the point phase 1 hands off to phase 2: a
# pending reply becomes PAM_SUCCESS, so the module never prompts, never polls, and
# never learns whether the user approved.
echo "==> reintroducing the v0.1.x bypass"
perl -0777 -i -pe '
    $n = s{(    /\* A started device flow is never an authenticated user)}
          {    if (strcmp(r->status, STATUS_PENDING) == 0) \{\n        free(r);\n        return PAM_SUCCESS;\n    \}\n\n$1};
    END { print STDERR $n }
' "$BRIDGE" 2>"$WORK/edits"
if [ "$(cat "$WORK/edits")" != "1" ]; then
    echo "SETUP FAILED: the mutation matched nothing; pam_sm_authenticate has moved" >&2
    exit 1
fi

# never_authorized: the user is prompted and never approves, so the login must be
#   refused — this is the bypass case itself.
# denied_by_github: the user actively declines, which the mutated module never
#   even asks about.
CASES=(never_authorized denied_by_github)

echo "==> running the harness with the bypass in place: ${CASES[*]}"
echo "    (failures below are the point; a pass is the problem)"
"$WORK/test/integration/run-tests.sh" "${CASES[@]}" >"$WORK/out" 2>&1
status=$?

echo
if [ "$status" -eq 0 ]; then
    echo "MISSED — the harness passed with the v0.1.x auth bypass reintroduced."
    echo "Neither ${CASES[*]} is pinning down 'a started device flow is not a login'."
    echo "Full output:"
    sed 's/^/    /' "$WORK/out"
    exit 1
fi

# Which cases failed, so a harness that broke for an unrelated reason (a build
# error, say) is not mistaken for one that caught the bypass.
if grep -qE '^ +FAIL  ' "$WORK/out"; then
    grep -E '^ +(pass|FAIL)  ' "$WORK/out"
else
    echo "the harness exited $status without reporting case results — check that it"
    echo "failed because of the mutation and not because the stack would not build:"
    tail -30 "$WORK/out" | sed 's/^/    /'
    exit 1
fi

echo
echo "caught — the harness refuses the login the v0.1.x module would have granted"
