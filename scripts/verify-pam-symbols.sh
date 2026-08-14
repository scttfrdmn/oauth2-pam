#!/bin/sh
# Verify that a built PAM module exports all six pam_sm_* entry points.
#
#   usage: verify-pam-symbols.sh path/to/oauth2_pam.so
#
# The gate exists because v0.1.1 published a .so with none of these symbols and
# nothing noticed for a month: PAM logs an error and the auth line behaves as
# though the module were absent, so the broken artifact looks like a working
# install. It lives in one file because it was asked three different ways in three
# places — the release workflow per symbol, `make build` and the installer as a
# count of lines containing "pam_sm_", which six occurrences of anything with that
# substring satisfy.
#
# Two rules this encodes, both learned from the loose versions:
#
#   - one grep per symbol, anchored on " T <sym>" at end of line, so a partial
#     match or the same symbol six times is not six entry points;
#   - no nm is a failure, not a pass. A build or install host that cannot answer
#     the question has not answered it, and this is the check standing between an
#     operator and an artifact PAM cannot load.

set -eu

fail() {
    # ::error:: under Actions, so moving the loop out of release.yml does not turn
    # its annotation into a line of log nobody reads.
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::error::$*"
    else
        echo "verify-pam-symbols: $*" >&2
    fi
}

SO="${1:-}"
[ -n "$SO" ] || { echo "usage: $0 path/to/oauth2_pam.so" >&2; exit 2; }

if [ ! -f "$SO" ]; then
    fail "$SO does not exist"
    exit 1
fi

if ! command -v nm >/dev/null 2>&1; then
    fail "nm not found, so the entry points in $SO cannot be verified — install binutils"
    exit 1
fi

missing=0
for sym in pam_sm_authenticate pam_sm_setcred pam_sm_acct_mgmt \
           pam_sm_open_session pam_sm_close_session pam_sm_chauthtok; do
    if ! nm -D --defined-only "$SO" | grep -q " T $sym\$"; then
        fail "MISSING ENTRY POINT: $sym"
        missing=$((missing + 1))
    fi
done

if [ "$missing" -ne 0 ]; then
    fail "$SO is missing $missing of the six pam_sm_* entry points; PAM cannot load it"
    exit 1
fi

echo "All six pam_sm_* entry points present in $SO."
