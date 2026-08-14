#!/usr/bin/env bash
# Compile and run the C unit tests for the PAM module bridge.
#
#   test/cbridge/run.sh            native on Linux, in a container elsewhere
#   NATIVE=1 test/cbridge/run.sh   never use Docker (what CI does)
#
# The module's C only builds against Linux-PAM, so on a Mac this delegates to a
# Debian container — the same arrangement `make docker-build-pam` uses.

set -euo pipefail

cd "$(dirname "$0")/../.." || exit 1

SRC=test/cbridge/cbridge_test.c
BIN=${TMPDIR:-/tmp}/cbridge_test

# -Wconversion is on deliberately: this file does socket and buffer arithmetic
# with a mixture of ssize_t, size_t and int, which is exactly where an implicit
# narrowing turns a bounds check into a no-op.
CFLAGS=(-std=c11 -D_GNU_SOURCE -Wall -Wextra -Wconversion -Werror -g -O1)
LDLIBS=(-lpam -ljson-c)

compile_and_run() {
    gcc "${CFLAGS[@]}" -o "$BIN" "$SRC" "${LDLIBS[@]}"
    "$BIN"
}

if [ "${NATIVE:-0}" = "1" ] || [ "$(uname -s)" = "Linux" ]; then
    compile_and_run
    exit $?
fi

command -v docker >/dev/null || {
    echo "the C tests need Linux-PAM headers: install Docker, or run this on Linux" >&2
    exit 1
}

echo "not Linux — running the C tests in a container"
exec docker run --rm -v "$PWD":/src -w /src debian:bookworm-slim bash -c '
    set -e
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends gcc libc6-dev libpam0g-dev libjson-c-dev >/dev/null
    NATIVE=1 test/cbridge/run.sh
'
