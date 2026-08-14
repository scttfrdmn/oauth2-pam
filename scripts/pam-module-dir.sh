#!/bin/sh
# Print the directory this system keeps its PAM modules in.
#
#   usage: PAMDIR=$(pam-module-dir.sh)
#
# /lib/security is right on RHEL and wrong on Debian/Ubuntu multiarch, where the
# modules are under /usr/lib/<triplet>/security. So ask the package manager where
# the system's own modules are rather than guessing — `make install` guessed, and
# guessed the RHEL answer, while the release installer three directories away was
# already asking.
#
# PAMDIR from the environment wins and is not second-guessed beyond having to
# exist: it is the escape hatch for a layout neither branch below knows about.

set -eu

if [ -n "${PAMDIR:-}" ]; then
    [ -d "$PAMDIR" ] || { echo "pam-module-dir: PAMDIR=$PAMDIR is not a directory" >&2; exit 1; }
    printf '%s\n' "$PAMDIR"
    exit 0
fi

dir=""
if command -v dpkg >/dev/null 2>&1; then
    # pam_permit.so belongs to libpam-modules on every Debian derivative, so
    # wherever dpkg says that file is, is where a PAM module goes.
    permit=$(dpkg -L libpam-modules 2>/dev/null | grep -m1 '/pam_permit\.so$' || true)
    [ -n "$permit" ] && dir=$(dirname "$permit")
fi
if [ -z "$dir" ]; then
    for d in /lib64/security /lib/security /usr/lib64/security /usr/lib/security; do
        [ -d "$d" ] && { dir="$d"; break; }
    done
fi

[ -n "$dir" ] || {
    echo "pam-module-dir: cannot find the PAM module directory; set PAMDIR= explicitly" >&2
    exit 1
}

printf '%s\n' "$dir"
