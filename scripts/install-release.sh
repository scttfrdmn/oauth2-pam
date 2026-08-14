#!/bin/sh
# Install oauth2-pam from a release archive. Run from the unpacked directory.
#
# This installs software that decides who gets a shell on this host. It does not
# touch /etc/pam.d — wiring the module into a PAM stack is a deliberate step you
# should take with a second root session already open, because a mistake there
# locks you out. See README.md and SECURITY.md.

set -eu

PREFIX="${PREFIX:-/usr/local}"
CONFDIR="${CONFDIR:-/etc/oauth2-pam}"

die() { echo "install: $*" >&2; exit 1; }

# Where this script's helpers sit: the top level of the unpacked archive, next to
# install.sh, and scripts/ in a source checkout. Both are "the directory this
# script is in".
HERE=$(dirname "$0")

[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo ./install.sh)"
[ "$(uname -s)" = "Linux" ] || die "the PAM module is Linux-only"

for f in oauth2_pam.so oauth2-pam-broker oauth2-pam-admin oauth2-pam-enroll; do
    [ -f "$f" ] || die "$f not found — run this from the unpacked archive directory"
done

# Check the archive this directory came out of, if it is still beside it. Every
# release publishes a .sha256 next to the tarball and until now nothing read it,
# which made it a file rather than a check.
#
# Verifying after the unpack is weaker than verifying before, which is why the
# README documents doing it first — but this is the check that runs on the host
# where nobody read the README, and a truncated or substituted download still
# fails it. It is not a signature: tarball and checksum come from the same place,
# so this says the bytes arrived intact, not who produced them (see #40).
archive="$(basename "$PWD").tar.gz"
if [ -f "../$archive" ] && [ -f "../$archive.sha256" ]; then
    command -v sha256sum >/dev/null 2>&1 \
        || die "sha256sum not found, so ../$archive cannot be verified — install coreutils"
    (cd .. && sha256sum -c "$archive.sha256" >/dev/null) \
        || die "$archive does not match its published sha256 — do not install this artifact"
    echo "Verified $archive against its published sha256."
else
    echo "Note: $archive and its .sha256 are not next to this directory, so the"
    echo "      download itself was not verified here. See \"Get the software\" in"
    echo "      README.md for the check to run before unpacking."
fi

# The module must export its entry points. A .so without them loads as nothing:
# PAM logs an error and the auth line behaves as though the module were absent.
#
# The same script the release workflow and `make build` run, and it fails when nm
# is absent instead of skipping: this is the last check between an operator and an
# artifact PAM cannot load, and it used to be the loosest of the three.
[ -f "$HERE/verify-pam-symbols.sh" ] \
    || die "verify-pam-symbols.sh is missing — unpack the whole archive and run install.sh from it"
"$HERE/verify-pam-symbols.sh" oauth2_pam.so \
    || die "do not install this artifact"

# /lib/security is right on RHEL and wrong on Debian/Ubuntu multiarch. Ask the
# package manager where the system's own modules live rather than guessing.
#
# A PAMDIR from the environment wins and is not second-guessed: it is the escape
# hatch the failure at the end of this block names, and until now an unconditional
# PAMDIR="" here threw it away before the discovery ever ran.
PAMDIR="${PAMDIR:-}"
if [ -n "$PAMDIR" ]; then
    [ -d "$PAMDIR" ] || die "PAMDIR=$PAMDIR is not a directory"
else
    if command -v dpkg >/dev/null 2>&1; then
        permit=$(dpkg -L libpam-modules 2>/dev/null | grep -m1 '/pam_permit\.so$' || true)
        [ -n "$permit" ] && PAMDIR=$(dirname "$permit")
    fi
    if [ -z "$PAMDIR" ]; then
        for d in /lib64/security /lib/security /usr/lib64/security /usr/lib/security; do
            [ -d "$d" ] && { PAMDIR="$d"; break; }
        done
    fi
fi
[ -n "$PAMDIR" ] || die "cannot find the PAM module directory; set PAMDIR= explicitly"

echo "Installing:"
echo "  PAM module -> $PAMDIR/oauth2_pam.so"
echo "  binaries   -> $PREFIX/bin"
echo "  config     -> $CONFDIR"

install -m 0644 -o root -g root oauth2_pam.so "$PAMDIR/oauth2_pam.so"
for b in oauth2-pam-broker oauth2-pam-admin oauth2-pam-enroll; do
    install -m 0755 -o root -g root "$b" "$PREFIX/bin/$b"
done

install -d -m 0750 -o root -g root "$CONFDIR"
if [ -f "$CONFDIR/broker.yaml" ]; then
    echo "  keeping existing $CONFDIR/broker.yaml"
else
    # 0600: this file holds the OAuth client secret in cleartext.
    install -m 0600 -o root -g root configs/example.yaml "$CONFDIR/broker.yaml"
    echo "  wrote $CONFDIR/broker.yaml from the example — edit it before starting the broker"

    # Fill in the encryption key now. Left unset, secure_token_storage does
    # nothing and access tokens sit in the broker's memory in the clear; and a
    # generated key beats whatever an administrator would type by ~200 bits.
    key=$("$PREFIX/bin/oauth2-pam-admin" gen-key) || die "gen-key failed"
    # The sed script arrives on stdin rather than in argv. /proc/<pid>/cmdline is
    # world-readable on Linux, so a key passed as an argument is recoverable by
    # any local user polling /proc for the length of the install — the one value
    # in this file whose entire purpose is to be secret, in a file installed 0600
    # two lines up. A here-document is a pipe (or an unlinked file) the shell owns.
    # | as the delimiter: base64 contains / but never |.
    sed -i -f - "$CONFDIR/broker.yaml" <<EOF
s|# token_encryption_key: "paste the output of gen-key here"|token_encryption_key: "$key"|
EOF
    if grep -q '^[[:space:]]*token_encryption_key:' "$CONFDIR/broker.yaml"; then
        echo "  generated a token_encryption_key"
    else
        echo "  WARNING: could not set token_encryption_key; run 'oauth2-pam-admin gen-key'"
        echo "           and paste the result into $CONFDIR/broker.yaml"
    fi
fi

if [ -d /etc/systemd/system ]; then
    install -m 0644 -o root -g root configs/systemd/oauth2-pam-broker.service \
        /etc/systemd/system/oauth2-pam-broker.service
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload
    echo "  installed the systemd unit (not enabled)"
fi

cat <<'EOF'

Installed. Nothing is running and no PAM stack has been changed yet.

Next:
  1. Edit the config — at minimum client_id, a mapper rule, and the client
     secret. The config is installed 0600 root-owned so an inline
     client_secret is accepted; to keep the secret out of the file, see
     client_secret_file and LoadCredential= in the config's comments.
  2. sudo systemctl enable --now oauth2-pam-broker
  3. oauth2-pam-admin status         # confirm the broker is answering
  4. oauth2-pam-admin test-auth --user YOUR_GITHUB_LOGIN
  5. Only then add the auth line to /etc/pam.d/sshd — "auth required", after
     the distribution's own auth stack, so this is a second factor rather than
     the whole decision. With a second root session open, and a working
     key-based or console login available. See "Configure PAM (SSH)" in
     README.md before you edit that file.
EOF
