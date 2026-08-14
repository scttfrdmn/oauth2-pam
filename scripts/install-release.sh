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

[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo ./install.sh)"
[ "$(uname -s)" = "Linux" ] || die "the PAM module is Linux-only"

for f in oauth2_pam.so oauth2-pam-broker oauth2-pam-admin oauth2-pam-enroll; do
    [ -f "$f" ] || die "$f not found — run this from the unpacked archive directory"
done

# The module must export its entry points. A .so without them loads as nothing:
# PAM logs an error and the auth line behaves as though the module were absent.
if command -v nm >/dev/null 2>&1; then
    count=$(nm -D --defined-only oauth2_pam.so 2>/dev/null | grep -c ' pam_sm_' || true)
    [ "$count" -ge 6 ] || die "oauth2_pam.so exports $count pam_sm_* symbols, expected 6 — do not install this artifact"
fi

# /lib/security is right on RHEL and wrong on Debian/Ubuntu multiarch. Ask the
# package manager where the system's own modules live rather than guessing.
PAMDIR=""
if command -v dpkg >/dev/null 2>&1; then
    permit=$(dpkg -L libpam-modules 2>/dev/null | grep -m1 '/pam_permit\.so$' || true)
    [ -n "$permit" ] && PAMDIR=$(dirname "$permit")
fi
if [ -z "$PAMDIR" ]; then
    for d in /lib64/security /lib/security /usr/lib64/security /usr/lib/security; do
        [ -d "$d" ] && { PAMDIR="$d"; break; }
    done
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
    # | as the delimiter: base64 contains / but never |.
    sed -i "s|# token_encryption_key: \"paste the output of gen-key here\"|token_encryption_key: \"$key\"|" \
        "$CONFDIR/broker.yaml"
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
  5. Only then add the auth line to /etc/pam.d/sshd — with a second root
     session open, and a working key-based or console login available.
EOF
