#!/usr/bin/env bash
# Cut a release: stamp the README badge, roll [Unreleased] into a dated section,
# commit, tag, and (after confirmation) push.
#
# The Release workflow re-checks that the tag, the README badge and the CHANGELOG
# all agree. This script exists so that check is never the thing that tells you
# they don't.
#
#   scripts/release.sh 0.3.0        # leading 'v' optional

set -euo pipefail

die() { echo "release: $*" >&2; exit 1; }

[ $# -eq 1 ] || die "usage: scripts/release.sh <version>   e.g. 0.3.0"

VERSION="${1#v}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] \
    || die "'$VERSION' is not a semver version"
TAG="v$VERSION"

cd "$(dirname "$0")/.."

[ -z "$(git status --porcelain)" ] || die "working tree is dirty; commit or stash first"
[ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || die "not on main"
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "$TAG already exists"

grep -q '^## \[Unreleased\]' CHANGELOG.md \
    || die "CHANGELOG.md has no '## [Unreleased]' section to roll"

# Refuse to cut a release whose Unreleased section is empty — an empty section
# means the changes were never written down, and the release notes come from here.
if ! awk '/^## \[Unreleased\]/{f=1;next} /^## \[/{f=0} f && NF && !/^###/ {found=1} END{exit !found}' CHANGELOG.md; then
    die "the [Unreleased] section is empty; write the entries first"
fi

echo "Releasing $TAG"

# 1. README version badge.
if grep -q 'badge/version-' README.md; then
    perl -pi -e "s#badge/version-[^)]+-blue#badge/version-$VERSION-blue#" README.md
else
    die "README.md has no version badge; the Release workflow's check needs one"
fi

# 2. Roll [Unreleased] into a dated section, leaving a fresh empty one behind.
DATE="$(date -u +%Y-%m-%d)"
perl -0pi -e "s{^## \[Unreleased\]\n}{## [Unreleased]\n\n## [$VERSION] - $DATE\n}m" CHANGELOG.md

# 3. Show the operator what will be published before anything is committed.
echo
echo "--- release notes for $TAG ---"
awk -v v="$VERSION" '
  $0 ~ "^## \\[" v "\\]" { inside = 1; next }
  inside && /^## \[/      { exit }
  inside                  { print }
' CHANGELOG.md
echo "--- end ---"
echo

git --no-pager diff --stat
read -r -p "Commit, tag $TAG and push? [y/N] " reply
[ "$reply" = "y" ] || [ "$reply" = "Y" ] || { git checkout -- README.md CHANGELOG.md; die "aborted"; }

git add README.md CHANGELOG.md
git commit -m "chore(release): $TAG"
git tag -a "$TAG" -m "oauth2-pam $TAG"
git push origin main
git push origin "$TAG"

echo
echo "Pushed $TAG. The Release workflow verifies the version, builds amd64 and"
echo "arm64, checks the .so exports its six pam_sm_* entry points, and publishes."
echo "  gh run watch"
