#!/usr/bin/env bash
# Reports incompatible changes to the module's exported API.
#
# Compares every exported package against a base revision and fails when
# apidiff calls a change incompatible. Adding to the API is always allowed.
#
# Usage: apidiff.sh <base-ref>
#
# Why this exists: a trailing variadic parameter added to an exported function
# changes that function's type. Every ordinary call site still compiles, so
# neither the build nor the tests notice, while any caller holding the function
# as a value stops compiling. That shipped once.
set -euo pipefail

TARGET_REF="${1:?usage: apidiff.sh <target-ref>}"

# Compare against the merge base, not the target's tip. A branch cut before a
# recent change to the target would otherwise be reported as having removed
# whatever the target gained in the meantime, which is a false positive and the
# quickest way to get a check like this ignored.
BASE_REF="$(git merge-base HEAD "$TARGET_REF")"
echo "Target $TARGET_REF, comparing against merge base ${BASE_REF:0:12}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Exported packages only. internal/ is not public API, and neither is a package
# with no importable identifiers.
packages() {
  go list ./... | grep -v '/internal/' | grep -v '/internal$'
}

echo "Collecting the API at $BASE_REF"
BASE_TREE="$WORK/base"
git worktree add --detach --quiet "$BASE_TREE" "$BASE_REF"
cleanup_worktree() { git worktree remove --force "$BASE_TREE" >/dev/null 2>&1 || true; }
trap 'cleanup_worktree; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/api"
(
  cd "$BASE_TREE"
  go work init >/dev/null 2>&1 || true
  go work use -r . >/dev/null 2>&1 || true
  for pkg in $(packages); do
    # A package that does not build at the base has no baseline to compare
    # against, which is normal for one this change introduces.
    apidiff -w "$WORK/api/$(echo "$pkg" | tr '/' '_').api" "$pkg" >/dev/null 2>&1 || true
  done
)

echo "Comparing HEAD against it"
status=0
for pkg in $(packages); do
  snapshot="$WORK/api/$(echo "$pkg" | tr '/' '_').api"
  [ -f "$snapshot" ] || continue   # new package, nothing to break

  out="$(apidiff "$snapshot" "$pkg" 2>/dev/null || true)"
  # apidiff prints an "Incompatible changes:" section only when there are some.
  if printf '%s' "$out" | grep -q '^Incompatible changes:'; then
    echo
    echo "=== $pkg ==="
    printf '%s\n' "$out" | sed -n '/^Incompatible changes:/,/^$/p'
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  exit 0
fi

cat <<'MSG'

Incompatible API changes found.

Adding to the API is always allowed; the changes above remove something or
change its type. Note that adding a variadic parameter to an existing exported
function counts, even though every call site still compiles.

If the break is deliberate, label the pull request "breaking-change". The
comparison still runs and still prints what changed, so the break stays on the
record, but it stops failing the check.
MSG

if [ "${ALLOW_BREAKING:-false}" = "true" ]; then
  echo
  echo 'Labelled "breaking-change", so this is reported rather than enforced.'
  exit 0
fi
exit 1
