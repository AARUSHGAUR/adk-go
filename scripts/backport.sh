#!/usr/bin/env bash
#
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Backport merged `main` pull requests onto the `v1` maintenance branch.
#
# Workflow: a PR into `main` is labelled `v2` when it also needs to ship to
# 1.x (`v2-only` means it does not). This script drains that queue: it replays
# each merged PR's squash commit onto `v1` and opens a single backport PR.
#
# The one systematic obstacle is the module path: `main` is
# `google.golang.org/adk/v2`, `v1` is `google.golang.org/adk`, so every Go
# file's import block differs and a plain `git cherry-pick` conflicts on any
# patch that touches imports. That difference is a pure string rewrite, so the
# patch is rewritten before it is applied and the common case lands cleanly.
# Genuine semantic drift still conflicts, and is left for a human to resolve.
#
# Work happens in a throwaway worktree, so the current checkout is untouched.

set -euo pipefail

readonly REPO="${ADK_REPO:-google/adk-go}"
readonly MAIN_BRANCH="main"
readonly V1_BRANCH="v1"
readonly V2_MODULE="google.golang.org/adk/v2"
readonly V1_MODULE="google.golang.org/adk"

# Labels. `v2` marks a merged main PR as needing a 1.x equivalent and is what
# the queue reads; `v1` marks a PR that targets the maintenance branch and goes
# on the ones this script opens. Named separately from the branches above,
# which they only coincidentally match.
readonly V2_LABEL="v2"
readonly V1_LABEL="v1"

# How long to wait for CI to register on a new PR before reporting it missing.
readonly CHECKS_TIMEOUT="${ADK_CHECKS_TIMEOUT:-120}"

# Options.
list_only=false
take_all=false
open_pr=false
skip_gomod=false
watch_checks=false
force=false
branch=""
worktree=""
prs=()

usage() {
  cat <<'EOF'
Backport merged `main` pull requests onto the `v1` maintenance branch.

Usage:
  scripts/backport.sh --list                 Show the pending backport queue.
  scripts/backport.sh 1301 1302              Backport specific PRs.
  scripts/backport.sh --all                  Backport everything pending.
  scripts/backport.sh --all --pr             ... and push + open the v1 PR.

Options:
  -l, --list          List merged `main` PRs labelled `v2` that are not on `v1`
                      yet, then exit.
  -a, --all           Backport every PR in the pending queue, oldest first.
  -p, --pr            Push the branch and open the backport PR. Without this
                      the commits are just left in a local worktree for review.
                      Afterwards the script confirms CI registered on the PR,
                      and says how to re-fire it if it somehow did not.
  -w, --watch         With --pr, block until the checks finish rather than
                      just confirming they started.
      --branch NAME   Branch to create (default: backport/v1/pr-N for a single
                      PR, backport/v1/batch-YYYYMMDD for several).
      --worktree DIR  Where to place the scratch worktree
                      (default: $TMPDIR/adk-backport/<branch>).
      --force         Backport a PR even if it already looks present on v1.
      --skip-gomod    Drop go.mod / go.sum hunks from each patch. Useful when
                      backporting code around a dependency bump that does not
                      apply to the 1.x dependency set.
  -h, --help          Show this help.

The queue is derived from labels, and clears itself: a PR drops off once its
number is referenced by a commit on `v1` or by an open PR targeting `v1`.

Requires the `gh` CLI, authenticated (`gh auth login`).
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

info() { echo "==> $*"; }
warn() { echo "warning: $*" >&2; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
}

# Prints the name of the git remote pointing at $REPO.
detect_remote() {
  if [[ -n "${ADK_REMOTE:-}" ]]; then
    echo "${ADK_REMOTE}"
    return
  fi
  local remote
  while read -r remote _; do
    local url
    url="$(git remote get-url "${remote}")"
    # Matches both git@github.com:google/adk-go.git and https URLs.
    if [[ "${url}" == *"${REPO}"* ]]; then
      echo "${remote}"
      return
    fi
  done < <(git remote -v | awk '$3 == "(fetch)"')
  die "no git remote points at ${REPO}; set ADK_REMOTE to choose one"
}

# Prints the "owner" of a remote's GitHub URL, for both SSH and HTTPS forms.
remote_owner() {
  git remote get-url "$1" |
    sed -E 's#(\.git)?/?$##; s#^.*github\.com[:/]([^/]+)/[^/]+$#\1#'
}

# Waits for CI to register on a freshly opened PR and prints what it finds.
#
# Workflows do fire here: the `pull_request` triggers in go.yml and apidiff.yml
# filter on the *base* branch, and v1 is listed. The rule that suppresses
# workflow runs applies only to the built-in GITHUB_TOKEN, which is why the
# workflow insists on a PAT or App token instead and why running this by hand
# is fine. Either way it is checked rather than assumed, because a backport
# that cannot show green CI cannot be merged.
confirm_checks() {
  local pr="$1"
  local deadline=$((SECONDS + CHECKS_TIMEOUT))
  local out=""

  info "waiting up to ${CHECKS_TIMEOUT}s for workflows to register on PR #${pr}"
  while ((SECONDS < deadline)); do
    # Read stdout only. A PR with no checks yet, and a PR number that does not
    # resolve at all, both report on stderr and leave stdout empty; scraping
    # the combined stream would mistake an API error for a live check run.
    out="$(gh pr checks "${pr}" --repo "${REPO}" --json name,state 2>/dev/null || true)"
    if [[ "${out}" == \[{* ]]; then
      gh pr checks "${pr}" --repo "${REPO}" || true
      if [[ "${watch_checks}" == true ]]; then
        info "watching until the checks finish"
        gh pr checks "${pr}" --repo "${REPO}" --watch || true
      fi
      return 0
    fi
    sleep 5
  done

  warn "no workflow runs registered on PR #${pr} within ${CHECKS_TIMEOUT}s"
  cat >&2 <<EOF

  Nothing has gone wrong with the backport itself, but the PR cannot be merged
  until CI reports. To re-fire the pull_request event:

    gh pr close ${pr} --repo ${REPO} && gh pr reopen ${pr} --repo ${REPO}

  A 'reopened' event re-runs the workflows. Pushing another commit to the
  branch works too. If runs still do not appear, check whether the repository
  requires approval before running workflows on this PR.
EOF
  return 1
}

# Prints every PR number already backported to v1, one per line. Covers landed
# commits and in-flight backport PRs alike, so a queued PR disappears as soon as
# someone picks it up.
#
# Only the places that actually *record* a backport are read: the commit
# subject, where GitHub's squash puts "(#N)" and where a batched backport lists
# every number it carries, and the "* subject (#N)" bullets a squash leaves in
# the body for the commits it folded in. Bodies are otherwise prose and full of
# numbers that mean something else — "Fixes google/adk-go#1152" names an issue,
# and one v1 commit explains it bumped dependencies "rather than a cherry-pick
# of main's Dependabot commits (#1021, #1144, ...)", naming seven PRs precisely
# because they were *not* backported. Matching those would silently drop a real
# fix from the queue, which is the one failure this tool must not have.
backported_prs() {
  local remote="$1" base open_titles
  local bullet='^[[:space:]]*\*[[:space:]].*\(#[0-9]+\)[[:space:]]*$'
  base="$(git merge-base "${remote}/${MAIN_BRANCH}" "${remote}/${V1_BRANCH}")"

  # Fetched up front so a failure here stops the run. Folded into the group
  # below it would be swallowed by the trailing `|| true`, and an exclusion set
  # that is quietly short opens duplicate pull requests -- unattended, nightly,
  # with nobody watching.
  # Titles only: every PR this script opens carries its numbers there, in the
  # trailing "(#N)" of a single backport or the "(#a, #b, #c)" of a batch.
  open_titles="$(gh pr list --repo "${REPO}" --base "${V1_BRANCH}" --state open \
    --limit 200 --json title --jq '.[].title')" ||
    die "could not list open ${V1_BRANCH} pull requests; refusing to guess at what is already backported"

  {
    git log --format='%s' "${base}..${remote}/${V1_BRANCH}"
    git log --format='%b' "${base}..${remote}/${V1_BRANCH}" | grep -E "${bullet}" || true
    printf '%s\n' "${open_titles}"
  } | grep -oE '#[0-9]+' | tr -d '#' || true
}

# Prints "number<TAB>title" for each pending PR, oldest merge first.
pending_queue() {
  local remote="$1"
  local done_file
  done_file="$(mktemp)"
  # shellcheck disable=SC2064  # Expand the path now, not at trap time.
  trap "rm -f '${done_file}'" RETURN
  backported_prs "${remote}" | sort -u >"${done_file}"

  gh pr list --repo "${REPO}" --base "${MAIN_BRANCH}" --state merged \
    --label "${V2_LABEL}" --limit 200 \
    --json number,title,mergedAt \
    --jq 'sort_by(.mergedAt)[] | "\(.number)\t\(.title)"' |
    while IFS=$'\t' read -r number title; do
      grep -qx "${number}" "${done_file}" || printf '%s\t%s\n' "${number}" "${title}"
    done
}

# Replays one PR's squash commit into the current worktree.
# Usage: apply_pr <pr-number> <worktree-dir>
apply_pr() {
  local pr="$1" dir="$2"
  local sha subject author date

  sha="$(gh pr view "${pr}" --repo "${REPO}" --json mergeCommit \
    --jq '.mergeCommit.oid // empty')"
  [[ -n "${sha}" ]] || die "PR #${pr} has no merge commit; is it merged?"

  git -C "${dir}" cat-file -e "${sha}^{commit}" 2>/dev/null ||
    die "commit ${sha} for PR #${pr} is not in this clone; fetch and retry"

  subject="$(git -C "${dir}" log -1 --format=%s "${sha}")"
  info "PR #${pr}: ${subject}"

  local -a pathspec=()
  if [[ "${skip_gomod}" == true ]]; then
    pathspec=(-- . ':(exclude)go.mod' ':(exclude)go.sum'
      ':(exclude)*/go.mod' ':(exclude)*/go.sum')
  fi

  local patch
  patch="$(mktemp)"
  # shellcheck disable=SC2064
  trap "rm -f '${patch}'" RETURN

  # `main` squash commits always have a single parent, so `git show` is the
  # whole change. Rewriting the module path makes the context lines match the
  # v1 tree, which is what lets the patch apply directly.
  git -C "${dir}" show --binary --format= "${sha}" "${pathspec[@]}" |
    sed "s|${V2_MODULE}|${V1_MODULE}|g" >"${patch}"

  if [[ ! -s "${patch}" ]]; then
    warn "PR #${pr} produced an empty patch; skipping"
    return 0
  fi

  author="$(git -C "${dir}" log -1 --format='%an <%ae>' "${sha}")"
  date="$(git -C "${dir}" log -1 --format=%aD "${sha}")"

  local message
  message="$(git -C "${dir}" log -1 --format=%B "${sha}" |
    sed "s|${V2_MODULE}|${V1_MODULE}|g")"
  message="${message}
(cherry picked from commit ${sha})"

  if git -C "${dir}" apply --index "${patch}" 2>/dev/null; then
    git -C "${dir}" commit --quiet --author="${author}" --date="${date}" \
      --message="${message}"
    info "  applied cleanly"
    return 0
  fi

  # Fall back to a partial apply so the human gets .rej files to work from
  # rather than an all-or-nothing failure.
  warn "PR #${pr} does not apply cleanly; leaving conflicts for manual fixup"
  git -C "${dir}" apply --reject "${patch}" || true

  cat >&2 <<EOF

  The patch was applied where it could be. To finish this one:

    cd ${dir}
    # resolve the *.rej files, then:
    git add -A
    git commit --author='${author}' --date='${date}' -m '<original message>
(cherry picked from commit ${sha})'

  Then re-run with the remaining PR numbers.

  If only go.mod / go.sum were rejected, --skip-gomod plus a 'go mod tidy'
  is usually the right move: the 1.x dependency set differs from main's.
EOF
  exit 1
}

main() {
  require_cmd git
  require_cmd gh
  gh auth status >/dev/null 2>&1 || die "gh is not authenticated; run 'gh auth login'"

  git rev-parse --git-dir >/dev/null 2>&1 || die "not inside a git repository"

  local remote
  remote="$(detect_remote)"
  info "using remote '${remote}' for ${REPO}"
  # Spell the refspecs out. A CI checkout configures a narrow remote.fetch
  # covering only the branch it cloned, and under it a bare
  # `git fetch <remote> v1` updates FETCH_HEAD without ever writing
  # refs/remotes/<remote>/v1, which everything below refers to.
  git fetch --quiet "${remote}" \
    "+refs/heads/${MAIN_BRANCH}:refs/remotes/${remote}/${MAIN_BRANCH}" \
    "+refs/heads/${V1_BRANCH}:refs/remotes/${remote}/${V1_BRANCH}" ||
    die "failed to fetch ${MAIN_BRANCH} and ${V1_BRANCH} from ${remote}"

  git merge-base "${remote}/${MAIN_BRANCH}" "${remote}/${V1_BRANCH}" >/dev/null 2>&1 ||
    die "${MAIN_BRANCH} and ${V1_BRANCH} have no common ancestor here; a shallow
clone cannot be used, check out with fetch-depth: 0"

  if [[ "${list_only}" == true ]]; then
    local queue
    queue="$(pending_queue "${remote}")"
    if [[ -z "${queue}" ]]; then
      info "nothing pending: no merged '${MAIN_BRANCH}' PR labelled '${V2_LABEL}' is missing from '${V1_BRANCH}'"
      return 0
    fi
    info "pending backports (oldest merge first):"
    printf '%s\n' "${queue}" | while IFS=$'\t' read -r number title; do
      printf '  #%-6s %s\n' "${number}" "${title}"
    done
    return 0
  fi

  if [[ "${take_all}" == true ]]; then
    [[ ${#prs[@]} -eq 0 ]] || die "--all cannot be combined with explicit PR numbers"
    local queue
    queue="$(pending_queue "${remote}")"
    [[ -n "${queue}" ]] || { info "nothing pending; done"; return 0; }
    while IFS=$'\t' read -r number _; do
      prs+=("${number}")
    done <<<"${queue}"
  fi

  [[ ${#prs[@]} -gt 0 ]] || { usage; die "no PRs given; pass numbers, --all, or --list"; }

  # Drop anything already on v1. --all filters this way by construction; doing
  # it for explicit numbers too keeps a re-run a no-op rather than an error,
  # which is what lets the workflow retry a PR safely.
  local pr
  if [[ "${take_all}" != true && "${force}" != true ]]; then
    local done_prs kept=()
    done_prs="$(backported_prs "${remote}" | sort -u)"
    for pr in "${prs[@]}"; do
      if grep -qx "${pr}" <<<"${done_prs}"; then
        info "PR #${pr} is already on ${V1_BRANCH}; skipping (use --force to override)"
      else
        kept+=("${pr}")
      fi
    done
    [[ ${#kept[@]} -gt 0 ]] || { info "nothing left to backport; done"; return 0; }
    prs=("${kept[@]}")
  fi

  if [[ -z "${branch}" ]]; then
    if [[ ${#prs[@]} -eq 1 ]]; then
      branch="backport/v1/pr-${prs[0]}"
    else
      branch="backport/v1/batch-$(date +%Y%m%d)"
    fi
  fi
  [[ -n "${worktree}" ]] || worktree="${TMPDIR:-/tmp}/adk-backport/${branch//\//-}"

  # A branch that already exists means this is the second half of a two-step
  # run: build the commits, review them, then come back with --pr.
  local resume=false
  if git show-ref --quiet --verify "refs/heads/${branch}"; then
    [[ "${open_pr}" == true ]] ||
      die "branch ${branch} already exists; pass --branch to pick another name"
    resume=true
  fi

  if [[ "${resume}" == true ]]; then
    info "branch ${branch} already exists; skipping straight to the PR"
  else
    [[ ! -e "${worktree}" ]] ||
      die "${worktree} already exists; remove it or pass --worktree"

    info "creating worktree ${worktree} on ${branch} (from ${remote}/${V1_BRANCH})"
    mkdir -p "$(dirname "${worktree}")"
    git worktree add --quiet -b "${branch}" "${worktree}" "${remote}/${V1_BRANCH}"

    for pr in "${prs[@]}"; do
      apply_pr "${pr}" "${worktree}"
    done
  fi

  local count="${#prs[@]}"
  local refs
  refs="$(printf '#%s, ' "${prs[@]}")"
  refs="${refs%, }"

  [[ "${resume}" == true ]] || info "applied ${count} commit(s) to ${branch}"

  if [[ "${open_pr}" != true ]]; then
    cat <<EOF

Done, locally. Nothing has been pushed.

A clean apply does not mean a correct backport: 1.x can lack a helper or a
prerequisite that main already had, so the result may not build. Always run
the verify step before opening the PR.

  Review:   cd ${worktree} && git log --oneline ${remote}/${V1_BRANCH}..
  Verify:   cd ${worktree} && go work init && go work use -r . \\
              && go build -mod=readonly work \\
              && go test -race -mod=readonly -count=1 -shuffle=on work
  Open PR:  scripts/backport.sh --branch ${branch} --worktree ${worktree} --pr ${prs[*]}
  Discard:  git worktree remove --force ${worktree} && git branch -D ${branch}
EOF
    return 0
  fi

  local title body
  if [[ ${count} -eq 1 ]]; then
    # Keep the original subject: GitHub appends the v1 PR number on squash,
    # producing the "(#1301) (#1310)" form already used on the branch.
    title="$(git log -1 --format=%s "${branch}")"
  else
    title="fix: backport ${count} fixes from ${MAIN_BRANCH} (${refs})"
  fi

  body="Backports ${refs} from \`${MAIN_BRANCH}\` to \`${V1_BRANCH}\`.

Import paths were rewritten from \`${V2_MODULE}\` to \`${V1_MODULE}\`; the
changes are otherwise identical to the originals.

Generated by \`scripts/backport.sh\`."

  info "pushing ${branch} to ${remote}"
  git push --quiet --set-upstream "${remote}" "${branch}"

  # A branch pushed to a fork needs an owner-qualified head ref. A remote that
  # is not a GitHub URL yields no usable owner, so leave the ref alone.
  local head_ref="${branch}" owner
  owner="$(remote_owner "${remote}")"
  if [[ "${owner}" != "${REPO%%/*}" && "${owner}" != */* ]]; then
    head_ref="${owner}:${branch}"
  fi

  info "opening PR against ${V1_BRANCH}"
  local url
  url="$(gh pr create --repo "${REPO}" --base "${V1_BRANCH}" --head "${head_ref}" \
    --title "${title}" --body "${body}")"
  echo "${url}"

  # Labelled as a second step on purpose. `gh pr create --label` fails outright
  # on a label the repository does not have, and a rename of `v1` would then
  # cost the whole pull request: the branch is already pushed by this point, so
  # the work would survive with nothing pointing at it. A missing label is worth
  # a warning, not that.
  gh pr edit "${url##*/}" --repo "${REPO}" --add-label "${V1_LABEL}" >/dev/null ||
    warn "could not label the new PR '${V1_LABEL}'; add it by hand"

  if [[ -d "${worktree}" ]]; then
    info "cleaning up worktree"
    git worktree remove --force "${worktree}"
  fi

  confirm_checks "${url##*/}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l | --list) list_only=true ;;
    -a | --all) take_all=true ;;
    -p | --pr) open_pr=true ;;
    -w | --watch) watch_checks=true ;;
    --skip-gomod) skip_gomod=true ;;
    --force) force=true ;;
    --branch)
      [[ $# -ge 2 ]] || die "--branch needs a value"
      branch="$2"
      shift
      ;;
    --worktree)
      [[ $# -ge 2 ]] || die "--worktree needs a value"
      worktree="$2"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*) die "unknown option: $1" ;;
    *)
      [[ "$1" =~ ^#?[0-9]+$ ]] || die "not a PR number: $1"
      prs+=("${1#\#}")
      ;;
  esac
  shift
done

main
