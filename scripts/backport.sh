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
# A PR into `main` is labelled `v1-needed` when it also has to ship to 1.x.
# This script drains that queue: one backport pull request per labelled PR.
#
# The one systematic obstacle is the module path: `main` is
# `google.golang.org/adk/v2`, `v1` is `google.golang.org/adk`, so every Go
# file's import block differs and a plain cherry-pick conflicts on any patch
# that touches imports. That difference is a pure string rewrite, so the patch
# is rewritten before it is applied and the common case lands cleanly. Genuine
# semantic drift still conflicts, and is left for a human.
#
# Each PR is replayed on its own branch, cut fresh from v1, in its own throwaway
# worktree. One conflict costs one backport, not the run; the current checkout
# is never touched.

set -euo pipefail
# Without this, a `die` inside a command substitution is silently ignored and
# the caller carries on with an empty result.
shopt -s inherit_errexit

readonly REPO="${ADK_REPO:-google/adk-go}"
readonly MAIN_BRANCH="main"
readonly V1_BRANCH="v1"
readonly V2_MODULE="google.golang.org/adk/v2"
readonly V1_MODULE="google.golang.org/adk"

# `v1-needed` marks a merged main PR as still owing a 1.x equivalent and is what
# the queue filters on. `v1` is informational, and goes on the PRs this opens.
readonly BACKPORT_LABEL="v1-needed"
readonly V1_LABEL="v1"

# Every branch this script pushes lives under here. Also the guard: nothing
# outside this prefix is ever pushed.
readonly BRANCH_PREFIX="backport/v1/pr-"

# Hidden marker on the conflict comment, so a nightly re-run recognises its own
# earlier message and does not post it again.
readonly COMMENT_MARKER="<!-- adk-backport-conflict -->"

list_only=false
open_pr=false
skip_gomod=false
declare -a prs=()

info() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() {
  printf '\033[1;31merror:\033[0m %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<EOF
Backport merged '${MAIN_BRANCH}' PRs labelled '${BACKPORT_LABEL}' onto '${V1_BRANCH}'.

Usage:
  scripts/backport.sh --list             Show what is pending.
  scripts/backport.sh [PR...]            Replay locally; nothing is pushed.
  scripts/backport.sh --pr [PR...]       Replay, push, and open the PRs.

With no PR numbers, the whole pending queue is taken. One pull request is
opened per backported PR: a conflict on one does not stop the others.

Options:
  -l, --list        List the pending queue and exit.
  -p, --pr          Push each branch and open its pull request. Without this
                    nothing leaves the machine.
      --skip-gomod  Leave go.mod / go.sum out of the patch. The 1.x dependency
                    set differs from main's, so those hunks often reject on
                    their own; run 'go mod tidy' on the result.
  -h, --help        This text.

Environment:
  ADK_REPO          Override the repository (default ${REPO}).
  ADK_REMOTE        Override the git remote to use.
EOF
}

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"; }

# Prints the remote pointing at REPO.
detect_remote() {
  if [[ -n "${ADK_REMOTE:-}" ]]; then
    printf '%s\n' "${ADK_REMOTE}"
    return
  fi
  local remote url
  while read -r remote url _; do
    if [[ "${url}" == *"${REPO}"* ]]; then
      printf '%s\n' "${remote}"
      return
    fi
  done < <(git remote -v | awk '$3 == "(fetch)"')
  die "no git remote points at ${REPO}; set ADK_REMOTE to choose one"
}

# True when this source commit is already on v1.
#
# Keyed off the "(cherry picked from commit <sha>)" trailer that this script
# writes on every backport, so the question is answered by an exact match on
# something the automation owns. Reading PR numbers out of commit subjects and
# titles instead would mean parsing prose: "Fixes #1152" names an issue, and one
# v1 commit lists seven PR numbers precisely because they were *not* backported.
already_backported() {
  local remote="$1" sha="$2" found
  found="$(git log --format=%H --fixed-strings \
    --grep="cherry picked from commit ${sha}" \
    "${remote}/${V1_BRANCH}" | head -1)"
  [[ -n "${found}" ]]
}

# True when a backport branch for this PR is already pushed, meaning a backport
# PR is open or was opened and its branch kept. Deleting the branch re-queues
# the PR, which is the escape hatch when one goes stale.
in_flight() {
  local remote="$1" pr="$2"
  git ls-remote --exit-code --heads "${remote}" "${BRANCH_PREFIX}${pr}" >/dev/null 2>&1
}

# Prints "number<TAB>merge-sha<TAB>title" for each pending PR, oldest merge
# first, so backports land on v1 in the order they landed on main.
pending_queue() {
  local remote="$1" listing
  listing="$(gh pr list --repo "${REPO}" --base "${MAIN_BRANCH}" --state merged \
    --label "${BACKPORT_LABEL}" --limit 200 \
    --json number,title,mergedAt,mergeCommit \
    --jq 'sort_by(.mergedAt)[] | "\(.number)\t\(.mergeCommit.oid // "")\t\(.title)"')" ||
    die "could not list merged ${MAIN_BRANCH} pull requests"

  local number sha title
  while IFS=$'\t' read -r number sha title; do
    [[ -n "${number}" ]] || continue
    if [[ -z "${sha}" ]]; then
      warn "PR #${number} has no merge commit; skipping"
      continue
    fi
    already_backported "${remote}" "${sha}" && continue
    in_flight "${remote}" "${number}" && continue
    printf '%s\t%s\t%s\n' "${number}" "${sha}" "${title}"
  done <<<"${listing}"
}

# Comments on the original PR asking for a manual backport, at most once.
comment_conflict() {
  local pr="$1" existing
  existing="$(gh pr view "${pr}" --repo "${REPO}" --json comments \
    --jq '[.comments[].body | select(contains("'"${COMMENT_MARKER}"'"))] | length')" ||
    {
      warn "could not read comments on PR #${pr}; not commenting"
      return 0
    }
  if [[ "${existing}" != "0" ]]; then
    info "  conflict already reported on PR #${pr}; not commenting again"
    return 0
  fi

  gh pr comment "${pr}" --repo "${REPO}" --body "${COMMENT_MARKER}
Automatic backport to \`${V1_BRANCH}\` failed: this change does not replay
cleanly, which usually means 1.x lacks something 2.x already had.

To finish it by hand:

\`\`\`bash
scripts/backport.sh ${pr}
\`\`\`

That leaves the conflicts in a scratch worktree with \`.rej\` files. Re-run with
\`--pr\` once it builds.

This is reported once. The backport is still queued and will be retried, so if a
later \`${V1_BRANCH}\` change makes it apply, it lands without further action." >/dev/null ||
    warn "could not comment on PR #${pr}"
}

# Replays one PR onto its own branch and, with --pr, opens the backport PR.
#
# Returns 0 on success, 1 on conflict, 2 when the patch is empty, 3 when the
# push or the PR call failed. The distinction matters: a conflict is a normal
# outcome that a human resolves, while a 3 means the tooling could not do its
# job and the run should go red.
backport_one() {
  local remote="$1" pr="$2" sha="$3"
  local branch="${BRANCH_PREFIX}${pr}"
  local worktree="${TMPDIR:-/tmp}/adk-backport/${branch//\//-}"
  local subject author date patch message

  git cat-file -e "${sha}^{commit}" 2>/dev/null ||
    die "commit ${sha} for PR #${pr} is not in this clone; fetch and retry"

  subject="$(git log -1 --format=%s "${sha}")"
  info "PR #${pr}: ${subject}"

  # Clear any leftover from an earlier run. Removing the directory alone is not
  # enough: git keeps the worktree registered in .git/worktrees and then refuses
  # to re-add the path as "missing but already registered".
  git worktree remove --force "${worktree}" 2>/dev/null || true
  rm -rf "${worktree}"
  git worktree prune
  mkdir -p "$(dirname "${worktree}")"
  git worktree add --quiet --detach "${worktree}" "${remote}/${V1_BRANCH}"
  git -C "${worktree}" checkout --quiet -B "${branch}"

  local -a pathspec=()
  if [[ "${skip_gomod}" == true ]]; then
    pathspec=(-- . ':(exclude)go.mod' ':(exclude)go.sum'
      ':(exclude)*/go.mod' ':(exclude)*/go.sum')
  fi

  patch="$(mktemp)"

  # A main squash commit has a single parent, so `git show` is the whole change.
  # Rewriting the module path makes the context lines match the v1 tree, which
  # is what lets the patch apply directly.
  git show --binary --format= "${sha}" "${pathspec[@]}" |
    sed "s|${V2_MODULE}|${V1_MODULE}|g" >"${patch}"

  if [[ ! -s "${patch}" ]]; then
    warn "  empty patch; nothing to backport"
    rm -f "${patch}"
    cleanup_worktree "${worktree}" "${branch}"
    return 2
  fi

  if ! git -C "${worktree}" apply --index "${patch}" 2>/dev/null; then
    warn "  does not apply cleanly"
    if [[ "${open_pr}" == true ]]; then
      # Unattended: the worktree is worthless to anyone, so take it away.
      rm -f "${patch}"
      cleanup_worktree "${worktree}" "${branch}"
      comment_conflict "${pr}"
    else
      # By hand: leave the .rej files where they can be worked on.
      git -C "${worktree}" apply --reject "${patch}" || true
      rm -f "${patch}"
      cat >&2 <<EOF

  Conflicts are in ${worktree}, as *.rej files. To finish:

    cd ${worktree}
    # resolve the .rej files, then:
    git add -A && git commit -m '<message>'
    git push ${remote} ${branch} && gh pr create --base ${V1_BRANCH}

EOF
    fi
    return 1
  fi
  rm -f "${patch}"

  author="$(git log -1 --format='%an <%ae>' "${sha}")"
  date="$(git log -1 --format=%aD "${sha}")"

  # Command substitution strips trailing newlines, so appending a blank line
  # here always leaves exactly one before the trailer. It matters: around one in
  # eight main squash commits has no body, and without the separator git folds
  # the trailer into the subject and the PR title ends in a bare 40-char SHA.
  message="$(git log -1 --format=%B "${sha}" | sed "s|${V2_MODULE}|${V1_MODULE}|g")

(cherry picked from commit ${sha})"

  git -C "${worktree}" commit --quiet --author="${author}" --date="${date}" \
    --message="${message}"
  info "  applied cleanly"

  if [[ "${open_pr}" != true ]]; then
    info "  branch ${branch} is ready in ${worktree} (nothing pushed)"
    return 0
  fi

  open_backport_pr "${remote}" "${pr}" "${branch}" "${worktree}" "${subject}"
}

# Pushes the branch and opens its pull request.
open_backport_pr() {
  local remote="$1" pr="$2" branch="$3" worktree="$4" subject="$5" url

  # Both of these are cheap and both have bitten this script: a branch name from
  # somewhere unexpected must never reach a push, and a branch with no commits
  # pushes fine and then fails at PR creation, leaving an orphan behind.
  [[ "${branch}" == "${BRANCH_PREFIX}"* ]] ||
    die "refusing to push '${branch}': not a ${BRANCH_PREFIX} branch"
  [[ "$(git -C "${worktree}" rev-list --count "${remote}/${V1_BRANCH}..HEAD")" -gt 0 ]] ||
    die "no commits on ${branch}; refusing to push"

  info "  pushing ${branch}"
  if ! git -C "${worktree}" push --quiet "${remote}" "${branch}"; then
    warn "could not push ${branch}"
    cleanup_worktree "${worktree}" "${branch}"
    return 3
  fi

  local err
  err="$(mktemp)"
  url="$(gh pr create --repo "${REPO}" --base "${V1_BRANCH}" --head "${branch}" \
    --title "${subject}" --body "Backports #${pr} from \`${MAIN_BRANCH}\` to \`${V1_BRANCH}\`.

Import paths were rewritten from \`${V2_MODULE}\` to \`${V1_MODULE}\`; the change
is otherwise identical to the original.

A clean apply is not a correct backport — 1.x can lack a helper that main
already had — so read the diff rather than just the checks.

If the merge box says the workflows are awaiting approval, click **Approve
workflows to run**: pull requests opened by \`github-actions[bot]\` start their
CI held.

Generated by \`scripts/backport.sh\`.")" 2>"${err}" || {
    # The one failure that is a repository setting rather than a mistake, and
    # the error for it reads as a bare permissions problem otherwise.
    if grep -q 'not permitted to create or approve pull requests' "${err}"; then
      warn "this repository does not allow GitHub Actions to create pull requests.
  Enable Settings -> Actions -> General -> 'Allow GitHub Actions to create and
  approve pull requests' (it may be inherited from the organization). Branch
  ${branch} is pushed and the PR can be opened by hand."
    else
      warn "could not open the PR for #${pr}: $(tr '\n' ' ' <"${err}")
  Branch ${branch} is pushed and can be used by hand."
    fi
    rm -f "${err}"
    cleanup_worktree "${worktree}" "${branch}"
    return 3
  }
  rm -f "${err}"
  info "  ${url}"

  # Labelled separately: `gh pr create --label` fails outright on a label the
  # repository does not have, and the pull request is already open by now.
  gh pr edit "${url##*/}" --repo "${REPO}" --add-label "${V1_LABEL}" >/dev/null ||
    warn "could not add the '${V1_LABEL}' label; add it by hand"

  cleanup_worktree "${worktree}" "${branch}"
}

cleanup_worktree() {
  local worktree="$1" branch="$2"
  git worktree remove --force "${worktree}" 2>/dev/null || rm -rf "${worktree}"
  git branch -D "${branch}" >/dev/null 2>&1 || true
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
  # covering only the branch it cloned, and under it a bare `git fetch <remote>
  # v1` updates FETCH_HEAD without ever writing refs/remotes/<remote>/v1, which
  # everything below refers to.
  git fetch --quiet "${remote}" \
    "+refs/heads/${MAIN_BRANCH}:refs/remotes/${remote}/${MAIN_BRANCH}" \
    "+refs/heads/${V1_BRANCH}:refs/remotes/${remote}/${V1_BRANCH}" ||
    die "failed to fetch ${MAIN_BRANCH} and ${V1_BRANCH} from ${remote}"

  git merge-base "${remote}/${MAIN_BRANCH}" "${remote}/${V1_BRANCH}" >/dev/null 2>&1 ||
    die "${MAIN_BRANCH} and ${V1_BRANCH} have no common ancestor here; a shallow
clone cannot be used, check out with fetch-depth: 0"

  # Explicit numbers are filtered out of the same queue rather than resolved
  # separately, so a hand-run and an unattended run cannot disagree about what
  # is pending or what a PR's merge commit is. Asking for one that is already
  # backported is then a no-op, which is what makes a re-run safe.
  local queue
  queue="$(pending_queue "${remote}")"
  if [[ ${#prs[@]} -gt 0 && -n "${queue}" ]]; then
    local wanted
    wanted="$(printf '%s\n' "${prs[@]}")"
    queue="$(awk -F'\t' 'NR==FNR {want[$0]; next} $1 in want' \
      <(printf '%s\n' "${wanted}") <(printf '%s\n' "${queue}"))"
  fi

  if [[ -z "${queue}" ]]; then
    info "nothing pending: no merged '${MAIN_BRANCH}' PR labelled '${BACKPORT_LABEL}' is missing from '${V1_BRANCH}'"
    return 0
  fi

  if [[ "${list_only}" == true ]]; then
    info "pending backports (oldest merge first):"
    while IFS=$'\t' read -r number _ title; do
      printf '  #%-6s %s\n' "${number}" "${title}"
    done <<<"${queue}"
    return 0
  fi

  local number sha title status
  local -a done_prs=() conflicted=() empty=() broken=()
  while IFS=$'\t' read -r number sha title; do
    status=0
    backport_one "${remote}" "${number}" "${sha}" || status=$?
    case "${status}" in
      0) done_prs+=("${number}") ;;
      1) conflicted+=("${number}") ;;
      2) empty+=("${number}") ;;
      *) broken+=("${number}") ;;
    esac
  done <<<"${queue}"

  info "backported ${#done_prs[@]}, conflicted ${#conflicted[@]}, empty ${#empty[@]}, failed ${#broken[@]}"
  [[ ${#conflicted[@]} -eq 0 ]] ||
    warn "needs a manual backport: ${conflicted[*]/#/#}"

  # A conflict is a real outcome rather than a broken run: the PRs that applied
  # have their pull requests, and the comment on the original is the signal. A
  # push or PR call that failed is different -- nobody has been told, so the run
  # has to go red.
  [[ ${#broken[@]} -eq 0 ]] ||
    die "could not open backports for: ${broken[*]/#/#}"
  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -l | --list) list_only=true ;;
    -p | --pr) open_pr=true ;;
    --skip-gomod) skip_gomod=true ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*) die "unknown option: $1" ;;
    *)
      [[ "$1" =~ ^[0-9]+$ ]] || die "not a PR number: $1"
      prs+=("$1")
      ;;
  esac
  shift
done

main
