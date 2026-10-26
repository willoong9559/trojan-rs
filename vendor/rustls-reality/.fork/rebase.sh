#!/usr/bin/env bash
set -euo pipefail
while IFS= read -r variable; do
    unset "$variable"
done < <(git rev-parse --local-env-vars)
cd "$(git rev-parse --show-toplevel)"
if [[ $# != 2 ]]; then
    printf 'Usage: bash .fork/rebase.sh UPSTREAM_REF NEW_WORKTREE\n' >&2
    exit 2
fi
target=$(git rev-parse --verify "$1^{commit}")
source=$(git rev-parse HEAD)
base=$(git merge-base "$source" "$target")
upstream_base=$(git merge-base "$source" upstream/rel-0.23)
if ! git merge-base --is-ancestor "$upstream_base" "$target" ||
   ! git merge-base --is-ancestor "$target" upstream/rel-0.23; then
    printf 'Target is not an upgrade on upstream/rel-0.23; fetch and select that branch.\n' >&2
    exit 1
fi
if [[ -n $(git rev-list --merges "$base..$source") ]]; then
    printf 'Fork patches must be a linear series; review merge commits before rebasing.\n' >&2
    exit 1
fi
if [[ -n $(git status --porcelain --untracked-files=all) ]]; then
    printf 'Commit or stash changes before preparing an upgrade.\n' >&2
    exit 1
fi
version=$(git show "$target:rustls/Cargo.toml" | sed -n 's/^version = "\([^"]*\)"/\1/p' | head -n 1)
if [[ $version != 0.23.* ]]; then
    printf 'Refusing a breaking upgrade to %s; review the API migration separately.\n' "$version" >&2
    exit 1
fi
branch="reality-rebase/$(date -u +%Y%m%dT%H%M%SZ)-${target:0:12}"
printf 'Source: %s\nUpstream: %s\n' "$source" "$target"
git worktree add -b "$branch" "$2" "$source"
if ! git -C "$2" rebase --onto "$target" "$base"; then
    printf 'Resolve conflicts in %s, then run git rebase --continue. Main is untouched.\n' "$2" >&2
    printf 'After completion, in that worktree run:\n  git range-diff %s..%s %s..HEAD\n  bash .fork/check.sh %s\n' "$base" "$source" "$target" "$target" >&2
    exit 1
fi
git range-diff "$base..$source" "$target..$branch"
printf '\nCandidate: %s\nRun: cd %q && bash .fork/check.sh %s\nNo remote refs were updated.\n' "$branch" "$2" "$target"
