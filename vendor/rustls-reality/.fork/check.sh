#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
base=$(git merge-base HEAD "${1:-upstream/rel-0.23}")
git diff --check "$base" HEAD
if [[ -n $(git status --porcelain --untracked-files=all) ]]; then
    printf 'Commit the candidate before validation; staged and untracked changes are not tested releases.\n' >&2
    exit 1
fi
bash .fork/test-rebase.sh
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_INCREMENTAL=0
cargo fmt --all --check
cargo test --locked -p rustls --lib --tests
cargo test --locked -p rustls --no-default-features --features std,ring,tls12 --lib --tests
cargo check --locked -p rustls --no-default-features --features hashbrown,aws_lc_rs
cargo check --locked -p rustls --no-default-features --features hashbrown,ring
