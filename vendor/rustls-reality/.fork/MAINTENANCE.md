# Maintaining cfal/rustls

`main` is a rebased patch series over upstream `rel-0.23`. It is not upstream's
breaking `0.24` development branch. Git's merge-base with the fetched upstream
branch identifies the base, including after a manually resolved rebase.
REALITY APIs are opt-in and connection-owned; ordinary TLS and QUIC retain the
upstream paths. Record padding is supported by the AWS-LC provider only.

## Upgrade Procedure

1. Fetch `https://github.com/rustls/rustls.git` as remote `upstream`, then
   `git fetch upstream rel-0.23`. Start from the published fork `main`.
2. Run `bash .fork/rebase.sh upstream/rel-0.23 "$HOME/tmp/rustls-upgrade"`.
   This creates a separate candidate branch/worktree. It never changes `main`
   or pushes. Resolve conflicts there; inspect the printed range-diff and
   upstream security/release notes. After a conflict, finish `git rebase --continue`
   and run the exact range-diff/check commands printed by the script. There is no
   base metadata to finalize and no accumulating per-upgrade bookkeeping commit.
   Targets outside the fetched compatible branch, older than the current base,
   and `0.24` targets are rejected. Fork patches must form a linear series.
3. In the candidate, run `bash .fork/check.sh upstream/rel-0.23` (or the exact
   upstream commit printed by the script). Commit all resolutions first; the
   validation gate refuses dirty candidates. Use an external
   `CARGO_TARGET_DIR` on constrained machines. Review every affected invariant:
   finalized ClientHello/SID state, exact transcript bytes, provider-owned
   exchange binding, config isolation, and record padding/epochs.
4. Point a Shoes worktree at the candidate revision and run its REALITY security,
   fallback, Vision, pinned Xray, sing-box, and ordinary TLS/QUIC suites. Do not
   infer Shoes compatibility from rustls tests alone.
5. Before publishing a tag or updating a consumer pin, fetch `origin/main` and
   require it to equal the `Source:` commit printed when preparing this candidate.
   If it changed, prepare a new candidate containing those intervening patches.
   Review and publish an immutable annotated tag, e.g.
   `cfal-reality-0.23.46-1`. Never move or delete a published tag. Pin Shoes to
   the full commit ID, not `main`; update its lockfile. Tags keep old pins
   reachable even after later rebases.
6. Keep the original `Source:` commit as the final concurrency guard when
   promoting the reviewed candidate:
   `git push --force-with-lease=refs/heads/main:<source-id> origin HEAD:main`.
   Never use unrestricted `--force`. Preserve a tag for the previous deployed
   revision before replacing `main`.
7. Remove the candidate worktree after promotion, retain release tags, and
   prune only obsolete local candidate branches.

The scheduled workflow prepares and validates an upgrade candidate, then
uploads a Git bundle and range-diff for review. It does not automatically
rewrite `main`, modify consumer pins, or publish releases. Fork Actions must
be enabled in GitHub for scheduled checks to run. Disable inherited upstream
scheduled workflows in the fork; enable only this candidate workflow unless
additional upstream jobs are deliberately wanted.

## Consumer Contract

- `new_reality` does not supply authentication. The caller owns per-connection
  certificate policy and must verify HMAC/required ML-DSA and CertificateVerify.
- The server must synthesize in memory, validate the complete staged record
  layout, then publish bytes. On any pre-commit error discard the connection,
  including all queued ServerHello, CCS and alert records.
- `RealityUnsupported` describes template/peer incompatibility. Invalid local
  config or absent provider padding support is not permission to forward.
- No TLS 1.2, resumption, 0-RTT, ECH or HelloRetryRequest in authenticated REALITY.
  Server ALPN, client auth and `max_fragment_size` are rejected. Browser profile
  emulation and target background probing are not implemented.
