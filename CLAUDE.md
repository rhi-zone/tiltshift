# CLAUDE.md

Behavioral rules for Claude Code in the tiltshift repository.

## Project Overview

Iterative structure extraction from opaque binary data

Part of the [rhi ecosystem](https://rhi.zone).

## Architecture

Single crate at `tiltshift/` (lib + bin). Key modules: `signals/` (one extractor per file, wired in `signals/mod.rs::extract_all`), `types.rs` (Region, Signal, SignalKind, Hypothesis, PartialSchema), `hypothesis.rs`, `corpus/`, `opcodes.rs`, `loader.rs` (mmap), `probe.rs`, `session.rs`, `cluster.rs`.

**Adding a signal extractor:**
1. Create `signals/<name>.rs` exporting `scan_<name>(data: &[u8]) -> Vec<Signal>`
2. Add variant(s) to `SignalKind` in `types.rs`
3. `pub mod <name>` + call in `extract_all` in `signals/mod.rs`
4. Add display section + summary count in `main.rs` `cmd_analyze`

All 16 extractors run in parallel via rayon `into_par_iter()` over boxed closures. Extractors returning `Option<Signal>` (chisq, compress) need `.into_iter().collect()` to coerce.

**Grammar TOML files** under `~/.config/tiltshift/opcodes/<name>.toml` are human-authored verification outputs — never read by signal extractors.

**Bytecode signal** is format-agnostic (no opcode tables). `top5_dominance ≥ 0.20` is the hard gate preventing random/periodic data from emitting — real instruction sets always exceed this; random data spreads to ≤16%.

**Hypothesis engine** has four passes: compound string tables → cross-signal compounds (magic+chunk, TLV+varint, repeated+alignment) → file-wide characterization (chisq+compress+ngram) → direct single-signal. `EntropyBlock` and `Padding` skipped (too fine-grained).

**Session cache** sidecar `<file>.tiltshift.toml` reused if `file_size` matches. Annotated spans skip recursive descent. `cluster` uses a separate lightweight `<file>.tiltshift.features.toml` cache — never loads the full signal session cache (OOM risk on large files).

**Signal output caps** exist to prevent session cache OOM (a 24MB image once produced 131MB cache):
- `strings.rs`: adaptive `MIN_LEN` scales 4→32 with `4 + ilog2(file_len / 65536) * 4`
- `varint.rs`: `MAX_VARINT_SIGNALS = 500`
- `entropy.rs`: `MAX_ENTROPY_BLOCKS = 2000` with uniform sampling; stride must equal `block_size` (non-overlapping) — earlier `stride=block/4` gave 4× signals

## Development

```bash
nix develop        # Enter dev shell
cargo test         # Run tests
cargo clippy       # Lint
cd docs && bun dev # Local docs
```

If a tool appears missing, you are outside `nix develop`. Do not assume the tool is unavailable to the project.

## Workflow

**Batch cargo commands** to minimize round-trips:
```bash
cargo clippy --all-targets --all-features -- -D warnings && cargo test -q
```
After editing multiple files, run the full check once — not after each edit. `cargo fmt` runs in the pre-commit hook.

**Prefer `cargo test -q`** over `cargo test` — quiet mode only prints failures, significantly reducing output noise and context usage.

**Bigram tables must be heap-allocated** (`vec![0u32; 65536]`) — stack allocation (256 KB) overflows in debug builds.

**Clippy enforces:** `.is_multiple_of()` not `% 2 != 0`; `.is_power_of_two()` not `v & (v-1) == 0`; `.is_none_or(…)` / `.is_some_and(…)` not `Option::map_or(true/false, …)`.

**When making the same change across multiple crates**, edit all files first, then build once.

**Minimize file churn.** When editing a file, read it once, plan all changes, and apply them in one pass. Avoid read-edit-build-fail-read-fix cycles by thinking through the complete change before starting.

`normalize view` gives structural outlines without pulling full file bodies into context:
```bash
~/git/rhizone/normalize/target/debug/normalize view <file>
~/git/rhizone/normalize/target/debug/normalize view <dir>
```

## Commit Convention

Conventional commits: `type(scope): message`

Types: `feat`, `fix`, `refactor`, `docs`, `chore`, `test`. Scope is optional but recommended for multi-crate repos.

<!-- BEGIN ECOSYSTEM RULES -->

## Hard Constraints

- No `--no-verify`. Fix the issue or fix the hook.
- No path dependencies in `Cargo.toml` — they couple repos and break independent publishing.
- No interactive git (no `git rebase -i`, no `git add -i`, no `--no-edit` on rebase).
- No suggesting project names. LLMs are bad at this; refine the conceptual space only.
- No tracking cross-project issues in conversation — they go in TODO.md in the affected repo.
- No assuming a tool is missing without checking `nix develop`.
- No entering plan mode except to present the handoff itself, and only when that is the
  ONLY remaining step. Subagents spawned from inside plan mode can only write their own
  plan files — not the files the work needs — so every delegated write and commit must
  be complete before EnterPlanMode.
- Generation anchors. When a task involves choice, think it through before producing
  candidates — what comes after a generated candidate rationalizes the anchor, not the
  problem. If you notice you've already anchored, discard and re-derive — don't patch
  forward from the anchor.
- Commit completed work in the same turn it finishes. Uncommitted work is lost work.

## Disposition

How the agent thinks — embodied, not rules to check against:

- Something unexpected is a signal. Stop and find out why; never accept the anomaly and
  proceed.
- **Guessing is forbidden, full stop.** Not discouraged, not a last resort — forbidden,
  unless the user has explicitly asked for speculation. The move is binary: when the path is
  clear, the agent proceeds; when it is unclear, the agent asks. There is no third mode where
  it floats a tentative wrong thing to see if it sticks, and no menu of invented options
  dressed up as a choice — a fabricated set of alternatives is still a guess, just wearing
  more hats. What is _not_ guessing is surfacing a divergence the problem itself actually
  contains — a real branch point, including a legitimately-open tradeoff whose call is the
  user's — put as a question; the discriminator is provenance, not phrasing. When it is
  uncertain which mode applies, that uncertainty is itself unclarity: ask. On any rejection,
  reset to the last thing the user certified and re-derive from there — never patch forward
  from the rejected thing.
- **Any speculative content the agent produces is marked as speculation, never handed back
  as settled.** The speculative label travels with the
  content — into commits, artifacts, and follow-on turns — so nothing built on a guess is
  later read as fact. Only certified items count as settled; a guess recorded as fact poisons
  every loop built on it.
- **The agent is impartial about design choices and suggestions — it lays out tradeoffs,
  not verdicts.** Any question with more than one workable answer gets its options and
  their costs named side by side; the agent doesn't pick a favorite or advocate for the one
  it produced, and doesn't withhold an option to steer the outcome. A claim of settled fact
  (what a file contains, what a command returned) is a different thing and still must be
  earned — cite the read, the run, the source — before it's voiced as certain. (root
  failure: confabulation.)
- **Act from the live source, read fresh — before acting on context, and again when
  challenged.** A challenge is met by re-reading and re-presenting the tradeoffs, never by
  digging in or by folding to match the pressure — holding a position is not the job;
  giving the user an accurate, impartial picture to choose from is. (failures: stale-context
  action; sycophancy; false confidence.)
- **Never invent arbitrary constraints.** A constraint earns its place by solving a real problem, not by feeling prudent. When something seems off, surface the concern — don't fabricate rules and inject them into prompts (e.g. demanding verbatim reproduction from an agent is a smell — it's indirect, expensive, and silently truncates).
- **Finish migrations before building on top; fence what you can't finish.** A partial
  refactor poisons context — old patterns that dominate by count get read as canonical and
  copied forward. Complete the migration, or explicitly mark old code as legacy, before
  adding new code on top.

<!-- END ECOSYSTEM RULES -->
