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

## Delegation

The main session is an orchestrator. Allowed actions: `Agent`/`Task*`/`AskUserQuestion`/plan-mode/`ScheduleWakeup`, and Bash limited to `git commit`, `git push`, `git status`, `git log --oneline`. Everything else delegates to a subagent. The hook is evidence of a prompting failure, not a behavioral guide. If a tool call hits the hook AT ALL, the prompt failed to prevent it. Delegate before the decision point, not after.

### Triggers

Before calling Read, Grep, Glob, or any Bash beyond the four git commands — stop. Dispatch an Agent instead.

Before editing any file — stop. Dispatch an Agent. This includes plan files in `~/.claude/plans/`: in plan mode, dispatch a subagent to write to the plan file; do not Write it yourself. The plan file's content must not enter main context.

When you need git context beyond status/log-oneline (a diff, a blame, a show) — dispatch an Agent.

When a tool call is denied by the hook — do not retry, do not narrate. Dispatch the equivalent Agent and continue.

When a code-modifying subagent returns — `git status`, then `git commit` before any user-facing reply.

Before dispatching an Agent that modifies code — scan your prompt for "do not commit" or "based on your findings". Delete them.

Before dispatching: if your prompt says "if you find", "based on your findings", or "as appropriate" — stop. Investigate first; dispatch with the decision made.

When you can't verify something — do not speculate or guess at file locations, names, or contents. Dispatch a Read subagent or ask. Confabulation is failure.

### Model Tiers

- Sonnet — exploration, lookup, mechanical multi-file edits, implementation, default.
- Opus — architectural judgment, design, subagents that themselves spawn subagents.

Always set `subagent_type` and `model` explicitly.

### Prompt Rules

- Never tell a subagent "do not commit." Code-modifying subagents commit their own work.
- Don't ask for a diff summary. After a code-modifying subagent, `git status` in main and dispatch a review Agent if you need to see the diff.
- Don't re-explain CLAUDE.md. Subagents inherit it.
- Cite locations by content ("the block that does X"), not line numbers — files shift between reads.
- Name files explicitly; don't outsource the grep.
- Match agent type to deliverable: `Explore` for lookup/search, `general-purpose` for reports and file-modifying work.
- On unsatisfying output, change something before retrying. Same prompt + same tier = same result.
- Dispatch independent subagents in parallel (multiple Agent blocks in one message).
- Pair `isolation: worktree` with `run_in_background: true`.
- Code-modifying subagents must verify their own changes before returning (re-read the diff, run tests, etc.). The orchestrator does not get a second pass with git diff — that's hook-blocked.

## Hard Constraints

- No Edit/Write/NotebookEdit in main. Plan files in `~/.claude/plans/` are written by subagents, not by main.
- No Read/Grep/Glob/NotebookRead in main. Delegate.
- No Bash in main beyond `git commit`, `git push`, `git status`, `git log --oneline`.
- No `--no-verify`. Fix the issue or fix the hook.
- No path dependencies in `Cargo.toml` — they couple repos and break independent publishing.
- No interactive git (no `git rebase -i`, no `git add -i`, no `--no-edit` on rebase).
- No suggesting project names. LLMs are bad at this; refine the conceptual space only.
- No tracking cross-project issues in conversation — they go in TODO.md in the affected repo.
- No ecosystem changes without checking all affected repos.
- No assuming a tool is missing without checking `nix develop`.
- Commit completed work in the same turn it finishes. Uncommitted work is lost work.

## Meta

- Something unexpected is a signal. Stop and find out why. Do not accept the anomaly and proceed.
- Corrections from the user are conversation, not material for new rules. Rules are added when a failure mode is observed repeatedly.

<!-- END ECOSYSTEM RULES -->
