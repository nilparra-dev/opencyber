# OpenCyber architecture roadmap

This document is the single architectural plan for the next stage of OpenCyber. Active tasks live in GitHub Issues and Milestones. Previous design records (`plan.md`, `toolset.md`, `audit.md`, `harness.md`) stay in `docs/cyber/` as historical reference.

Baseline: `origin/custom` on upstream `v2.4.1` (31 registered cyber tools, 73 modules in `packages/core/src/fork-cyber/`, 0 internal import cycles, 109 modified upstream files covered by `FORK.md` section 7).

## Architecture decisions

### ADR-01: Hardened default mode with explicit `--dev`

`opencyber` starts hardened by default (`assessment` mode) and never loads `.opencode/`, plugins, MCP servers, or `AGENTS.md` from the working directory. Opening the binary inside a client repository or target folder cannot execute untrusted project configuration.

Operators who want coding-agent behavior pass `--dev` (or set `OPENCYBER_MODE=development`), or use the official `opencode` binary that already shares sessions and logins through `F-004`.

### ADR-02: Approved ad-hoc scripts in Kali and on host

Auditors need custom one-off scripts (PoCs, decoders, parsers, targeted checks) during engagements. OpenCyber supports ad-hoc Python and Node script execution in two backends, both requiring explicit per-run operator approval (`ask` showing the exact script body) and storing the script and output as evidence artifacts:

- **Kali backend (recommended for full audits).** Runs inside the pinned Kali container under the engagement's `scoped` egress policy, byte/rate budgets, and container isolation. Required for hardened and client-facing audits.
- **Host backend (convenience for local workflows).** Runs on the operator's host inside a dedicated engagement scratchpad directory when Kali is not used. The approval prompt states clearly that host networking is outside Kali's egress firewall.

### ADR-03: Bounded automatic delegation

Small, fast models (currently DeepSeek V4.1 Flash) perform better when fanning out narrow parallel workers than when running a long single-agent session. Assessment profiles can enable automatic delegation in configuration with hard caps (default: 4 concurrent subagents, 16 per session). `manual` delegation remains available per session.

### ADR-04: Evidence storage and schema migrations

Keep captured artifact payloads inside `evidence.sqlite` for now. Move large payloads to content-addressed files keyed by `sha256` only if real engagements push `evidence.sqlite` past ~200 MB or cause measurable WAL lock contention.

In Track 1, the hand-rolled migration blocks in `packages/core/src/fork-cyber/store.ts` moved to a single migration array runner, and the rigid SQLite `CHECK (kind IN (...))` constraint on `engagement_credential` was replaced by `length(kind) > 0` (validation stays at the Effect Schema boundary in `credentials.ts`) so new credential kinds no longer force table drop-and-rebuild migrations.

## Triage of prior W0 to W3 items

Every open or `Partial` item from `toolset.md` has a clear disposition before new work starts:

| ID | Disposition | Target track | Notes |
| --- | --- | --- | --- |
| `OC-108` | Active | Track 0 and 5 | Run baseline on `v2.4.1` with DeepSeek V4.1 Flash before behavioral changes, then measure consolidation (`http_*`, `finding_retest`) |
| `OC-307` (web) | Active | Track 4 | Add authenticated web identities (multi-role cookies/tokens/sessions) to the credential broker |
| `OC-204` | Active (partial) / Closed | Track 4 | Decide risk class and add anonymous FTP probe. Close `udp_top` with its known limit (no raw sockets in unprivileged container) |
| `OC-205` | Active | Track 4 | Adopt one pinned offline advisory source (OSV snapshot) for SCA and expand curated Semgrep rules |
| `OC-206` | Grouped with `OC-205` | Track 4 | Reuse the same pinned offline advisory snapshot for `image_scan` |
| `OC-302` | Grouped with `OC-205` | Track 4 | Reuse the same pinned offline advisory snapshot for Linux `patch_inventory` |
| `OC-303` | Fix TLS / Freeze AD lab | Track 4 | Add certificate verification for StartTLS credential binds. Freeze Windows AD laboratory |
| `OC-404` | Active (partial) / Closed | Track 4 | Add cumulative anti-lockout budget for `auth_test`. Close real Elasticsearch container lab |
| `OC-301` | Frozen | None | Linux host lab (`fork-lab/linux-host/`) stays active. Windows VM tier is frozen |
| `OC-304` | Frozen | None | Live cloud account laboratory is frozen. Local fixture tests remain active |
| `OC-403` | Closed with limit | None | Offline hash cracking (`john` and wordlists) stays outside the harness |

## Implementation tracks

Work proceeds one track at a time, in small PRs directly to `custom`.

### Track 0: Baseline and cleanup

- Consolidate the 26 root `fork-cyber-*.md` guides into `docs/cyber/` and fix stale documentation statements (`OC-401` status and tool count). Done.
- Publish this roadmap and align GitHub Milestones and Issues with the triage table above. Done.
- Run `packages/core/script/fork-cyber-evaluate.ts` once on the current `v2.4.1` build with DeepSeek V4.1 Flash to save a baseline before behavioral changes.
- Exit criteria: single active backlog, clean root directory, `fork-ledger-check.ts` passing, baseline report saved under `reports/`.

### Track 1: Structural hygiene and fork health

Zero intentional behavioral change for the model. Goal is to remove bottlenecks before changing harness and prompt behavior.

- Decouple `packages/core/src/fork-cyber/policy.ts` from `ForkCyberRoles.tools("cyber-validate")` with explicit per-mode tool lists, and remove duplicate tool entries in `packages/core/src/fork-cyber/roles.ts` (also removing the stale `OC-401` comment). Landed in #137.
- Harden Windows credential key storage in `packages/core/src/fork-cyber/credentials.ts` with a user-only ACL. Landed in #137; the profile launcher still relies on the profile directory's ACL.
- Shrink the upstream diff of `F-023` by moving analysis/profile export logic out of `packages/core/src/session/transfer.ts` into `packages/core/src/fork-cyber/transfer.ts`, and delegating where practical in `packages/tui/src/ui/dialog-export-options.tsx`. The export move landed in #138; the TUI delegation remains pending.
- Split `packages/core/src/plugin/fork-cyber.ts` (was 1,692 lines) into domain tool registration modules (`packages/core/src/fork-cyber/tools/*.ts`) and a thin plugin entrypoint. Landed in #140.
- Refactor `packages/core/src/fork-cyber/store.ts` (was 1,215 lines) into a migration runner plus focused repositories receiving `sql` (matching `coordination.ts`), and relax the `CHECK` constraint on `engagement_credential.kind`. Landed in #139.
- Add three automated fitness functions (see below). Landed in #137 and #140.
- Exit criteria: `plugin/fork-cyber.ts` under 300 lines, diff in `session/transfer.ts` under 30 lines, all unit/lab checks and fitness functions green. Achieved: `plugin/fork-cyber.ts` is 138 lines and the `session/transfer.ts` diff is 27 lines.

### Track 2: Hardened runtime and execution harness

- Implement ADR-01: hardened default mode (`assessment`) with explicit `--dev` opt-in.
- Implement ADR-02: operator-approved ad-hoc script execution in Kali (`scoped` or `none` network) and on host (explicit warning that host traffic bypasses Kali's egress firewall), with script and output captured as evidence artifacts.
- Implement ADR-03: bounded automatic delegation configurable in the assessment profile (concurrent and per-session caps).
- Exit criteria: opening `opencyber` in a test repo with `.opencode/` plugins or `AGENTS.md` executes nothing from the target, both script backends require approval and record artifacts, and bounded auto-delegation enforces its caps in tests.

### Track 3: Model ergonomics (catalog, context, bookkeeping)

- Filter exposed cyber tools dynamically based on declared engagement scope targets so irrelevant surfaces (AD, cloud, OT, binary, database) do not enter the prompt on web or network engagements.
- Narrow specialist agent tool lists in `packages/core/src/fork-cyber/roles.ts` (remove `...observe` spillover from `cyber-exploit-web` and `cyber-exploit-net`) so each specialist sees 6 to 10 tools.
- Remove duplicate `cyber_web_plan` tool (already covered by `cyber_web_test.plan`).
- Automate task execution and artifact linking in `execute.after` so subagents stop spending model turns copying task revisions and artifact UUIDs.
- Split the monolithic `OPERATOR` prompt into a short core prompt plus surface-specific modules loaded only when relevant.
- Exit criteria: active tool catalog drops from 31 to ~10 to 14 tools per focused engagement, subagent tests confirm automatic artifact linkage, and token overhead per turn measurably drops.

### Track 4: Surface depth and upstream contributions

- Web: authenticated multi-role web identities (`OC-307`), stronger budgeted discovery/fuzzing, and systematic multi-account access-control comparison.
- Network and services: anonymous FTP decision and probe (`OC-204`), StartTLS certificate verification (`OC-303`), cumulative anti-lockout budget for `cyber_database.auth_test` (`OC-404`).
- Offline advisories: adopt pinned OSV snapshot to finish `OC-205` (SCA), `OC-206` (`image_scan`), and `OC-302` (`patch_inventory`) together, plus broader curated Semgrep rules.
- Upstream: open PRs to `anomalyco/opencode` for the six generic fixes already marked `Yes` in `FORK.md` section 7 (`F-020`, `F-024`, `F-025`, `F-026`, `F-028`, `F-029`), starting with `F-025` and `F-026`.
- Exit criteria: every active triage item closed with positive and negative lab tests, and upstream PRs opened for generic patches.

### Track 5: Labs, measurement, and tuning

- Build reproducible local lab targets covering web (multi-role auth, access control, injection, SPA), network services, and other active surfaces.
- Run repeated matched evaluations with DeepSeek V4.1 Flash measuring real findings detected, false positives, tool-call argument errors, steps spent on bookkeeping, elapsed time, and token cost.
- Use those measurements to finalize `OC-108` (whether to merge `http_*` and `finding_retest`) and tune prompts, tool schemas, and delegation caps iteratively.
- Exit criteria: documented comparison table across iterations showing measurable improvement over the Track 0 baseline without new false positives or scope violations.

## Fitness functions

Add these checks in Track 1 alongside `script/fork-ledger-check.ts`:

1. **Tool registry consistency test.** Fails if any tool registered in `ForkCyberPlugin` is missing from `ForkCyberDecision.declared`, `ForkCyberRoles`, or `ForkCyberPolicy`, or if `decision.ts` declares an unregistered tool.
2. **Fork-cyber acyclic import test.** Verifies 0 inter-module import cycles inside `packages/core/src/fork-cyber/`.
3. **Upstream diff budget check in `script/fork-ledger-check.ts`.** Flags any upstream non-generated file exceeding a per-file diff line threshold (with explicit allowlist for existing exceptions) so large inline patches do not creep back into upstream files.

## Working rules

- Keep only one track active at a time.
- Never mix structural refactoring and behavioral changes in the same PR.
- Land small PRs directly to `custom` rather than accumulating long-lived integration branches that conflict with `fork-sync`.
- Record new irreversible architectural decisions in this file before implementing them.
