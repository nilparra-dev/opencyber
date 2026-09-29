# Phase 6: tasks, hypotheses and coverage

`cyber_tasks` and `cyber_coverage` are native tools backed by the fork-owned evidence database. Parent and child sessions share the top-level engagement's task list. An unrelated engagement cannot claim a task or use its evidence.

## Work contract

Create one stable key per intended unit of work. Include the asset, procedure and assessment identity in the naming convention used by the coordinating session. Read existing tasks before creating more work. A repeated create with the same key and fields returns the existing task; conflicting fields fail. Keys are exact and case-sensitive. The system does not recognize equivalent prose or prevent someone from describing the same work under two different keys.

The primary session creates tasks and delegates their keys. The executing child claims its task itself. Creating a task does not launch a subagent or send traffic. Task asset descriptions do not add targets to the engagement scope.

Example inputs for `cyber_tasks`:

```json
{"action":"list"}
{"action":"create","key":"api-items-bob-validation","asset":"GET /api/items/42 as bob","procedure":"Compare bob's access to alice's object with anonymous and protected controls","phase":"cyber-validate","hypothesis":"Bob can read alice's private item"}
{"action":"get","key":"api-items-bob-validation"}
{"action":"claim","key":"api-items-bob-validation","revision":1}
```

Phases are `cyber-recon`, `cyber-enum`, `cyber-exploit-web`, `cyber-exploit-net`, `cyber-postex` and `cyber-validate`. Validation tasks require a hypothesis. A phase agent can claim only its own phase. The primary agent can claim work directly when delegation is unnecessary.

Claims are conditional SQLite writes. One task has one claimant, and one session/agent pair can hold one active task per engagement. Separate Locations and processes use the same constraints. Every transition requires the current revision; a conflict requires another read. Claims do not expire, so a slow or interrupted job cannot silently acquire a second worker.

Phase agents need a claim before local file inspection, HTTP, Kali or browser work. Execution creation attaches the task in the same database transaction, and rejects phase execution if the claim has ended. Each captured HTTP hop and browser action can contribute an execution; those counts are not counts of independent security tests. Kali lifecycle status/stop checks require a claim but are not assessment evidence. Administrative reads, notes, findings and comparisons do not require a claim. Ordinary primary-agent work remains usable without tasks and does not appear in task coverage unless it has an active claim.

The active task key enters normal context and compaction context. The full task, hypothesis, executions and evidence remain retrievable after compaction or plugin restart.

## Results and interruption

After executing the procedure, complete the task with its own output artifact IDs:

```json
{
  "action": "complete",
  "key": "api-items-bob-validation",
  "revision": 2,
  "outcome": "refuted",
  "rationale": "Bob and anonymous were denied; alice retrieved the expected object and the protected control behaved correctly",
  "evidence": ["http-output-bob", "http-output-alice", "http-output-anonymous", "http-output-control"]
}
```

The IDs above are placeholders for actual captured artifacts. Completion requires at least one completed execution's output artifact belonging to that task. Missing references, other tasks' outputs, error artifacts and cross-engagement evidence fail transactionally. Any unresolved `running` execution prevents completion. Failed executions remain visible even when later successful evidence supports a result.

Outcomes are `observed`, `supported`, `refuted` and `inconclusive`. Supported/refuted require a recorded hypothesis. They record the agent's interpretation and rationale, not an automatic vulnerability verdict. Use the existing `findings` tool for candidate, confirmed and discarded findings; shared artifact references connect findings to task executions. A refuted hypothesis does not establish that an asset is secure.

`release` returns an active claim to pending only if no execution has started. Once work has started, complete it or use `block` with a reason. A blocked task retains its executions, has no successful coverage result and cannot be reclaimed. Completed tasks cannot be reclaimed either. Use an explicitly new key for a deliberate follow-up procedure.

```json
{"action":"release","key":"not-started-yet","revision":2}
{"action":"block","key":"interrupted-check","revision":2,"reason":"Connection failed after submission; target-side outcome is unknown"}
```

The claimant can block its own task. The top-level primary session can also block an abandoned child claim. Blocking changes coordination state; it does not cancel a running process or roll back remote effects. Stop active work through its existing execution controls before arranging follow-up work. There is no automatic replay or transfer of started tasks after a crash.

## Coverage

Call `cyber_coverage` with `{}` or `{"offset":25}`. It returns 25 recorded task rows with asset, procedure, phase, hypothesis, state, outcome, rationale and counts of completed, failed and unresolved executions plus accepted evidence references. `cyber_tasks.list` uses the same pagination; `get` retrieves a task's evidence and 25 linked executions, with `offset` for later execution pages.

This is coverage of the recorded work plan. Unlisted assets, unsupported browser traffic and procedures never added to the plan remain unknown. A completed call is evidence of execution, not proof of a correct security conclusion. Reporting should list pending, active, blocked and inconclusive work alongside completed observations and findings.

## Execution permissions

The built-in role permission lists and the tool execution hook share one allowlist. The hook rejects prohibited tool names even if later user configuration adds permissive permission rules. HTTP method restrictions and archive mutation checks run in the native executors. Normal OpenCode permissions still apply and can deny allowed actions.

| Role                                           | Available work                                                                                                                                                     | Restrictions                                                                                                                 |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| Recon and enumeration                          | Local `read`, `glob`, `grep`; HTTP GET, HEAD and OPTIONS without a body; archive reads, notes, candidate/discarded findings, task coordination and HTTP comparison | No shell, Kali, replay, browser actions, external web tools, Code Mode, subdelegation, scope changes or confirmed findings   |
| Web/network exploitation and post-exploitation | Local inspection, scoped HTTP/replay, browser and Kali; archive and task operations                                                                         | Active claim required; no host shell, subdelegation or scope changes                                                            |
| Validation                                     | Same execution tools, with a validation-phase task carrying an explicit hypothesis                                                                                 | Runtime checks task ownership and phase, not whether an arbitrary command semantically reproduces only the stated hypothesis |
| Reporting                                      | Local inspection, archive/task/coverage reads and recorded HTTP comparison                                                                                         | No network tools, shell, environments, archive mutations or claims                                                           |

The normal primary agent is not converted into a restricted phase agent. Report-local reads still produce automatic tool audit records, as before; "read-only" concerns requested mutations and assessment effects.

An HTTP method does not classify a security technique. GET can trigger side effects or carry an attack payload; the recon policy bounds tools and methods rather than claiming to understand every request. All cyber phase roles reject the host shell, including under permissive agent configuration. Command-capable roles use Kali's [CY-10 network controls](fork-cyber-network.md). The ordinary primary agent and external plugins remain outside that container boundary.

## Storage and verification

Schema 3 adds fork-owned task, task-execution and task-evidence tables. Schema 1/2 archives migrate in place without replacing evidence. CY-10 now uses schema 4; earlier executables reject it. Back up the private archive before upgrading if rollback is required. Export format `opencyber-archive-v2` includes all three tables; purge removes their rows with the rest of the engagement. No upstream session migration, public HTTP API or generated client change is involved.

Run from `packages/core`:

```sh
bun test test/plugin/fork-cyber-coordination.test.ts test/plugin/fork-cyber-integration.test.ts test/plugin/fork-cyber-store.test.ts
bun typecheck
```

The tests use real SQLite clients and competing processes, real Location tool dispatch, local files and a loopback HTTP server. They cover exclusive claims, revisions, role/session ownership, execution attachment, transactional evidence checks, restart, compaction, migration, export/purge and direct calls under permissive agent configuration. No external assessment target is contacted.

Local validation on Windows with Bun 1.4.2 passed 129 tests across 13 Core files, including real Chromium and Kali Docker labs, with five existing Windows skips. Root `bun run check` passed lint and all 35 typecheck tasks. Prettier and `git diff --check` passed. The first regression run, concurrent with typechecking, exceeded the existing vanilla boot test's five-second deadline; that test passed in isolation and the entire regression passed on rerun without changing its timeout.

Linux validation on [PR #30](https://github.com/nilparra-dev/opencyber/pull/30) also passed the complete fork CI, real Docker and Chromium labs, and compiled browser capture smoke. The later [CY-10 live smoke](fork-cyber-network.md) validated compiled-CLI delegation with Fireworks DeepSeek V4.1 Flash: one claimed recon task, one loopback HTTP request and one evidence-linked completion. It does not validate the TUI, release installer/updater or assessment quality.
