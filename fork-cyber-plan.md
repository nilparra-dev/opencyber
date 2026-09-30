# OpenCyber implementation plan

## Goal and boundaries

Build a security assessment system that records what was tested, how a finding was validated, and what remains unexamined. Preserve OpenCode V2 session execution, recovery, permissions and compaction. Add domain behavior through plugins and fork-owned files.

Support for a surface means a tested workflow with reproducible evidence. Installing a tool does not establish support. Web/API and code review are the first workflows. Network services, cloud, identity, mobile, binaries, wireless and operational technology follow according to actual engagements and available test environments.

Docker/Kali is an optional execution environment. Local code review must remain usable without Docker. Additional VM, remote Linux and device environments should implement the same execution contract when needed.

## Baseline

The initial audit examined `960aae2675` on `cyber-compliance`, based on upstream `v2.0.18`. The existing fork had engagement prompts, seven phase agents, bounded shared notes, provider-specific instruction suffixes and a live refusal-rate evaluation.

The original two fork test files passed 39 tests and 92 assertions. Core typecheck passed. Root `bun run check` passed with all 35 Turbo typecheck tasks served from cache. These results establish a code baseline, not assessment quality. No model benchmark or external target assessment was run.

Reproduced gaps:

- A prompt containing an excluded hostname admitted that hostname as a target.
- IPv6 URL extraction produced `[`; IPv4 `/99` networks and negative request rates were accepted.
- Empty answers counted as non-refusals, while some ordinary technical explanations counted as refusals.
- The 51st note removed the oldest entry, even if it described a confirmed finding. A single rendered note could exceed the stated 1,500-character budget.

Code review also identified project-local activation, inconsistent child engagement resolution, instructions presented as execution controls, and unverified authorization claims. The roadmap below assigns these gaps explicit owners and acceptance tests.

## Architecture decisions

1. Register the fork plugin once in the built-in plugin list. Project files configure engagements rather than importing repository source.
2. Keep engagement data separate from behavioral instructions. Record the operator's explicit scope using the structured tool or a manifest. Do not extract authority or scope from arbitrary prose, URLs, filenames or tool output.
3. Preserve declared provenance. A manifest is not proof of a signature. Legacy automatically extracted records remain readable but are labelled unverified candidates.
4. Use one effective engagement resolver for tools, primary requests and compaction. Session overrides precede inherited records and the project file. Only a top-level session changes scope; child sessions read it.
5. Store raw evidence separately from model context. Model-visible summaries refer to retrievable artifacts. Working notes are not the evidence archive.
6. Reuse tool registration and execution hooks. Keep runtime dependencies Schema -> Core/Protocol -> Server. Client may use Schema and Protocol, never Core or Server. Regenerate Client after public Protocol/HttpApi changes.
7. Keep the database schema and runner untouched in phase 1. Phase 2 will select fork-owned storage with atomic writes and a lifecycle separate from upstream session tables.
8. Model execution credentials remain in the OpenCyber service. A Kali environment receives only engagement-specific inputs and credentials.
9. Evaluate outcomes, false positives, scope violations, reproducibility, cost and latency. Refusal rate is not task success. Compare against upstream behavior with the same model, fixtures and budget.

## Delivery phases

| Phase | Deliverable                                                                          | Acceptance                                                                                                                | Status                                                                |
| ----- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| 0     | Architecture, audit backlog, baseline, migration instructions                        | Every identified gap has a phase and a verification method                                                                | Implemented in this document                                          |
| 1     | Built-in activation, structured scope, shared resolution, no corrective refusal loop | Offline unit and real-Location integration tests pass; malformed inputs do not mutate state                               | Implemented; validation recorded below                                |
| 2     | Engagement storage, executions, artifacts, findings and retrievable memory           | Restart and compaction preserve evidence; concurrent writes do not lose records; findings link to executions              | Implemented; see storage guide                                        |
| 3     | HTTP request, replay, compare and evidence retrieval                                 | Controlled two-account lab confirms access-control failures and rejects healthy controls; redirects and errors are tested | Implemented; see HTTP guide                                           |
| 4     | Versioned Kali image and execution jobs                                              | Environment per engagement; start, output, cancellation and cleanup work; artifacts survive container removal             | Implemented; see Kali guide                                           |
| 5     | Browser sessions and traffic capture                                                 | Captured requests correlate to browser actions and findings; unsupported capture paths are reported                       | Implemented; see browser guide                                        |
| 6     | Coverage, hypotheses, task ownership and phase permissions                           | Agents coordinate without duplicate jobs; role restrictions apply at execution, not only in prompts                       | Implemented; see coordination guide                                   |
| 7     | Additional surface modules                                                           | Each module ships procedures, parsers, tools, known-positive and known-negative labs                                      | Local workflows implemented; external infrastructure coverage pending |
| 8     | Model capability profiles and tuning                                                 | Repeated matched-budget comparisons show improvement on held-out tasks without regressing correctness                     | Planned                                                               |

Evaluations grow from phase 1 onward. Phase 8 uses those evaluations for optimization; it is not the first testing phase. Each phase may need several small PRs to `custom`. Complete and verify each change before starting the next dependency.

Phase 4 usage and limits are documented in [fork-cyber-kali.md](fork-cyber-kali.md). Jobs use fresh workspaces and explicit artifact transfers. The [CY-10 implementation](fork-cyber-network.md) adds enforced destinations/exclusions, connection and packet rates, byte quotas, durable aggregate reservations and command deadlines. Cyber phase agents execute commands only in Kali; the primary agent remains outside this isolation boundary.

Phase 5 usage and capture limits are documented in [fork-cyber-browser.md](fork-cyber-browser.md). Isolated Chromium identities route intercepted HTTP through phase 3 evidence capture. Worker/OOPIF traffic, WebRTC, streaming and other unsupported paths do not constitute verified coverage. Kali network controls do not extend browser capture coverage.

Phase 6 coordination and role contracts are documented in [fork-cyber-coordination.md](fork-cyber-coordination.md). Stable task keys have exclusive durable claims; execution-linked evidence supports hypothesis outcomes and planned coverage. Runtime role checks restrict tools and HTTP methods, not the semantic intent of arbitrary commands or requests. Interrupted tasks retain ownership and are never automatically replayed.

Before phase 7, CY-10 is implemented with the bounded contract in its guide. A real Fireworks DeepSeek V4.1 Flash run through the compiled CLI completed a delegated recon task with exactly one loopback HTTP request and one linked evidence artifact. Linux CI for these changes and the release installer/updater are separate from the local checks.

Phase 7 includes the [local code-review module](fork-cyber-code-review.md): explicit source snapshots, a bounded SARIF parser, a restricted review role, evidence-linked tasks and a reproducible SQL-injection/healthy-control lab. The [TCP service module](fork-cyber-services.md) adds bounded unprivileged Nmap inventory, original XML and normalized evidence, and real IPv4/IPv6 open/closed controls. The [additional local workflows](fork-cyber-surfaces.md) add service-port/transport scope, TLS/SSH protocol validation, identity matrices, AWS S3 listing/policy inspection, Android APK manifests, ELF analysis/reproduction, wireless PCAP and Modbus simulators. Each includes procedures, parsers, tools, positive/negative controls and CI. The compiled workflow connects reconnaissance, candidates, validation, findings and coverage reporting. Live cloud accounts, emulators/devices, radio equipment and physical OT validation remain explicitly pending. Phase 8 model evaluations, capability profiles, tuning and comparisons have not started.

## Audit backlog and verification

| ID    | Priority | Gap and planned behavior                                      | Phase | Verification                                                                                                         |
| ----- | -------- | ------------------------------------------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------- |
| CY-01 | High     | Cyber behavior available outside the source checkout          | 1     | Cold real Location in an empty temporary project reports one active built-in plugin and callable state tools         |
| CY-02 | High     | Mentioned or excluded assets must not become inferred targets | 1     | Prose prompt does not create scope; structured manifest preserves separate exclusion list                            |
| CY-03 | High     | Host, IPv4, IPv6, CIDR and rate validation                    | 1     | Boundary tests reject malformed addresses, URL/path widening and invalid rates before storage                        |
| CY-04 | High     | Accurate authorization provenance and no refusal re-anchoring | 1     | Legacy records labelled; remove event watcher, wire repairs, refusal classifier and automatic prompt admission       |
| CY-05 | High     | Parent/child consistency and read-only access                 | 1     | Child reads follow parent updates; reads do not create a child snapshot; child writes fail                           |
| CY-06 | High     | Invalid config must stay distinguishable from missing config  | 1     | Tool returns error and context reports invalid configuration; corrected file is reloaded                             |
| CY-07 | Medium   | Reporting agent can read working notes without mutating them  | 1     | Real tool registry exposes notes and engagement; writes rejected at executor                                         |
| CY-08 | High     | Durable evidence and memory beyond 50 notes                   | 2     | Old confirmed evidence survives new entries, restart, compaction and retrieval                                       |
| CY-09 | High     | Concurrent updates and storage ownership                      | 1, 2  | Phase 1 serializes same-Location state writes; phase 2 verifies durable atomic updates across actual storage clients |
| CY-10 | High     | Enforce destinations, exclusions, rate and impact budgets     | 3, 4  | Denied destination and redirect never reached; agents share request budget; raw-process network restrictions tested  |
| CY-11 | High     | Replace willingness evaluation with outcome evaluation        | 1, 3  | Retire external-target auto runner; lab graders distinguish pass, fail, error, timeout and incomplete                |
| CY-12 | Medium   | Role separation and task coordination                         | 6     | Recon/report roles cannot perform disallowed effects; shared coverage reflects executed jobs                         |
| CY-13 | Medium   | Technical model profiles, not blanket authorization suffixes  | 1, 8  | Remove built-in suffixes; retain explicit overrides; later compare tool compatibility and context settings           |
| CY-14 | Medium   | Independent engagement data profile                           | 2     | Separate client data, credentials, retention and export from shared official OpenCode state                          |
| CY-15 | Medium   | Limit auxiliary instruction injection                         | 1     | Cyber context applies to primary requests/compaction, not title or generic generation                                |

## Phase 1 usage and migration

The plugin is built into this fork's Core, in source and compiled builds. It is not gated on the CLI channel. The project-local `.opencode/plugin/fork-cyber.ts` loader is removed to avoid duplicate registration. Remove any manually copied loader with the same plugin ID from your project/global plugin configuration when adopting this version.

Use `.opencode/cyber/scope.jsonc`, or ask the agent to record explicit scope through the `engagement` tool's `manifest` field. No network request or second authorization confirmation occurs during registration. The model remains responsible for translating operator intent accurately; phase 1 does not create a trusted approval channel or enforce network boundaries.

Example for a local lab:

```jsonc
{
  "engagement": "local-api-lab",
  "authorized_by": "operator",
  "authorization_ref": "local-lab-plan",
  "scope": {
    "domains": ["localhost", "127.0.0.1", "::1"],
    "cidrs": [],
    "excluded": [],
  },
  "rules_of_engagement": {
    "no_dos": true,
    "max_rps": 2,
    "window": "local lab session",
    "contact": "operator",
  },
}
```

Use actual operator-provided values. Missing operational details should be resolved before the dependent action. The tool does not fabricate references, contacts, time windows or rate limits.

Host fields accept exact hostnames and unbracketed IPv4/IPv6 addresses. Networks accept IPv4/IPv6 CIDRs. URLs, embedded ports, paths and wildcard hosts are rejected rather than silently widened. Phase 7 adds `scope.services` and `scope.excluded_services` with explicit targets, TCP/UDP transport and port lists. Leave host/network lists empty when authorization is service-only. `scope.resources` records authorized S3 bucket ARNs. Path-level and wildcard scope remain unsupported. Exclusions take precedence in HTTP requests and scoped Kali jobs; see the [surface guide](fork-cyber-surfaces.md) for these boundaries.

An empty `engagement` call only reads. A top-level session can supply `manifest` to create/replace its override or use `add_targets`, `remove_targets`, `exclude`, `include`, and `contact`. If both manifest and patches are supplied, patches apply to that manifest. Session overrides are not written into the project file. Existing child overrides remain nearest-precedence records for compatibility, but new child mutations are rejected.

Legacy `derived: true` manifests remain explicitly unverified until replaced with an explicit manifest without that flag. Invalid legacy records produce a configuration error; they are not discarded or treated as an empty scope.

Custom `.opencode/cyber/adapters.jsonc` suffixes remain opt-in and operator-controlled. Provider defaults that asserted blanket authorization are removed. Title and generic generation requests do not receive cyber instructions.

In phase 1, `notes` held at most 50 bounded, normalized entries. Phase 2 replaces that storage with durable, paginated rows and captures tool evidence separately. See [fork-cyber-storage.md](fork-cyber-storage.md) for storage contracts, migration, retrieval, export/purge and the optional independent profile. Reporting agents can read the archive but cannot mutate scope, notes or findings.

The old live `fork-cyber-eval.ts` runner and its refusal suite are removed. They launched autonomous tasks against external targets and could classify empty/error results as successful. No live replacement runs until a controlled lab and outcome graders exist.

## Execution and evidence contracts for subsequent phases

Phase 3 HTTP behavior, examples, limits and schema migration are documented in [fork-cyber-http.md](fork-cyber-http.md). HTTP scope and pacing apply to specialized request/replay tools and phase 5's intercepted browser requests. Other browser capture paths and raw-process enforcement retain the limits described in their guides.

Keep the first storage design small: engagement records, execution records, artifact metadata and findings with evidence references. Distinguish candidate, confirmed and discarded findings. Record tool/version, environment/image version, parameters, timestamps, exit status and output references. Retain raw bytes where fidelity matters and provide redacted model-visible views.

The Docker manager will own environment lifecycle outside the model-controlled container. Build a versioned image from official Kali with selected tools and an inventory. Start on demand, reuse per engagement, and keep inputs, working files and persistent artifacts separate. Do not mount the Docker socket or provider credentials. Default to minimal capabilities; use separate profiles when raw-network access or devices are required. CPU, memory, disk, deadlines, cancellation and cleanup need tests. Network scope enforcement is a separate mechanism from container isolation.

HTTP instrumentation only observes traffic that uses it. Browser/proxy and command-line capture require explicit integrations and compatibility tests. Do not claim complete traffic visibility from the HTTP client alone. Windows/Docker networking, VPNs and remote labs need platform-specific verification before release.

## Verification commands

Run from `packages/core`:

```sh
bun test test/plugin/fork-cyber.test.ts test/plugin/fork-cyber-integration.test.ts test/plugin/fork-anthropic-oauth.test.ts
bun typecheck
```

Run from the repository root:

```sh
bun run check
bun script/fork-ledger-check.ts
```

The ledger checker compares committed ancestry; run it after the local implementation commit. No public Protocol or Server HttpApi changes are part of phases 0/1, so client generation is unnecessary.

Offline integration checks exercise real Location activation, SQLite-backed plugin storage, hook dispatch and tool execution. They disable model execution, model-catalog networking and filesystem watchers. They do not establish live model quality, compiled release behavior, network scope enforcement or Docker support.

Validation on Windows with Bun 1.4.2:

- The expanded regression run passed 71 tests across the fork suites, session activation, vanilla instances, supervisor activation and supervisor reload.
- The final integration suite passed seven tests, including the additional legacy-record migration case. It also verifies that reading a project manifest does not freeze it into session storage and that a plugin reactivation reloads stored notes and scope.
- The final root check passed lint and all 35 typecheck tasks after the last test changes; 28 tasks used cache and seven ran again. Prettier and `git diff --check` also passed.

Future release validation should add a compiled-binary smoke test in a clean project and Linux CI results. These are distinct from the real-Location source integration checks above.
