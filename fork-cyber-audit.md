# Audit corrections and controlled modes

This delivery implements the reproduced defects from the September 30 harness audit. Model comparisons and additional execution backends remain separate work. The original report stays private under `reports/harness-audit/`.

| Finding | Implementation | Remaining limits |
| --- | --- | --- |
| AUD-01 | Review/assessment disable target configuration, plugins, MCP, agents and instruction discovery before Location startup. Nested reads do not inject AGENTS.md. Operator plugins still load. | Approved plugins retain the service's OS permissions. This is not a process sandbox. |
| AUD-02 | The selected tool policy applies to the primary and all children. Assessment permits scoped native backends, while host shell, CodeMode execute, webfetch, websearch and MCP tools are unavailable. | No separate external research channel or arbitrary isolated host backend yet. |
| AUD-03 | Hardened engagement writes return proposals. The operator CLI approves revisioned scope and retains its manifest/hash. Model-written and legacy scope cannot inherit approval. Ordinary mutations enforce permission denials. | Local operator authority, not signatures. Active jobs retain admitted scope. The textual window remains descriptive. |
| AUD-04 | Checkpoint previews allowlist metadata and omit all cookie/localStorage values before pagination. Invalid state never falls back to raw text. Original bytes still restore identities. | Generic previews retain convenience redaction; HTTP credential references remain pending. |
| AUD-05 | Imports, artifact analysis and Kali inputs share a 2 MiB boundary. Excessive sources fail before evidence creation. A padded valid 2 MiB ELF traverses import, analysis and recovery. | Large files need a bounded file transfer backend. |
| AUD-06 | Confirmation requires a candidate, a completed supported cyber-validate task for the asset, accepted outputs from its recorded authorized session/executor, and method, identity, expected/observed behavior, demonstrated impact, controls, reproduction and remediation. Direct primary validation retains the real agent. | These contracts establish provenance and require an impact record. Technical correctness and severity/CVSS still require review. |
| AUD-07 | Retry creates a successor with reason, declared authorization, effect state and reconciliation references. Previous work and evidence remain with the predecessor. | No automatic replay. Reconciliation needs technical judgment. |
| AUD-08 | Notes enter user-message data as bounded JSON with source and sequence references. New entries record session/agent. Instruction delimiters are escaped, including during compaction. | Legacy authors are unknown; adversarial model evaluations remain pending. |
| AUD-11 | Offline artifact jobs derive network=none from the configured Kali ceiling; network procedures still require scoped networking. | Windows, VM, remote, device and radio backends remain pending. |
| AUD-12 | fork-ci calls the four specialized reusable workflows for relevant changes. Its required test check rejects unsuccessful or skipped required labs. | The new workflow graph needs remote CI verification. |
| AUD-09, AUD-10 | Evaluation and capability work remains on the roadmap; existing fixtures provide positive and healthy controls. | No new model-performance claim or broad SOC/IR, cloud or malware capability is made. |

## Controlled modes

`development` retains ordinary OpenCode access and project discovery. `review` permits source/evidence inspection and code review. `assessment` also permits scoped HTTP, browser, Kali and surface tools, plus delegation under the same policy. Role restrictions and ordinary permissions remain additional constraints.

Launch a dedicated profile before importing application modules. From the repository root on Windows:

```powershell
bun script/fork-cyber-profile.ts --review C:\review-profile -- C:\path\opencyber.exe --standalone C:\target
bun script/fork-cyber-profile.ts --assessment C:\assessment-profile -- C:\path\opencyber.exe --standalone C:\target
```

Use a binary built with these changes. `--standalone` makes the selected process construct its own Locations; an explicit connection to another server uses that server's policy. The launcher clears inherited explicit configuration, isolates data/configuration/state and sets `OPENCYBER_MODE` before startup. Embedded hosts can select `Instance.Options.cyberMode` before building a Location.

Put operator provider/backend configuration in the profile's `config/opencode` directory. Target `.opencode/cyber` files remain data. Approved provider plugins load, while their custom tools need backend/policy integration before the restricted registry admits them.

Scope can come from the operator profile's `config/opencode/cyber/scope.jsonc`. To approve a session-specific proposal, save its manifest as JSON outside the target and run this from the operator terminal:

```powershell
bun packages/core/script/fork-cyber-authorize.ts C:\assessment-profile ses_example C:\operator\scope.json 0
```

The last argument is the expected current revision, with 0 for a new record. Proposals report owner and revision. Stale approvals fail. This command is unavailable to the model's restricted tools. Stop active jobs before reducing scope, since admitted jobs retain their snapshot.

## Findings, migration and retry

Create candidates first. Complete the validation task before confirming, and link only its accepted outputs. Static and configuration methods are supported alongside dynamic reproduction. Healthy controls remain controls.

The October corrections align primary task claims, effective phase permissions and finding provenance. New confirmations require `validation.impact`; existing validation records remain readable. Coverage separates completed validation tasks from accepted provenance for confirmation. Native tool interruption closes its audit record with unknown effects and an explicit termination reason, preserving cancellation rather than converting it into an ordinary result. Model overrides remain explicit user choices, and interruption does not establish a provider defect. See [task coordination](fork-cyber-coordination.md).

Public WordPress REST CORS headers establish a header observation, not protected authenticated access or a medium-severity vulnerability. The standard implementation reflects Origin and allows credentials, while cookie authentication without a REST nonce clears the current user. Test the actual authentication path, protected content, browser access and controls before claiming impact. Sources: [WordPress CORS implementation](https://developer.wordpress.org/reference/functions/rest_send_cors_headers/) and [REST cookie authentication](https://developer.wordpress.org/reference/functions/rest_cookie_check_errors/).

A 403 records denial for the tested request and path; it does not establish directory-listing configuration. A 301 records redirection; it does not verify TLS or subdomain readiness for HSTS. Long max-age and includeSubDomains recommendations must state verified deployment prerequisites and remaining unknowns, since [HSTS includeSubDomains covers subdomains](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security).

Schema 5 adds approval history, validation and successor links in the fork-owned database. Exports retain `opencyber-archive-v2` and add `approvals`, `finding_validation` and `task_retries`. Previous confirmations become candidates with their evidence retained and revision incremented. Older binaries reject schema 5; keep a database backup when changing versions.

For a recoverable failed read:

```json
{"action":"retry","key":"read-fixture","revision":3,"successor":"read-fixture-2","reason":"Temporary read failure","authorization":"Operator authorized another observation","effect_state":"read_only","reconciliation":[]}
```

The store checks captured predecessor operations for read-only retry and rejects unresolved running executions. Other operations require `effect_state: "reconciled"` and completed output evidence from the same engagement. Authorization text records the caller's declaration; runtime permissions control access. It does not authenticate a remote effect. Claim the successor normally; its completion cannot reuse predecessor outputs.

## Verification and remaining work

Local verification covers actual startup, SQLite migrations, permission denials, excluded targets, browser restore/redaction, successors, confirmed TLS findings with controls, the 2 MiB ELF path, and compiled surface/CLI smokes. These are implementation tests, not model evaluations.

`bun run check`, focused regression tests and actionlint pass. The final Windows CLI build passed the TCP/TLS delivery smoke on a fresh rerun. One preceding run failed with a Docker command deadline during TCP setup; its evidence was retained and its lab resources were cleaned up. This intermittent failure remains a reproducibility limit.

The next evaluation delivery should compare upstream, the previous cyber configuration and these modes with the same model, budget and fixtures. Reserve cases outside prompt development. Keep success, refusal, timeout, tool error, empty output and unresolved results separate. Grade fixture truth and recorded evidence, negative controls, scope attempts, cost, recovery and compaction. Run actual models before reporting any capability improvement.

Select additional task families from real usage. SOC/IR, authenticated cloud inventory and disposable sample analysis require different backends and acceptance fixtures. Existing laboratory parsers do not establish those capabilities.
