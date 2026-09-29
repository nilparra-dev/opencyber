# OpenCyber evidence storage (phase 2)

The built-in cyber plugin stores its archive at `Global.data/opencyber/evidence.sqlite`, outside the checkout and upstream session tables. The existing SQLite runtime adapter supplies the database, WAL and scoped connection lifetime. No new package dependencies or upstream database migrations are needed.

[Phase 6](fork-cyber-coordination.md) added tasks, hypotheses and execution-linked coverage. [CY-10](fork-cyber-network.md) extends the archive to schema 4 with durable network byte reservations. Portable `opencyber-archive-v2` exports include coordination rows and a `network_budget` array; purge removes them too. Schema 1/2/3 data migrates in place. Earlier binaries reject schema 4.

An engagement archive belongs to a top-level Session ID. Descendants share it; unrelated sessions cannot retrieve or reference its artifacts through the cyber tools. This is tool-level separation within a local application, not an OS sandbox: an agent with unrestricted shell or file access can access the same user's files. The existing installation keeps its shared profile by default; use the optional launcher below for separate on-disk data and credentials.

## Records and guarantees

- Engagement manifests use revisions and conditional updates. Concurrent patches cannot silently overwrite each other; a conflict requires a fresh read. Project JSONC stays live until an explicit session override is written.
- Notes are append-only rows, retaining their text without the former 50-entry eviction. Calls return 25 entries with sequence cursors. Only the newest summary, capped at 1,500 characters, enters context and compaction prompts.
- Tool hooks record the session, agent, tool, timestamps, input and outcome. Provenance includes the Location and effective scope snapshot. Tool and environment versions are explicitly unknown until a specialized executor supplies them.
- Input and result artifacts retain exact serialized tool data as UTF-8 bytes. The store also supports binary artifacts, preserving NULs, non-UTF-8 bytes and line endings. Every artifact has a SHA-256 and byte count checked on retrieval. A digest detects corruption; it is not a signed chain of custody.
- Findings have `candidate`, `confirmed` and `discarded` states, a rationale, revision and artifact references. Confirmation requires a completed output artifact from the same engagement. This checks traceability, not whether the model's vulnerability interpretation is correct. Updates and evidence links commit together or roll back together.

The archive captures what reaches the tool hooks. It does not observe arbitrary traffic, external processes, interactive terminal output or complete files behind a tool's truncated response. A completed tool call is not necessarily a successful command: inspect its output for the command's exit status. The [phase 3 HTTP tools](fork-cyber-http.md) supply their own request, response and body artifacts; Kali execution follows in phase 4.

`running` means the before-hook persisted a record and no terminal result has been recorded. A later hook rejection, interruption, defect or process death can leave that state; it must not be interpreted as success or proof that work is still running. Restart preserves it and does not rerun the tool. After-hook storage failures propagate rather than returning a silently unarchived success. Administrative tools (`engagement`, `notes`, `evidence`, `findings`) are excluded from execution capture.

## Retrieval

These tools are native tools, available outside CodeMode:

```json
{"tool":"notes","input":{}}
{"tool":"notes","input":{"before":123}}
{"tool":"evidence","input":{"offset":0}}
{"tool":"evidence","input":{"execution":"execution-id"}}
{"tool":"evidence","input":{"artifact":"artifact-id","position":0}}
{"tool":"findings","input":{}}
```

For notes, pass the oldest returned `seq` as `before`. Execution and finding lists use offsets in pages of 25. Artifact text previews use `next_position` in the redacted text; each page is at most 8,000 characters. Previews are UTF-8 text views, not binary exports. Artifact metadata and the store's `readArtifact(owner, id)` API provide the original media type and verified bytes for subsequent adapters/export integrations.

Create a finding with `write: { revision: 0, title, status, rationale, evidence: [artifactID] }`. The result gives its ID and revision. Supply both with the full replacement fields on an update. Reporting agents may read all four tools but cannot change scope, append notes or write findings.

## Migration and lifecycle

Legacy KV scope remains readable until the first explicit durable scope update. Legacy notes import on access with stable origin keys, so reactivation or concurrent access does not duplicate them. KV is retained for rollback; notes evicted before this phase cannot be recovered. Legacy changes after migration do not replace the archive. Rolling back to phase 1 will not expose notes or scope written only to the new archive.

Raw data may contain credentials. Common authorization, cookie, password, token and API-key fields are masked in model-visible artifact previews; this is a convenience filter, not a comprehensive secret detector. Raw archives are neither redacted nor encrypted. The directory is created with mode 0700 where supported; Windows uses inherited ACLs. Keep database backups private.

No automatic retention or session-deletion cascade is enabled: removing a chat does not remove its audit evidence. For a complete backup, stop the background server and copy the entire `opencyber` data directory, including any WAL sidecars. Restore it with the server stopped.

For a portable JSON export or explicit per-engagement purge, run the operator maintenance script from the repository root with the background server stopped. Export includes raw base64 artifacts and verifies their hashes; it refuses to overwrite an existing file. Purge requires the exact owner ID twice, removes only that archive, and retains a tombstone to prevent reimporting legacy KV. It does not erase upstream session messages, old KV, project scope files or previously exported copies, and is not forensic secure erasure.

```powershell
bun packages/core/script/fork-cyber-archive.ts --database C:\audit-profile\data\opencode\opencyber\evidence.sqlite --owner ses_example --output C:\exports\audit.json
bun packages/core/script/fork-cyber-archive.ts --database C:\audit-profile\data\opencode\opencyber\evidence.sqlite --owner ses_example --purge --confirm ses_example
```

## Optional independent profile

The launcher sets data, configuration, cache, state, database, TUI channel and temporary paths before loading application modules. Existing configuration/database overrides cannot redirect it back into the shared profile. It neither copies old credentials nor changes the default installed behavior. Use the same launcher for subsequent service commands so they discover the matching profile's background service.

```powershell
# Installed fork binary
bun script/fork-cyber-profile.ts C:\audit-profile -- opencyber
# Source checkout
bun script/fork-cyber-profile.ts C:\audit-profile -- bun packages/cli/src/index.ts
# Stop that profile's service before backup or purge
bun script/fork-cyber-profile.ts C:\audit-profile -- opencyber service stop
```

Authenticate within the new profile. Provider keys supplied through the inherited environment and explicit command-line server connections remain available; the launcher is on-disk profile separation, not process isolation. Paths are portable: use an absolute POSIX directory on Linux/macOS. Encrypted storage, an export/import UI and automatic retention policies remain follow-up work.

## Validation

Run from `packages/core`:

```sh
bun test test/plugin/fork-cyber.test.ts test/plugin/fork-cyber-store.test.ts test/plugin/fork-cyber-integration.test.ts
```

Tests exercise independent SQLite clients and processes, concurrent first-open initialization, stale revisions, transactional rollback, cross-engagement references, exact binary recovery after closing/reopening, real read-tool success/error capture, report-agent restrictions and retrieval after compaction. They make no external target requests.

Windows/Bun 1.4.2 validation: the final Core regression run passed 95 tests across nine files, with five existing Windows skips. The CLI profile test also passed. Root `bun run check` passed lint and all 35 typecheck tasks. Linux CI and compiled-binary behavior are separate release checks.
