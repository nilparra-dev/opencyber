# Architecture

OpenCyber is a fork of OpenCode V2 with a security assessment layer on top. OpenCode provides the engine: sessions, the runner, permissions, compaction, providers and the TUI. The fork adds explicit scope, a risk policy, controlled execution backends, durable evidence and phase agents. The unit of work is an assessment session, not a code project.

It is not an operating system sandbox, it does not prove that a scope is real, and it does not replace human review of a report. It also shares the OpenCode process, server and, by default, session database.

This page describes how the pieces fit. [`FORK.md`](../../FORK.md) covers how the fork follows upstream, and the [guides](README.md#guides) cover each module.

## Context

```mermaid
flowchart LR
  operator([Operator]) -->|TUI or CLI| client[opencyber client]
  client --> server[OpenCode server<br/>channel cyber]
  server --> models[(Model providers)]
  server --> plugin[ForkCyberPlugin]
  plugin --> backends[HTTP, Kali, Chromium,<br/>cloud and local backends]
  backends --> targets[(In-scope targets)]
  server --> opencodedb[(opencode.db)]
  plugin --> evidencedb[(evidence.sqlite)]
```

The `opencyber` binary is the client. The engine runs in a local background server (`opencode serve --service` on the `cyber` channel), so tools run in the server and not in the TUI. The server opens SQLite, talks to the model and starts the backends. Evidence stays on the operator's machine.

## Runtime

A normal OpenCode session goes prompt, server, `Session.prompt`, inbox, runner. The model receives the base context, `AGENTS.md`, skills and project instructions, then calls tools through the upstream permission system. Everything lands in `opencode.db` and the TUI follows it over SSE.

A cyber session adds this on top:

- The mode (`development`, `review` or `assessment`) is chosen before the process starts.
- The engagement, its scope and its rules of engagement go into the context.
- The tool catalog is filtered by role and risk ceiling.
- Each call passes the `execute.before` gate, gets a decision, asks for R2 approval if needed, and is captured.
- The backend runs it and produces artifacts, which feed tasks, findings and the report.

### What the fork changes in each layer

| Layer             | Upstream OpenCode V2                                                       | What the fork adds or changes                                                                                                           |
| ----------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| CLI and TUI       | `packages/cli`, `packages/tui`: entry point, commands, Solid TUI, client   | Wordmark, ` (Cyber)` version, own updater, shared state (F-004), assessment profile launcher, export profiles                           |
| Server            | `packages/server`: HttpApi, auth, SSE, Location middleware                 | Session export handler and transfer contract. The rest is untouched                                                                     |
| Core              | Session runner, agents, tools, permissions, plugins, compaction, MCP       | `ForkCyberPlugin`, process policy, hardened file access, attempt tracing, tool input repair, manual delegation                          |
| Providers         | `packages/ai` protocols and providers                                      | Claude Pro/Max OAuth plugin (F-002)                                                                                                     |
| Data              | `opencode.db`: sessions, messages, credentials, projects, permissions      | Separate `evidence.sqlite`. `opencode.db` is shared with the official install by default                                                |
| Clients           | Web app, desktop, session UI, SDK                                          | Auto-approval and permission model adjustments in `app`. Desktop untouched                                                              |
| Build and release | Bun build, `latest` and `beta` channels, npm                               | `cyber` channel build, GitHub Releases, Windows verification, own installer and updater                                                 |
| CI                | Upstream workflows on hosted and Blacksmith runners (disabled in the fork) | `fork-*` workflows on `ubuntu-latest`: typecheck, tests, Kali, Chromium, code review and surface labs, ledger, release, runner recovery |

Every change to an upstream file is recorded in the [ledger](../../FORK.md#7-ledger-of-fork-changes-to-upstream-code), and CI fails when one is missing.

## The cyber layer

The cyber layer is a built-in plugin that hooks into the OpenCode session lifecycle, not a separate service. It reads best as a stack:

| Plane       | What it holds                                                                        |
| ----------- | ------------------------------------------------------------------------------------ |
| Operator    | Authority and configuration that live outside the model: profile, scope, approvals   |
| Integration | Session lifecycle hooks: context, `execute.before`, `execute.after`, compaction      |
| Policy      | Mode, role, risk class, scope and approval                                           |
| Domains     | 31 typed tools grouped by target type, listed in the [tool reference](tools.md)      |
| Backends    | Isolated, bounded execution: HTTP client, Kali jobs, Chromium identities, cloud APIs |
| Evidence    | Artifacts, decisions, tasks, coverage and findings, across all planes                |

The code lives in `packages/core/src/fork-cyber/` (one module per domain), with tool registrations and the session hooks under `packages/core/src/fork-cyber/tools/`. `packages/core/src/plugin/fork-cyber.ts` is the thin plugin entrypoint. Tests are in `packages/core/test/plugin/fork-cyber*.test.ts`.

What is stored: the input and output of every non-administrative execution, binary artifacts with hashes, provenance, effective scope, allow and deny decisions, approvals, tasks, coverage and findings.

What is not stored: model reasoning, provider secrets, credential values (only leases), and the internal state of Kali or Chromium.

## What happens in a tool call

The decision happens before execution. A denied call sends no traffic and opens no execution record. An allowed call opens its execution record before touching the target.

```mermaid
sequenceDiagram
  participant M as Model
  participant G as Cyber gate
  participant O as Operator
  participant E as Executor
  participant T as Target
  participant D as evidence.sqlite
  M->>G: tool call
  G->>D: write decision (allow or deny)
  alt denied
    G-->>M: refused_by_policy, no traffic
  else R2 action
    G->>O: approval prompt (action and target)
    O-->>G: approve for 10 minutes
  end
  G->>D: open execution record
  G->>E: run
  E->>E: scope, budget, claim
  E->>T: bounded request or job
  T-->>E: response
  E->>D: original bytes and hashes
  E-->>M: redacted preview and artifact IDs
```

The gate checks, in order:

1. Mode: `development`, `review` or `assessment`.
2. Role: can this agent call this tool?
3. Action: is the variant declared with a risk class?
4. Ceiling: do the mode and the phase allow that risk?
5. Declaration: for R2, does the engagement declare the action?
6. Approval: for R2, is there a current operator approval?

Then the executor checks:

1. Scope: the exact host, CIDR, service or resource.
2. Budget: `max_rps`, bytes, connections and duration.
3. Claim: a phase worker needs an active task.

Each decision, allowed or denied, is written to `cyber_decision` before anything else happens. The table is append-only, enforced by a trigger. The model never sees raw credential values. It gets redacted previews of at most 8,000 characters and artifact IDs it can pass to `cyber_artifacts` or `evidence`.

## Policy

### Modes

`development` keeps ordinary OpenCode access and project discovery. `review` allows source and evidence inspection and code review. `assessment` adds scoped HTTP, browser, Kali and surface tools, and delegation under the same policy. Review and assessment also disable target configuration, plugins, MCP servers, agents and instruction discovery before the Location starts, so a reviewed repository cannot load its own extensions. The [audit corrections](audit.md#controlled-modes) explain the details.

Modes are policy, not a process sandbox. Approved operator plugins keep the service's OS permissions.

### R2 approval

An R2 action runs only when all of this is true:

- The session is in `assessment` mode.
- The agent's phase ceiling reaches R2.
- The engagement declares the exact action in `rules_of_engagement.validation`.
- The operator approves that action on that target.

The approval lasts ten minutes and there is no "always". It does not prove that the target is a lab (`environment: laboratory` is a manifest attestation), it does not identify the operator cryptographically, and it covers origin plus path without the query string. See the [approval guide](approval.md).

### Roles and ceilings

| Agent               | Ceiling | Main lane                                                          | Can confirm findings          | Notes                                                                  |
| ------------------- | ------- | ------------------------------------------------------------------ | ----------------------------- | ---------------------------------------------------------------------- |
| primary (top-level) | By mode | Full assessment set plus delegation                                | Yes, with validation evidence | Only agent that can propose or change scope. In assessment it proposes |
| `cyber-recon`       | R1      | Observe: read, glob, grep, HTTP GET/HEAD/OPTIONS, `cyber_services` | No                            | Never exploits. No shell, no arbitrary Kali                            |
| `cyber-enum`        | R1      | Services, endpoints and authentication surfaces                    | No                            | Produces candidates for exploitation                                   |
| `cyber-exploit-web` | R2      | HTTP replay, browser, web test                                     | Only with a validation task   | No Kali, no host shell                                                 |
| `cyber-exploit-net` | R2      | Kali, services, surface, directory                                 | Only with a validation task   | No web tools                                                           |
| `cyber-postex`      | none    | None                                                               | No                            | No tools until a lab VM tier with per-action approval exists           |
| `cyber-validate`    | R2      | Validation, local validation, directory                            | Yes, that is its job          | Reproduces from scratch and does not improve the finding               |
| `cyber-code-review` | R0      | Source review, SARIF, artifacts, binary, directory                 | No                            | Never runs project code                                                |
| `cyber-report`      | R0      | Read-only: tasks, coverage, findings, report                       | No                            | Never changes scope, notes, findings or the environment                |

The role lanes are in `packages/core/src/fork-cyber/roles.ts` and the risk table in `packages/core/src/fork-cyber/decision.ts`.

## Data

There are two databases with different owners and lifecycles.

**`opencode.db`** belongs to OpenCode. It holds sessions, messages, events, credentials, projects, permissions and schedules. By default OpenCyber shares it with the official `opencode` install (F-004), so it contains the full transcript of an assessment, including targets and results. Upstream owns its migrations and the fork avoids touching them. Deleting a chat does not delete cyber evidence.

**`evidence.sqlite`** belongs to the harness and lives in `Global.data/opencyber`. It holds engagements, notes, executions, artifacts, findings, tasks, coverage, decisions, approvals, sealed credentials, budgets and attempt traces, at schema version 12. Each artifact has a SHA-256 hash. `cyber_decision` and `cyber_credential_lease` are append-only by trigger. Export and purge are manual and need the server stopped. The [storage guide](storage.md) covers the lifecycle.

### Shared and isolated profiles

| Resource               | Default `opencyber`                                          | Isolated profile (`script/fork-cyber-profile.ts`)   |
| ---------------------- | ------------------------------------------------------------ | --------------------------------------------------- |
| Sessions and logins    | `opencode.db` shared with the official install               | The profile's own database                          |
| Evidence               | `Global.data/opencyber/evidence.sqlite`                      | `<profile>/data/opencode/opencyber/evidence.sqlite` |
| Configuration          | `~/.config/opencode`                                         | `<profile>/config/opencode`                         |
| TUI state              | `latest` channel, shared                                     | The profile's own channel                           |
| Engagement credentials | Sealed in `evidence.sqlite`, key in `Global.state/opencyber` | Key and database inside the profile                 |
| Recommended for        | Development, labs, everyday coding                           | Assessments with client data                        |

Engagement credentials are encrypted with AES-256-GCM, with the owner, label and kind as associated data. The key is kept in the state directory, apart from the database. On POSIX the file mode is forced to 0600. On Windows the profile ACL protects it.
