<h1 align="center">
  <img src=".github/assets/opencyber.svg" alt="OpenCyber" width="420">
</h1>

<p align="center"><strong>The open source cybersecurity harness.</strong></p>

<p align="center">
  <a href="https://github.com/nilparra-dev/opencyber/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/nilparra-dev/opencyber?style=flat-square"></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/github/license/nilparra-dev/opencyber?style=flat-square"></a>
  <a href="https://opencyber.tech"><img alt="Website" src="https://img.shields.io/badge/website-opencyber.tech-b4232d?style=flat-square"></a>
</p>

OpenCyber is a terminal agent for authorized security testing. Give it a target you own or have written permission to test: a web app, an API, a server, a cloud account or a codebase. It maps the surface, tests one hypothesis at a time, and writes a report where every confirmed finding carries the request, the response and the steps that reproduce it.

It is built on [opencode](https://github.com/anomalyco/opencode), which provides the agent runtime, TUI, model providers and session storage. Scope enforcement, evidence, HTTP testing, isolated browsers, Kali jobs, code review and the assessment workflow are OpenCyber's.

> [!WARNING]
> Use OpenCyber only against systems you own or have written permission to test. Read the [authorized use policy](https://opencyber.tech/authorized-use) before you start.

## Install

OpenCyber publishes prebuilt binaries for Linux x64 and Windows x64.

```bash
# Linux
curl -fsSL https://opencyber.tech/install | bash
```

```powershell
# Windows (PowerShell)
irm https://opencyber.tech/install.ps1 | iex
```

The installer places `opencyber` in `~/.opencyber/bin`. On Windows it adds that directory to your user `PATH`; on Linux it prints the line to add to your shell profile. To pin a release:

```bash
curl -fsSL https://opencyber.tech/install | OPENCYBER_VERSION=2.4.1-cyber.1 bash
```

```powershell
$env:OPENCYBER_VERSION = "2.4.1-cyber.1"; irm https://opencyber.tech/install.ps1 | iex
```

Prebuilt archives and `SHA256SUMS` are on [Releases](https://github.com/nilparra-dev/opencyber/releases). `opencyber --version` prints the upstream version with the fork marker, for example `2.4.1 (Cyber)`.

## Quick start

```bash
cd /path/to/your/project
opencyber
```

Declare the engagement, then ask for the audit:

```text
Record an engagement for staging.example.com and api.staging.example.com.
Exclude admin.staging.example.com. I own this target and authorize testing.
Map the web app, test one hypothesis at a time, and write the report to ./report.
```

The agent records scope with the built-in `engagement` tool. Intrusive validation requires `assessment` mode and an explicit operator approval; active jobs keep the scope they were admitted with, and credentials are released per action rather than handed to the model. See [controlled modes](fork-cyber-audit.md#controlled-modes), [approvals](fork-cyber-approval.md) and [credentials](fork-cyber-credentials.md).

## What a run produces

- **Scope first.** Hosts, CIDR ranges, services, exclusions and rate limits are structured operator data enforced by the harness, not text in the prompt.
- **Evidence, not prose.** Executions and artifacts are stored outside the model context, and findings link back to the request and response that proved them.
- **Hypotheses and coverage.** The report lists what was tested, what was ruled out and what remains unexamined.
- **Isolation where it matters.** Local code review works without Docker. Kali jobs run in a fresh container, and the browser manager gives each identity its own context.
- **Your model.** Use any provider opencode supports, including existing logins and configuration.

A finding in a report looks like this:

```text
HIGH  Broken access control on /api/invoices/{id}

GET /api/invoices/1042
Cookie: session=<user B>
200 OK  { "customer": "user A", "total": 1840.00 }

Fix: verify that the invoice belongs to the session's account before returning it.
```

## Documentation

| Topic | Guide |
| --- | --- |
| How this fork works: branches, sync, ledger | [FORK.md](FORK.md) |
| Roadmap, phases and acceptance tests | [fork-cyber-plan.md](fork-cyber-plan.md) |
| Tool catalog and design rules | [fork-cyber-toolset.md](fork-cyber-toolset.md) |
| HTTP request, replay and compare | [fork-cyber-http.md](fork-cyber-http.md) |
| Isolated browser sessions and capture | [fork-cyber-browser.md](fork-cyber-browser.md) |
| Kali jobs and resource limits | [fork-cyber-kali.md](fork-cyber-kali.md) |
| Code review, SARIF and advisory snapshots | [fork-cyber-code-review.md](fork-cyber-code-review.md), [fork-cyber-advisory.md](fork-cyber-advisory.md) |
| Intrusive approvals | [fork-cyber-approval.md](fork-cyber-approval.md) |
| Credential custody | [fork-cyber-credentials.md](fork-cyber-credentials.md) |
| TCP service inventory | [fork-cyber-services.md](fork-cyber-services.md) |
| TLS, SSH, identity, cloud, mobile, binaries, wireless and OT | [fork-cyber-surfaces.md](fork-cyber-surfaces.md) |
| DNS and discovery | [fork-cyber-discovery.md](fork-cyber-discovery.md) |
| Tasks, coverage and roles | [fork-cyber-coordination.md](fork-cyber-coordination.md) |
| Evidence storage and archives | [fork-cyber-storage.md](fork-cyber-storage.md) |
| Network policy and limits | [fork-cyber-network.md](fork-cyber-network.md) |
| Controlled modes and audit corrections | [fork-cyber-audit.md](fork-cyber-audit.md) |
| Harness hardening and evaluation workflow | [fork-cyber-harness.md](fork-cyber-harness.md) |
| Model comparisons | [fork-cyber-evaluation.md](fork-cyber-evaluation.md) |

Each guide states its verified limits. Some workflows are local and bounded: live cloud accounts, emulators and devices, radio equipment and physical OT validation remain pending. Laboratory fixtures are not capability claims.

## Requirements

- Linux x64 or Windows x64 for the prebuilt binary.
- A model provider configured in `~/.config/opencode/`, or an interactive login on first run.
- Docker for Kali jobs and a local Chromium executable for the browser manager. Neither is required for local code review or HTTP testing.
- Permission to test the target.

## Relationship to opencode

OpenCyber is a fork of [opencode](https://github.com/anomalyco/opencode) that follows its V2 releases. Upstream supplies the session engine, permissions, compaction and provider integrations; every fork change is recorded in [FORK.md](FORK.md). OpenCyber shares configuration and the session database with an official opencode install by default, while running its own background service.

## Contributing

Read [FORK.md](FORK.md) and [AGENTS.md](AGENTS.md) before changing code, then follow [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities through [SECURITY.md](SECURITY.md), never in a public issue.

## License

MIT. See [LICENSE](LICENSE). The upstream opencode copyright notice is retained.
