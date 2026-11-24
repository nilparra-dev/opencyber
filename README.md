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

The agent records scope with the built-in `engagement` tool. Intrusive validation requires `assessment` mode and an explicit operator approval; active jobs keep the scope they were admitted with, and credentials are released per action rather than handed to the model. See [controlled modes](docs/cyber/audit.md#controlled-modes), [approvals](docs/cyber/approval.md) and [credentials](docs/cyber/credentials.md).

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
| All cyber assessment guides | [Cyber assessment guides](docs/cyber/README.md) |
| Roadmap, phases and acceptance tests | [Roadmap](docs/cyber/plan.md) |
| Tool catalog and design rules | [Tool catalog](docs/cyber/toolset.md) |
| Fork maintenance, sync and ledger | [FORK.md](FORK.md) |

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
