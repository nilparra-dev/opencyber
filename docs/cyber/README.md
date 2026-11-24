# Cyber assessment guides

OpenCyber records scope, runs bounded tests, stores evidence and writes findings. The [root README](../../README.md) covers install and quick start; [FORK.md](../../FORK.md) covers how the fork is maintained.

Start with [getting started](getting-started.md) to run a first scoped assessment, or [architecture](architecture.md) to change the code. The [active roadmap](roadmap.md) lists the next tracks; the [implementation plan](plan.md) and [toolset design](toolset.md) are the historical records they replace. Every guide states its verified limits. Laboratory fixtures are not capability claims.

## Reference

| Document | What it covers |
| --- | --- |
| [Getting started](getting-started.md) | Install, isolated profiles, modes, recording scope, optional backends and exports |
| [Architecture](architecture.md) | Runtime, the cyber layer, the decision chain, roles and data ownership |
| [Tool reference](tools.md) | The 31 native tools with their risk class per action and the guide for each |
| [Roadmap](roadmap.md) | Active architecture decisions, triage outcomes and Tracks 0 to 5 |

## Guides

| Guide | What it covers |
| --- | --- |
| [Implementation plan](plan.md) | Historical delivery phases, acceptance tests, current limits and migration |
| [Toolset design](toolset.md) | Historical target catalog, risk classes, design rules and planned work |
| [Audit corrections](audit.md) | Controlled modes, provenance, findings and remaining backend work |
| [Harness](harness.md) | Diagnostics, exports, evidence access and the evaluation workflow |
| [Storage](storage.md) | Evidence archive, schema migrations, export and purge |
| [Coordination](coordination.md) | Durable tasks, hypotheses, coverage and role permissions |
| [Approvals](approval.md) | R2 actions, operator prompts and refusal reasons |
| [Credentials](credentials.md) | Brokered labels and credential custody |
| [Network](network.md) | Destinations, exclusions, rates and byte budgets |
| [Evaluation](evaluation.md) | Matched model comparisons and scoring |

## Web

| Guide | What it covers |
| --- | --- |
| [HTTP](http.md) | Request, replay, compare, scope, rate limits and evidence |
| [Browser](browser.md) | Isolated Chromium identities, checkpoints and traffic capture |
| [Web validation](web-validation.md) | R2 validators, oracles and validation records |

## Execution

| Guide | What it covers |
| --- | --- |
| [Kali](kali.md) | Container jobs, image builds, artifacts and resource limits |
| [Host](host.md) | Linux host audit and privilege configuration review |
| [Container](container.md) | Dockerfile, runtime and image review |
| [Database](database.md) | Unauthenticated, configuration and credential tests |

## Surfaces and review

| Guide | What it covers |
| --- | --- |
| [Discovery](discovery.md) | Passive DNS, certificates, host sweeps and fingerprints |
| [Services](services.md) | Bounded TCP service inventory |
| [Surfaces](surfaces.md) | TLS, SSH, identity, cloud, mobile, binary, wireless and OT |
| [Directory](directory.md) | Read-only directory service assessment |
| [Directory auth](directory-auth.md) | R2 directory authentication and cracking |
| [Binary](binary.md) | Offline ELF analysis and reproduction |
| [Cloud](cloud.md) | Offline configuration review and live read-only inventory |
| [Code review](code-review.md) | Source snapshots, SARIF import and SCA |
| [Advisory](advisory.md) | Pinned advisory snapshots and matching rules |
