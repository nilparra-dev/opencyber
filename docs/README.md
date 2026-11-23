# OpenCyber documentation

Start with [getting started](getting-started.md) if you want to run an assessment, or with [architecture](architecture.md) if you want to change the code. Maintaining the fork itself (branches, upstream sync, the ledger, CI and releases) is covered in [`FORK.md`](../FORK.md).

## Overview

| Document                              | What it covers                                                                    |
| ------------------------------------- | --------------------------------------------------------------------------------- |
| [Getting started](getting-started.md) | Install, isolated profiles, modes, recording scope, optional backends and exports |
| [Architecture](architecture.md)       | Runtime, the cyber layer, the decision chain, roles, data ownership               |
| [Tool reference](tools.md)            | The 31 native tools with their risk class per action and the guide for each       |

## Guides

How each module works, how to configure it and where it stops.

**Engagement and evidence**

| Guide                                  | What it covers                                                                            |
| -------------------------------------- | ----------------------------------------------------------------------------------------- |
| [Evidence storage](guides/storage.md)  | `evidence.sqlite`, records and guarantees, retrieval, export, purge and isolated profiles |
| [Coordination](guides/coordination.md) | Tasks, hypotheses, exclusive claims, coverage and runtime phase permissions               |
| [R2 approval](guides/approval.md)      | What must be true before an intrusive action runs, and what an approval does not prove    |
| [Credentials](guides/credentials.md)   | Brokered credential labels, leases and how values stay out of model context               |

**Execution environments**

| Guide                                   | What it covers                                                                        |
| --------------------------------------- | ------------------------------------------------------------------------------------- |
| [Kali jobs](guides/kali.md)             | Image build, configuration, binary allowlist, artifact transfers, limits and cleanup  |
| [Network controls](guides/network.md)   | Destination and exclusion enforcement, rates, byte quotas and deadlines for Kali jobs |
| [Browser identities](guides/browser.md) | Isolated Chromium identities, checkpoints, HTTP evidence correlation and capture gaps |

**Target types**

| Guide                                                   | What it covers                                                                           |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| [HTTP](guides/http.md)                                  | Request, replay, compare and discovery with scope, rate limits and exact capture         |
| [Web validation](guides/web-validation.md)              | Per-class R2 oracles: open redirect, path traversal, SQLi, command injection, XSS, SSRF  |
| [Discovery](guides/discovery.md)                        | Passive DNS, certificate transparency, host sweeps and fingerprinting                    |
| [TCP services](guides/services.md)                      | Unprivileged Nmap inventory and fixed unauthenticated probes                             |
| [Surface workflows](guides/surfaces.md)                 | TLS, SSH, identity, S3, Android APK, ELF, wireless PCAP and Modbus                       |
| [Linux hosts](guides/host.md)                           | SSH audit, privilege-escalation conditions and the Linux host lab                        |
| [Directories](guides/directory.md)                      | LDAP enumeration, password policy, Kerberos and AD CS review                             |
| [Directory credential checks](guides/directory-auth.md) | Declared authentication tests and offline cracking with recovered values kept in the job |
| [Databases](guides/database.md)                         | Redis and Elasticsearch exposure checks, config review and declared logins               |
| [Cloud](guides/cloud.md)                                | IAM analysis, Checkov IaC scans, and read-only AWS S3 and Kubernetes RBAC checks         |
| [Containers](guides/container.md)                       | Dockerfile and runtime review, image advisory matching and pinned pulls                  |
| [Binaries and firmware](guides/binary.md)               | PE parsing and firmware signature scans in network-disabled jobs                         |
| [Code review](guides/code-review.md)                    | Source snapshots, SARIF import, secret scanning, dependency matching and Semgrep         |
| [Advisory snapshots](guides/advisory.md)                | The pinned advisory data that dependency and image matching use                          |

## Design records

Decisions and history. These describe why the system looks the way it does and what is still planned. They are not usage guides.

| Record                                   | What it covers                                                                     |
| ---------------------------------------- | ---------------------------------------------------------------------------------- |
| [Implementation plan](design/plan.md)    | Goals, architecture decisions, delivery phases 0 to 8 and the CY audit backlog     |
| [Toolset design](design/toolset.md)      | Cross-cutting tool rules, risk classes, delivery waves and the OC work item status |
| [Audit corrections](design/audit.md)     | The September 30 audit fixes and the controlled modes                              |
| [Harness corrections](design/harness.md) | H01 to H18, the operator workflow and the deterministic checks                     |
| [Model evaluation](design/evaluation.md) | The first matched baseline and candidate model comparison                          |

## Writing docs

- User-facing guides go in `docs/guides/`, decision records in `docs/design/`.
- Every new tool needs a row in the [tool reference](tools.md) with the risk classes from `packages/core/src/fork-cyber/decision.ts`.
- Use relative links. Docs live in fork-only paths, so they never conflict with upstream.
