# Tool reference

OpenCyber registers 31 native tools from `packages/core/src/fork-cyber/tools/` through the `packages/core/src/plugin/fork-cyber.ts` entrypoint. This page lists each one with its risk class and the guide that explains it. The risk classes come from `packages/core/src/fork-cyber/decision.ts`, and the tool descriptions in those modules are the source of truth for inputs and outputs.

Risk classes:

- **R0** sends no traffic to a target. Local or offline analysis and governance.
- **R1** sends bounded traffic to an in-scope target.
- **R2** is intrusive validation. It runs only in `assessment` mode, only when the engagement declares the action, and only after the operator approves it for ten minutes. See the [approval guide](approval.md).
- **R3** (impact) is never declared, so no tool can run it.

Each mode has a ceiling: `development` allows R0 and R1, `review` allows R0, `assessment` allows R0 to R2. Each phase agent has its own ceiling on top of that, listed in [architecture](architecture.md#roles-and-ceilings). A call has to pass both.

## Engagement and governance

| Tool                 | Risk | What it does                                                                                            | Guide                                              |
| -------------------- | ---- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `engagement`         | R0   | Reads the effective engagement. A top-level session can record a manifest or patch scope.               | [plan](plan.md#phase-1-usage-and-migration) |
| `notes`              | R0   | Reads or appends durable engagement notes. The model context only gets a short recent summary.          | [storage](storage.md)                       |
| `cyber_tasks`        | R0   | Shared tasks and hypotheses with exclusive claims. Interrupted work is never replayed automatically.    | [coordination](coordination.md)             |
| `cyber_coverage`     | R0   | Planned coverage with task state and execution counts. It lists recorded tasks, not the whole target.   | [coordination](coordination.md)             |
| `cyber_capabilities` | R0   | Diagnoses operator configuration and what each role can call, without touching targets.                 | [harness](harness.md#operator-workflow)     |
| `cyber_credentials`  | R0   | Lists declared credential labels and their limits. Values are never returned.                           | [credentials](credentials.md)               |
| `evidence`           | R0   | Reads captured executions, artifact metadata and redacted previews.                                     | [storage](storage.md)                       |
| `findings`           | R0   | Lists findings or writes a candidate, confirmed or discarded one. Confirmation needs a validation task. | [storage](storage.md)                       |
| `cyber_report`       | R0   | Report projection with exact counts, blocked work, pending coverage and evidence references.            | [coordination](coordination.md)             |

## Web and HTTP

| Tool             | Risk                                                     | What it does                                                                                         | Guide                                      |
| ---------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `http_request`   | R1                                                       | One HTTP(S) request inside scope. Every redirect is checked and the exact response bytes are stored. | [http](http.md)                     |
| `http_replay`    | R1                                                       | Replays a captured request, optionally with other headers to test another account.                   | [http](http.md)                     |
| `http_compare`   | R0                                                       | Compares two captured responses without network traffic.                                             | [http](http.md)                     |
| `http_discover`  | R1                                                       | Checks a fixed list of read-only paths, one GET each, and suppresses soft 404s.                      | [http](http.md)                     |
| `finding_retest` | R1                                                       | Replays up to three requests from a finding's evidence to check whether a fix holds.                 | [plan](plan.md)                     |
| `cyber_browser`  | R1                                                       | Isolated Chromium identity. Its HTTP traffic goes through the same scope and capture as HTTP tools.  | [browser](browser.md)               |
| `cyber_web_plan` | R0                                                       | Builds a pending test plan from observed web features. It plans, it does not test.                   | [harness](harness.md)               |
| `cyber_web_test` | `openapi`, `jwt`, `plan` R0. `graphql` R1. `validate` R2 | OpenAPI and JWT analysis, one GraphQL introspection query, and per-class validation oracles.         | [web validation](web-validation.md) |

## Network, hosts and directories

| Tool              | Risk                                                                                                                                                                                 | What it does                                                                                                        | Guide                                                                           |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `cyber_discover`  | `passive_dns`, `certificates` R0. `host_sweep`, `fingerprint` R1                                                                                                                     | Passive DNS, certificate transparency, and bounded host sweeps inside declared ranges.                              | [discovery](discovery.md)                                                |
| `cyber_services`  | `procedures` R0. `scan`, `version`, `udp_top`, `probe` R1                                                                                                                            | Unprivileged Nmap connect scans of one host and up to 32 TCP ports, and fixed unauthenticated probes.               | [services](services.md)                                                  |
| `cyber_surface`   | `procedures`, `import`, `cloud.policy`, `mobile.apk`, `wireless.pcap`, `binary.elf` R0. `tls.probe`, `ssh.probe`, `identity.matrix`, `cloud.s3`, `ot.modbus` R1. `binary.execute` R2 | Module procedures, artifact import and the TLS, SSH, identity, S3, APK, ELF, wireless and Modbus workflows.         | [surfaces](surfaces.md)                                                  |
| `cyber_host`      | `procedures` R0. `audit`, `privesc_config` R1                                                                                                                                        | Read-only Linux host audit over SSH with a declared credential. No exploitation.                                    | [host](host.md)                                                          |
| `cyber_directory` | `procedures`, `kerberos_config`, `adcs_templates` R0. `ldap_enum`, `password_policy`, `collect` R1. `auth_test`, `crack` R2                                                          | LDAP enumeration, password policy, bounded subtree reads, offline Kerberos and AD CS review, and credential checks. | [directory](directory.md), [credential checks](directory-auth.md) |
| `cyber_database`  | `config_review` R0. `unauth_check` R1. `auth_test` R2                                                                                                                                | Unauthenticated Redis and Elasticsearch checks, offline config review, and one declared login attempt.              | [database](database.md)                                                  |

## Code, artifacts, cloud and containers

| Tool                     | Risk                                                                     | What it does                                                                                                      | Guide                                |
| ------------------------ | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `cyber_code_review`      | R0                                                                       | Source snapshots, secret scanning, dependency matching, SARIF import and pinned Semgrep. Project code never runs. | [code review](code-review.md) |
| `cyber_artifacts`        | R0                                                                       | Searches the original bytes of captured artifacts for literals, bounded secret patterns and asset references.     | [harness](harness.md)         |
| `cyber_binary`           | R0                                                                       | PE parsing with pefile and firmware signature scans with binwalk, in a network-disabled Kali job.                 | [binary](binary.md)           |
| `cyber_cloud`            | `iam_analyze`, `iac_scan` R0. `inventory`, `config_audit`, `k8s_rbac` R1 | Offline IAM and Checkov analysis, and read-only GET requests to AWS S3 and Kubernetes RBAC endpoints.             | [cloud](cloud.md)             |
| `cyber_container`        | `dockerfile_lint`, `runtime_review`, `image_scan` R0. `pull` R1          | Offline Dockerfile and `docker inspect` review, advisory matching, and pulling one image pinned by digest.        | [container](container.md)     |
| `cyber_local_validation` | R2                                                                       | Reproduces a reviewed fixture with a healthy and a candidate input in separate network-disabled Kali jobs.        | [approval](approval.md)       |

## Execution environment

| Tool               | Risk | What it does                                                                                          | Guide                                                         |
| ------------------ | ---- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `kali_run`         | R1   | Runs an allowlisted binary in a Kali Docker job. Other binaries, shells and interpreters are refused. | [kali](kali.md), [network controls](network.md) |
| `kali_environment` | R0   | Shows this engagement's Kali containers, or stops them and clears stale locks.                        | [kali](kali.md)                                        |

## Errors

Every cyber tool reports failures with one of seven categories: `not_configured`, `invalid_input`, `outside_scope`, `target_unreachable`, `budget_exceeded`, `tool_failure` and `refused_by_policy`. Each category has a recovery step in `packages/core/src/fork-cyber/diagnostics.ts`. The specific cause is in `kind`.
