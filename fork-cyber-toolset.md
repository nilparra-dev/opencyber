# OpenCyber audit toolset: design and roadmap

Status: accepted with the recommendations in section 7 (#81). Implementation status is in section 10. Baseline when proposed: `origin/custom` at `bc43767fcf`.

This document defines the target catalog of tools for authorized security assessments and the rules every tool must follow. It extends the phase plan in [fork-cyber-plan.md](fork-cyber-plan.md): phases 0 to 6 remain the implemented foundation, and new surface modules are planned here. Work items below use stable IDs (`OC-###`) and are tracked as GitHub issues.

## 1. Goals and non-goals

Goals:

- Support authorized assessments of different kinds of systems: web applications, network services, identity directories, cloud accounts, hosts, source code, dependencies, containers, databases, binaries and operational technology.
- Make every tool declare the target types it accepts, its risk class, its phase, and the evidence it produces.
- Enforce scope, rate limits and permissions in the harness, not in the prompt.
- Return structured results that a model can use with few tokens and few retries.

Non-goals:

- Benchmark and evaluation infrastructure. Those are covered by [fork-cyber-evaluation.md](fork-cyber-evaluation.md) and the harness guide.
- Post-exploitation, persistence, lateral movement and denial of service. These are risk class R3 and are performed by an operator outside the harness.
- Physical radio and hardware OT testing. These require equipment and a human operator.

## 2. Current state

The plugin registers 22 cyber tools today. The table lists what each one does and where it stops.

| Tool                                                                                                                                          | Current behavior                                                                                      | Verified limit                                         |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `http_request`, `http_replay`, `http_compare`                                                                                                 | HTTP(S) requests with scope, rate limits, evidence and response comparison                            | Web only. `http_discover` is planned                   |
| `cyber_browser`                                                                                                                               | Isolated Chromium identity: navigation, interaction, screenshots, cookie and localStorage checkpoints | No WebSockets, service workers, downloads or popups    |
| `cyber_web_plan`                                                                                                                              | Feature-based web test plan                                                                           | Documents work; runs no tests                          |
| `cyber_dns`                                                                                                                                   | A, AAAA, CAA, CNAME, TXT, MX, NS, SOA queries                                                         | No AXFR, SRV or PTR                                    |
| `cyber_services`                                                                                                                              | TCP inventory through an nmap connect scan, IPv4 and IPv6, up to 32 ports                             | No UDP, version detection or scripts                   |
| `cyber_surface`                                                                                                                               | Modules `tls`, `ssh`, `identity`, `cloud`, `mobile`, `binary`, `wireless`, `ot`                       | Each module is narrow. `cloud` covers S3 only          |
| `cyber_artifacts`                                                                                                                             | Analysis of original bytes: literal patterns and asset references                                     | No unpacking or decompilation                          |
| `cyber_code_review`                                                                                                                           | Source snapshots and SARIF import                                                                     | Does not run the analyzer                              |
| `cyber_local_validation`                                                                                                                      | Candidate compared with a healthy control in an offline container                                     | Local laboratory only                                  |
| `kali_run`, `kali_environment`                                                                                                                | Arbitrary `argv` in a Kali container; network `none` by default                                       | No typed inputs, no declared risk, no binary allowlist |
| Governance: `engagement`, `notes`, `cyber_tasks`, `cyber_coverage`, `cyber_capabilities`, `findings`, `evidence`, `cyber_report`, `subagents` | Provenance, tasks, coverage, findings and reporting                                                   | `findings` has no re-verification action               |

Phase roles (`roles.ts`) currently grant `observe` to recon and enumeration, and the same `assess` set to exploit-web, exploit-net, postex and validate. The exploitation and post-exploitation roles therefore share one tool set, and the phase split is nominal. `cyber-postex` has no tools of its own.

In short, the typed tools are mostly web tools. Work outside the web relies on `kali_run`, where the model writes commands without typed inputs, risk declaration or allowlisting.

## 3. Cross-cutting rules

These rules apply to every tool. They should be in place (W0) before new domain tools are added.

**R-1. Typed targets.** The scope manifest models hosts, CIDR ranges, services and S3 resources. It must support the following target types, each with a named enforcement point:

| Target type              | Example                                               | Enforcement point                                                                          |
| ------------------------ | ----------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `host`, `cidr`, `domain` | `10.0.0.5`, `10.0.0.0/24`, `app.example.test`         | Kali egress policy; pinned addresses in HTTP (existing)                                    |
| `service`                | `10.0.0.5:445/tcp`                                    | Egress policy per port (existing)                                                          |
| `url`                    | `https://app.example.test/api`                        | HTTP scope (existing)                                                                      |
| `cloud_resource`         | `arn:aws:s3:::bucket`, account, subscription, project | Read-only identity and resource filter before each API call. Network policy does not apply |
| `repo_path`              | Snapshot of a directory                               | No access outside the snapshot                                                             |
| `container_image`        | `registry/repo@sha256:…`                              | Pull by digest only                                                                        |
| `device`                 | Industrial or wireless device address or serial       | Same as `host`; simulator by default                                                       |
| `directory`              | Active Directory domain or organizational unit        | Bounded read-only directory account                                                        |

**R-2. Risk class per action.**

| Class                    | Definition                                                                             | Allowed in                                                                       |
| ------------------------ | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| R0, passive or local     | No traffic to targets: file analysis, offline review, declared public OSINT            | `review`, `assessment`                                                           |
| R1, bounded active       | Traffic inside scope with rate limits and no destructive effects: reads, benign probes | `assessment`                                                                     |
| R2, intrusive validation | Test payloads, credential testing, exploitability confirmation                         | Only with an engagement flag and per-action approval. Laboratory only by default |
| R3, impact               | Denial of service, writes, persistence, lateral movement, access to real data          | Not implemented in the harness                                                   |

Until the approval flow exists (OC-401), R2 actions are denied in every mode.

**R-3. One decision point.** A single function evaluates (action, target type, risk class, phase, engagement flags) and returns `allow`, `ask` or `deny` before `execute()`. Every decision is written to the audit log, including denials. This replaces the repeated checks in `plugin/fork-cyber.ts` (around lines 180, 239–251 and 531), which currently combine `ForkCyberPolicy.allowed` with `ForkCyberRoles.allowed`.

**R-4. Phase ceilings.** Each phase declares the highest risk class its tools may use.

| Phase               | Ceiling             | Tool families                                            |
| ------------------- | ------------------- | -------------------------------------------------------- |
| `cyber-recon`       | R1                  | Discovery, DNS, stateless HTTP, inventory                |
| `cyber-enum`        | R1                  | Service and identity enumeration without validation      |
| `cyber-exploit-web` | R2, flag required   | Web validation tools                                     |
| `cyber-exploit-net` | R2, flag required   | Service validators                                       |
| `cyber-postex`      | None                | No tools until a VM tier exists with per-action approval |
| `cyber-validate`    | R2, laboratory only | Candidate validation                                     |
| `cyber-code-review` | R0                  | Code, dependencies, secrets, containers (offline)        |
| `cyber-report`      | Read                | Findings, evidence, coverage                             |

**R-5. Typed wrappers over `kali_run`.** Each binary used in Kali is exposed as an action with a fixed `argv` and schema-validated parameters. `kali_run` remains for R0 and R1 work without a wrapper. It uses a binary allowlist and only reaches targets inside scope.

**R-6. Result and error contract.** Every tool returns:

- a short summary, structured fields, and an artifact ID for raw output;
- a truncated preview with `next_offset` for long results;
- an error with a category (`not_configured`, `invalid_input`, `outside_scope`, `target_unreachable`, `budget_exceeded`, `tool_failure`, `refused_by_policy`) and a concrete recovery step.

Parts of this contract exist already (H04 to H07 in the harness guide). New tools must follow it completely.

**R-7. Tool count.** Model performance degrades as the catalog grows. The catalog proposed here adds 9 tools and absorbs 2 (`cyber_dns` and `cyber_web_plan`), for 29 in total. That is above the small-catalog guidance in the research notes. Two decisions reduce it:

- Merge `http_request`, `http_replay` and `http_compare` into one `http` tool with actions (3 to 1), giving 27 tools. Decision D-6.
- Measure tool-call errors per tool with the repeated model matrix before and after each wave.

Every new tool needs a discriminator test and one literal example call in its description, as established in #53.

**R-8. Credentials stay out of the model and the container.** Cloud and directory credentials live in the OpenCyber service with the minimum scope needed by an engagement. Kali receives only what a single action needs. The model sees tool metadata and redacted output, never secret values.

**R-9. External data sources.** Queries to third parties (certificate transparency logs, internet-wide host search services) reveal interest in the target. They run only when the engagement declares passive OSINT as permitted (D-5).

## 4. Tool catalog by domain

"Candidate base" names the tool expected to back an action. None of these has been evaluated yet. Each needs a license check, a maintenance check and a pinned version before it enters the image.

### D1. Discovery

| Action                          | Risk | Target   | Status                   | Candidate base                                  |
| ------------------------------- | ---- | -------- | ------------------------ | ----------------------------------------------- |
| `cyber_discover` `passive_dns`  | R0   | `domain` | New; absorbs `cyber_dns` | dnsutils (present)                              |
| `cyber_discover` `certificates` | R0   | `domain` | New; subject to R-9      | Public certificate transparency query           |
| `cyber_discover` `host_sweep`   | R1   | `cidr`   | New                      | nmap `-sn` (present)                            |
| `cyber_discover` `fingerprint`  | R1   | `url`    | New                      | HTTP client plus a web technology fingerprinter |

### D2. Network services

| Action                       | Risk | Target    | Status       | Candidate base                                                                                                                         |
| ---------------------------- | ---- | --------- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| `cyber_services` `inventory` | R1   | `service` | Exists (TCP) | nmap (present)                                                                                                                         |
| `cyber_services` `udp_top`   | R1   | `service` | New          | nmap `-sU`; requires privileges, to be evaluated                                                                                       |
| `cyber_services` `version`   | R1   | `service` | New          | nmap `-sV` without scripts                                                                                                             |
| `cyber_services` `probe`     | R1   | `service` | New          | Unauthenticated checks: anonymous FTP, LDAP root DSE, SMB signing, NFS exports, Redis, MongoDB and Elasticsearch information endpoints |
| `cyber_surface` `tls`        | R1   | `service` | Exists       | testssl or sslyze, to be evaluated                                                                                                     |
| `cyber_surface` `ssh`        | R1   | `service` | Exists       | ssh-audit, to be evaluated                                                                                                             |

### D3. Web applications

| Action                                        | Risk | Target   | Status                          | Candidate base                                                                                                                        |
| --------------------------------------------- | ---- | -------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `http_request`, `http_replay`, `http_compare` | R1   | `url`    | Exist                           | —                                                                                                                                     |
| `http_discover`                               | R1   | `url`    | Planned                         | Bounded content discovery with a fixed wordlist and rate limit (e.g. ffuf)                                                            |
| `cyber_browser`                               | R1   | `url`    | Exists                          | Chromium                                                                                                                              |
| `cyber_web_test` `openapi`                    | R0   | artifact | New                             | Local schema analysis                                                                                                                 |
| `cyber_web_test` `graphql`                    | R1   | `url`    | New                             | Controlled schema introspection                                                                                                       |
| `cyber_web_test` `jwt`                        | R0   | artifact | New                             | Offline token analysis                                                                                                                |
| `cyber_web_test` `access_matrix`              | R1   | `url`    | New; partly in `identity` today | HTTP with two or three identities                                                                                                     |
| `cyber_web_test` `validate`                   | R2   | `url`    | New                             | Per-class validators: SQL injection, XSS, SSRF, open redirect, path traversal, command injection (e.g. sqlmap, browser-confirmed XSS) |
| `cyber_web_test` `plan`                       | R0   | `url`    | New; absorbs `cyber_web_plan`   | —                                                                                                                                     |

Validation oracles must be deterministic: a canary, an echoed value or a measured difference. The appearance of a string in a response is not an oracle. SSRF is confirmed by a callback to a server inside the scope.

### D4. Identity and directory (VM or lab tier)

| Action                              | Risk | Target          | Status                   | Candidate base                                                        |
| ----------------------------------- | ---- | --------------- | ------------------------ | --------------------------------------------------------------------- |
| `cyber_directory` `ldap_enum`       | R1   | `directory`     | New                      | ldapsearch, enum4linux-ng, to be evaluated                            |
| `cyber_directory` `kerberos_config` | R1   | `directory`     | New                      | Configuration only: accounts without pre-authentication, exposed SPNs |
| `cyber_directory` `password_policy` | R1   | `directory`     | New                      | Policy read                                                           |
| `cyber_directory` `adcs_templates`  | R1   | `directory`     | New                      | Template read                                                         |
| `cyber_directory` `collect`         | R1   | `directory`     | New                      | Read-only collection, to be evaluated                                 |
| `cyber_directory` `auth_test`       | R2   | `directory`     | New; disabled by default | Allowlisted accounts and lockout-aware pacing                         |
| `cyber_directory` `crack`           | R2   | Supplied hashes | New; disabled by default | Only hashes supplied for the engagement                               |

### D5. Cloud

| Action                       | Risk | Target           | Status | Candidate base                                                 |
| ---------------------------- | ---- | ---------------- | ------ | -------------------------------------------------------------- |
| `cyber_surface` `cloud` (S3) | R1   | `cloud_resource` | Exists | —                                                              |
| `cyber_cloud` `iam_analyze`  | R0   | artifact (JSON)  | New    | Offline analysis of exported policies                          |
| `cyber_cloud` `iac_scan`     | R0   | `repo_path`      | New    | checkov or similar, to be evaluated                            |
| `cyber_cloud` `inventory`    | R1   | `cloud_resource` | New    | Provider CLI with a read-only audit identity                   |
| `cyber_cloud` `config_audit` | R1   | `cloud_resource` | New    | prowler or ScoutSuite, to be evaluated                         |
| `cyber_cloud` `k8s_rbac`     | R1   | `cloud_resource` | New    | Read-only kubeconfig; kubescape or kube-bench, to be evaluated |

Cloud enforcement relies on identity and resource filtering. Kali needs an allowlist of provider API endpoints, which is separate from target addresses.

### D6. Hosts

| Action                         | Risk | Target   | Status        | Candidate base                                                                |
| ------------------------------ | ---- | -------- | ------------- | ----------------------------------------------------------------------------- |
| `cyber_host` `audit`           | R1   | `device` | New (VM tier) | Benchmark-style configuration checks through a read-only SSH or WinRM account |
| `cyber_host` `privesc_config`  | R1   | `device` | New (VM tier) | SUID, capabilities, sudoers, cron and service permissions. No exploitation    |
| `cyber_host` `patch_inventory` | R0   | artifact | New           | Installed packages matched against a pinned advisory database                 |

### D7. Source code, dependencies and secrets

| Action                             | Risk           | Target      | Status | Candidate base                                                                               |
| ---------------------------------- | -------------- | ----------- | ------ | -------------------------------------------------------------------------------------------- |
| `cyber_code_review` `snapshot`     | R0             | `repo_path` | Exists | —                                                                                            |
| `cyber_code_review` `sast`         | R0             | `repo_path` | New    | semgrep (SARIF import exists)                                                                |
| `cyber_code_review` `sca`          | R0             | `repo_path` | New    | Lockfiles matched against a pinned advisory database (osv-scanner or grype, to be evaluated) |
| `cyber_code_review` `secrets`      | R0             | `repo_path` | New    | gitleaks over the snapshot and its history; redacted output                                  |
| `cyber_code_review` `import_sarif` | R0             | artifact    | Exists | —                                                                                            |
| `cyber_local_validation`           | R2, laboratory | `repo_path` | Exists | —                                                                                            |

### D8. Containers

| Action                              | Risk | Target            | Status | Candidate base                                |
| ----------------------------------- | ---- | ----------------- | ------ | --------------------------------------------- |
| `cyber_container` `image_scan`      | R0   | `container_image` | New    | trivy or grype with a pinned offline database |
| `cyber_container` `dockerfile_lint` | R0   | `repo_path`       | New    | hadolint                                      |
| `cyber_container` `runtime_review`  | R0   | artifact (JSON)   | New    | Analysis of exported `docker inspect` output  |
| `cyber_container` `pull`            | R1   | `container_image` | New    | Pull by digest from a registry in scope       |

### D9. Binaries, mobile and firmware

| Action                         | Risk           | Target   | Status   | Candidate base                           |
| ------------------------------ | -------------- | -------- | -------- | ---------------------------------------- |
| `cyber_surface` `mobile` (APK) | R0             | artifact | Exists   | aapt (present)                           |
| `cyber_surface` `binary` (ELF) | R0             | artifact | Exists   | binutils (present)                       |
| `cyber_binary` `pe`            | R0             | artifact | New      | To be evaluated                          |
| `cyber_binary` `firmware`      | R0             | artifact | New      | binwalk, isolated                        |
| `cyber_binary` `dynamic`       | R2, laboratory | artifact | Deferred | Execution in a container without network |

### D10. Databases

| Action                           | Risk | Target    | Status                   | Candidate base                              |
| -------------------------------- | ---- | --------- | ------------------------ | ------------------------------------------- |
| `cyber_database` `unauth_check`  | R1   | `service` | New                      | Official client per engine, to be evaluated |
| `cyber_database` `config_review` | R0   | artifact  | New                      | Exported configuration                      |
| `cyber_database` `auth_test`     | R2   | `service` | New; disabled by default | Same controls as directory `auth_test`      |

### D11. Wireless and operational technology

| Action                                  | Risk | Target   | Status               |
| --------------------------------------- | ---- | -------- | -------------------- |
| `cyber_surface` `wireless` (PCAP)       | R0   | artifact | Exists               |
| `cyber_surface` `ot` (Modbus simulator) | R1   | `device` | Exists               |
| Live radio and physical OT              | —    | —        | Out of harness scope |

### D12. Validation

| Action                                                 | Risk | Target                     | Status                                                 |
| ------------------------------------------------------ | ---- | -------------------------- | ------------------------------------------------------ |
| Validator contract: pre-state, action, oracle, cleanup | R2   | Per validator              | New. Shared by `validate` and `cyber_local_validation` |
| `findings` `retest`                                    | R1   | Same target as the finding | New. Re-runs the finding's validator to confirm a fix  |

### D13. Governance

| Element                                                                                                 | Status  | Change                                                  |
| ------------------------------------------------------------------------------------------------------- | ------- | ------------------------------------------------------- |
| `engagement`                                                                                            | Exists  | Expanding scope requires operator approval              |
| `cyber_tasks`, `cyber_coverage`, `cyber_capabilities`, `notes`, `evidence`, `cyber_report`, `subagents` | Exist   | No catalog change                                       |
| `findings`                                                                                              | Exists  | Add `retest`                                            |
| R2 approval                                                                                             | New     | Reuse the upstream `ask` permission flow for R2 actions |
| Audit log                                                                                               | Partial | Record decisions denied by the matrix                   |

## 5. Delivery waves

Each wave ends with the positive and negative laboratory fixtures for its domains and a repeated model matrix run. A wave is complete when its acceptance criteria pass, not when its tools exist.

| Wave                                     | Purpose                                                                     | Work items       |
| ---------------------------------------- | --------------------------------------------------------------------------- | ---------------- |
| **W0** Foundations                       | Make scope, risk and decisions explicit before adding tools                 | OC-101 to OC-108 |
| **W1** R0 and R1 without a VM            | Complete web, discovery, code, container and offline cloud coverage         | OC-201 to OC-207 |
| **W2** VM tier, directory and live cloud | Host, directory, live cloud and database checks with read-only identities   | OC-301 to OC-307 |
| **W3** R2 with approval                  | Validation and credential testing, disabled by default outside laboratories | OC-401 to OC-405 |

### Work items

| ID     | Work item                                                                                                           | Depends on     |
| ------ | ------------------------------------------------------------------------------------------------------------------- | -------------- |
| **W0** |                                                                                                                     |                |
| OC-101 | Typed targets in the scope manifest (R-1), with a test per target type                                              | —              |
| OC-102 | Risk class on every tool action; decision function (R-2, R-3)                                                       | OC-101         |
| OC-103 | Phase ceilings; remove duplicated permission checks (R-4)                                                           | OC-102         |
| OC-104 | Binary allowlist for `kali_run`; typed wrapper pattern (R-5)                                                        | OC-102         |
| OC-105 | Error categories and result contract (R-6)                                                                          | —              |
| OC-106 | `findings retest` action                                                                                            | OC-102         |
| OC-107 | Audit log records denied decisions                                                                                  | OC-102         |
| OC-108 | Decide tool consolidation (D-6) with measurements from the matrix                                                   | —              |
| **W1** |                                                                                                                     |                |
| OC-201 | `http_discover`: bounded content discovery                                                                          | OC-102, OC-105 |
| OC-202 | `cyber_web_test`: `openapi`, `graphql`, `jwt`, `plan`                                                               | OC-102, OC-105 |
| OC-203 | `cyber_discover`: `passive_dns` (absorbs `cyber_dns`), `host_sweep`, `fingerprint`, `certificates` (subject to D-5) | OC-101, OC-102 |
| OC-204 | `cyber_services`: `version`, `udp_top`, `probe`                                                                     | OC-104, OC-105 |
| OC-205 | `cyber_code_review`: `sast`, `sca`, `secrets`                                                                       | OC-104         |
| OC-206 | `cyber_container`: `image_scan`, `dockerfile_lint`, `runtime_review`, `pull`                                        | OC-101, OC-104 |
| OC-207 | `cyber_cloud` offline actions: `iam_analyze`, `iac_scan`                                                            | OC-102         |
| **W2** |                                                                                                                     |                |
| OC-301 | Laboratory VM tier: Windows directory and Linux hosts, reproducible from code                                       | W1             |
| OC-302 | `cyber_host`: `audit`, `privesc_config`, `patch_inventory`                                                          | OC-301, OC-307 |
| OC-303 | `cyber_directory`: `ldap_enum`, `kerberos_config`, `password_policy`, `adcs_templates`, `collect`                   | OC-301, OC-307 |
| OC-304 | `cyber_cloud` live actions: `inventory`, `config_audit`, `k8s_rbac`                                                 | OC-307         |
| OC-305 | `cyber_database`: `unauth_check`, `config_review`                                                                   | OC-104         |
| OC-306 | `cyber_binary`: `pe`, `firmware`                                                                                    | OC-104         |
| OC-307 | Credential brokering for cloud and directory identities (R-8)                                                       | OC-101         |
| **W3** |                                                                                                                     |                |
| OC-401 | R2 approval flow using the `ask` permission path                                                                    | OC-102, OC-107 |
| OC-402 | `cyber_web_test` `validate` with per-class oracles                                                                  | OC-401, OC-405 |
| OC-403 | `cyber_directory` `auth_test` and `crack`; disabled by default                                                      | OC-401, OC-307 |
| OC-404 | `cyber_database` `auth_test`; disabled by default                                                                   | OC-401, OC-307 |
| OC-405 | Validator contract and canary oracles, shared with `cyber_local_validation`                                         | OC-401         |

## 6. Definition of done for a tool

A tool is complete when all of the following hold:

- Its actions are typed with a schema. Its description contains one literal example call, and a test covers the action discriminator.
- Its target types and risk class are declared, and the decision function is tested.
- A decision of `deny` produces zero network traffic. This is tested, not assumed.
- It has one positive and one negative laboratory fixture with a known outcome.
- Its output follows R-6: summary, structured fields, artifact reference, `next_offset` for long results, categorized errors.
- Model-visible output contains no secret values.
- It is documented in a `fork-cyber-*.md` guide.
- It is fork-owned code, so it needs no ledger entry. Any change to upstream files requires a ledger row under `FORK.md` section 7.

## 7. Open decisions

Each decision was accepted with its recommendation (#81). Outcomes:

- **D-1** applied in #55: the scope manifest validates all ten kinds and records six. `repo_path` and `container_image` are refused by manifests until OC-205 and OC-206 record them.
- **D-2** applied in #57: R2 is denied in every mode. No approval flow exists yet (OC-401), so `cyber_local_validation` and `binary.execute` are unavailable.
- **D-3** kept: the VM tier waits for the W1 milestone.
- **D-4** kept as the design: credential custody belongs to the OpenCyber service. OC-307 has not started.
- **D-5** kept as the design: passive OSINT needs an engagement declaration. OC-203 will check it before `certificates`.
- **D-6** deferred: the three `http_*` tools stay separate until OC-108 measurements exist. Measuring needs model runs, and those need a budget decision.
- **D-7** accepted: W2 and W3 issues stay public. They hold acceptance criteria, not exploit payloads. Review any detail beyond that before publishing it.

| ID  | Decision                                   | Recommendation                                                                                                       |
| --- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| D-1 | Target types in W1                         | `host`, `cidr`, `domain`, `url`, `repo_path`, `container_image`. Cloud and directory targets move to W2              |
| D-2 | Credential testing (R2)                    | Outside the harness by default. Inside it only with per-action approval and a fixed list                             |
| D-3 | Timing of the VM tier                      | After W1, once the laboratory has a reproducible build                                                               |
| D-4 | Custody of cloud and directory credentials | OpenCyber service, never the Kali container                                                                          |
| D-5 | Passive OSINT                              | Allowed only when the engagement declares it                                                                         |
| D-6 | Merging `http_*` into one tool             | Decide with the repeated model matrix results from OC-108                                                            |
| D-7 | Public visibility of W2 and W3 content     | The repository is public (`FORK.md` section 2.1). Keep W3 details in a private tracker, or publish them after review |

## 8. Verification and risks

- **Licenses and maintenance.** Every candidate base is checked for license, maintenance status and a pinned version before it enters the image.
- **Unverified candidates.** Candidate bases marked "to be evaluated" must not be used until the laboratory validates them.
- **False positives.** A finding is confirmed only by its deterministic oracle. Tool output alone is an observation.
- **Scope enforcement.** Network scope is enforced at egress. Cloud and directory scope is enforced by identity and resource filters. Each enforcement point has its own tests.
- **Reproducibility.** Laboratory targets are built from code and images pinned by digest. A run is reproducible from its recorded configuration, not from its transcript.
- **Model performance.** Tool count and schema complexity are measured with the repeated model matrix in [fork-cyber-harness.md](fork-cyber-harness.md) before and after each wave.

## 9. Tracking

- This document is the design source of truth. Changes to scope or risk classes are made here through a pull request.
- Each work item (`OC-###`) is one GitHub issue titled with its ID, for example `OC-101: typed targets in the scope manifest`. The issue links to its section of this document.
- The wave is a GitHub milestone (W0 to W3). Dependencies are recorded as linked issues.
- Pull requests reference their issue with `Refs #<n>`, and the title follows the repository convention `type(scope): summary`.
- Open decisions (D-1 to D-7) are tracked in a single issue, and each decision is closed by updating this document.

## 10. Implementation status

Updated with each merge. "Done" means the acceptance criteria in the work item's issue are met, with exceptions named below.

| ID     | Status  | Change                                                                                                                                  |
| ------ | ------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| OC-101 | Done    | #55, PR #83: typed targets in the scope manifest                                                                                        |
| OC-102 | Done    | #57, PR #84: risk class per action and one decision function                                                                            |
| OC-103 | Open    | #61                                                                                                                                     |
| OC-104 | Open    | #60. Needs the Kali image to verify                                                                                                    |
| OC-105 | Partial | #58, PR #86: seven shared categories, recovery steps and the `kind` mapping. Open: the long-output contract for Kali outputs, and migration of tool-specific recovery text |
| OC-106 | Open    | #62                                                                                                                                     |
| OC-107 | Done    | #63, PR #85: append-only decision log, including denials                                                                                |
| OC-108 | Open    | #59. Needs a model budget decision                                                                                                      |
| OC-201 | Done    | #64, PR #87: `http_discover`                                                                                                             |
| OC-202 | Done    | #65, PR #88: `cyber_web_test` with openapi, jwt, graphql and plan. `cyber_web_plan` stays registered beside it                         |
| OC-203 to OC-207 | Open | #66 to #70                                                                                                                       |
| OC-301 to OC-307 | Open | #71 to #77 and #72. Need the VM lab and credential brokering                                                                      |
| OC-401 | Open    | #78. Required before any R2 action can run                                                                                              |
| OC-403, OC-404 | Open | #89 and #90, created from this document                                                                                            |
| OC-405 to OC-402 | Open | #79 and #80                                                                                                                       |

Deviations from the tables above, recorded where they were made:

- `http_compare` is R0. Its description states it makes no network activity; the table grouped it with R1.
- `cyber_dns` is R0, and it queries the operator's resolver for an authorized name.
- `kali_run` is R1 even though its argv is free-form. OC-104 narrows it.
- `cyber_surface` `cloud.policy` and `binary.elf` are R0, because they read a local artifact.
- `cyber_web_plan` stays registered beside `cyber_web_test`'s `plan` action, which shares its implementation.
