# TCP service inventory

Phase 7 adds `cyber_services`: procedures and a bounded TCP connect inventory for one host and at most 32 explicit ports. It uses the existing Kali job manager, task ownership and evidence archive. Recon and enumeration can use this tool while retaining their restrictions on arbitrary commands and confirmed findings.

## Enable and run

Build image version 3 from the repository root:

```sh
docker build --tag opencyber-kali:3 fork-kali
docker image inspect opencyber-kali:3 --format '{{.Id}}'
```

Version 3 removes the packaged Nmap binary's file capabilities. The module invokes `/usr/lib/nmap/nmap --unprivileged` directly because Kali's `/usr/bin/nmap` wrapper requests privileged mode for non-root users. The workload retains `cap-drop=ALL` and `no-new-privileges`; no raw-socket profile is added. Rebuilding against the rolling package repository can change installed versions. The immutable image ID and captured package inventory identify the actual tools.

Configure the printed image ID and a dedicated scoped Docker network in the operator's `opencyber-kali.jsonc`, following [Kali configuration](fork-cyber-kali.md) and [network enforcement](fork-cyber-network.md). Record an explicit, non-derived engagement with network budgets. Service-only authorization now uses `scope.services` with target, TCP/UDP transport and explicit ports, leaving whole-host/network lists empty. Every requested scan port must be authorized. See the [phase 7 surface guide](fork-cyber-surfaces.md).

Read procedures without installing Docker or configuring Kali:

```json
{ "action": "procedures" }
```

Create and claim a `cyber-recon` or `cyber-enum` task for the assigned asset, ports and exposure hypothesis. Then call `cyber_services`:

```json
{ "action": "scan", "host": "target", "ports": [8000, 8001], "timeout_ms": 15000 }
```

The default address family is IPv4. Set `"family":"ipv6"` for IPv6; literal IPs must match that selection. Hostnames use the first address selected by Nmap from the engagement's pinned hosts file. Multiple DNS addresses are not exhaustively scanned. Ports are deduplicated and sorted; CIDRs, ranges and arbitrary scanner arguments are not accepted as scan inputs.

The module uses unprivileged TCP connect scanning with host discovery, ARP discovery and reverse DNS disabled. Nmap establishes TCP connections rather than sending privileged raw probes, as described in its [connect scan documentation](https://nmap.org/book/man-port-scanning-techniques.html). It uses one probe at a time, one retry and a scan delay derived from the connection budget. The existing nftables policy independently enforces pinned destinations, exclusions, packet/connection rates, byte quotas and command duration. Each job reserves its full byte allowance against the durable engagement total.

The input deadline defaults to 30 seconds and is capped by the operator configuration and engagement duration. No NSE scripts, OS detection or service-specific exploit procedure is included.

## Version, UDP and probe actions

- `version` takes the same input as `scan`. It adds `-sV --version-light`, which is Nmap's light version detection without scripts. Open ports can gain `product`, `version` and `extrainfo` fields with `method: "probed"`.
- `udp_top` runs nothing and returns `not_configured`. UDP scans need raw sockets, and this workload drops every capability. The action says so instead of failing silently. A UDP profile needs an operator-approved image that grants NET_RAW.
- `probe` takes one port and one check. It makes one TCP connection, sends one unauthenticated request, reads one bounded reply and sends no credentials. The checks and what each sends:
  - `redis_info`: `INFO server`.
  - `elasticsearch_root`: `GET /` over HTTP/1.1.
  - `ldap_root_dse`: an LDAP searchRequest for the root DSE (base scope, `objectClass` present, four attributes) without a bind, so the session stays anonymous. Plaintext LDAP only, with no StartTLS. Reports the vendor name and version, the supported LDAP version and the number of naming contexts. Anonymous denial is `auth_required`.
  - `smb_signing`: one SMB2 NEGOTIATE offering dialects 2.0.2 to 3.0.2, with no session setup. Reports the negotiated dialect and whether signing is `required`, `enabled` (offered but not required) or `disabled`. An SMB1-only server is `unexpected`.
  - `nfs_exports`: one ONC RPC call to MOUNT protocol v3 `EXPORT` (program 100005, procedure 5) with AUTH_NONE. Give the mountd TCP port. The portmapper is not queried because it would be a second, unscoped port. Reports the export count and directory names, not the group lists.
  - `mongodb_build_info`: one OP_MSG `buildInfo` command against `admin` with no authentication. Reports the server version. A reply with error code 13 is `auth_required`.

  Parsing is strict. A truncated or malformed reply is `unexpected`, not an answer.

- A probe reports a state (`answered`, `auth_required`, `closed`, `no_response`, `unexpected` or `error`), the fields it read, the checks that `ran`, and `not_run`. `not_run` lists the checks the design names but this version does not implement: anonymous FTP. Anonymous FTP is excluded because logging in is an authentication attempt: it would send `USER anonymous` and a password, which the probe contract (no credentials) does not allow. Adding it needs an explicit operator decision on its risk class and approval, so it stays pending.

## Evidence and interpretation

Each successful call returns one completed `cyber_services` execution with:

- `capture`: scanner/version, scanned address/family, requested ports, port states/reasons, table-derived service names, aggregate port groups and `unreported_ports`.
- `capture.xml_artifact`: the original XML bytes emitted by Nmap.
- `capture.report_artifact`: the normalized JSON report produced inside the job.
- `stdout`, `stderr`, `files` and `evidence`: existing Kali capture IDs; `evidence` is the completed output artifact for task completion and finding references.

Package inventory, network policy/pinned addresses, quotas and network counters remain retrievable through `evidence`. The completed output includes the normalized capture and original file IDs. Parser failure marks the same execution as an error before completion; raw files already archived and stderr remain available. Failed outputs cannot serve as completed task evidence. Cancellation and cleanup keep the existing Kali lifecycle.

The XML parser uses Python's standard-library ElementTree inside the isolated job. It rejects malformed/truncated XML, external/entity declarations, failed or missing completion, multiple hosts/scans, unsupported scan types and excessive port ranges. Core validates the JSON boundary and verifies requested port coverage, uniqueness, counts, address family and literal IP identity. This is a parser for reports generated by this module, not a general Nmap report importer.

Table-derived service names are guesses. Names from `version` come from light version detection and are still observations; neither kind proves a protocol or a software version on its own; Nmap documents the distinction between table lookup and active probing in its [XML output reference](https://nmap.org/book/output-formats-xml-output.html). An open port records reachability on this path. It does not prove missing authentication, exploitability or a CVE. Closed and filtered ports do not establish security. Budget drops and network policy can influence an observation.

Collapsed XML groups remain aggregate counts; ports without explicit rows are listed as unreported. The module never automatically creates or confirms a finding. Record a candidate only with deployment expectations and completed output evidence, then reproduce an authentication or impact claim through a separate protocol-specific validation task.

## Reproducible controls and checks

The lab creates an internal Docker network with a synthetic TCP management listener on port 8000 and a closed control on 8001. It verifies listener readiness through actual socket reads, runs real Nmap over IPv4 and IPv6, and checks that only the listening port is reported open. No external assessment target is contacted. The positive hypothesis is listener reachability, not a vulnerability claim.

The new probe checks have their own lab in `packages/core/test/plugin/fork-cyber-services-probe-remaining.test.ts`. Each check has a positive and a negative control. The closed port on the LDAP lab's address is a further control:

| Check                | Positive                                         | Negative                              | Known outcome                |
| -------------------- | ------------------------------------------------ | ------------------------------------- | ---------------------------- |
| `ldap_root_dse`      | open root DSE on 1389                            | anonymous denied (result 8) on 1390   | `answered` / `auth_required` |
| `smb_signing`        | SMB2 with signing enabled, not required, on 1445 | signing required on 1446              | `enabled` / `required`       |
| `nfs_exports`        | one export `/srv/export` on 20048                | no exports on 20049                   | `export_count` 1 / 0         |
| `mongodb_build_info` | real `mongo:7.0`                                 | closed port 27018 on the same address | version `7.0.*` / `closed`   |

The LDAP, SMB and MOUNT labs are synthetic responders in the Kali image. Their replies follow the protocol layouts, so they check the parser and the state mapping, not any vendor implementation. The MongoDB lab is the only one against a real server. It runs only when `OPENCYBER_TEST_MONGO_IMAGE` is set to the digest-pinned official image, for example `mongo@sha256:1f995ad6fdb93244a1addab1b58f934a0bc2f5643c38e02f5e9d7f0c7d227a7b` (`mongo:7.0` as pulled on 2026-10-10); otherwise it is skipped. Verification against Samba, OpenLDAP and a real NFS export is pending. No images are pinned for the first two yet, and a kernel NFS server needs privileges that this workload does not have.

The parser fixture `packages/core/test/fixture/fork-cyber-services/closed.xml` was emitted by Nmap 7.99 in image version 3 over network-disabled loopback. Negative cases cover scanner errors, truncation, unsupported scans/declarations and oversized ranges; aggregate groups retain their original meaning. A real job with invalid normalization verifies error evidence and cleanup. Location integration checks native tool registration, procedure access without Docker, scope/config prerequisites and permission/claim denials.

Run from `packages/core`:

```sh
export OPENCYBER_TEST_KALI_IMAGE="$(docker image inspect opencyber-kali:3 --format '{{.Id}}')"
bun test test/plugin/fork-cyber-services.test.ts test/plugin/fork-cyber-services-probes.test.ts test/plugin/fork-cyber-services-probe-remaining.test.ts test/plugin/fork-cyber-kali.test.ts test/plugin/fork-cyber-network.test.ts test/plugin/fork-cyber-integration.test.ts
bun build --compile --format=esm --minify --bytecode test/fixture/fork-cyber-services-smoke.ts --outfile /tmp/opencyber-services-smoke
cd /tmp
./opencyber-services-smoke
```

PowerShell uses `$env:OPENCYBER_TEST_KALI_IMAGE = docker image inspect opencyber-kali:3 --format '{{.Id}}'`. Without the image variable, Docker tests are explicitly skipped. `.github/workflows/fork-kali.yml` builds version 3 on Linux and runs these controls plus the compiled smoke outside the checkout. Root `bun run check` remains the canonical lint/typecheck verification.

Local Windows validation with Bun 1.4.2 and Docker Linux containers passed 133 tests across 12 Core files, with five existing Windows skips. This includes real Chromium, Kali, HTTP and network labs. Root lint and all 35 typecheck tasks passed. The compiled TCP capture smoke passed outside the checkout, and formatting plus `git diff --check` passed.

The [additional local phase 7 modules](fork-cyber-surfaces.md) now cover TLS/SSH, identity, AWS S3, Android manifests, ELF, wireless captures and Modbus simulators. Their external infrastructure coverage remains listed as pending. Phase 8 has not started. Image version 4 retains this module's Nmap contract and is built by the current Kali CI workflow.
