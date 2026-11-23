# Phase 7 local surface workflows

`cyber_surface` adds procedures and evidence-producing workflows for TLS, SSH, identity, AWS S3, Android APKs, ELF binaries, wireless captures and Modbus simulators. Existing local code review and TCP inventory remain available through their own tools. These are bounded starting workflows, with the supported checks and pending coverage below.

## Service and resource scope

Hosts and CIDRs continue to authorize all TCP/UDP ports. Use empty host/network lists for service-only authorization. Whole-asset exclusions and service exclusions override every inclusion.

```json
{
  "domains": [],
  "cidrs": [],
  "excluded": [],
  "services": [
    { "target": "lab.example", "protocol": "tcp", "ports": [443, 2222] },
    { "target": "192.0.2.0/24", "protocol": "udp", "ports": [53] }
  ],
  "excluded_services": [{ "target": "192.0.2.10", "protocol": "udp", "ports": [53] }],
  "resources": ["arn:aws:s3:::authorized-bucket"]
}
```

This object is the manifest's `scope` field. `protocol` means transport, TCP or UDP. It does not authorize URL paths or distinguish applications sharing a port. HTTP checks its effective TCP port on initial admission, DNS pinning, rate admission and each redirect. TCP inventory and protocol probes check all requested endpoints before starting Docker. Kali resolves service targets with the same pinned resolver as whole hosts; its nftables output rules match destination, transport and port. All raw-process jobs retain the connection, packet, byte and duration budgets.

An authorized hostname can resolve to several addresses. HTTP rejects any excluded resolved service address, and the Kali firewall excludes resolved addresses before inclusion. A job retains its admitted scope snapshot. Stop it before changing that scope. Old manifests remain readable; existing scope patches preserve the new fields. Replace a manifest to change service or cloud-resource lists.

S3 additionally requires its exact bucket ARN in `scope.resources`. Network endpoint authority and cloud resource authority are separate. The operator must verify that the supplied endpoint represents that bucket. A matching XML name does not establish AWS account ownership.

## Tools and execution

Read procedures using `{"module":"tls","action":"procedures"}`, substituting a module from the table below. Procedures need no Docker. Validation phase agents can use the tool after claiming an assigned task. Reconnaissance, source-review and reporting roles retain their existing restrictions. The primary agent can operate it within ordinary permissions.

Cloud policies, APKs, binaries and PCAPs first need an explicit project file import:

```json
{ "module": "binary", "action": "import", "file": "lab/program" }
```

Imports require both `cyber_surface` and `read` permission, reject paths outside the project including escaping symlinks, and accept regular files of at most 2 MiB. The result includes an immutable source artifact ID and SHA-256. Subsequent analysis uses that engagement-owned artifact, rather than reading a mutable project path. Original bytes, parser reports, stdout/stderr, environment inventory, network policy and completed output IDs remain in the archive. Errors retain error evidence and never provide completed task evidence.

Use image version 4 for the new Docker labs:

```sh
docker build --tag opencyber-kali:4 fork-kali
docker image inspect opencyber-kali:4 --format '{{.Id}}'
```

Configure its immutable ID in `opencyber-kali.jsonc`, following [Kali setup](fork-cyber-kali.md). TLS, SSH and Modbus require `network.kind = "scoped"`. APK, ELF and PCAP jobs always derive `network.kind = "none"` from the configured profile, so the same scoped profile can serve network and offline work without configuration changes. Image 4 adds OpenSSH, binutils, GCC and Android packaging tools for reproducible labs, while retaining unprivileged Nmap. Package inventory records actual versions from the rolling repository.

ELF `execute` explicitly enables an executable `/work` tmpfs for that job. Other jobs default to `noexec`; `/tmp` remains `noexec`. The workload stays non-root with no capabilities, a read-only container filesystem, bounded CPU/memory/files/processes and no network. Docker shares the host kernel. Run controlled reproduction artifacts on a disposable lab host when stronger isolation is needed.

## Supported workflows and controls

| Module   | Call after reading procedures                                                                   | Positive and healthy control                                                                                                                               | Pending coverage                                                                                                                    |
| -------- | ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| TLS      | `{"module":"tls","action":"probe","host":"target","port":8443}`                                 | Actual TLSv1 handshake against a legacy Python/OpenSSL listener; TLSv1.2/1.3-only listener as control                                                      | Certificate trust/hostname, full cipher coverage, client authentication, STARTTLS                                                   |
| SSH      | `{"module":"ssh","action":"probe","host":"target","port":2222}`                                 | Real OpenSSH servers with legacy group1 key exchange versus current default algorithms                                                                     | Login, host-key authentication, user authorization, full negotiation                                                                |
| Identity | `matrix` with explicit identities, requests, protected-data markers and allowed/denied controls | Owner session succeeds; lower-role token reaches a broken endpoint but is denied by the healthy endpoint; anonymous, expired and revoked tokens are denied | Token issuance and cryptographic validation, IdPs, directories, application-specific session lifecycle                              |
| Cloud    | `s3` with bucket ARN and endpoint, or `policy` with ARN and artifact ID                         | S3-compatible unsigned ListObjectsV2 with public listing and private AccessDenied; wildcard grant versus deny/conditional policy controls                  | Real AWS account integration, signing, effective IAM permissions, object access/writes, ACLs, public-access blocks, other providers |
| Mobile   | `{"module":"mobile","action":"apk","artifact":"SOURCE_ID"}`                                     | Real aapt-generated binary Android manifests with explicit debug/cleartext flags versus release flags                                                      | Emulator/device validation, runtime traffic, native code, signatures, iOS                                                           |
| Binary   | `elf`, then optional `execute` with artifact and explicit `stdin`                               | GCC-built ELF crashes with the fixture input; healthy ELF returns normally with the same input                                                             | PE/Mach-O, other architectures, emulation, fuzzing, security impact of a crash                                                      |
| Wireless | `{"module":"wireless","action":"pcap","artifact":"SOURCE_ID","bssid":"02:00:00:00:00:01"}`      | Classic PCAP beacons advertising an open network versus an RSN/CCMP control                                                                                | Physical capture/association, adapters, radio reachability, PCAPNG, injection, authentication                                       |
| OT       | `modbus` with `environment:"simulator"`, endpoint, unit, address and count                      | Actual function-03 TCP read returns register value 4242; illegal address returns exception 2                                                               | Physical equipment, process impact, other protocols/functions, production authorization                                             |

TLS records four exact-version handshake attempts and certificate validity dates. Its probes deliberately disable trust verification to inspect protocol support; `trust_verified` is always false. A failed handshake retains the client/network error and never proves server-side rejection. The SSH parser requires an SSH-2.0 identification and complete, bounded KEXINIT framing/name lists, following [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253). Its legacy algorithm list is a small, explicit check, not a complete cryptographic policy.

An identity matrix needs distinct identities, an allowed control and a denied control. Each request preserves HTTP evidence and disables redirects. Success requires a 2xx status and the protected marker. Denial requires 401/403 without the marker. Other responses are inconclusive. For example:

```json
{
  "module": "identity",
  "action": "matrix",
  "cases": [
    {
      "identity": "owner",
      "control": "allowed",
      "request": { "url": "https://lab.example/object", "headers": { "Authorization": "Bearer OWNER_TOKEN" } },
      "marker": "fixture-record"
    },
    {
      "identity": "reader",
      "control": "denied",
      "request": { "url": "https://lab.example/object", "headers": { "Authorization": "Bearer READER_TOKEN" } },
      "marker": "fixture-record"
    }
  ]
}
```

Tokens and cookies are sensitive evidence. They remain in raw request artifacts and receive the existing redacted evidence previews. Identity labels and resource ownership come from the operator; the parser cannot establish them from labels alone.

The S3 request uses [ListObjectsV2](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html) with `max-keys=1`, no signing, no redirects and a 64 KiB response limit. XML declarations/entities, malformed structures, mismatched bucket names, excessive counts and unexpected statuses fail. Policy inspection supports explicit `Statement` arrays with Effect/Principal/Action/Resource and optional conditions. An unconditional anonymous grant is a candidate. Statement-level inspection preserves denies and conditions and does not calculate effective AWS permissions.

Android analysis reads the compiled manifest directly from the APK ZIP without extraction. It bounds string pools, references, chunk sizes, nesting and component count. Missing flags remain missing. Explicit `debuggable` and cleartext flags are candidates, as are explicitly exported components without declared permissions. Their meanings follow the [Android application manifest documentation](https://developer.android.com/guide/topics/manifest/application-element); runtime consequences remain unverified.

ELF analysis invokes `readelf`, never `ldd`. Reproduction passes only explicit stdin, without arbitrary arguments, and distinguishes signal exits, normal exits and two-second timeouts. It retains bounded output bytes. PCAP analysis accepts classic raw-802.11 and radiotap link types, selects an explicit BSSID, validates frame/element bounds and reports beacon security advertisements plus unsupported-frame counts. RSN does not establish secure authentication. Modbus accepts one read of at most 16 holding registers and validates transaction, protocol, unit, function and byte count. The simulator designation is an operator assertion; it is not device fingerprinting.

## Completion and verification

The compiled smoke exercises reconnaissance, a candidate, separate validation with a healthy control, finding confirmation, task completion and reporting. Its report contains planned coverage still requiring external infrastructure. Completion of these local workflows does not mark that external coverage as tested. No model profiles, model evaluations, tuning or upstream comparisons are included.

From `packages/core`:

```sh
export OPENCYBER_TEST_SURFACES_IMAGE="$(docker image inspect opencyber-kali:4 --format '{{.Id}}')"
bun test test/plugin/fork-cyber-surfaces.test.ts test/plugin/fork-cyber-integration.test.ts
bun build --compile --format=esm --minify --bytecode test/fixture/fork-cyber-surfaces-smoke.ts --outfile /tmp/opencyber-surfaces-smoke
cd /tmp
OPENCYBER_SURFACE_REPORT=/tmp/opencyber-phase-seven-report.json ./opencyber-surfaces-smoke
```

PowerShell sets the same environment variables with `$env:NAME = ...`. Without `OPENCYBER_TEST_SURFACES_IMAGE`, Docker tests are explicitly skipped. `.github/workflows/fork-surfaces.yml` builds image 4 on Linux, exercises the modules and publishes the synthetic report/evidence archive as a CI artifact. The existing Kali CI uses image 4 for lifecycle and TCP regression checks. Root `bun run check` remains the canonical lint/typecheck check.

The installed CLI delivery smoke uses a local deterministic protocol fixture with no provider credential, external target or model evaluation. It executes the real CLI, local service, tool registry, Kali 3 inventory, candidate finding, task completion and coverage. Run from `packages/cli`:

```sh
OPENCYBER_TEST_KALI_IMAGE="$(docker image inspect opencyber-kali:3 --format '{{.Id}}')" bun script/fork-cyber-delivery.ts /path/to/opencyber
```

The script prints a retained isolated profile containing raw evidence and CLI output. Its temporary scope and configuration do not change the installed client's engagement data.

For a binary built from this change, pass `--surfaces` and image 4 to extend that CLI workflow with service-only scope, real TLS protocol validation, a healthy TLS control and finding confirmation. The surface CI runs this extended mode.

Local Windows validation with Bun 1.4.2 passed 136 regression tests across 12 Core files, with five existing Windows skips. The final artifact controls and the additional HTTP service-redirect regression also passed. Root lint and all 35 typecheck tasks passed. The installed `2.0.19-cyber.5` CLI passed with Kali 3; the new compiled CLI passed with Kali 4. The separate compiled reconnaissance/candidate/validation/report smoke passed outside the checkout and retained its synthetic archive. Linux execution is assigned to the fork workflows and remains a separate check.
