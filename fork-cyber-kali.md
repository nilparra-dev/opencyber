# Kali jobs

Phase 4 adds optional `kali_run` and `kali_environment` tools. Docker runs on the operator's host; the model supplies command arguments and artifact references. The Core plugin captures stdout, stderr, selected files, package inventory, image ID, engagement scope and runtime configuration in the phase 2 evidence database.

The implementation uses a fresh container per job, associated with the top-level engagement and data profile. Docker's unique container name admits one job per engagement across processes. Separate engagements can run concurrently. Files move between jobs through explicit artifact inputs and outputs. This replaces the roadmap's proposed persistent workspace: temporary state and background processes cannot silently carry into the next job.

## Build and enable

Use Docker with Linux containers and a Docker CLI accessible to the OpenCyber service. Build from the repository root:

```sh
docker build --tag opencyber-kali:5 fork-kali
docker image inspect opencyber-kali:5 --format '{{.Id}}'
```

The Dockerfile pins the official Kali base by digest. Its package repository is rolling, so a rebuild can install newer package versions. The resulting image ID and `/opt/opencyber/packages.txt` identify what actually ran; this is not a claim of bit-for-bit reproducible builds. Keep/export the built image if exact replay matters. The initial selection includes curl, nmap, DNS utilities, sqlmap, Python, jq, ripgrep and OpenSSL. Installed is not the same as allowed: `kali_run` runs only the binaries listed in [Binary allowlist and typed wrappers](#binary-allowlist-and-typed-wrappers). Extend the Dockerfile deliberately; the base image does not contain every Kali tool.

Image version 3 removes Nmap's packaged file capabilities so it can run under the existing capability-free workload. The [TCP inventory module](fork-cyber-services.md) invokes the underlying binary with `--unprivileged`; arbitrary privileged/raw scans remain unavailable.

Create `opencyber-kali.jsonc` in the service's operator configuration directory, `Global.config`. With the optional profile launcher this is that profile's configuration directory. This file is not loaded from the assessed project's `.opencode` directory. Replace the sample image value with the full local ID printed above:

```jsonc
{
  "image": "sha256:<64 hex characters from docker image inspect>",
  "network": { "kind": "none" },
  "cpus": 1,
  "memory_mb": 512,
  "work_mb": 128,
  "timeout_ms": 300000,
}
```

An absent or malformed file disables Kali execution. Image tags are rejected; execution uses the immutable local image ID. The model cannot supply an image, host mount, Docker socket, privileged flag, device, capability or network override through these tools. Docker is not contacted during normal plugin activation.

Record an explicit engagement with the existing `engagement` tool, then call:

```json
{ "argv": ["jq", "--version"] }
```

Nmap is not on the allowlist. Its TCP scans run through [`cyber_services`](fork-cyber-services.md), which builds the Nmap command itself.

To preserve a generated file, copy an input artifact to an output name:

```json
{
  "argv": ["cp", "source.txt", "result.txt"],
  "inputs": [{"name":"source.txt","artifact":"<artifact ID>"}],
  "outputs": ["result.txt"],
  "timeout_ms": 10000
}
```

`kali_run` returns an execution ID, output evidence ID, stdout/stderr artifact IDs, exit code and declared file artifacts. Retrieve previews through `evidence`. A later job can pass `inputs: [{"name":"source.txt","artifact":"<artifact ID>"}]`. Inputs must belong to the same engagement. Files use simple names directly under `/work`; traversal, absolute paths and symlink exports are rejected. The host never extracts an untrusted archive or mounts an assessment directory.

## Binary allowlist and typed wrappers

`kali_run` accepts a free-form `argv`, so its first element is checked before anything starts. `argv[0]` must be a bare name from this list, which is versioned with the image recipe (`org.opencyber.kali.version`, currently 5):

`base64`, `cat`, `cp`, `cut`, `file`, `grep`, `head`, `jq`, `md5sum`, `sha256sum`, `strings`, `tail`, `tr`, `uniq`, `wc`

The list lives in `packages/core/src/fork-cyber/kali-allowlist.ts`. A test fails when its `IMAGE_VERSION` disagrees with the recipe, and a Docker test checks that every listed name exists in the configured image. The check is part of the same permission decision as the role and risk rules. A refusal is recorded in the decision log with reason `binary_not_allowlisted`, returned as `refused_by_policy`, and made before any Kali container is created.

Names must be bare. A path such as `/usr/bin/cat` or `/work/cat` is refused. The image's `PATH` resolves names under `/usr/bin`, and `/work` is not on it.

Excluded on purpose:

- Interpreters and shells (`python3`, `sh`, `node`, `env`) run arbitrary code.
- `rg` and `sort` run the program named by `--pre` or `--compress-program`, so an allowed name could run anything.
- `nmap`, `curl`, `dig`, `whois` and `sqlmap` reach targets. Those actions belong to typed tools that record scope and evidence.
- `readelf` runs through `cyber_surface`. `aapt` has no tool yet. `nft` needs `NET_ADMIN`, which job containers do not have.

None of the listed utilities contacts a network. Scoped networking through `kali_run` therefore has no allowlisted binary; network work runs through typed tools.

**Typed wrappers.** A binary outside the list is exposed only as a typed action. The tool validates its own parameters with a schema, builds the argv itself from fixed values, calls the Kali manager directly, and parses the binary's output before it returns anything. The model never supplies the argv. `cyber_services` is the reference implementation. It runs Nmap with fixed connect-scan flags (`--unprivileged -sT`) against one in-scope host and at most 32 declared ports, then parses the XML with a restricted parser that rejects entity declarations and checks the report against the requested ports. See [TCP service inventory](fork-cyber-services.md).

To expose a new binary, install it in the Dockerfile, add the typed action with positive and negative fixtures, and bump `org.opencyber.kali.version` and `IMAGE_VERSION` in the same change. Add the binary to the allowlist only if it is offline and cannot run other programs.

## Limits and lifecycle

Each workload container runs as UID/GID 1000 with a read-only root filesystem, all capabilities dropped, no-new-privileges, 128 processes, 1,024 open descriptors and no inherited service credentials. The default CPU limit is one core. Memory and swap allowance are both set to 512 MiB, leaving no additional swap allowance. Temporary mounts bound `/work` to 128 MiB, `/tmp` to 32 MiB and shared memory to 16 MiB. Docker logs are disabled; the host captures command streams. These bounds cover job working data, not Docker's image cache or accumulated evidence storage.

The default command timeout is 60 seconds, capped by the operator's configured ceiling, which defaults to five minutes. A request can select at most 15 minutes. GNU timeout bounds the command; the host bounds each Docker CLI operation. The environment's PID 1 also expires after the command budget plus 120 seconds for preparation/export, so host death does not leave it running indefinitely. A stalled daemon can prevent timely cleanup; that is reported as an error.

Each stdout/stderr stream and each output file is capped at 2 MiB. Exceeding a stream limit fails the job, retains its bounded prefix and destroys the container. Up to 16 input and 16 output files are accepted, with a combined input budget of 4 MiB of base64. Requested files are captured after the command exits and before removal. A timeout or cancellation retains available stdout/stderr, but does not promise generated-file recovery.

Success, nonzero exits, timeouts and interruptions produce durable terminal records when storage is available. Exit zero plus successful capture and cleanup is `completed`; other outcomes are `error`. An abrupt host crash or failed evidence write may leave a `running` record, which remains unresolved and must not be treated as success. Execution and Docker changes are not one atomic transaction. Jobs are never automatically replayed.

Use `kali_environment` with `{"action":"status"}` to inspect this engagement's containers, or `{"action":"stop"}` to cancel active work and remove its containers and admission locks. The same stop operation clears stale locks after a service restart. Cleanup uses ownership labels and immutable container IDs, and does not delete evidence. Failed cleanup leaves diagnostic information and can require operator intervention. Do not purge an engagement archive while its job is running.

The reporting agent cannot operate these tools. Both tools assert the existing permission service. Child sessions use their parent's engagement and admission lock. These restrictions apply to this execution path; the ordinary host shell and other plugins remain governed by their own permissions. Operator configuration is an OS file, not a separate security boundary against a model that already has unrestricted host filesystem access.

## Network profiles

`none` is the default. Only loopback exists in the container. Use the phase 3 HTTP tools when their scope, redirect and request-rate controls match the task.

For an audit network provisioned by the operator, use the enforced profile:

```jsonc
"network": {
  "kind": "scoped",
  "name": "audit-lab"
}
```

The named network must already exist. Built-in `host`, `bridge` and `none` names are rejected. The manager installs manifest-derived nftables rules before creating the workload. A separate manager-only root container owns `NET_ADMIN`; the workload retains UID 1000 and zero capabilities. See [CY-10 network controls](fork-cyber-network.md) for mandatory network budgets, pinned names, evidence and migration. Legacy `operator-managed` configuration is rejected; it cannot silently retain unrestricted networking.

Workloads do not receive raw-socket capabilities, host networking, USB access or wireless devices. TCP connect scans work within the scoped profile. Raw-packet and device workflows need a separately designed profile. Cyber phase agents cannot use the host shell, even under permissive agent configuration. The ordinary primary agent remains outside this boundary.

## Verification

The Docker suite builds no mocks. It executes the selected Kali image, transfers exact binary bytes, reopens the evidence store, checks fresh workspaces, validates cgroup limits and network isolation, exercises a local HTTP fixture on an internal Docker network, tests timeout/output overflow, cancellation, concurrent clients, nonzero exits and symlink rejection. The Location suite tests native registration, optional configuration, scope, reporting restrictions and permission denials.

PowerShell:

```powershell
$env:OPENCYBER_TEST_KALI_IMAGE = docker image inspect opencyber-kali:5 --format '{{.Id}}'
Set-Location packages/core
bun test test/plugin/fork-cyber-kali.test.ts test/plugin/fork-cyber-network.test.ts
```

Without `OPENCYBER_TEST_KALI_IMAGE`, the ordinary test run skips the real-Docker cases. `.github/workflows/fork-kali.yml` builds the image and sets this variable on Linux. Its `docker` check complements the existing fork CI; it is not automatically added to GitHub branch protection. No image is published by this workflow.

Local validation used Bun 1.4.2 and Docker Desktop's Linux engine on Windows: 114 tests passed across 11 Core files, including all seven Kali tests; five existing Windows-specific skips remained. Root `bun run check` passed all 35 typecheck tasks and lint. The image was built and the fixtures ran locally; no external assessment targets or compiled CLI smoke test were used.

Runtime decisions follow the official [Kali image guide](https://www.kali.org/docs/containers/using-kali-docker-images/), [Docker container options](https://docs.docker.com/engine/containers/run/), [resource constraints](https://docs.docker.com/engine/containers/resource_constraints/) and [tmpfs documentation](https://docs.docker.com/engine/storage/tmpfs/).
