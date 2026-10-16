# Binary and firmware analysis

`cyber_binary` implements OC-306 (#77) for two actions, both risk class R0. Nothing is executed on the host, and the sample is never executed in the container. Both actions run as one offline Kali job with `network: "none"`, through the Kali manager described in [fork-cyber-kali.md](fork-cyber-kali.md). The fixed analysis scripts live in `packages/core/src/fork-cyber/binary.ts`; the model supplies only an artifact ID and a page offset.

## Actions

Import the sample first with `cyber_surface` (module `binary`, action `import`). The import returns the artifact ID.

```json
{ "action": "pe", "artifact": "<artifact ID>" }
```

```json
{ "action": "firmware", "artifact": "<artifact ID>", "offset": 200 }
```

- `pe` parses a Windows PE with pefile. It returns the headers, sections (with entropy and hashes), imports, overlay size and anomaly candidates. The pefile version is in `tool.version`, and the full report is in `report_artifact`. A file that pefile cannot parse is an `invalid_input` error with the execution recorded.
- `firmware` runs a binwalk signature scan with single-level extraction. It returns the signatures and the path, size and SHA-256 of each extracted file. Extracted contents are hashed and never returned.
- Both actions page their rows: 200 per call, with `next_offset` set when more remain. The combined firmware rows are signatures followed by extracted files.

Anomalies and signatures are candidates for review, not verdicts.

## Image

Image version 7 adds the `opencyber` account (UID and GID 1000). Without it, binwalk's extraction aborts, because Python cannot resolve the workload user. The allowlist version moved with it. After rebuilding, update `opencyber-kali.jsonc` with the new image ID.

```powershell
docker build --tag opencyber-kali:7 fork-kali
docker image inspect opencyber-kali:7 --format '{{.Id}}'
```

The image provides pefile 2024.8.26 (BSD-3-Clause) and binwalk 2.4.3 (Expat for the code; the magic files carry their own permissive notices). Both come from the Kali repository and are not pinned beyond that.

## Laboratory

The fixtures are generated from code in `packages/core/test/fixture/fork-cyber-binary/lab.ts`, so nothing binary is checked in:

- A PE32 with `.text`, `.idata` (kernel32 `CreateFileW` and `ReadFile`, user32 `MessageBoxA`) and `.data` is the positive sample. Its anomaly list is empty.
- The same layout without an import directory is the negative sample, which reports `no_import_directory` as a candidate.
- A writable and executable `.text` section yields `writable_executable_section`.
- Two hundred sixty imports exercise paging.
- A gzip member at offset 256 is the positive firmware. Its payload is identified by hash. An image with no signatures is the negative firmware.

The Docker cases are skipped unless `OPENCYBER_TEST_KALI_IMAGE` is set. The non-Docker cases check the action schema, the R0 declaration, the role decision and the refusal path. A refused role and an artifact outside the engagement both fail before any container starts.

```powershell
$env:OPENCYBER_TEST_KALI_IMAGE = docker image inspect opencyber-kali:7 --format '{{.Id}}'
Set-Location packages/core
bun test test/plugin/fork-cyber-binary.test.ts
```

## Limits

- pefile reads at most 96 sections and 4096 imports. Resources, Authenticode signatures, delay imports, exports and .NET metadata are not analyzed.
- Firmware extraction is single level. Nested archives are not recursively extracted. Extraction utilities run inside the network-disabled container, bounded to 256 files of at most 4 MiB on a 128 MiB work mount. Extraction failures inside binwalk appear in the stderr artifact.
- Inputs are limited to 2 MiB, the same bound as the Kali transfer.
- binwalk 2.x is past its upstream end of life, and the tool prints an EOL notice. A move to binwalk 3 needs its own pinned install and license review.
- An empty result does not prove that a file has no code, data or secrets.

## Not done

- `cyber_binary` `dynamic` (R2, laboratory only, in the design as deferred). Execution is outside this change.
- Mach-O, nested firmware recursion and firmware filesystems that need extractors absent from the image. Each needs a reviewed extractor and its own fixture.
- Provenance: `kali.ts` labels every captured Kali job that is not `cyber_services` or `cyber_discover` as `validation`. That includes these analysis jobs, the same as `cyber_surface` today. Correcting it means editing `kali.ts`, which this change does not do.
