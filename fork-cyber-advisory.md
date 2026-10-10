# Pinned advisory snapshots

The `sca` action of [`cyber_code_review`](fork-cyber-code-review.md) and the `image_scan` action of [`cyber_container`](fork-cyber-container.md) match package versions against an advisory snapshot. The snapshot is a JSON file that an operator chooses and pins by SHA-256 digest. The tools never download advisory data, never query a registry and never contact a service.

## Snapshot contract

```json
{
  "format": "opencyber-advisory-snapshot-v1",
  "source": "name of the dataset the records came from",
  "snapshot_version": "version label chosen by the operator",
  "records": [
    {
      "ecosystem": "npm",
      "package": "example-package",
      "range": ">=1.0.0 <1.4.3",
      "id": "ADVISORY-ID",
      "severity": "high",
      "summary": "One sentence describing the affected behaviour.",
      "fixed": "1.4.3"
    }
  ]
}
```

- `ecosystem` is `npm` or `PyPI`. Records for other ecosystems are never matched.
- `range` is one or more space-separated comparators (`<`, `<=`, `>`, `>=`, `=` or `==`). Every comparator must hold. Versions are dotted numbers with an optional prerelease. Alternatives (`||`), wildcards and other syntax are refused when the snapshot loads.
- `severity` is one of `critical`, `high`, `medium`, `low` or `unknown`. It is the record's own label, not a CVSS calculation.
- `fixed` is optional and informational.
- Limits: 20,000 records, 200 characters per range, 500 characters per summary.

## Pinning and integrity

Set both variables for the process that runs the tools:

- `OPENCYBER_ADVISORY_SNAPSHOT`: the path to the snapshot file.
- `OPENCYBER_ADVISORY_SHA256`: the lowercase SHA-256 digest of the file's exact bytes.

The file is read and hashed before any record is used. A digest mismatch, an unreadable file or a document that does not match the contract fails with `not_configured`, and no execution is recorded. When a variable is missing, the failure names both variables.

Every `sca` and `image_scan` result includes the snapshot identity:

```json
{ "source": "...", "snapshot_version": "...", "sha256": "...", "records": 2 }
```

## Matching rules

- npm names are compared exactly. PyPI names are compared case-insensitively, and each run of `-`, `_` or `.` counts as one `-` (PEP 503 normalization).
- Versions compare by their dotted numeric core, with missing parts counted as zero. A prerelease ranks below its release, and its identifiers compare in order (numeric identifiers numerically). Build metadata is ignored.
- A version that is not a plain dotted version is not compared. Examples are `0.9.1rc1` and distribution versions such as `1.36.1-r0`. Unsupported ecosystems are not compared either. Both are reported as unevaluated, never as clean.

## Test fixture

`packages/core/test/fixture/fork-cyber-advisory/snapshot.json` is a synthetic test fixture. Its `source` is `opencyber-test-fixture`, its `snapshot_version` is `test-fixture-1`, and its advisory IDs (`OCFX-TEST-*`) and packages (`ocfx-parser`, `ocfx-py`) do not describe real software. The laboratory tests use it. Do not configure it for an assessment: an empty result against the fixture says nothing about real packages.

## Not pinned

No real advisory database is pinned. Choosing one is an open operator decision. It depends on the licence and redistribution terms, maintenance, size and update cadence, as described in [fork-cyber-toolset.md](fork-cyber-toolset.md) section 8. Until a snapshot is pinned, `sca` and `image_scan` return `not_configured`.

The snapshot must be produced outside these tools, from a named source and version. The tools check the file's integrity; they do not check its completeness or freshness.
