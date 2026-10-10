# Cloud configuration analysis

`cyber_cloud` analyzes cloud configuration offline. Both actions are R0: they make no cloud API call and no network request. Their target data is untrusted, and nothing in it is executed on the host.

## iam_analyze

Reads an exported JSON IAM policy artifact (import the document with `cyber_surface` first) and lists statements that need review. Each finding names a JSON pointer to its statement.

| Flag                             | Meaning                                                            |
| -------------------------------- | ------------------------------------------------------------------ |
| `wildcard_action`                | Allows every action, or every action of a service                  |
| `wildcard_resource`              | Applies to every resource                                          |
| `not_action_allow`               | Allows everything except the listed actions                        |
| `not_resource_allow`             | Applies to every resource except the listed ones                   |
| `public_principal`               | Any principal may use the statement                                |
| `privilege_escalation_candidate` | The action can create or hand out identities, credentials or roles |

Findings are candidates for review, not proof of over-privilege. Documents larger than 1 MiB are refused.

## iac_scan

Runs Checkov 3.3.26 over up to 16 infrastructure files from a code review snapshot. Each source names a source artifact that the snapshot produced. The job never reads a host path, so a file is scanned only if it was captured first.

- Accepted extensions: `.tf`, `.yaml`, `.yml`, `.json`. Other extensions and parent segments (`..`) are refused before a job starts.
- The staged files total at most 2 MiB. The job runs in `opencyber-kali:6` with `network: none`. The execution's provenance records that policy, so a reviewer can confirm it.
- Output: a summary (`passed`, `failed`, `skipped`, `parsing_errors`, `files`), the frameworks Checkov read, and failed checks with their snapshot file label, check ID, name, lines and resource. Results are paginated with `offset` and `limit`. The full report is stored as an artifact.

Example:

```json
{ "action": "iac_scan", "files": [{ "file": "infra/main.tf", "artifact": "snapshot-artifact-id" }] }
```

### Limits

- Results describe the staged files only. Passed and skipped checks are counts, not evidence that a configuration is secure.
- A failed check is a configuration observation. It does not establish exploitability or impact.
- The rule set is the one bundled with the pinned Checkov version. Upgrading the image can change which checks run, and the report records the version it used.

### Laboratory

`packages/core/test/plugin/fork-cyber-iac.test.ts` stages a public-read S3 bucket and a private one. Only the public bucket raises CKV_AWS_20, and the report names each file by its snapshot label. The Docker test runs only when `OPENCYBER_TEST_KALI_IMAGE` points at image 6. The validation tests run without Docker.
