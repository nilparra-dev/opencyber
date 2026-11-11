# Cloud configuration analysis

`cyber_cloud` analyzes cloud configuration offline and, for three live actions, reads a provider with a brokered read-only identity. `iam_analyze` and `iac_scan` are R0: they make no cloud API call and no network request. Their target data is untrusted, and nothing in it is executed on the host. The live actions are described under Live reads.

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

Runs Checkov 3.3.26 over up to 16 infrastructure files from a code review snapshot. Each source names a file label and an artifact that a completed `cyber_code_review` snapshot recorded together. An HTTP response, an operator import or a label the snapshot did not record is refused before a job starts. The job never reads a host path, so a file is scanned only if it was captured first.

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

`packages/core/test/plugin/fork-cyber-iac.test.ts` captures a public-read S3 bucket and a private one with `cyber_code_review` snapshot. Only the public bucket raises CKV_AWS_20, and the report names each file by its snapshot label. The Docker test runs only when `OPENCYBER_TEST_KALI_IMAGE` is set to the image ID of version 6 (`docker image inspect --format '{{.Id}}' opencyber-kali:6`), because the Kali config requires a `sha256:` digest. The validation tests run without Docker. The refusal tests (non-snapshot artifact, mismatched label) and the configuration test also run without Docker.

## Live reads

`inventory`, `config_audit` and `k8s_rbac` read a live provider. Each is R1 and needs an engagement that declares its credential label for that action and target. The label is a brokered read-only identity from OC-307 (see [fork-cyber-credentials.md](fork-cyber-credentials.md)). The model never sees the value.

| Action | Target | Requests (all GET) | Checks |
| --- | --- | --- | --- |
| `inventory` | AWS account ARN, `arn:aws:iam::<12 digits>:root` | STS GetCallerIdentity, S3 ListBuckets | Bucket names and creation dates. The caller account must equal the target. |
| `config_audit` | S3 bucket ARN | S3 GetBucketAcl, GetPublicAccessBlock, GetBucketPolicy | Public ACL grants to AllUsers or AuthenticatedUsers; a public access block with all four flags; Allow statements for anonymous principals without a condition (candidates). |
| `k8s_rbac` | Cluster API server, `host` and `port` in scope | ClusterRoleBindings and ClusterRoles, first 500 of each | Bindings to `system:anonymous` or `system:unauthenticated` (`anonymous_cluster_admin` when bound to cluster-admin); roles with `*` verbs on `*` resources, excluding cluster-admin and `system:*`. |

Examples:

```json
{ "action": "inventory", "label": "aws-audit", "target": "arn:aws:iam::123456789012:root" }
{ "action": "config_audit", "label": "aws-audit", "target": "arn:aws:s3:::lab-public" }
{ "action": "k8s_rbac", "label": "k8s-audit", "host": "10.0.0.5", "port": 6443 }
```

Labels are registered by the operator with `packages/core/script/fork-cyber-credential.ts` as kind `cloud_key`. An AWS label holds `ACCESS_KEY_ID:SECRET_ACCESS_KEY`. A Kubernetes label holds one bearer token. Each label must be declared in the approved manifest for its action and target, with `read_only` true.

Each call runs these checks in order. The first failure stops the call:

1. Role, mode and the R1 decision. Workers need a claim.
2. Provider endpoints: `https://sts.amazonaws.com` and `https://s3.amazonaws.com`, fixed in code. Kubernetes requires https.
3. Target in scope, before any request: `scope.resources` for ARNs, and the recorded host and port rules for the cluster.
4. Operator permission for the target.
5. Lease: declared, in scope, registered, unexpired and decryptable. Each outcome is recorded in `cyber_credential_lease`.
6. Requests. Each is a GET with the lease value, and the value is released when the action ends.

Output (`opencyber-cloud-live-v1`): the identity label and kind, the summary, the structured checks or resources, `calls` with one entry per request (method, origin, path, status and the identity label that made it), `next_offset` for paginated lists, and the execution and evidence artifact. Signatures, headers and token values are never returned.

### Live limits

- AWS requests are signed with SigV4 for us-east-1, path style. Session tokens are not supported. Redirects are not followed, so a bucket in another region is reported as a transport failure.
- Kubernetes reads the first 500 cluster-scoped bindings and roles. `truncated` reports whether more exist. Namespaced RBAC is not read. TLS uses the system trust store.
- `config_audit` checks three bucket properties. It does not evaluate conditions, IAM, organization policies or object ACLs, so a policy finding is a candidate, not exposure.
- `inventory` covers S3 buckets and the caller account. Other services need their own read-only operations.
- Each response is read whole and rejected above 2 MiB once received.
- Only the lease buffer is zeroed on release. Strings made while a request is built are not.
- Analyzer-backed audits (prowler, ScoutSuite, kubescape, kube-bench) are not adopted. The checks above are the ones implemented, which is an owner decision (toolset D5).
- Review mode offers no `cyber_cloud` action, so R0 offline actions also need an assessment or development run.

### Live laboratory

`packages/core/test/plugin/fork-cyber-cloud-live.test.ts` starts a local fixture on 127.0.0.1 that implements the read subset. It verifies each SigV4 signature against the laboratory key and checks the bearer token. It refuses any non-GET method with 405 and records every request, so tests count traffic.

- Positive configuration: a public bucket (public ACL, no public access block, anonymous policy), a private bucket, and a cluster with an anonymous cluster-admin binding and a wildcard role. Known outcome: `acl_public`, `public_access_block` and `policy_anonymous_allow` fail for the public bucket, and both Kubernetes findings are reported.
- Negative configuration: a private bucket with all four flags, and a read-only cluster. Known outcome: no failed check and no Kubernetes finding.

The laboratory needs no Docker and no network service, so it never skips. The tests also cover: a denied run and a report agent send no request; a resource outside scope, a foreign account and an unregistered label send none (or only the identity probe); an endpoint outside the fixed list, or a plaintext cluster, sends none; the output contains no secret; and the signature matches AWS's published get-vanilla example.

### Not done

- A dedicated live test account with known misconfigurations (the issue's laboratory). No account is available here. It needs an operator-provisioned account and an engagement that declares it.
- Session-token credentials, Azure and GCP, and services beyond S3 and STS.
- Analyzer-backed audits, pending the owner's choice of analyzer.
