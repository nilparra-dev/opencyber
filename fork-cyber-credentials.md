# Credential brokering (OC-307)

Design for issue [#72](https://github.com/nilparra-dev/opencyber/issues/72). Status: design only, no code. [fork-cyber-toolset.md](fork-cyber-toolset.md) sets the rules (R-6, D-4) and section 10 records the status.

## Problem

Directory and cloud checks (OC-302 to OC-304, OC-403 and OC-404) need identities. Today a secret reaches a tool only as input the model writes. `cyber_http` accepts arbitrary headers, and the identity-matrix procedure tells the agent to send session cookies and bearer tokens there, so the model sees those values in its own context.

Brokering gives directory and cloud identities a different path: the operator enters the secret, the service holds it, and the model only names it. Web session tokens stay on the current path (see Limits).

## Rules

1. The operator enters a secret; the model never does. Entry happens in an operator script outside the model's tool registry, the same way manifests are approved (`packages/core/script/fork-cyber-authorize.ts`).
2. The model sees labels, kinds, targets and expiry. It never receives a value.
3. A value is released to one execution, and only when the approved manifest names its label for that action and target.
4. Every release and every refusal is recorded in an append-only table.
5. A released value never appears in tool results, artifacts, the decision log or evidence.

## Operator registration

`packages/core/script/fork-cyber-credential.ts` has three commands: `add`, `revoke` and `list`. `add` reads the value from stdin, so it never appears in argv, the process list or shell history. It prints the label, kind and expiry, never the value.

## Declaration

Labels are declared in the engagement manifest, so they are part of the approved revision. A declaration names the label, its kind (`directory_bind` or `cloud_key`), its typed targets and the actions allowed to use it. `read_only` must be `true` in this work item; write-capable identities are refused.

## Storage

Table `engagement_credential`: `owner`, `label`, `kind`, `expires_at`, `revoked_at`, `nonce` and `ciphertext`, with primary key `(owner, label)`.

- Values are encrypted with AES-256-GCM. The additional authenticated data is `owner`, `label` and `kind`, so a row copied into another engagement fails to decrypt.
- The 32-byte key is generated once and kept in a file outside the evidence database, with mode 0600 where the platform enforces it. Archives made by `fork-cyber-archive.ts` must not include the key. Without the key, an archive holds only ciphertext.
- No unkeyed hash of the value is stored. A plain hash of a weak password can be checked offline from the database.

## Lease

`lease({ owner, label, action, target, execution })` makes one decision before any value leaves storage:

1. The manifest declares the label for this action and target. If not: `refused_by_policy` with reason `not_declared`.
2. The label is registered, not expired and not revoked. If the operator has not registered it: `not_configured`, and the recovery step names the `add` command. If it is expired or revoked: `refused_by_policy`.
3. The action's risk class is R1 or lower. R2 is refused with `above_ceiling`.
4. The row decrypts. A failure is `tool_failure`.

Every outcome, allowed or refused, is written to `cyber_credential_lease` and to `cyber_decision`. A refused lease returns no value. The caller releases the value when the execution ends, and the buffer is zeroed then.

## Delivery

- **Kali.** A lease becomes one entry in the job's `inputs`. Today `kali_run` accepts only stored artifacts there. A `lease` source feeds the same stdin loader, which writes the file with mode 0600 under a random name in the `/work` tmpfs. `argv` carries the path, never the value. The value leaves with the job container, and no artifact stores the input.
- **Host.** Cloud API calls made by the host process use the value for one call and then drop it. This is the preferred path for cloud: each Kali copy is one more place the value can end up.

## Output

Before any stdout, stderr, output file, artifact or tool result is stored or returned, the job's leased values are replaced with `[CREDENTIAL]`. The check covers the raw value and its base64 form. A tool that transforms the value (hashing, slicing, re-encoding) is outside this check. The lab test covers the cases the check claims to handle.

## Model-facing tool

`cyber_credentials` has one action, `list`, which returns label, kind, targets, `read_only` and `expires_at`. It has no add, revoke or value action. Its description contains one literal example call.

## Schema

Schema version 9 becomes 10. The migration adds `engagement_credential` and `cyber_credential_lease`. The lease table is append-only, using the same trigger as `cyber_decision`. Lease rows hold label, action, target, execution, outcome and time. They never hold values.

## Acceptance criteria

| #72 criterion | Test |
| --- | --- |
| Credentials are scoped to one engagement | Real SQLite with two owners. The other owner gets `not_configured`. A row copied to another owner fails to authenticate. |
| Kali receives a credential only for one action | Docker test in `fork-kali.yml`. The value is readable inside the job, a second job cannot read it, and the job container is gone afterwards. |
| A seeded secret never appears in model-visible output | The seeded value is absent from the tool result, artifacts, the decision log and evidence, in raw and base64 form. |
| Each use is recorded with identity, action and target | A lease row exists for allowed and refused leases, with label, action, target and execution. |
| A denied call produces zero network traffic | A refused lease stops before the Kali environment starts. The test asserts that no container is created. |

## Limits

- **Windows.** NTFS does not enforce mode 0600. The key file then relies on the ACL of the profile directory. See decision 1.
- **Target types.** `cloud_resource` accepts only S3 ARNs. OC-304 (live cloud and Kubernetes RBAC) needs new target types before its resource filter can be scoped.
- **Web session tokens.** `cyber_http` headers and the identity-matrix procedures pass cookies and bearer tokens through the model. OC-307 does not change that. See decision 4.
- **Transformed values.** See Output.
- **Memory.** Buffers are zeroed on release. Strings created while a request is built are not.

## Decisions for the owner

1. **Key custody.** Recommendation: AES-256-GCM with a key file outside the evidence database, with the Windows limit documented. The alternative is the OS keychain. It needs a new dependency in `packages/core/package.json`, which is an upstream file, so it needs a ledger row. I would not do it in this work item.
2. **Read-only leases without per-action approval.** Recommendation: an R1 lease needs only the manifest declaration in an approved revision. Write-capable or R2 use stays refused until OC-401 and OC-403 provide per-action approval.
3. **Lifetime.** Recommendation: `expires_at` is required at registration, with a maximum of 30 days. A lease lasts at most as long as the action's timeout.
4. **Web identities.** Recommendation: move web session tokens onto leases in a separate issue. The host would inject the cookie or bearer token, and the model would pass only a label. OC-307 stays with directory and cloud identities, as #72 says.

## Build order

1. Migration, storage and encryption helpers, with their tests.
2. Operator script.
3. Manifest declaration and the lease decision, including refusals.
4. The Kali `lease` input and output replacement, with Docker tests.
5. `cyber_credentials list`, this guide, the section 10 status and the F-014 tool list in `FORK.md`.

The steps can land as separate PRs. No tool depends on a lease until OC-302 or OC-303 uses one.
