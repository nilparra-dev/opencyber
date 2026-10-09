# Credential brokering (OC-307)

Design for issue [#72](https://github.com/nilparra-dev/opencyber/issues/72). Status: all five steps of the build order are built, in #108, #109, #111, #112 and the PR for step 5. One item stays open: decision 4 (web identities), under Limits. Issue #72 closes with the PR that adds the wrapped forms. [fork-cyber-toolset.md](fork-cyber-toolset.md) sets the rules (R-6, D-4) and section 10 records the status.

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

Labels are declared in `rules_of_engagement.credentials` of the engagement manifest, so they are part of the approved revision. A declaration names the label, its kind (`directory_bind` or `cloud_key`), its typed targets and the actions allowed to use it. Rules the manifest enforces:

- `read_only` must be `true`. Write-capable identities are refused.
- Targets are `host`, `domain`, `cidr` or `cloud_resource`. A directory credential names the host it authenticates to. `url` and `service` wait for the work item that brings web identities.
- Each target must already be in the recorded scope. The lease checks this again, because scope can change between revisions.
- Labels are unique within a manifest, and each action is `tool` or `tool.action`.

## Storage

Table `engagement_credential`: `owner`, `label`, `kind`, `expires_at`, `revoked_at`, `nonce` and `ciphertext`, with primary key `(owner, label)`.

- Values are encrypted with AES-256-GCM. The additional authenticated data is `owner`, `label` and `kind`, so a row copied into another engagement fails to decrypt.
- The 32-byte key is generated once and kept in a file outside the evidence database, with mode 0600 where the platform enforces it. Archives made by `fork-cyber-archive.ts` must not include the key. Without the key, an archive holds only ciphertext.
- No unkeyed hash of the value is stored. A plain hash of a weak password can be checked offline from the database.

## Lease

`lease({ owner, label, action, target, execution })` makes one decision before any value leaves storage:

The checks run in this order, against the approved revision of the engagement. The first failure refuses the lease:

1. **Declared.** The approved manifest declares the label for this action and target. Otherwise `refused_by_policy`, reason `not_declared`.
2. **In scope.** The declared target is inside the recorded scope. Otherwise `outside_scope`, reason `outside_scope`.
3. **Risk.** The action's tool has a declared risk class (`undeclared_action` otherwise, `refused_by_policy`). R3, and anything the agent's ceiling or the mode does not permit, is `above_ceiling`. An R2 action also needs the engagement's validation list to name it (`not_declared`) and an active operator approval for this action and target (`approval_required`). The approval is the one the permission prompt records, and it expires after ten minutes.
4. **Role.** The agent and mode permit the tool (`outside_role_or_mode`).
5. **Registered.** The operator registered the label (`not_configured`, with the `add` command as recovery). Revoked (`revoked`) and expired (`expired`) labels are `refused_by_policy`.
6. **Opens.** The key file can be read and the row decrypts with it. Otherwise `tool_failure`, reasons `key_unavailable` or `unreadable`.

Every outcome, granted or refused, is written to `cyber_credential_lease` and to `cyber_decision` before the result returns. A refused lease carries no value. A granted lease returns a Buffer, and the caller releases it when the execution ends, which zeroes the buffer.

## Delivery

- **Kali.** A lease reaches a job as a file, never as part of its `Run` input. The model-facing `kali_run` schema has no lease field, so only a typed domain action can pass one, through the Kali manager's `leases` argument. Each lease is written as one entry of the job's `inputs`, through the same stdin loader, with mode 0600 in the `/work` tmpfs. The file name must be a plain name, because it becomes an argv path. `argv` carries the path, never the value. The job's stored input, summary and artifacts never hold the value, and the job container is removed when the job ends.
- **Host.** Cloud API calls made by the host process use the value for one call and then drop it. This is the preferred path for cloud: each Kali copy is one more place the value can end up.
- **Lifetime.** The caller releases each lease after the job returns, which zeroes the buffer. A lease serves one job; the next action takes a new lease.

## Output

Before any stdout, stderr, output file, artifact, error text or execution summary is stored or returned, the job's leased values are replaced with `[CREDENTIAL]`. The check covers the raw value and its base64 form, on one line or wrapped at 64 columns (openssl) or 76 columns (coreutils `base64`), with LF or CRLF line ends. A tool that transforms the value some other way (hashing, slicing, another encoding) is outside this check.

A captured stream stops at 2 MiB. When a capture reaches that limit, the last bytes that could start a match are dropped, so a value straddling the cut cannot survive as a prefix. Without leases, output is unchanged.

## Model-facing tool

`cyber_credentials` has one action, `list`, and no add, revoke or value action. It lists the credentials the approved engagement declares: label, kind, `read_only`, targets, actions, `expires_at` and a status, which is `available`, `not_registered`, `revoked` or `expired`. Registration is the operator's step, so a model that sees `not_registered` knows to ask the operator rather than retry.

The list reads the approved revision, the same one a lease reads, so the model never sees a credential that the lease would refuse for lack of approval. The result is read-only metadata and runs without an engagement execution record. The key of the list is `declared`, not `credentials`: the redaction layer replaces any value under a `credential` or `credentials` key, which would hide the list.

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
2. **Read-only leases without per-action approval. Decided by the owner:** an R1 lease needs only the manifest declaration in an approved revision. R2 use is allowed only for an action the engagement validates, and only with an active per-action approval (OC-401, in place since #78). Write-capable use stays refused; no work item provides it.
3. **Lifetime.** Recommendation: `expires_at` is required at registration, with a maximum of 30 days. A lease lasts at most as long as the action's timeout.
4. **Web identities.** Recommendation: move web session tokens onto leases in a separate issue. The host would inject the cookie or bearer token, and the model would pass only a label. OC-307 stays with directory and cloud identities, as #72 says.

## Build order

1. Migration, storage and encryption helpers, with their tests.
2. Operator script.
3. Manifest declaration and the lease decision, including refusals.
4. The Kali `lease` input and output replacement, with Docker tests.
5. `cyber_credentials list`, this guide, the section 10 status and the F-014 tool list in `FORK.md`.

The steps can land as separate PRs. No tool depends on a lease until OC-302 or OC-303 uses one.
