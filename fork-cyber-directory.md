# Directory assessment (OC-303)

Issue [#74](https://github.com/nilparra-dev/opencyber/issues/74). `cyber_directory` assesses a directory service with read-only operations. Its implementation is `packages/core/src/fork-cyber/directory.ts`; the tool is registered in `packages/core/src/plugin/fork-cyber.ts`. Risk classes are declared in `decision.ts` (R-2), and the cyber-code-review and recon/enum phases list the tool in `roles.ts`. Credential binds use the brokering path in [fork-cyber-credentials.md](fork-cyber-credentials.md). The R2 actions `auth_test` and `crack` belong to another module and are documented in `fork-cyber-directory-auth.md` when they land.

## Actions

| Action | Risk | Input | What it does | Identity |
| --- | --- | --- | --- | --- |
| `procedures` | R0 | none | Returns the operator procedure and limits | none |
| `ldap_enum` | R1 | `host`, optional `port` (389), `base_dn`, `credential`, `timeout_ms` | Reads the rootDSE, attempts an anonymous bind, searches the base (or first naming context) with `objectClass` only, and reports anonymous visibility. With `credential`, it also binds as the registered identity after StartTLS | anonymous, and a brokered label |
| `password_policy` | R1 | `host`, `base_dn` (policy container), `credential`, `timeout_ms` | Reads `pwdPolicy` objects and lists review candidates: minimum length below 12, lockout disabled, lockout threshold above 10 or unbounded, quality check disabled | anonymous, or a brokered label |
| `collect` | R1 | `host`, `base_dn`, `max_entries` (1 to 500), `credential`, `timeout_ms` | Bounded subtree read with an allowlisted attribute set. The artifact holds the collection; the result holds the first 25 entries | anonymous, or a brokered label |
| `kerberos_config` | R0 | `artifact`, optional `offset` | Offline review of an exported JSON array of accounts: no pre-authentication, SPNs on user accounts, encryption types without AES | none |
| `adcs_templates` | R0 | `artifact`, optional `offset` | Offline review of exported certificate templates: an enrollee-supplied subject with a client-capable EKU, no manager approval and no authorized signatures is a candidate. Incomplete templates are marked | none |

Example call: `{"action":"ldap_enum","host":"dc.lab.example.test","port":389}`.

`ldap_enum`, `password_policy` and `collect` need a non-derived engagement, a scoped Kali network, explicit network budgets and, for workers, an active claim. The host and port must be inside the recorded scope before anything starts. `kerberos_config` and `adcs_templates` need only an engagement and the artifact.

## Read-only operations

The probe speaks four LDAP operations: bind (0x60), search (0x63), unbind (0x42) and the StartTLS extended request (0x77). Its `send` refuses any other operation, so add, modify, delete, rename and compare requests cannot be encoded. Tests check the probe source, and a loopback peer records every operation the probe sends.

A credential is never sent in cleartext. The probe sends it only after the server advertises and accepts StartTLS. When StartTLS is unavailable or refused, the report says so and no bind is sent (tested against a peer that records the wire).

## Brokered identities

`credential` names a label that the engagement declares for `cyber_directory.<action>` with `read_only: true`, a `host` target, and a directory kind. The lease is taken before the Kali job exists, so a refused lease starts no container. The registered value is the bind DN, a line feed and the password:

```text
uid=reader,ou=people,dc=lab,dc=example,dc=test
<password>
```

The job receives the value as a 0600 file under `/work`, never in argv. The module releases the lease when the execution ends. The model sees the label and the outcome (`accepted`, `rejected`, `refused`, `unavailable`); it never sees the DN or the password. The probe output contains no secret, and a test asserts the password is absent from the output.

The server certificate is **not verified** for the StartTLS bind. The laboratory certificate is self-signed, and verification would need a trust decision the operator has not made. The output and the limits say so. A credential bind therefore proves the account works, but not that the server is the intended one.

## Output

Every live result carries `format` (`opencyber-directory-v1`), `action`, `target`, `probe_state`, `identities`, `summary`, `findings` (`id`, `state`, `dn` where relevant), `fields`, `report_artifact` and `limitations`. Findings are candidates for review. Transport failures are categorized `target_unreachable`; scope, lease and claim refusals keep their own categories. The offline actions paginate their rows with `offset` and `next_offset`.

## Laboratory

The OpenLDAP laboratory uses `osixia/openldap` pinned by digest (`sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28`, OpenLDAP 2.4.57). Two configurations run in containers on loopback:

- **exposed**: anonymous bind accepted, the anonymous session reads every entry, and a weak policy (minimum length 6, lockout off, no quality check).
- **hardened**: anonymous bind disallowed (`olcDisallows: bind_anon`), data hidden from anonymous sessions, the policy subtree readable, and a strong policy (minimum length 14, lockout after 5 failures, quality check on).

Run the laboratory from `packages/core` with Docker running:

```sh
OPENCYBER_TEST_DIRECTORY_LAB=1 OPENCYBER_TEST_PYTHON=python3 bun test test/plugin/fork-cyber-directory.test.ts
```

Without the variable, the four laboratory tests are skipped. Set `OPENCYBER_TEST_PYTHON` when `python3` on PATH is not a working interpreter. The non-laboratory tests cover the decision table, the action union, the wire-level read-only guarantee, the credential-before-StartTLS guarantee, the closed port, lease refusal, scope refusal with zero connections, and both offline fixtures.

The laboratory checks these known outcomes:

- `ldap_enum`: exposed gives `anonymous_bind: exposed`, `anonymous_read: user_objects_visible`; hardened gives `anonymous_bind: not_exposed`, `anonymous_read: base_not_visible`. StartTLS is offered in both.
- `password_policy`: the weak policy yields `minimum_length_below_12`, `lockout_disabled` and `quality_check_disabled`; the strong policy yields no candidates.
- `collect`: exposed returns the people subtree (two entries: the unit and the user) with no password; hardened returns nothing (`no_base`).
- Credentials: a wrong password is `rejected` with no search; the right one is `accepted` and reads the directory.

The laboratory runs the probe on host Python and the same classification as the Kali job. It does not start the Kali container or the scoped network, which the database auth path also leaves to its Kali integration run.

## Limits

- Anonymous and credential visibility is observed for one search per identity. ACLs that hide an object from the search are reported as visibility, not as absence.
- `password_policy` reads `pwdPolicy` objects only. Active Directory domain password policy is not read.
- `kerberos_config` and `adcs_templates` read exported JSON with AD attribute names. The export shape is the one in the action's limits; other formats are rejected. Enrollment rights and template ACLs are not in the export, so an ADCS candidate is a configuration pattern, not an exploitable path.
- `collect` returns a preview of 25 entries. The artifact holds the bounded collection, but there is no paged artifact read, so the result's `next_offset` is not offered.
- Server certificates are not verified for StartTLS binds (see above).
- The Kali job path is not exercised end to end by a test in this change.

## Not done

- **Windows directory laboratory (OC-301).** The Active Directory checks (domain password policy, real Kerberos and ADCS configuration, and live `kerberos_config` and `adcs_templates`) need the Windows domain controller that cannot run on the current machine. The offline reviews are fixture-tested only.
- **`collect` on Active Directory.** Needs the same Windows laboratory; the OpenLDAP laboratory verifies the protocol path only.
- **Certificate verification for credential binds.** Needs a decision on the trust anchor (operator-supplied CA or pinned certificate). Until then, credential binds are unverified over StartTLS.
- **Paged reads of collections (`next_offset` for `collect`).** Needs an offset on `cyber_artifacts`, which is outside this module.
- **Role change in `F-014`.** `packages/core/test/location-layer.test.ts` lists the native cyber tools and fails until `cyber_directory` is added to that list (upstream file, ledger row F-014).
