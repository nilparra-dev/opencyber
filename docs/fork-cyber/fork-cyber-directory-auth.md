# Directory credential checks (OC-403)

Design for issue [#89](https://github.com/nilparra-dev/opencyber/issues/89). [fork-cyber-toolset.md](fork-cyber-toolset.md) sets the rules (R-2, D-2, OC-403). The approval rules are in [fork-cyber-approval.md](fork-cyber-approval.md) and credential custody in [fork-cyber-credentials.md](fork-cyber-credentials.md).

`cyber_directory` gains two R2 actions, `auth_test` and `crack`. Both are disabled by default. The read-only actions of the same tool (#74) live in a separate module.

## Gates

An action runs only when all of these hold. Each refusal is recorded in the decision log before anything starts.

1. **Mode and phase.** The session is in `assessment` mode. The agent's phase reaches R2: `cyber-exploit-net`, `cyber-validate`, or the primary agent in assessment mode.
2. **Engagement declaration.** `rules_of_engagement.validation.actions` names `cyber_directory.auth_test` or `cyber_directory.crack`. Without it the call is refused with `not_declared` and no prompt is shown.
3. **Operator approval.** The operator approves the action on its target in the permission prompt, valid for ten minutes. For `auth_test` the target is the host. For `crack` the target is the exact input, so each hash set and wordlist needs its own approval.
4. **For `auth_test`, a credential.** The label is declared in `rules_of_engagement.credentials` with kind `directory_bind`, the directory `account` (a DN), a host target in scope, and the action `cyber_directory.auth_test`. The operator registers its password with `script/fork-cyber-credential.ts add`, which reads the value from stdin.

## `auth_test`

```jsonc
{ "action": "auth_test", "label": "lab-alice", "host": "ldap.lab.test", "port": 389 }
```

- **Account.** Only the account declared for the label is used. The model names a label, never a DN or a password.
- **Attempt.** One LDAP simple bind over TCP per call, through a scoped Kali job. The password is leased and written into the job as a file in `/work`; it is never in argv or the stored input. The probe runs under `python3 -I` and uses only the standard library.
- **States.** `accepted`, `rejected` (invalid credentials, including an unknown account, which the directory answers the same way), `locked` (Active Directory sub-code 775), `closed`, `no_response`, `error`. An empty credential is an `error` and sends nothing, so it can never succeed as an anonymous bind.
- **Pacing.** A lease allows one granted attempt per label and host in any 60 seconds. A second rule caps the label and host at three granted attempts in any 30 minutes (`attempt_limit`), counting attempts whatever their outcome. The fixed default stays below common lockout thresholds of five; the target's real threshold is not known to the harness (see Not done).
- **Value lifetime.** The lease is released when the job ends, which zeroes the buffer. Refused leases carry no value.

## `crack`

```jsonc
{ "action": "crack", "format": "nt", "hashes": "<artifact ID>", "wordlist": "<artifact ID>" }
```

- **Supplied only.** `hashes` and `wordlist` must be artifacts recorded under the kinds `operator.hashes` and `operator.wordlist`. A tool never creates those kinds, so tool output cannot be cracked. The credential store is not read.
- **Bounds.** One to 16 non-empty hash lines, each at most 256 characters. The wordlist is bounded by the Kali input limit of 2 MiB. Formats are `nt` (NTLM) and `raw-md5`.
- **Job.** Network `none`. Inside the job, one john run per hash against the wordlist, with its output captured and never printed. The pot file lives in the job's `/work` and goes with the container.
- **Output.** Hash indexes and a cracked or not-cracked status per hash. The plaintext is withheld from the output, the job's stdout and stderr, and every artifact.
- **Missing binary.** When the image has no `john`, the job reports `not_configured` and the tool fails with the `not_configured` category. Nothing is cracked.

## Output and errors

Both actions return a `summary`, typed fields, the execution and evidence IDs and the job's artifact IDs. The output never contains a password, a hash or a recovered plaintext. The decision log records the host only. The execution record stores the request, which names a label and a host and never a value.

Errors use the shared categories: `refused_by_policy` (role, mode, declaration, approval), `outside_scope`, `budget_exceeded` (pacing or attempt cap), `invalid_input` (artifact kind, count or length), `not_configured` (no john) and `tool_failure`. A closed port or a silent host is a state, not an error.

## Laboratory

- `test/plugin/fork-cyber-directory-auth.test.ts` runs without Docker. It covers the action discriminator, the decisions for each mode, the lease gates and pacing, the attempt cap, the supplied-artifact checks and the probe classification against a loopback LDAP fixture. The fixture answers real BER bind requests, so the classification is exercised over a socket, and the test asserts that the password never appears in output. An empty credential is checked to make no connection at all.
- `test/plugin/fork-cyber-directory-auth-lab.test.ts` runs the probe against OpenLDAP `osixia/openldap:1.5.0` pinned by digest `sha256:18742e9c…d7c28`. The gate is `OPENCYBER_TEST_KALI_IMAGE`, as for the Redis lab. The test leases the real stored values, so the classification covers the path a production lease takes. The probe runs on host Python, not in a scoped Kali job, as the Redis lab does.
- The crack laboratory is gated by `OPENCYBER_TEST_CRACKER=john`. It proves `md5("password")` is cracked from a fixture wordlist and that md5 of a string outside the wordlist is not. The `not_configured` test runs only where the image lacks john.

## Limits

- **Cleartext bind.** The probe speaks plain LDAP on port 389, so the password crosses the network unencrypted. LDAPS and StartTLS are not implemented. An engagement that tests a directory must accept that exposure.
- **Active Directory sub-codes.** Only sub-code 775 is distinguished. An expired password (532) and other sub-codes are reported as `rejected`.
- **Lockout.** The three-per-30-minutes cap is a fixed default, not the target's policy.
- **Host dependence.** A closed port is classified `closed` only where the probe's interpreter sees a refusal. On the author's Windows host connections to closed loopback ports time out, so that test is skipped there and must be run elsewhere.
- **Crack binary.** The john invocation is unverified until the crack laboratory runs in an image that contains john. The output parser depends on the message `1 password hash cracked`.

## Not done

- **john in the Kali image.** `fork-kali` v5 has no cracking binary. Adding one needs a pinned build, a license check and an image version bump, which belong to the image owner. Until then `crack` reports `not_configured`.
- **Operator import of hash sets and wordlists.** No path records artifacts of kinds `operator.hashes` and `operator.wordlist`, so `crack` cannot yet receive hashes. Engagement artifacts need an execution row, so the import is an operator script of its own.
- **Recovered plaintext.** Withholding the plaintext is the default. Where a recovered value should live (the sealed registry, or an operator-only export) is a decision for the owner.
- **Per-engagement lockout threshold.** Declaring the target's threshold in the approved revision would replace the fixed cap. Owner decision.
- **LDAPS and StartTLS**, and Active Directory sub-codes beyond 775.
- **Scoped-network path in the laboratory.** A laboratory run through a scoped Kali job needs a directory reachable from that network.
- **Shared wiring for the integrator.** `packages/core/test/location-layer.test.ts` (upstream, ledger F-014) must list `cyber_directory` among the native cyber tools. `fork-cyber-approval.md` should list the two new validation actions. `.github/workflows/fork-kali.yml` should run the laboratory file. `cyber_capabilities` does not yet report `cyber_directory` as available in the environment list.
