# Discovery (`cyber_discover`)

`cyber_discover` gathers what an engagement may observe about its declared targets. It replaces `cyber_dns` in the catalog. Its four actions differ in risk and in what they require.

| Action         | Risk | Target                     | Requires                                                                                        |
| -------------- | ---- | -------------------------- | ----------------------------------------------------------------------------------------------- |
| `passive_dns`  | R0   | One in-scope hostname      | Scope. Same record types as the former `cyber_dns`                                              |
| `certificates` | R0   | One in-scope domain        | Scope and `rules_of_engagement.passive_osint: true`. Third-party query                          |
| `host_sweep`   | R1   | One IPv4 range, /24 to /32 | Exact declaration in `scope.cidrs`, a scoped Kali network, network budgets, a claim for workers |
| `fingerprint`  | R1   | One in-scope HTTP(S) URL   | Scope, as for every HTTP request. Shared request rate and evidence                              |

Every action returns execution and evidence IDs, a summary, structured fields and categorized errors (R-6). Refused requests use the categories in `fork-cyber-toolset.md`.

## passive_dns

Queries the harness-controlled resolver, as `cyber_dns` did. The record types come from the same schema, so every type the old tool supported is still supported. The resolver stays operator infrastructure. A hostname outside scope fails with `outside_scope` before any query.

## certificates

Lists names that public certificate transparency records associate with an in-scope domain. Passive OSINT reveals interest in the target to a third party (R-9), so the lookup is refused unless the engagement declares it:

```json
"rules_of_engagement": { "passive_osint": true }
```

Without that declaration the call fails with `refused_by_policy`, and no request is made. The domain must be in scope and not excluded. The default source is `https://crt.sh/`, queried over HTTPS with no redirects, a 15-second timeout and a 2 MiB response limit. A response that exceeds the limit is an error execution, not a partial result.

Names are candidates. They are never added to scope. `declared_in_scope` lists only names that exactly match a declared domain. Wildcard labels are reported without the `*.` prefix. The raw response is kept as an artifact. The summary lists at most 200 names, and `truncated` says whether more exist. This action has no offset parameter, so names beyond 200 are available only in the raw artifact.

The declaration is part of the engagement record. The model writes that record through `engagement`, the same way it writes scope, so the flag carries the same authority as the scope it sits beside.

## host_sweep

Checks which addresses in one IPv4 range answer. The range must match a `scope.cidrs` entry exactly. Sub-ranges and hosts are not inferred from it. The range is refused when an `excluded` entry overlaps it. Prefixes shorter than /24 are rejected by the schema, so one job covers at most 256 addresses.

The job runs in scoped Kali with a fixed argv: `nmap --unprivileged -sn -n` with one retry, one parallel probe, a per-probe delay derived from `connections_per_second`, and a host timeout. The network guard enforces the destination range and the budgets, as for `cyber_services`. The Nmap report must cover every address in the range, or the job fails.

Unprivileged discovery uses TCP connect probes. A host that neither accepts nor resets them is reported down, so filtering can hide live hosts. The result describes reachability from this network position only.

## fingerprint

Sends one `GET` through the HTTP engine, which checks scope before connecting and follows redirects only within scope. It reports hints from one response: the `Server` and `X-Powered-By` header values, cookie names from `Set-Cookie` (never their values), the `generator` meta tag, and three fixed body paths. The hints are heuristics. They do not confirm a version or the presence of a weakness.

## Limits

- `certificates` uses one public source. Other passive sources are not implemented.
- `host_sweep` covers IPv4 only. IPv6 ranges are unbounded in size, so the schema refuses them.
- Names from `certificates` beyond 200 stay in the raw artifact, as described above.

## Verification

`packages/core/test/plugin/fork-cyber-discovery.test.ts` covers the schema, the decisions, and the refusals that happen before any request. It runs `certificates` and `fingerprint` against local fixtures, so no test contacts a third party. The real sweep test creates an internal IPv4 Docker network with one live container and checks that the live address is reported and an unused one is not. It runs only when `OPENCYBER_TEST_KALI_IMAGE` is set, as the other Kali tests do.
