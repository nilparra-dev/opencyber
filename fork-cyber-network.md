# CY-10 network controls

Cyber phase agents execute commands only through Kali. The execution hook rejects the host `shell` even if later configuration grants it. Recon, enumeration and reporting keep their narrower tool sets. The ordinary primary agent, third-party plugins and operator processes are outside this isolation boundary.

## Configure scoped jobs

Rebuild `opencyber-kali:3` and configure its immutable image ID as described in [Kali jobs](fork-cyber-kali.md). Set `network` to `{"kind":"scoped","name":"audit-lab"}` in the operator's `opencyber-kali.jsonc`. The existing Docker network must reach the assessment targets. The previous `operator-managed` profile is rejected. `none` remains available without network budgets or nftables.

Supply explicit process budgets in the engagement's `rules_of_engagement.network`. These example values are lab settings, not recommended production limits:

```json
{
  "connections_per_second": 2,
  "packets_per_second": 100,
  "bytes_per_job": 1048576,
  "bytes_total": 10485760,
  "duration_ms": 60000
}
```

All fields are positive integers. `bytes_per_job` cannot exceed `bytes_total`. HTTP `max_rps` remains a separate shared request-start budget for HTTP tools and captured browser requests. Arbitrary TCP traffic cannot be counted as HTTP requests.

## Enforcement and evidence

The manager resolves declared hostnames and hostname exclusions in a short-lived resolver container. Failure to resolve an exclusion fails the job. It pins every returned address in the guard's hosts file and records the resolution in evidence. It installs a complete IPv4/IPv6 nftables policy before creating the workload in the guard's network namespace. The guard alone has `NET_ADMIN`; it never executes model-supplied commands. Workloads cannot change the firewall or hosts file. No model credentials or host mounts enter these containers.

Exclusions precede inclusions, including IP/CIDR exclusions. The policy allows only TCP/UDP to included addresses and networks. It blocks loopback, including Docker's embedded DNS, before destination NAT. Runtime hostname lookups use pinned hosts entries. Explicitly in-scope DNS servers remain ordinary allowed destinations. IPv6 neighbor discovery uses a separate bounded allowance so permitted IPv6 connections work. The policy does not allow incoming listening services or forwarding.

Connection rate limits apply to packets in conntrack's `new` state, including retransmissions and unanswered UDP traffic. Packet rate limits apply to outgoing allowed traffic. Both use a token bucket with a one-packet burst; excess traffic is dropped rather than queued. The byte quota shares one counter across outgoing and incoming IP packets. A packet crossing the quota is dropped. This bounds delivery through the namespace, not bytes a remote peer has already put on the wire. ARP and bounded IPv6 neighbor discovery are link-control traffic outside that quota.

Before network access, SQLite atomically reserves the full `bytes_per_job` against the top-level engagement's `bytes_total`. Different clients and child sessions share that total. Failed jobs, cancellation and restarts do not refund reservations. This conservative accounting avoids promising unused credit after a crash. Increasing the explicit manifest total permits additional work without deleting prior accounting. Export includes the budget row; an operator purge deletes it with the archive. One job per engagement is admitted at a time by the existing Docker lock.

The command deadline is the smallest of the requested timeout, operator ceiling and engagement `duration_ms`. Existing CPU, memory, filesystem and output limits still apply. Each execution records the manifest and configuration, plus `kali.network.policy` with the resolved addresses, nftables rules, budget and cumulative reservation. `kali.network.counters` records terminal kernel counters when the guard remains available. Losing that audit or failing cleanup makes the execution an error. Cancellation still preserves available command output and cleans up containers.

A job uses the scope snapshot admitted at its start. Stop active work before changing its scope. Addresses behind a permitted host may serve other virtual hosts; an IP firewall cannot distinguish them. These numeric controls do not prove a request is nondestructive, enforce the free-text time window, or interpret `no_dos` as a semantic classifier. They do not cover raw sockets, devices, an allowed remote proxy's onward traffic, or unsupported browser capture paths.

## Storage migration

Archive schema 4 adds `network_budget`; schema 1/2/3 archives migrate in place without replacing notes, tasks or evidence. Earlier binaries reject schema 4. Portable `opencyber-archive-v2` exports gain an additive `network_budget` array. No upstream database migration, public Protocol change or generated client change is involved.

## Verification

`fork-cyber-network.test.ts` uses real Docker, nftables, SQLite and local HTTP/UDP fixtures. It checks permitted IPv4/IPv6, hostname and CIDR exclusions, IPv4-mapped IPv6, redirect blocking, embedded DNS blocking, firewall mutation denial, connection and packet rates, byte exhaustion, job duration, schema migration and shared persistent reservations. The Kali suite covers lifecycle, cancellation, output bounds and artifact retention. The real Location suite verifies host-shell rejection under permissive phase-agent configuration.

Run the Core suites with `OPENCYBER_TEST_KALI_IMAGE` set to the rebuilt image ID. The fork Kali workflow runs both suites on Linux. A local Windows/Docker result does not substitute for that CI run.

The opt-in live smoke uses a compiled CLI installed into a temporary profile, a real Fireworks model and a synthetic loopback fixture. From `packages/cli`:

```sh
bun script/fork-cyber-live.ts <compiled-binary> <existing-credential-database>
```

It reads only the existing Fireworks API credential, passes it in the CLI process environment and writes no credential into the temporary profile. It uses `accounts/fireworks/models/deepseek-v4p1-flash`, at most eight steps per agent and a four-minute process deadline. Success requires one completed recon task, one HTTP request and one linked evidence artifact. The profile retains transcripts, the database and `result.json` for inspection. This is an opt-in paid model call, not a CI test or model-quality benchmark. The GUI, automatic updater and installer download paths are not exercised.

Local validation on Windows with Bun 1.4.2 passed 102 tests across ten Core files, including real Docker and Chromium fixtures. Root `bun run check` passed lint and all 35 typecheck tasks. The compiled Windows CLI completed the live Fireworks smoke twice, including a copy installed outside the checkout in a separate temporary profile. Both runs recorded exactly one completed recon task, one HTTP request and one linked evidence artifact. The binary build omitted the web UI. Linux CI for this change has not been run locally.

Mechanisms follow the [nftables manual](https://netfilter.org/projects/nftables/manpage.html) and [Docker container options](https://docs.docker.com/engine/containers/run/). The live model ID is published in the [Fireworks model catalog](https://fireworks.ai/models/deepseek-ai/deepseek-v4p1-flash).
