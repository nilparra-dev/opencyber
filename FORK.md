# FORK.md: how this fork works and is maintained

> **For agents:** read this whole file before making any change to this repository.
> Where it conflicts with `AGENTS.md`, this file wins, but only for branches, remotes, syncing and CI. The style, testing and typecheck rules in `AGENTS.md` still apply.

This repository is a fork of [`anomalyco/opencode`](https://github.com/anomalyco/opencode), called **upstream** below. It follows upstream's **V2 line** (`@opencode/cli`, the `v2` branch and its `v2.X.Y` release tags). It has two goals:

1. Keep our own changes and improvements.
2. Receive every upstream release **automatically**, with as little manual work as possible.

To get there, everything here is designed to **keep our diff against upstream as small and as isolated as possible**. Every line we change in upstream code can become a future conflict.

---

## 0. Variables

These are the configured values for this fork.

| Variable               | Value                                       | Description                                       |
| ---------------------- | ------------------------------------------- | ------------------------------------------------- |
| `FORK_OWNER`           | `nilparra-dev`                              | Owner of the fork                                 |
| `FORK_REPO`            | `opencyber`                                 | Fork repository name                              |
| `UPSTREAM_URL`         | `https://github.com/anomalyco/opencode.git` | Original repository                               |
| `UPSTREAM_TAG_PATTERN` | `^v2\.[0-9]+\.[0-9]+$`                      | Upstream releases we follow (stable V2 tags only) |
| `FORK_BRANCH`          | `custom`                                    | Main fork branch (our code)                       |
| `SYNC_BRANCH`          | `sync-upstream`                             | Branch the bot uses for syncs                     |

---

## 1. Branch and remote model

```
upstream tags  ── v2.0.16 ─────── v2.0.17 ───── v2.0.18 ──►   (anomalyco/opencode; read-only for us)
                      \               \              \
origin/custom  ────────●──○──○─────────●──○───────────●──►    (our main branch and the fork's default branch)
                          ↑  ↑         ↑              ↑
                        our commits  upstream      upstream
                                     release       release
                                     merge         merge
```

- **Remotes:**
  - `origin`: our fork (`github.com/nilparra-dev/opencyber`).
  - `upstream`: `anomalyco/opencode`. **Never** push to `upstream`.
- **What we follow: release tags, not a branch tip.** The sync merges the newest stable tag matching `UPSTREAM_TAG_PATTERN` (`v2.0.16`, `v2.0.17`…). A tag is exactly what upstream shipped, so `custom` is always "upstream release X plus our changes". Upstream's `v2` branch runs ahead of the latest tag; we never merge it directly.
- **Branches:**
  - `custom`: the fork's main branch and its **default branch on GitHub**. It holds the latest upstream release plus our changes, and only receives changes through Pull Requests.
  - `sync-upstream`: a throwaway bot branch. It holds `custom` with the newest upstream release merged on top.
  - Work branches: branch off `custom` and return to `custom` through a PR. Names are at most three words separated by hyphens, with no slashes (per `AGENTS.md`). Examples: `custom-theme`, `fix-sync-ci`.
  - The fork has no `dev` or `v2` branch of its own.
- **Integration strategy: MERGE, not rebase.** `custom` is public and the bot works on it. Merging never rewrites history, never needs a force-push, resolves each conflict only once (and `rerere` remembers the resolution), and is safe to automate.
- **Critical rule:** sync PRs (`sync-upstream → custom`) are always integrated with a **merge commit**, **never with squash or rebase**. A squash breaks the ancestry link with upstream, and every later sync brings back the same conflicts.

### Note on `AGENTS.md` in this fork

`AGENTS.md` says the default branch is `v2`. **In this fork, read that as:**

- Base branch for work and PRs: `custom` (`origin/custom`).
- Diff for "what have we changed relative to upstream": `git diff <latest v2 tag>...custom`, for example `git diff v2.0.16...custom`. The command in section 7 finds the tag for you.

### History: the move from V1 to V2

Until September 2026 the fork followed `upstream/dev`, the V1 line (`opencode-ai`, `packages/opencode`). V1 went into maintenance while upstream's work moved to `v2`, so the fork moved too: `custom` was rebuilt from the `v2.0.16` tag with the fork changes ported, and the old `custom` history was joined with an `ours` merge so no force-push was needed. The V1-only patches were retired (see the end of section 7).

The V2 fork build (`opencyber`, section 10) shares the official V2 `opencode`'s database (F-004), so it sees the same sessions and logins. **Log in to Anthropic with "Claude Pro/Max"** from `opencyber` the first time. A V1 login imported by the official V2 `opencode` uses a generic `oauth` method that has no refresh and is not recognized as a subscription, so it would not work either.

---

## 2. Initial setup (one time)

Steps marked 👤 need a human (browser, credentials or decisions). An agent with authenticated `git` and `gh` can do the rest.

### 2.1 👤 Decision: public fork or private repository

| Option                             | How it is created                     | Pros                                                             | Cons                                                  |
| ---------------------------------- | ------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------- |
| **A. Public fork** (_Fork_ button) | GitHub → Fork                         | Visible link to upstream; PRs to upstream can be opened directly | Must be **public**                                    |
| **B. Private repository**          | Create an empty private repo and push | Code stays private                                               | Contributing to upstream needs a separate public fork |

Upstream is MIT-licensed, so both options are valid. The rest of this document works the same for A and B. This fork uses option A.

### 2.2 Create the repository and remotes

Starting from an existing upstream clone:

```bash
# Option A: create the public fork (copy all branches, not only the default one)
gh repo fork anomalyco/opencode --fork-name opencyber --clone=false --default-branch-only=false
# Option B: create an empty private repository
gh repo create nilparra-dev/opencyber --private

git remote rename origin upstream          # the current clone points at anomalyco → it becomes upstream
git remote add origin https://github.com/nilparra-dev/opencyber.git
git remote set-url --push upstream DISABLED # prevents accidental pushes to upstream
git fetch upstream --tags

tag=$(git tag -l 'v2.*' | grep -E '^v2\.[0-9]+\.[0-9]+$' | sort -V | tail -1)
git checkout -b custom "$tag"
git push -u origin custom
gh repo edit nilparra-dev/opencyber --default-branch custom
# Option A: delete the branches copied by the fork that could trigger upstream workflows
git push origin --delete dev v2
```

### 2.3 Local git configuration (on every machine and every clone)

```bash
git config rerere.enabled true            # remembers how each conflict was resolved
git config rerere.autoupdate true
git config merge.conflictstyle zdiff3     # also shows the common base in conflicts
git config pull.ff only                   # never create implicit merges with a pull
git config fetch.prune true
```

On Windows, the repository may contain symlinks. Enable Developer Mode (Settings → System → For developers) so git can create them, then run `git config core.symlinks true` and `git checkout -- .` on a clean tree. Without this, symlinks are checked out as text files holding the target path and typecheck fails in the packages that use them.

### 2.4 👤 Token for the sync bot

`GITHUB_TOKEN` **does not work** for this, for two reasons:

1. It cannot push commits that modify `.github/workflows/**`, and upstream changes those often. The result is the error `refusing to allow a GitHub App to create or update workflow ... without workflows permission`.
2. PRs created with `GITHUB_TOKEN` **do not trigger** other workflows, so CI would never run on the sync PR.

Create a **fine-grained personal access token** scoped to `nilparra-dev/opencyber` with these permissions:

| Permission    | Level                                        |
| ------------- | -------------------------------------------- |
| Contents      | Read and write                               |
| Pull requests | Read and write                               |
| Issues        | Read and write                               |
| Workflows     | Read and write                               |
| Actions       | Read and write (needed to disable workflows) |
| Metadata      | Read (required)                              |

Store it as a secret:

```bash
gh secret set FORK_SYNC_TOKEN --repo nilparra-dev/opencyber   # paste the token when prompted
```

Set a reminder before it expires. Once it expires, `fork-sync` cannot disable workflows, push the sync branch or manage its PR.

Keep this token out of repository code execution. Do not define it at job scope or pass it to checkout when later steps run dependency installation, tests or code generation. Set `persist-credentials: false` on checkout, then expose `GH_TOKEN` only to steps that call `gh` or push.

### 2.5 GitHub repository settings

```bash
# Allow auto-merge and merge commits, both required for the sync PR
gh repo edit nilparra-dev/opencyber \
  --enable-auto-merge \
  --enable-merge-commit \
  --delete-branch-on-merge=false

# Labels used by the workflows
gh label create fork-sync            --color 0E8A16 --description "Automated upstream sync PR" --repo nilparra-dev/opencyber
gh label create fork-sync-conflict   --color D93F0B --description "Upstream sync needs conflict resolution" --repo nilparra-dev/opencyber
gh label create needs-review         --color FBCA04 --description "Resolved by an agent; needs human review" --repo nilparra-dev/opencyber
```

👤 In the UI (Settings → Branches → Add rule, or Rulesets) for the `custom` branch:

- **Require a pull request before merging** (no required approvals if you work alone; otherwise 1).
- **Require status checks to pass**: select `typecheck` and `test`, the aggregate checks from `fork-ci`. They only show up after `fork-ci` has run once.
- **Block force pushes** and **Restrict deletions**.

👤 In Settings → Actions → General:

- Enable Actions. They are disabled by default on forks.
- Under _Workflow permissions_, keep "Read repository contents" (each workflow requests what it needs).

### 2.6 Disable upstream workflows in the fork

Upstream ships many workflows (`publish.yml`, `deploy.yml`, `triage.yml`, `test.yml`…). They **must not run** in the fork, for three reasons:

- They use `blacksmith-*` runners we don't have, so their jobs sit in the queue until they fail.
- They need upstream's secrets.
- Some of them publish or deploy.

The `fork-sync` workflow automatically disables every workflow whose file name does not start with `fork-`, and does so on every run, so it also covers new workflows that upstream adds later. For the first time, run it by hand:

```bash
gh workflow list --repo nilparra-dev/opencyber --all --limit 200 --json path,state \
  --jq '.[] | select(.state=="active") | select(.path | startswith(".github/workflows/fork-") | not) | .path' |
  while read -r p; do gh workflow disable "$(basename "$p")" --repo nilparra-dev/opencyber; done
```

**Convention:** every fork workflow is named `.github/workflows/fork-*.yml`. No upstream file will ever have that prefix, so fork workflows never conflict.

### 2.7 Verify the setup

```bash
gh workflow run fork-sync.yml --repo nilparra-dev/opencyber
gh run watch --repo nilparra-dev/opencyber
```

Expected result: the workflow finishes green and one of these three things happens:

- There was no new upstream release.
- A `chore(fork): sync upstream` PR was created with auto-merge enabled.
- A `fork-sync-conflict` issue was opened.

---

## 3. How the automation works

```
every hour / manual
      │
      ▼
fork-sync.yml ──► disables upstream workflows that are not fork-*
      │
      ├─ newest upstream tag matching v2.X.Y (git ls-remote, no clone)
      │
      ├─ does the base already contain that tag and custom? ──► yes: stop (compare API, no clone)
      │     base = the open sync PR branch if there is one, otherwise custom
      ▼
 merge what is missing (custom, then the tag) into sync-upstream, starting from the base
      │
      ├─ no conflicts ──► regenerate client ──► push ──► PR (label fork-sync, auto-merge with merge commit)
      │                                                     │
      │                                                     ▼
      │                                      fork-ci.yml (typecheck + tests + generated)
      │                                                     │
      │                                          green ──► merged into custom automatically ✅
      │                                          red   ──► stays open for an agent or a human ⚠️
      │
      ├─ conflicts only in files the fork has not changed ──► taken from the release, then as "no conflicts"
      │
      └─ other conflicts ──► "fork-sync-conflict" issue listing the files
                            │
                            ├─ (optional) fork-resolve.yml: an agent resolves and opens a "needs-review" PR
                            └─ otherwise a local agent resolves it following section 6
```

- The schedule is hourly. Upstream publishes about one V2 release a day, so most runs find nothing new.
- The newest release is found with `git ls-remote` on upstream's tags; when the base already contains it, the workflow answers from the GitHub compare API without cloning and finishes in seconds.
- While a sync PR is open, the run builds on `sync-upstream` instead of rebuilding it from `custom`, so fixes pushed to the sync branch (section 6) are kept. It merges new `custom` commits into it (branch protection requires PRs to be up to date with `custom`, so otherwise auto-merge would stall) and then a newer release, if one appeared. A sync PR that already contains both is left alone.
- Upstream tags each release on a side commit (`release: v2.X.Y`) that bumps the version in every `package.json` and in `bun.lock`, so release tags are not ancestors of each other and every sync conflicts on those lines. The merge step takes unchanged fork files from the new release, following section 6.2. For manifests and the lockfile changed by the fork, it replays the fork diff with a three-way merge so independent dependency additions survive changed context. An unresolved lockfile replay resets that file to the release and requests regeneration. Remaining manifest or code conflicts abort the merge and open the issue. Dependency installation and lockfile regeneration only run after a successful merge. The merge commit lists the resolved files.
- An open `fork-sync-conflict` issue is kept current by editing its body, not by adding a comment on every run.
- The sync PR is updated by pushing `sync-upstream`, which is a bot branch. `custom` is **never** force-pushed.
- The `publish` jobs only load a bundle and push, so their checkouts are blobless (`filter: blob:none`). The jobs that merge (`fork-sync`'s `sync`, `fork-resolve`) use full clones: in a blobless clone the merge fetches missing blobs lazily from `origin`, which does not serve upstream-only objects, and the merge fails with `upload-pack: not our ref`.
- Conflict reports need Issues enabled on the repository (`gh repo edit nilparra-dev/opencyber --enable-issues`); `fork-resolve` is also triggered by them.

---

## 4. Fork files

All of these files are **fork-only**: upstream does not have them, so they never conflict. The files themselves are the source of truth; this section explains what they do and why.

| File                                                        | Purpose                                                                        |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `FORK.md`                                                   | This document: rules and patch ledger                                          |
| `CLAUDE.md`                                                 | Makes Claude Code load `AGENTS.md` and `FORK.md` (`@AGENTS.md` and `@FORK.md`) |
| `.github/workflows/fork-sync.yml`                           | Automatic sync with upstream releases (section 3)                              |
| `.github/workflows/fork-ci.yml`                             | Fork CI on standard GitHub runners (4.2)                                       |
| `.github/workflows/fork-resolve.yml`                        | (Optional) Conflict resolution by an agent (4.3)                               |
| `.github/workflows/fork-release.yml`                        | Builds and publishes `opencyber` releases (4.5)                                |
| `.github/actions/fork-setup-bun/action.yml`                 | Bun setup for fork workflows, caching `node_modules` by lockfile (4.4)         |
| `script/fork-install.ps1`, `script/fork-install.sh`         | Install or update `opencyber` from this repository's releases (section 10)     |
| `script/fork-ledger-check.ts`                               | Verifies the section 7 ledger against the tree in fork CI (4.2)                |
| `packages/core/src/plugin/provider/fork-anthropic-oauth.ts` | Claude Pro/Max login (ledger F-002)                                            |
| `packages/core/test/plugin/fork-anthropic-oauth.test.ts`    | Tests for it                                                                   |
| `packages/cli/src/services/fork-updater.ts`                 | `opencyber` updates from this repository's releases (ledger F-003)             |
| `packages/cli/src/fork-shared-state.ts`                     | `opencyber` shares the official install's database and TUI state (F-004)       |
| `packages/cli/src/fork-version.ts`                          | The ` (Cyber)` display version shown by the TUI and `--version` (F-005)        |
| `packages/tui/src/fork-logo.ts`                             | The `opencyber` wordmark rendered by `component/logo.tsx` (ledger F-011)       |

The only changes to upstream files are the ones in the ledger (section 7).

The cybersecurity roadmap, phase acceptance tests, current limits and engagement migration instructions live in [fork-cyber-plan.md](fork-cyber-plan.md). The fork-owned implementation is in `packages/core/src/fork-cyber/` and `packages/core/src/plugin/fork-cyber.ts`, with unit and real-Location integration tests in `packages/core/test/plugin/fork-cyber*.test.ts`.

Phase 2 storage and lifecycle instructions are in [fork-cyber-storage.md](fork-cyber-storage.md). Fork-only additions include `packages/core/src/fork-cyber/store.ts`, the operator maintenance script `packages/core/script/fork-cyber-archive.ts`, and the optional profile launcher `script/fork-cyber-profile.ts` backed by `packages/cli/src/fork-cyber-profile.ts`. The launcher isolates on-disk data and credentials without changing F-004's installed defaults. Tests cover the archive, concurrent process writers and profile path resolution.

Phase 3 adds `packages/core/src/fork-cyber/http.ts` and its offline HTTP lab in `packages/core/test/plugin/fork-cyber-http.test.ts`. [fork-cyber-http.md](fork-cyber-http.md) documents request/replay/compare, scope and rate enforcement, evidence capture and limits. HTTP fixture clients and public self-signed TLS fixture credentials live under `packages/core/test/fixture/fork-cyber-*`. The existing F-014 tool-list adjustment includes these native tools.

Phase 4 adds the fork-owned Kali manager in `packages/core/src/fork-cyber/kali.ts`, the versioned image recipe under `fork-kali/`, real Docker tests in `packages/core/test/plugin/fork-cyber-kali.test.ts`, and `.github/workflows/fork-kali.yml`. [fork-cyber-kali.md](fork-cyber-kali.md) covers configuration, artifact transfers, resource limits, cancellation and the network-policy boundary. F-014 also excludes the two new native tools from the upstream-only registry assertion.

Phase 5 adds the fork-owned browser manager in `packages/core/src/fork-cyber/browser.ts`, real Chromium fixtures and a compiled capture smoke test, with `.github/workflows/fork-browser.yml` for Linux validation. [fork-cyber-browser.md](fork-cyber-browser.md) documents identities, authentication checkpoints, HTTP evidence correlation and unsupported capture paths. F-015 records the pinned driver dependency; F-016 records the narrow binary-build adjustment.

Phase 6 adds fork-owned `coordination.ts` and `roles.ts` under `packages/core/src/fork-cyber/`. [fork-cyber-coordination.md](fork-cyber-coordination.md) documents exclusive durable task claims, hypotheses, execution-linked coverage, schema 3/export migration and runtime phase permissions. Real SQLite process races and Location integration tests verify coordination and role checks. F-014 includes the two new native coordination tools.

Phase 7 starts with fork-owned `code-review.ts`, the `cyber_code_review` tool and restricted `cyber-code-review` role. [fork-cyber-code-review.md](fork-cyber-code-review.md) documents local source snapshots, bounded SARIF imports, task/evidence integration and the SQL-injection/healthy-control lab. `.github/workflows/fork-code-review.yml` regenerates the lab report with pinned Semgrep and verifies a compiled capture client on Linux. Runtime review requires no Docker, analyzer installation or network scope. F-014 includes the new native tool.

The next phase 7 module is fork-owned `services.ts` and `cyber_services`. [fork-cyber-services.md](fork-cyber-services.md) documents bounded TCP connect inventory, XML/JSON parsing, task-linked evidence and real IPv4/IPv6 open/closed controls. It reuses scoped Kali enforcement and extends recon/enumeration with a structured scanner. Image version 3 removes Nmap file capabilities; `.github/workflows/fork-kali.yml` runs the labs and a compiled inventory smoke. F-014 includes this native tool.

The remaining local phase 7 workflows use fork-owned `surface.ts`, `modules.ts`, `service-validation.ts`, `identity-cloud.ts`, `artifact-validation.ts` and `ot.ts`, registered through `cyber_surface`. [fork-cyber-surfaces.md](fork-cyber-surfaces.md) documents TCP/UDP service scope, explicit S3 resource authorization, TLS/SSH protocol probes, identity controls, S3 listing/policies, Android binary manifests, isolated ELF reproduction, wireless PCAP and Modbus simulators. Image 4 supplies the local lab tools; `.github/workflows/fork-surfaces.yml` runs positive/negative labs, a compiled evidence/report workflow and the CLI delivery smoke. Device, radio and live-cloud coverage remain pending. No phase 8 model evaluations are included. F-014 includes this native tool.

Audit corrections, controlled process modes, operator approval, schema 5 migration and remaining evaluation/backend work are documented in [fork-cyber-audit.md](fork-cyber-audit.md). Fork-only additions include `policy.ts` and `findings.ts` under `packages/core/src/fork-cyber/`, the operator approval command `packages/core/script/fork-cyber-authorize.ts`, and audit/policy regression suites. F-019 records the narrow upstream startup and read-instruction changes.

The harness corrections H01–H18, operator setup and repeated model-evaluation workflow are documented in [fork-cyber-harness.md](fork-cyber-harness.md). Fork-only additions under `packages/core/src/fork-cyber/` provide environment and capability diagnosis, typed errors, pagination, original-artifact analysis, DNS, local validation, feature-based web plans, Instructions-backed notes, redaction, physical-attempt tracing and independent evaluation scoring. Operator scripts live in `packages/core/script/fork-cyber-{setup,web-scope,evaluate}.ts`; `packages/cli/script/fork-cyber-assess.ts` selects isolation before imports, and `packages/tui/src/fork-cyber-export.ts` renders the shared export contract. Schema 6 stores request snapshots and attempts outside the Session event aggregate. F-019 through F-023 cover the required upstream boundaries. Docker, Chromium and real-model evaluations have explicit runtime prerequisites; deterministic fixtures do not establish those results.

`packages/core/src/plugin/fork-tool-input-repair.ts` selects an object union alternative only when every branch requires a shared literal discriminator and exactly one matches. The existing input-repair plugin then normalizes that branch's fields, including string revisions from `cyber_tasks`. F-025 records this integration; fork-owned tests exercise discriminator selection and real Location task transitions.

### 4.1 `fork-sync.yml`

Described in section 3. Security notes that must stay true when editing it:

- `FORK_SYNC_TOKEN` is only exposed to steps that call `gh` or push, never to steps that run repository code (`bun install`, `bun run generate`).
- The job that runs repository code has read-only permissions. It hands the merged branch to a separate `publish` job as a Git bundle, and only `publish` pushes.

### 4.2 `fork-ci.yml`

This is a reduced fork CI gate on standard GitHub runners (`ubuntu-latest`), not a replacement for all upstream checks. It runs typecheck, Linux unit tests and the generated-client check, split across parallel jobs:

- `changes` decides what the PR needs. A PR that only touches `*.md` files runs nothing. A PR that touches any other file outside `packages/` (lockfile, patches, workflows, `services/`, root config; every sync PR) runs everything. Otherwise only the packages that `turbo ls --affected` reports run, which includes every package depending on a changed one. Skipped jobs count as passing for branch protection; if `changes` itself fails, `test` fails.
- `typecheck (heavy)` (the slowest packages, listed in `HEAVY` in the `changes` job), `typecheck (rest)` (every other affected package, plus the generated-client check), `unit` (affected packages except `@opencode/core`) and eight `core (N/8)` shards (`bun test --shard`) run in parallel. Packages upstream adds later fall into `rest` automatically; `HEAVY` only needs revisiting if one group becomes much slower than the other. `packages/core` holds most of the test time, so it is the only package that is sharded. `bun test --shard` splits by file count, not by duration, so shards are uneven; more shards keep the slowest one short.
- `typecheck` and `test` aggregate those jobs so branch protection can keep requiring the `typecheck` and `test` checks. Both fail if `changes` fails. For relevant Core/CLI/dependency/runtime changes, `test` also requires the reusable Kali, Chromium, code-review and surface workflows, including compiled smokes. Skipped, cancelled or unsuccessful required labs fail the aggregate. Documentation-only changes still skip execution.
- `ledger` runs independently of `changes`: it runs `bun script/fork-ledger-check.ts`, which diffs the tree against the newest upstream tag and fails the PR when an upstream file the fork modifies has no section 7 row, when a fork-modified nongenerated code file carries no `// fork:` marker, or when a marker references an id section 7 does not define. Generated client files require ledger coverage and regeneration from the public API, rather than manual markers. It needs full history for the three-dot diff, so it fetches upstream's `v2.*` tags itself and checks out with `fetch-depth: 0`. Branch protection requires it next to `typecheck` and `test`, so a PR whose section 7 is stale cannot merge.
- It runs on PRs and on demand. Pushes to `custom` run only the `cache` job, and only when the lockfile, patches or a workspace `package.json` change, to save the `node_modules` cache where every PR can read it (caches saved by a PR are private to that PR).
- Every job installs dependencies through `fork-setup-bun` (4.4), which restores `node_modules` instead of Bun's download cache.
- The `core` shards start `pwsh` once before the tests. `ubuntu-latest` ships PowerShell, so the PowerShell shell tests in `packages/core/test/tool-shell.test.ts` run there, and the first `pwsh` start on a fresh runner can exceed their 5 s limit.
- The `core` shards install `ripgrep` with apt. Upstream's runners ship `rg`; without it `packages/core` tries to download ripgrep, the test preload blocks the request, and the search tests fail.

The workflow does not run Windows unit tests, E2E tests, the compiled-service smoke test or the generated-documentation check that upstream's `test.yml` runs. Add those jobs and require their checks in branch protection if sync PRs must pass them before auto-merge.

If upstream tests fail for reasons unrelated to our changes (flaky or environment-dependent tests), **do not disable them wholesale**. Record the specific test in section 8 and exclude it explicitly.

### 4.3 `fork-resolve.yml` (optional, maximum automation)

When a `fork-sync-conflict` issue is opened, this workflow has an opencode agent try to resolve the conflict in CI. **It never auto-merges**: it opens a PR labeled `needs-review` for a human to check. Resolution runs in a read-only job; a separate clean job publishes the resolved merge from a Git bundle. The agent still needs a provider credential, so use a dedicated key with a low spend limit and keep this workflow disabled unless you accept that the agent process can access that key.

To enable it:

- `gh variable set FORK_AGENT_RESOLVE --body true`
- `gh variable set FORK_AGENT_MODEL --body "<provider/model>"`
- Add the provider's API key as a secret, for example `gh secret set ANTHROPIC_API_KEY`.

### 4.4 `fork-setup-bun/action.yml`

Fork workflows use this action instead of upstream's `.github/actions/setup-bun`, which we do not edit. It installs the same Bun version, but caches the installed `node_modules` trees (`packages/*`, `packages/*/*` and `services/*` workspaces) keyed by `bun.lock`, `patches/**` and the workspace `package.json` files. An exact hit skips `bun install`; a partial hit runs it to complete the tree. With `install: "false"` it only puts Bun on `PATH`. It saves the cache only outside pull requests: `fork-sync` saves it for each merged lockfile, and `fork-ci` does so on pushes to `custom` that change those inputs.

### 4.5 `fork-release.yml`

Builds `opencyber` with upstream's own `packages/cli/script/build.ts` and publishes it to this repository's GitHub Releases (not npm).

- **Version:** `<upstream release>-cyber.<N>`, for example `2.0.18-cyber.1`. The upstream part is the newest `v2.X.Y` tag contained in `custom`; `N` counts our releases on top of it and restarts at 1 with each upstream release. Nobody writes versions by hand. The `-cyber.N` suffix is a SemVer prerelease on purpose: `+cyber.N` build metadata is ignored by npm and most tools, so two fork builds of the same upstream release would look identical. Release tags, service discovery and `parseReleaseVersion` all reject anything that is not plain SemVer, so the machine version stays untouched; human-facing surfaces show the upstream version with ` (Cyber)` appended and the `-cyber.N` prerelease dropped, so `2.0.18-cyber.1` reads as `2.0.18 (Cyber)` (F-005): `--version`, the TUI footer, the update notice and dialog (F-017), and the `opencyber upgrade` output.
- **When:** a push to `custom` publishes when the upstream release it contains has no fork release yet (a merged `fork-sync` PR), or when `packages/`, `patches/`, `bun.lock` or the root `package.json` changed since the last fork release (a merged fork change that affects the binary). Pushes that only touch docs, workflows or the install scripts publish nothing; the install scripts are downloaded from `custom` when used. Running the workflow by hand always publishes the next `N`.
- **Platforms:** Windows x64 and Linux x64, both cross-compiled from one Linux runner as upstream does. Each release has `opencyber-windows-x64.zip`, `opencyber-linux-x64.tar.gz` and `SHA256SUMS`. The binaries are not code-signed.
- **Channel `cyber`:** the build sets `OPENCODE_CHANNEL=cyber`. In V2 the channel selects the background server registration and its port, so `opencyber` gets `service-cyber.json` and its own port. With the official `latest` channel, the fork and the official `opencode` would share one background server and restart it on every version mismatch, and the Claude Pro/Max login (F-002) only works in the fork's server. Everything else is shared with the official install: configuration in `~/.config/opencode`, the database `opencode.db` and the TUI state of the `latest` channel (F-004). Upstream's `latest` and `beta` channels share `opencode.db` the same way; a server ignores migrations newer than its own, which covers the hours between an official release and the fork release that follows it. Service environment variables (`opencyber service set env …`) are still per channel.
- **Updates:** the fork build replaces upstream's updater with `ForkUpdater` (ledger F-003). It asks this repository's GitHub Releases for the latest `-cyber.N` release and installs it by running `script/fork-install.*` from `custom` with `OPENCYBER_VERSION` set. Only the binary in `~/.opencyber/bin` updates itself; `bun run dev` and other copies do not. Every start logs one `opencyber update check` line, and when a newer release exists the TUI announces it with its `/update` notice as `2.0.19 (Cyber)` (F-017) while nothing appears when there is none. Installing is on demand: `/update` → Update in the dialog, or `opencyber upgrade`. The shared config can still ask for `"update": "auto"` (install on start) or `"disable"`, and `OPENCODE_DISABLE_AUTOUPDATE=1` skips the check; the default is `notify`, the same as upstream, so a start never installs on its own.
- **Notes:** the upstream release with a link to its notes, the ledger table from section 7, and the fork-only commits since the previous fork release.
- The build job runs repository code with a read-only token; a separate `publish` job creates the release.

---

## 5. Rules for agents changing the fork

### 5.1 Before changing code: extension hierarchy

Use **the first option that solves the problem**. The further down the list, the higher the maintenance cost.

1. **User configuration** (`~/.config/opencode/`, global `opencode.jsonc`): does not touch the repo.
2. **Project extension points** in new files: plugins, agents, commands, tools, skills, themes and MCP servers under `.opencode/`. **Create new files with a `fork-` prefix** and do not edit the existing ones.
3. **Published or local plugin** using the `@opencode/plugin` API (integration methods, `session.hook(...)` for `context`, `model.request`, `http.request`, `retry` and others): the behavior lives outside the core.
4. **New `fork-` file inside a package** that the core imports from **a single point**, such as the `ProviderPlugins` list in `packages/core/src/plugin/provider.ts`: any possible conflict shrinks to that one line. The Claude Pro/Max login (F-002) is built this way.
5. **Modifying existing upstream code**: last resort. It must be recorded in the ledger (section 7).

Plugin hooks run in registration order, and config and user plugins register after the internal ones. A fork plugin that must see the final request (for example the final system prompt) should work in `http.request` on the wire request rather than in `context`.

### 5.2 If upstream code must change

- **Keep changes minimal and local.** Do not reformat, rename, reorder imports or make drive-by "improvements" to code you don't own.
- **Add rather than modify:** a new `if` branch, a new array entry or a new file is better than rewriting a function.
- Mark the block with a `// fork: <short reason>` comment so it stands out in conflicts.
- **Avoid files that change a lot upstream.** To check: `git log --since="30 days ago" --oneline upstream/v2 -- <file> | wc -l`. If it returns more than 10, look for a different hook point.
- **Do not edit** generated files (`packages/client/src/promise/generated`, `packages/client/src/effect/generated`, `packages/client/src/effect/api`, `*.gen.ts`). Regenerate them instead (see `AGENTS.md`).
- **Avoid** changing migrations or the database schema, and **avoid** adding dependencies to upstream `package.json` files. These are the most expensive conflicts (`bun.lock`). If there is no alternative, record it in the ledger.
- If the change would help anyone, **propose it upstream** (section 9). Once accepted, the fork's diff shrinks.

### 5.3 Workflow

```bash
git fetch origin
git fetch upstream --tags
git checkout -b <short-branch> origin/custom
# ... changes ...
cd packages/<package> && bun typecheck          # never tsc, never from the root
cd packages/<package> && bun test <files>       # tests never run from the root
git commit -m "feat(<scope>): ..."              # conventional commits (AGENTS.md)
git push -u origin <short-branch>
gh pr create --base custom --fill
```

- Feature PRs may be squashed. **Sync PRs may not** (section 1).
- If a PR touches upstream code, **update section 7 in the same PR**.
- If a sync lands on `custom` while your branch is open, run `git merge origin/custom` on your branch. Do not rebase branches that have already been shared.

### 5.4 What an agent NEVER does

- Push or open a PR to `upstream` unless a human explicitly asks.
- Force-push `custom`.
- Rebase `custom`, or integrate a sync PR with squash or rebase.
- Commit directly to `custom` (always go through a PR).
- Merge upstream's `v2` or `dev` branch tip into `custom`; only release tags are merged.
- Re-enable upstream workflows, or edit `.github/workflows/*.yml` files that do not start with `fork-`.
- Delete or disable upstream tests to make CI pass.
- Resolve a conflict by dropping a fork change recorded in section 7 without saying so in the PR.

---

## 6. Conflict resolution procedure (for agents)

Use this when a `fork-sync-conflict` issue exists, when CI fails on a `fork-sync` PR, or when `fork-resolve` runs.

### 6.1 Prepare

```bash
git fetch origin
git fetch upstream --tags
tag=$(git tag -l 'v2.*' | grep -E '^v2\.[0-9]+\.[0-9]+$' | sort -V | tail -1)   # the release named in the issue
git checkout -B sync-upstream origin/custom
git merge --no-ff "$tag" -m "chore(fork): merge upstream $tag"   # rerere reapplies known resolutions
git diff --name-only --diff-filter=U  # remaining conflicts
```

### 6.2 Resolve each file by type

| File type                                                                                                                                                      | Action                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Generated (`packages/client/src/promise/generated`, `packages/client/src/effect/generated`, `packages/client/src/effect/api`, `*.gen.ts`, migration snapshots) | `git checkout --theirs -- <file>`, then regenerate (6.3)                                                                                                                          |
| `bun.lock`                                                                                                                                                     | `git checkout --theirs -- bun.lock`, then `bun install` (reapplies our dependencies, if any) and `git add bun.lock`                                                               |
| `package.json`                                                                                                                                                 | Union: upstream versions plus our entries recorded in section 7                                                                                                                   |
| `.github/workflows/*` that are not `fork-*`                                                                                                                    | `git checkout --theirs -- <file>` (they are disabled; their content doesn't matter)                                                                                               |
| File **recorded in section 7**                                                                                                                                 | Start from the upstream version (`--theirs`) and **reapply the intent** described in the ledger, adapted to the new API. Don't try to keep the old code if upstream refactored it |
| File **not recorded** in section 7                                                                                                                             | We had no intentional change there: `git checkout --theirs -- <file>`                                                                                                             |
| `AGENTS.md`                                                                                                                                                    | Upstream version plus the pointer line as the first line (F-001)                                                                                                                  |
| `FORK.md`, `CLAUDE.md`, `fork-*`                                                                                                                               | Should never conflict. If they do, keep ours (`--ours`)                                                                                                                           |

Notes:

- During a merge into `custom`, `--ours` is the fork and `--theirs` is upstream.
- If upstream **implemented on its own** something the fork carried as a patch, adopt the upstream version and **remove the entry** from the ledger.
- If upstream **deleted** a file we modified (modify/delete conflict), find where the logic moved (`git log --follow --diff-filter=R "$tag" -- <path>`, or `grep` for the symbols) and reapply the intent there.
- A fork-only file can also break without a textual conflict when upstream changes an API it uses. `fork-ci` catches that as a typecheck or test failure on the sync PR; fix it on `sync-upstream` like any other failure.

### 6.3 Regenerate and verify

```bash
bun install
(cd packages/client && bun run generate)
git add -A

# Required checks before committing
git diff --name-only --diff-filter=U        # must be empty
git grep -nE '^(<<<<<<<|>>>>>>>)( |$)' -- . ':!*.md'   # must be empty
(cd packages/core && bun typecheck)         # plus every package touched by the ledger
(cd packages/core && bun test test/plugin/fork-anthropic-oauth.test.ts)
```

### 6.4 Finish

```bash
git commit --no-edit        # keeps the merge message
git push --force origin sync-upstream
gh pr create --base custom --head sync-upstream --title "chore(fork): sync upstream" --label fork-sync \
  --body "Resolves #<issue>. Upstream <tag>. Conflicts: <list>. Ledger changes: <if any>."
gh pr merge sync-upstream --auto --merge
```

- In the PR body, explain how the intent was reapplied for each section 7 file that conflicted.
- Close the `fork-sync-conflict` issue when the PR merges (`Resolves #N` does it automatically).
- If a conflict **cannot be resolved safely** (the ledger intent no longer makes sense with upstream's new architecture), do not guess: comment on the issue with what changed, propose options, and leave the PR as a draft.

---

## 7. Ledger of fork changes to upstream code

> Every change to a file that exists upstream **must** be listed here. This is the source of truth for resolving conflicts: it describes the **intent**, not the lines.
> Fork-only files (`fork-` prefix, `.opencode/**/fork-*`, `FORK.md`, `CLAUDE.md`) do not need entries, but the behavior they carry is described here when an upstream file registers them.

| ID    | Upstream file(s)                                                                    | Intent (what must stay true)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Reason                                                                                                                                 | Propose upstream?                   |
| ----- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| F-001 | `AGENTS.md` (line 1)                                                                | Agents know this is a fork and read `FORK.md` first                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Fork infrastructure                                                                                                                    | No                                  |
| F-002 | `packages/core/src/plugin/provider.ts` (one import and one `ProviderPlugins` entry) | `ForkAnthropicOAuthPlugin` from the fork-only `fork-anthropic-oauth.ts` is registered. It (1) adds a "Claude Pro/Max" OAuth method with refresh to the `anthropic` integration, keeping method ID `claude-pro-max`; (2) with that credential active, rewrites every Anthropic HTTP request so the system field is exactly the Claude Code identity, opencode's system prompt becomes the first user turn, and the Claude Code headers are sent (`anthropic-beta` appended to existing betas, `User-Agent`, `x-app`); (3) stops retries on subscription-window exhaustion; (4) makes concurrent refreshes of one rotating refresh token share a single token request. API-key auth and other providers are untouched. Upstream already sends OAuth credentials to Anthropic as a bearer token | Claude Pro/Max login; Anthropic rejects consumer OAuth requests that do not look like Claude Code, and rejects replayed refresh tokens | No (upstream removed it on purpose) |
| F-003 | `packages/cli/src/index.ts` (the `Updater` import and its `Effect.provide` line)    | The CLI provides `ForkUpdater.layer` from the fork-only `fork-updater.ts` instead of upstream's `Updater.layer`, keeping the `Updater.Service` interface. It (1) treats `~/.opencyber/bin/opencyber[.exe]` as the only updatable install (method `curl`); (2) reads the latest release from this repository's GitHub Releases; (3) upgrades by running `script/fork-install.*` from `custom` with `OPENCYBER_VERSION`; (4) defaults the update policy to `notify`, so a start only announces a new release through the TUI's `/update` notice, while still honoring `update`/`autoupdate` in the shared config (`auto` installs on start, `disable` skips the check) and `OPENCODE_DISABLE_AUTOUPDATE`. Upstream's `updater.ts` stays untouched                                                                                                                                                                                         | Upstream's updater only knows the official installer, npm-style managers and Homebrew, and checks opencode.ai for versions             | No                                  |
| F-004 | `packages/cli/src/index.ts` (one side-effect import of `./fork-shared-state`)       | In the published `cyber` build, `fork-shared-state.ts` defaults `OPENCODE_DISABLE_CHANNEL_DB=1` and `OPENCODE_TUI_CHANNEL=latest` before anything reads them, so `opencyber` uses the official install's `opencode.db` and TUI state while keeping its own background server (`service-cyber.json`, own port). Source runs (channel `local`) and explicit environment values are unaffected                                                                                                                                                                                                                                                                                                                                                                                                  | The fork should see the same sessions, logins, API keys and recent models as the official `opencode`                                   | No                                  |
| F-005 | `packages/cli/src`, `packages/cli/test/mini-host.test.ts` and `packages/cli/test/upgrade.test.ts`                        | The human-facing surfaces read `OPENCODE_DISPLAY_VERSION` from the fork-only `fork-version.ts`, which is the build version without its `-cyber.N` prerelease plus ` (Cyber)`: `src/index.ts` passes it to `Runtime.run` so `--version` prints it, `src/commands/handlers/default.ts` hands it to the TUI as `app.version` and attaches `displayVersion(...)` as `display` to every update notice, installing progress and `check` result it forwards, `src/commands/handlers/upgrade.ts` prints its `From … → …` and skipped lines in that form, `src/mini-host.ts` sets the mini host `version`, and `test/mini-host.test.ts` and `test/upgrade.test.ts` assert it. The TUI renders `display ?? version` (F-017). The build version in `version.ts`, service discovery, observability and the updater keep the plain SemVer value                                                                                                                                                                                                                                                         | Show the fork's name without breaking release tags, service discovery or `parseReleaseVersion`, which need plain SemVer                | No                                  |
| F-011 | `packages/theme/src/tui`, `packages/tui/src/component/logo.tsx`                     | The home screen shows the `opencyber` wordmark. `packages/theme/src/tui/schema.ts` declares the optional `text.brand` definition, `expand.ts` defaults it to `{ base: "$text.feedback.error.base" }` so every theme gets its own red, and `types.ts` exposes `text.brand.base: RGBA`. `component/logo.tsx` reads its glyphs from the fork-only `packages/tui/src/fork-logo.ts`, draws the right block in `theme.text.brand.base` instead of `theme.text.base` so "cyber" takes the theme red while "open" stays muted, and widens the layout thresholds from 22/44 to 27/49 for the 44-column wordmark (19 + gap + 24). What must stay true: `text.brand.base` resolves for every theme, the three width branches still fit, and upstream `logo.ts` and `routes/home.tsx` stay untouched.    | Fork identity: the TUI shows the fork's name, with the red taken from the active theme instead of a hard-coded color                   | No                                  |
| F-012 | `.gitignore` (three lines under "Local dev files")                                   | `reports/` and `research_notes/` stay untracked. What must stay true: they never appear in `git status`, so `git add -A` cannot stage them, and the two entries stay grouped under the `# fork: local research never leaves the machine (F-012)` comment so an upstream merge conflict can be resolved by keeping both blocks. No other ignore rule changes, and the files remain readable on disk                                                                                  | Local research and client-facing engagement material must not reach the public repository, including through an accidental bulk add   | No                                  |
| F-013 | `packages/core/src/plugin/internal.ts` | Register the fork-owned `ForkCyberPlugin.Plugin` once in the built-in list so engagement tools and phase agents are available in every Location, including projects outside the source checkout. The project-local loader is removed. Scope is structured operator data with host/CIDR/rate validation; tools and context share parent resolution; children cannot mutate scope. No automatic scope extraction, refusal re-anchoring or cyber HTTP wire rewrite remains. | Ship the cyber foundation without project-relative source imports | No |
| F-014 | `packages/core/test/location-layer.test.ts` | Exclude the fork's native cyber tools, including `cyber_tasks`, `cyber_coverage`, `cyber_code_review`, `cyber_services` and `cyber_surface`, from the upstream-only tool-list expectation; their presence and permissions are exercised by the fork integration suite. Provider-isolation checks remain intact. | Built-in cyber tools intentionally extend the upstream registry | No |
| F-015 | `packages/core/package.json`, `bun.lock` | Add pinned `playwright-core` 1.59.1 for the optional fork-owned browser manager. Load it lazily; use an operator-installed Chromium executable and isolated contexts rather than the desktop user's profile. | Existing desktop browser integration cannot provide independent headless assessment identities | No |
| F-016 | `packages/cli/script/build.ts` | Externalize `chromium-bidi/*`, Playwright's absent optional BiDi backend, while bundling the Chromium CDP implementation. The fork only launches Chromium through CDP. Preserve the compiled browser capture smoke test. | Bun otherwise tries to resolve unused optional BiDi modules and fails the binary build | No |
| F-017 | `packages/tui/src/context/update-notification.tsx`, `packages/tui/src/routes/home.tsx`, `packages/tui/src/component/dialog-update.tsx`, `packages/tui/test/fixture/app.ts` | The update notice and dialog show the human-facing release while keeping the machine one: `ClientNotice` and the `installing` state carry an optional `display`, home renders `display ?? version` in ` to install v…` / ` restart to use v…`, and the dialog renders `Installing OpenCode ${display ?? version}…`. `version` is untouched, so the dismissal history still keys on it and `apply` still receives it; the CLI attaches `display` (F-005). `test/fixture/app.ts` accepts an `updater` injection so the fork test drives the notice with a fake `UpdateSource`. What must stay true: `2.0.19-cyber.2` never reaches a human-facing surface, and a notice without `display` still renders `version` | Releases must read `2.0.19 (Cyber)` in the TUI while the updater, dismissal history and `parseReleaseVersion` keep plain SemVer | No |
| F-018 | `packages/tui/test/command-selection.test.tsx` | Wait for the variant dialog's filter to own focus before typing. Preserve the assertions for captured selection, server mutation order and session creation retries. Upstream v2.0.22 now supplies and disposes the temporary app-fixture state directory, so that part of the fork patch is retired. | A rendered dialog can precede its deferred focus | Yes |
| F-019 | `packages/core/src/instance.ts`, `packages/core/src/plugin/internal.ts`, `packages/core/src/file-access.ts`, `packages/core/src/tool/plugin/read.ts`, `packages/core/src/tool/plugin/glob.ts`, `packages/core/src/tool/plugin/grep.ts` | Select the fork-owned process policy before Location configuration and plugin startup. Hardened modes disable target discovery while retaining operator configuration, bind the policy into internal plugins, prevent configuration from removing cyber enforcement, and keep nested target AGENTS.md reads as file data. Canonical source roots reject external files and escaping symlinks before hardened read/glob/grep access; native tools preserve typed diagnostics. Ordinary development and vanilla discovery semantics remain available. | Reviewing third-party source must not execute its extensions, adopt its instructions or expose unrelated private files; assessment policy must apply to the primary and descendants | No |
| F-020 | `packages/core/src/codemode/tool.ts`, `packages/core/src/codemode/instructions.ts`, `packages/core/test/mcp.test.ts` | Derive a canonical child CallID from the execute container and invocation index before permissions, hooks and execution. Keep native tools callable directly, and explain the actual execute inventory. Capture children independently without relaxing unique execution identities. MCP permission tests retain their full assertions using the child CallID. | Repeated and concurrent nested calls must not collide, and the native catalog must describe usable invocation paths | Yes |
| F-021 | `packages/core/src/session/context.ts` | Compose the fork-owned notes Instructions source explicitly with the runner's existing sources. InstructionState retains version, epoch, fork and compaction ownership; unchanged notes do not become repeated User messages. | Durable notes are untrusted observations whose changes belong in the existing Instructions algebra | No |
| F-022 | `packages/core/src/session/runner/step.ts`, `packages/core/src/session/runner/llm.ts`, `packages/core/test/session-step.test.ts` | Bind the optional fork-owned request trace and pass the logical step to each physical attempt. Store redacted effective request snapshots, outcomes and reported usage separately from Session events. Preserve exactly one llm.stream call per attempt and the existing retry/continuation semantics. The step fixture exercises the real trace and storage. | Analysis exports need reconstructable settings and physical attempts without inventing usage or changing orchestration | No |
| F-023 | `packages/schema/src/session-transfer.ts`, `packages/protocol/src/groups/session.ts`, `packages/server/src/handlers/session.ts`, `packages/core/src/session/transfer.ts`, `packages/core/test/session-create.test.ts`, `packages/cli/src/commands/commands.ts`, `packages/cli/src/commands/handlers/session/export.ts`, `packages/cli/test/import-export.test.ts`, `packages/tui/src/ui/dialog-export-options.tsx`, `packages/tui/src/routes/session/index.tsx`, `packages/client/src/promise/generated`, `packages/client/src/effect/generated`, `packages/client/src/effect/api` | Add compatible redacted, private, sanitized and analysis export profiles, reasoning selection, descendant traces, activity and partial metadata. CLI and TUI default to redacted exports and pass the same options for JSON, Markdown and clipboard. Fix error sanitization and reuse the fork-owned formatter, removing unused upstream transcript imports. Regenerate client outputs from the public contract; generated files require ledger coverage but no hand-written fork markers. | Export privacy and technical completeness must be consistent across all product surfaces and include active/omitted work explicitly | No |
| F-024 | `packages/core/test/git.test.ts` | Run the invalid-config check-ignore control without a stdin pipe. Keep the exit-128 assertion, refresh error checks and tree-integrity assertions. | Git can exit before Bun's shell writer reads even an empty file, causing an unrelated EPIPE in the fixture | Yes |
| F-025 | `packages/core/src/plugin/tool-input-repair.ts` | Use the fork-owned literal discriminator selector for root and nested object unions before applying existing field repairs. Select only a unique branch using a required const/enum field shared by every alternative; preserve ambiguous or unsupported schemas and validate against the original input schema. | Native cyber task actions use a root union, so string revisions otherwise bypass numeric repair and claims fail before execution | Yes |
| F-026 | `packages/core/src/tool.ts` | Run the existing execute.after hook when a tool is interrupted, with error status and explicit interruption metadata. Preserve the interruption cause. The fork records a terminal audit result with unknown effects for native delegations and nested Code Mode calls. | Foreground delegation cancellation otherwise leaves execution evidence permanently running and can be misreported as provider failure | Yes |

The `ledger` job of fork CI (4.2) runs this check on every PR, and `bun script/fork-ledger-check.ts` runs it locally: it fails when an upstream file the fork modifies has no row below, when a fork-modified nongenerated code file carries no `// fork:` marker, or when a marker references an id this section does not define. Generated client files require ledger coverage and API regeneration. Use `bun script/fork-ledger-check.ts --worktree` to include tracked uncommitted changes. The underlying diff (fork-only files excluded):

```bash
tag=$(git tag -l 'v2.*' | grep -E '^v2\.[0-9]+\.[0-9]+$' | sort -V | tail -1)
git diff --name-only "$tag"...custom
```

This includes modified, added and deleted paths. Every upstream file in that list must appear in the table.

### Retired entries

Entries from the V1 era, kept so their IDs are not reused:

| ID                 | What it was                                                                                       | Why it is gone                                                                                                                                                            |
| ------------------ | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F-002 (V1) … F-005 | Claude Pro/Max login in `packages/opencode`, provider picker hints and `providers.mdx` docs       | `packages/opencode` does not exist in V2. The V2 pickers list integration methods by label, and the fork does not publish the docs site. The login lives in the new F-002 |
| F-006              | Terminal subscription-window exhaustion in `packages/opencode/src/session/retry.ts`               | Moved into the F-002 plugin as a `retry` hook. Upstream V2 also classifies "usage limit" 429s as quota errors and caps Retry-After at 15 minutes                          |
| F-007              | TUI display for the `TodoWrite` wire alias                                                        | V2 has no `todowrite` tool                                                                                                                                                |
| F-008              | Anthropic OAuth in the V2 runner (`model.ts`, `llm.ts`, `compaction.ts`, provider `anthropic.ts`) | Upstream's runner was rewritten and now sends OAuth as a bearer token. The rest is done by the F-002 plugin through hooks, with no edits to upstream files                |
| F-009              | Refresh lock in `packages/core/src/integration.ts`                                                | Replaced by refresh sharing inside the F-002 plugin                                                                                                                       |
| F-010              | Spy cleanup in `packages/opencode/test/cli/tui/editor-context.test.tsx`                           | File does not exist in V2                                                                                                                                                 |

---

## 8. Known exceptions

Upstream tests or checks that fail in `fork-ci` because of the environment, not because of our changes. Review them from time to time in case upstream has fixed them.

| Test / check | Reason | Since |
| ------------ | ------ | ----- |
| _(none)_     |        |       |

---

## 9. Contributing upstream

Best for generic improvements: every change upstream accepts is one less to maintain.

```bash
git fetch upstream
git checkout -b <short-branch> upstream/v2         # from upstream, NOT from custom
git cherry-pick <commits>                          # or redo the change cleanly
# Option A: git push origin <short-branch> && gh pr create --repo anomalyco/opencode --base v2
# Option B: push to a separate public fork
```

- Follow `AGENTS.md` to the letter: conventional commits and the project's style.
- Once upstream accepts it and it ships in a release, the next sync brings it in. At that point **remove the entry** from section 7 and, if it conflicts, keep the upstream version.

---

## 10. Using the fork build

Install or update the latest release (4.5) into `~/.opencyber/bin`, which the script adds to `PATH`:

```powershell
irm https://raw.githubusercontent.com/nilparra-dev/opencyber/custom/script/fork-install.ps1 | iex   # Windows x64
```

```bash
curl -fsSL https://raw.githubusercontent.com/nilparra-dev/opencyber/custom/script/fork-install.sh | bash   # Linux x64
```

After that it checks this repository's releases when it starts and shows the `/update` notice when a newer one exists; installing is on demand through that notice or with `opencyber upgrade` (4.5). Set `OPENCYBER_VERSION=2.0.18-cyber.1` to install a specific release. The binary is named `opencyber`, so it lives next to the official `opencode`; its help text still says `opencode` because the name comes from upstream's build script.

From source:

```bash
bun install
bun run dev                                            # development, from the root (runs packages/cli)
cd packages/cli && OPENCODE_CHANNEL=cyber bun run build --single   # current platform only → packages/cli/dist/<platform>/bin/
```

---

## 11. Quick troubleshooting

| Symptom                                                                              | Likely cause                                                              | Fix                                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fork-sync` fails at checkout or push with 401/403                                   | `FORK_SYNC_TOKEN` expired or missing permissions                          | Regenerate the token (2.4)                                                                                                                                                                          |
| `refusing to allow ... workflow ... without workflows permission`                    | Token lacks the _Workflows_ permission                                    | Add _Workflows: write_                                                                                                                                                                              |
| `fork-sync` fails with "no upstream release tag matches"                             | Upstream changed its tag scheme or moved to a new major line              | Update `UPSTREAM_TAG_PATTERN` in `fork-sync.yml` and `fork-resolve.yml`                                                                                                                             |
| The `fork-sync` PR doesn't run `fork-ci`                                             | PR was created with `GITHUB_TOKEN`                                        | Use `FORK_SYNC_TOKEN` for `gh`                                                                                                                                                                      |
| Jobs stuck in the queue waiting for a `blacksmith-*` runner                          | An upstream workflow is active                                            | Run the command from 2.6                                                                                                                                                                            |
| The same conflicts come back on every sync                                           | A sync PR was squashed or rebased                                         | Merge the upstream tag into `custom` again with a merge commit; never squash                                                                                                                        |
| Auto-merge doesn't turn on                                                           | Auto-merge disabled or no required checks                                 | Section 2.5                                                                                                                                                                                         |
| `check:generated` fails                                                              | The client was not regenerated after the merge                            | `cd packages/client && bun run generate`                                                                                                                                                            |
| The `pre-push` hook fails on the Bun version                                         | Local Bun differs from `packageManager`                                   | Install the version in `package.json` → `packageManager`                                                                                                                                            |
| A green sync PR does not auto-merge                                                  | `custom` advanced and the PR is out of date                               | The next hourly `fork-sync` merges `custom` into it; or run it by hand                                                                                                                              |
| Claude Pro/Max requests fail with 401/429 after moving from V1                       | The V1 login was imported without refresh                                 | Log in again and pick "Claude Pro/Max" (section 1)                                                                                                                                                  |
| GitHub says "N commits ahead/behind anomalyco/opencode:dev" and offers **Sync fork** | GitHub compares with upstream's default branch, which is still `dev` (V1) | Ignore the counter and **never press Sync fork**: it would merge V1 into `custom`. Compare with the release instead: `https://github.com/nilparra-dev/opencyber/compare/<latest v2 tag>...custom`   |
| `fork-release` did not publish after a push                                          | That upstream release already has a fork release                          | Expected; run `fork-release` by hand to publish the next `-cyber.N`                                                                                                                                 |
| `opencyber` does not see the sessions or logins of `opencode`                        | A build older than F-004, or `OPENCODE_DB` / `OPENCODE_TUI_CHANNEL` set   | Update (`opencyber upgrade`) or unset those variables                                                                                                                                               |
