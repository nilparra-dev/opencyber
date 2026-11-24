# Contributing to OpenCyber

OpenCyber is a fork of [opencode](https://github.com/anomalyco/opencode). Read [FORK.md](FORK.md) first: it defines the branch model, the upstream sync, the ledger of every change to upstream code, and the conflict procedure. [AGENTS.md](AGENTS.md) defines the code style and the checks.

## Before you change anything

Use the first option that solves the problem:

1. **Configuration** in `~/.config/opencode/` or a project's `.opencode/`.
2. **A new fork-owned file** under `.opencode/` with a `fork-` prefix: plugins, agents, commands, tools, skills, themes or MCP servers.
3. **A plugin** using the `@opencode/plugin` API.
4. **A new `fork-` file inside a package**, imported from a single point.
5. **Editing upstream code**, as a last resort. Record it in `FORK.md` section 7 in the same pull request.

Keep the diff against upstream small. Do not reformat or rename code you do not own, and do not edit generated client files by hand.

## Workflow

```bash
git fetch origin
git checkout -b <short-branch> origin/custom
bun install
# ... changes ...
```

- Branch names are at most three words separated by hyphens, with no type prefix or slash: `scan-timeout`, `browser-restore`.
- Commit messages and pull request titles use `type(scope): summary`, with `feat`, `fix`, `docs`, `chore`, `refactor` or `test`. Example: `fix(core): reject excluded hosts before storage`.
- Open the pull request against `custom`. Feature pull requests may be squashed.
- Sync pull requests (`sync-upstream → custom`) are integrated with a merge commit, never with squash or rebase.
- If an upstream file changed, add or update its section 7 entry and run `bun script/fork-ledger-check.ts --worktree`.
- If upstream adds something the fork already carried, adopt the upstream version and remove the old ledger entry.

## Development

OpenCyber requires the Bun version in `package.json` or newer. From the repository root:

```bash
bun install
bun run dev          # TUI and CLI from source
bun run dev:live     # development TUI against the installed service and live sessions
```

The main packages are `core` (domain and persistence), `cli` (entrypoint and service lifecycle), `tui` (terminal interface), `server`, `protocol`, `schema`, `client` (generated), `app` and `desktop`. Follow the `AGENTS.md` next to the package you touch.

## Checks

Run tests from the package directory, never from the repository root:

```bash
cd packages/core && bun typecheck && bun test test/plugin/fork-cyber-http.test.ts
```

Run the full repository check before opening a pull request:

```bash
bun run check
cd packages/client && bun run generate   # only after a public Protocol or Server HttpApi change
```

Fork CI runs typechecks, unit tests, the ledger check and the optional Cyber labs. Fix failures on the branch; do not disable upstream tests.

## Adding cyber capabilities

- A new surface module goes in `packages/core/src/fork-cyber/`, registers through `packages/core/src/plugin/fork-cyber.ts`, and ships with unit tests plus real or laboratory controls.
- Every tool declares its target types, risk class, phase and evidence. Scope, rate limits and approvals are enforced in the harness, never in the prompt.
- Add a `fork-cyber-*.md` guide with the verified workflow and its limits, then link it from `README.md`.
- A capability is not supported until it has a reproducible workflow and evidence. An installed tool is not a capability claim.

## Public face

The README, contribution guide, security policy and GitHub templates are fork-owned. Keep them describing OpenCyber, not upstream. Attribution to opencode belongs in the README and the license, not in the product name.

## Upstream contributions

Generic improvements are welcome upstream. Branch from upstream's `v2`, not from `custom`, and follow upstream's `AGENTS.md`. See [FORK.md section 9](FORK.md#9-contributing-upstream).

## Security

Do not report vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the MIT license in [LICENSE](LICENSE).
