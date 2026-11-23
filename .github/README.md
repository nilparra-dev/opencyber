# OpenCyber

OpenCyber is an AI agent for authorized security assessments. It runs in the terminal, works against an explicit scope you record, and keeps a durable record of what was tested, how each finding was validated, and what was left unexamined.

It is a fork of [OpenCode](https://github.com/anomalyco/opencode) V2. The assessment layer is a built-in plugin, so sessions, models, permissions and the TUI work as they do upstream.

> [!IMPORTANT]
> Use OpenCyber only against systems you are authorized to test. It enforces the scope you give it, but it cannot verify that the authorization is real.

## What it does

- **Scope is data, not prose.** The engagement manifest lists hosts, networks, services and cloud resources with exclusions and rate limits. The agent cannot widen it from a URL in a prompt, and in assessment mode scope changes are proposals you approve from your terminal.
- **Every call is decided before it runs.** Mode, role, risk class and scope are checked first, and the allow or deny decision goes to an append-only log. A denied call sends no traffic.
- **Intrusive actions need your approval.** R2 validation only runs in assessment mode, for actions the engagement declares, after you approve that action on that target. The approval lasts ten minutes.
- **Evidence is kept exactly.** Requests, responses, command output and files are stored with SHA-256 hashes. The model sees redacted previews and artifact IDs.
- **Findings need reproduction.** A finding is confirmed only after a validation agent reproduces it with method, expected and observed results, impact and remediation.
- **Phase agents with their own lanes.** Recon, enumeration, web and network exploitation, validation, code review and reporting each get a fixed tool set and risk ceiling.

The 31 tools cover HTTP and web validation, DNS and discovery, TCP services, TLS and SSH, Linux hosts, LDAP and Active Directory, databases, AWS and Kubernetes configuration, containers, binaries and firmware, and source code review. Network tools run in an optional Kali container with an allowlist and network controls, and browser work runs in isolated Chromium identities. See the [tool reference](../docs/tools.md).

## Install

Windows x64:

```powershell
irm https://raw.githubusercontent.com/nilparra-dev/opencyber/custom/script/fork-install.ps1 | iex
```

Linux x64:

```bash
curl -fsSL https://raw.githubusercontent.com/nilparra-dev/opencyber/custom/script/fork-install.sh | bash
```

This installs `opencyber` into `~/.opencyber/bin`. It sits next to an official `opencode` install without replacing it. Releases are on the [releases page](https://github.com/nilparra-dev/opencyber/releases), versioned as `<upstream release>-cyber.<N>`.

## Quick start

Start an isolated profile in assessment mode from a clone of this repository:

```bash
bun install
bun script/fork-cyber-profile.ts --assessment /srv/labs/acme -- opencyber
```

Log in to a model provider, record the engagement scope, and describe the work. The [getting started guide](../docs/getting-started.md) walks through each step, including the optional Kali and Chromium backends.

## Documentation

- [Getting started](../docs/getting-started.md): install, profiles, modes, scope and exports.
- [Architecture](../docs/architecture.md): how the policy, backends and data fit together.
- [Tool reference](../docs/tools.md): every tool with its risk class.
- [All guides and design records](../docs/README.md).
- [`FORK.md`](../FORK.md): how the fork follows upstream releases, the ledger of upstream changes, CI and releases.

## Build from source

```bash
bun install
bun run dev                                                     # run from source
cd packages/cli && OPENCODE_CHANNEL=cyber bun run build --single  # binary in packages/cli/dist/<platform>/bin/
```

Work happens on branches off `custom` and comes back through pull requests. Read [`FORK.md`](../FORK.md) before changing anything: it explains how to keep the diff against upstream small so the hourly sync keeps working.

## Relationship to OpenCode

OpenCyber follows upstream's stable V2 release tags and merges each new release automatically. It is not built by the OpenCode team and is not affiliated with them. Bugs in OpenCyber's assessment layer belong in this repository's issues, not upstream.

## License

MIT, like upstream. See [LICENSE](../LICENSE).
