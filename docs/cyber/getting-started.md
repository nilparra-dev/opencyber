# Getting started

This guide takes you from a fresh install to a first scoped assessment of a local lab. It assumes you are authorized to test the target. OpenCyber records scope and enforces it, but it cannot check that the authorization behind it is real.

## Requirements

- Windows x64 or Linux x64 for the released binary.
- A model provider account. Any provider OpenCode supports works, and Anthropic also accepts a Claude Pro/Max login.
- For the operator scripts used below: a clone of this repository and [Bun](https://bun.sh) at the version in `package.json` (`packageManager`).
- Optional: Docker with Linux containers for Kali jobs, and a Chromium executable for browser identities.

## Install

Windows:

```powershell
irm https://raw.githubusercontent.com/nilparra-dev/opencyber/custom/script/fork-install.ps1 | iex
```

Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/nilparra-dev/opencyber/custom/script/fork-install.sh | bash
```

The script installs `opencyber` into `~/.opencyber/bin` and adds it to `PATH`. Set `OPENCYBER_VERSION` (for example `2.2.7-cyber.1`) to pin a release. The binary checks this repository's releases on start and shows an `/update` notice when there is a newer one. It never installs on its own. Run `opencyber upgrade` or use the notice to update.

## Pick a profile and a mode

By default `opencyber` shares the official `opencode` install's sessions, logins and configuration, and starts in `development` mode. That is fine for labs and for coding. For anything with client data, start an isolated profile in `assessment` mode. From the repository root:

```powershell
bun script/fork-cyber-profile.ts --assessment C:/labs/acme -- opencyber
```

```bash
bun script/fork-cyber-profile.ts --assessment /srv/labs/acme -- opencyber
```

The profile directory must be absolute. The launcher gives the process its own data, configuration, cache, state, database and temporary paths, and sets `OPENCYBER_MODE` before anything loads. Use the same command prefix for every later command against that profile (`opencyber service stop`, `opencyber session export ...`) so it finds the right background service.

| Mode          | What it allows                                                                                              |
| ------------- | ----------------------------------------------------------------------------------------------------------- |
| `development` | Ordinary OpenCode access plus the cyber tools up to R1. The model can write scope                           |
| `review`      | Source and evidence inspection and code review (R0). Target extensions and instructions are data            |
| `assessment`  | Scoped HTTP, browser, Kali and surface tools up to R2. Scope changes become proposals the operator approves |

A new profile has no logins. Authenticate inside it the first time (`/connect` in the TUI). If you use Anthropic with a subscription, choose "Claude Pro/Max".

## Check the setup

Diagnose the profile before touching a target. These commands only read and write the profile's configuration:

```powershell
bun packages/core/script/fork-cyber-setup.ts --profile C:/labs/acme
bun packages/core/script/fork-cyber-setup.ts --profile C:/labs/acme --runtime
```

`--runtime` also inspects Docker, the pinned image and the network with read-only commands. Inside a session, the model can call `cyber_capabilities` for the same diagnosis plus what each role is allowed to call. A valid configuration is not proof that a backend starts, only that it is set up.

## Record the scope

The agent works only against an explicit engagement. Write the manifest yourself, with real values:

```jsonc
{
  "engagement": "local-api-lab",
  "authorized_by": "operator",
  "authorization_ref": "local-lab-plan",
  "scope": {
    "domains": ["localhost", "127.0.0.1", "::1"],
    "cidrs": [],
    "excluded": [],
  },
  "rules_of_engagement": {
    "no_dos": true,
    "max_rps": 2,
    "window": "local lab session",
    "contact": "operator",
  },
}
```

In an assessment profile, save it as `config/opencode/cyber/scope.jsonc` inside the profile directory. Files under the target's own `.opencode/cyber` are treated as data in hardened modes, so they cannot grant scope.

To approve a scope for one session instead, save the manifest as JSON outside the target and run this from your terminal. The last argument is the expected current revision, `0` for a new record:

```powershell
bun packages/core/script/fork-cyber-authorize.ts C:/labs/acme ses_example C:/labs/scope.json 0
```

The model cannot run this command. For a single web service, `packages/core/script/fork-cyber-web-scope.ts` writes a service-only proposal from a URL. The scope fields (typed targets, services, S3 resources and exclusions) are described in the [plan](plan.md#phase-1-usage-and-migration).

## Optional backends

- **Kali jobs.** Build the image with `docker build --tag opencyber-kali:6 fork-kali`, then point `opencyber-kali.jsonc` in the profile's configuration at the image ID. `kali_run` only accepts allowlisted binaries. See the [Kali guide](kali.md) and the [network controls](network.md).
- **Browser identities.** Register a Chromium executable with `fork-cyber-setup.ts --chromium <path>`. See the [browser guide](browser.md).

Code review, offline artifact analysis and the HTTP tools work without Docker.

## Run an assessment

Start the TUI in your profile and describe the work in plain language. The primary agent reads the engagement, plans tasks with `cyber_tasks`, and delegates to phase agents. Delegation is manual by default: you approve each subagent call, or switch with `/subagents automatic`.

Every tool call is checked against mode, role, risk and scope before it runs, and the decision is logged. Evidence lands in the profile's `evidence.sqlite`. A finding can only be confirmed after a `cyber-validate` task reproduces it. `cyber_report` gives the counts and pending coverage for the final report.

## Export and clean up

```powershell
bun script/fork-cyber-profile.ts --assessment C:/labs/acme -- opencyber session export <session-id> --standalone --profile analysis --reasoning=false
```

Exports are `redacted` by default. Use `private` for the original transcript or `analysis` for a technical trace with requests and evidence references. Stop the profile's service before you back up or purge its evidence. The [storage guide](storage.md) covers export, archive and purge.

## Next steps

- [Tool reference](tools.md) for what each tool does and its risk class.
- [Architecture](architecture.md) for how the policy, backends and data fit together.
- The [module guides](README.md#guides) for each target type.
