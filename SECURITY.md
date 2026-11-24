# Security

OpenCyber runs tools, starts processes and sends traffic. Treat it as production software with the permissions you grant it, not as a sandbox.

## Authorized use

OpenCyber exists for authorized security testing. Running it against a system without permission is out of scope here and may be illegal. The [authorized use policy](https://opencyber.tech/authorized-use) governs use of the project and the hosted website.

## Threat model

### The agent is not sandboxed

The permission system is a UX control: it asks before actions, and the operator can deny them. It is not an isolation boundary. An approved shell command, plugin, MCP server or Kali job runs with the permissions of the OpenCyber process.

If you need isolation, run OpenCyber in a VM or container, or use the `review` and `assessment` profiles. Those profiles disable target configuration, target plugins, MCP servers, agent discovery and instruction discovery before the Location starts. They still run as your operating-system user; they are a policy boundary, not a process sandbox.

### Kali and browser isolation are bounded

Kali jobs run in a fresh container with explicit inputs, outputs and network policy. Docker is the boundary; a container escape or kernel bug is outside the assessment design. The browser manager launches a separate Chromium process with one context per identity and never uses your everyday browser profile. WebSockets, service workers, downloads and popups are not covered capture paths.

### Evidence and credentials are sensitive

Executions and artifacts are stored in a local SQLite archive under the OpenCyber data directory. Reports and exports can contain target data, cookies, tokens and personal information. Protect the data directory and review exports before sharing them.

Credentials are entered by the operator and released to one execution when the approved engagement declares the label for that action and target. They are not part of the model's tool input. A misconfigured manifest or an over-broad label can still expose a credential to a tool: review rules of engagement before approving them.

### Model providers see what the model sees

Prompts, tool output and selected evidence are sent to the model provider you configure. That provider's retention and privacy policy applies. OpenCyber does not add a separate data-processing layer.

### Server mode

The local server is opt-in. Set `OPENCODE_SERVER_PASSWORD` to require HTTP Basic Auth. Without it, the server runs unauthenticated with a warning. Securing the network path to that server is the operator's responsibility.

### Out of scope

| Category | Rationale |
| --- | --- |
| Using OpenCyber without authorization | The project's purpose is authorized testing; misuse is not a vulnerability |
| Server access when you enable server mode without authentication | Expected behavior, documented above |
| Permission-system bypass with an approval you granted | The permission system is not a sandbox |
| LLM provider data handling | Governed by the provider you choose |
| MCP servers, plugins and configuration you install | Outside the project's trust boundary |
| Docker, Chromium or target-side compromise | Depends on the operator's environment and the target |

## Reporting a vulnerability

Report privately through the repository's [GitHub Security Advisory](https://github.com/nilparra-dev/opencyber/security/advisories/new) tab. Do not open a public issue, and do not test against systems you do not own.

Include:

- The OpenCyber version from `opencyber --version`.
- The mode or profile in use.
- A minimal reproduction with the exact configuration, command or request.
- The impact and what an attacker could do.

Reports without a concrete reproduction may be closed. The maintainer will acknowledge a valid report, agree on a disclosure timeline and credit the reporter unless asked otherwise.

If the issue is inherited from upstream opencode rather than introduced by the fork, report it to [anomalyco/opencode](https://github.com/anomalyco/opencode/security/advisories/new) as well.

## Supported versions

Security fixes target the latest OpenCyber release on the `custom` branch. Older `-cyber.N` builds are not maintained separately.
