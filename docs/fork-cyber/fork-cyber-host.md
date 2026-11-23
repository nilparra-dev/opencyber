# Host assessment: `cyber_host` and the Linux host laboratory

Status: `audit` and `privesc_config` are implemented and tested against the Linux laboratory. `patch_inventory` is not implemented. The Windows directory and the VM tier are not built. Work items: OC-301 (Linux half) and OC-302. Rules and the wider catalog are in [fork-cyber-toolset.md](fork-cyber-toolset.md); the brokering design is in [fork-cyber-credentials.md](fork-cyber-credentials.md).

## What the tool does

`cyber_host` runs fixed, read-only commands on one Linux host over SSH, using a host login that the operator registered and the engagement declared. The model supplies a host, an optional port, and a credential label. It never supplies a key, an account, or a command.

| Action           | Risk | Phase                          | What it reports                                                 |
| ---------------- | ---- | ------------------------------ | --------------------------------------------------------------- |
| `procedures`     | R0   | any phase with the tool        | The procedure, the checks, the conditions and the limits        |
| `audit`          | R1   | `cyber-enum`, `cyber-validate` | Six configuration checks: pass, fail or unknown                 |
| `privesc_config` | R1   | `cyber-enum`, `cyber-validate` | Four privilege-escalation conditions: present, clear or unknown |

Example call: `{"action":"audit","host":"127.0.0.1","port":2201,"label":"lab-audit"}`.

`patch_inventory` (R0) is not in the input schema, so the model cannot call it. It needs the pinned advisory module, which this workload does not contain.

### Gates, in order

1. Role and mode: `ForkCyberRoles` and `ForkCyberPolicy` allow the tool for the phase. Recon, exploitation and reporting phases do not receive it.
2. Risk: `ForkCyberDecision` declares both actions R1. `review` mode permits R0 only, so it refuses both.
3. Engagement: the approved revision must be valid and not derived.
4. Scope: `ForkCyberScope.authorize` checks the host and the port. A host entry authorizes every port; a `services` entry authorizes one port.
5. Lease: `ForkCyberCredentialLease` checks that the approved revision declares the label for `cyber_host.<action>` and this host, that the label is registered, unexpired and unrevoked, and that the key opens. Every outcome is recorded.

A refusal at gates 1 to 5 produces no SSH process. The unit tests check this with a real loopback listener that counts connections.

### Declaration

The approved engagement declares the login and the port:

```json
{
  "scope": {
    "domains": [],
    "cidrs": [],
    "excluded": [],
    "services": [{ "target": "127.0.0.1", "protocol": "tcp", "ports": [2201] }]
  },
  "rules_of_engagement": {
    "credentials": [
      {
        "label": "lab-audit",
        "kind": "host_login",
        "read_only": true,
        "account": "audit",
        "targets": [{ "type": "host", "value": "127.0.0.1" }],
        "actions": ["cyber_host.audit", "cyber_host.privesc_config"]
      }
    ]
  }
}
```

Rules the manifest enforces: `host_login` requires `account` and host targets. `account` is only allowed for `host_login`. A `cyber_host.*` action requires a `host_login` declaration. The account is the one the lease returns, so the model cannot pick it.

### Registration

The operator pipes the private key on stdin. The key never appears in argv:

```sh
bun script/fork-cyber-credential.ts add <absolute profile> <owner> lab-audit --kind host_login --expires-days 7 < audit
```

`--kind` also accepts `database_login`, `directory_bind` and `cloud_key`. Registration is an operator step, and `cyber_credentials list` shows the model the label's status.

### Execution

- One SSH connection per fixed command. The key lives in a private temporary directory for that call and is deleted afterwards. The lease buffer is zeroed on release.
- SSH options: `-F none`, key only, `IdentitiesOnly`, no agent, `BatchMode`, and `StrictHostKeyChecking=accept-new` with a per-call `known_hosts`.
- On Windows the key file is restricted to the current user with `icacls`. OpenSSH refuses keys that other principals can read, and inherited temp-directory ACLs can include other principals.
- Each command has a 30 second deadline and a 256 KiB output cap. Interruption kills the child.
- The transcript of every command is stored as a `host_transcript` artifact on the execution. The result carries a redacted excerpt, and `next_offset` points into the transcript for `evidence`.

## Command allowlist

Every remote command is a fixed string in `packages/core/src/fork-cyber/host.ts` (`commands`). Each one reads metadata or configuration. None redirects, pipes, runs a shell, uses `-exec` or `-delete`, or takes model input. The unit tests check these properties for every entry.

| Command ID          | Remote command                                                                 | Used by |
| ------------------- | ------------------------------------------------------------------------------ | ------- |
| `sshd_config`       | `cat /etc/ssh/sshd_config`                                                     | audit   |
| `login_defs`        | `cat /etc/login.defs`                                                          | audit   |
| `account_modes`     | `stat -c '%a %U %G %n' /etc/passwd /etc/shadow`                                | audit   |
| `suid_files`        | `find /usr/bin /usr/sbin /usr/local/bin -xdev -perm -4000 -type f -printf ...` | privesc |
| `sudo_rules`        | `grep -rhE NOPASSWD /etc/sudoers /etc/sudoers.d` (exit 1 means no match)       | privesc |
| `file_capabilities` | `/sbin/getcap -r /usr/bin /usr/sbin /usr/local/bin`                            | privesc |
| `cron_writable`     | `find /etc/crontab /etc/cron.d -perm -0022 -printf ...`                        | privesc |

`/etc/shadow` is stat-ed, never read. Account permissions are judged from modes only.

## Checks

Audit (`checks`):

| ID                            | Pass when                                                                | Lab hardened | Lab known-positive |
| ----------------------------- | ------------------------------------------------------------------------ | ------------ | ------------------ |
| `ssh.permit_root_login`       | `PermitRootLogin` is `no`, `prohibit-password` or `forced-commands-only` | pass         | fail (`yes`)       |
| `ssh.password_authentication` | `PasswordAuthentication no`                                              | pass         | fail (`yes`)       |
| `ssh.permit_empty_passwords`  | `PermitEmptyPasswords no`                                                | pass         | pass               |
| `account.pass_max_days`       | `PASS_MAX_DAYS` is 365 or less                                           | pass (90)    | fail (99999)       |
| `account.shadow_permissions`  | no access for other users                                                | pass (640)   | fail (644)         |
| `account.passwd_permissions`  | not writable by group or others                                          | pass         | pass               |

Privesc (`conditions`):

| ID                             | Present when                                 | Lab hardened | Lab known-positive                               |
| ------------------------------ | -------------------------------------------- | ------------ | ------------------------------------------------ |
| `suid.unexpected`              | a setuid file is outside the baseline        | clear        | present: `/usr/local/bin/backup-helper`          |
| `sudo.nopasswd`                | a non-comment sudoers line contains NOPASSWD | clear        | present: `ops ALL=(root) NOPASSWD: /usr/bin/tar` |
| `file.capabilities`            | any file has capabilities                    | clear        | present: `backup-helper cap_dac_read_search=ep`  |
| `cron.group_or_world_writable` | a cron file is group or world writable       | clear        | present: `/etc/cron.d/maint` (666)               |

A check reports `unknown` when its input cannot be read, when a key is absent and an `Include` directive could supply it, or when a command exits outside its allowed codes. Unknown is never a pass.

## Laboratory: `fork-lab/linux-host`

Two Debian bookworm hosts and an edge relay, built from code.

- `host/` builds one image per variant from `variants/`. `hardened` passes every check. `vulnerable` carries the known-positive findings in the table above, plus PASS_MAX_DAYS 99999, a 0644 shadow file, and a root login that is configured but has no key.
- `edge/` publishes two loopback ports (2201 for the hardened host, 2202 for the vulnerable one). Its output policy drops everything except loopback, replies to accepted connections, and SSH to the two hosts.
- `compose.yaml` puts the hosts on `lab-internal` (`internal: true`, no default route) and the edge on `lab-internal` and `lab-mgmt`. The only route in is the edge's published port.
- Base image: `debian:bookworm-slim` pinned by digest. Apt packages come from the Debian repository at build time and are not pinned, so rebuilds can differ in patch level.
- The audit account is `audit` (uid 1000, key only, member of `auditors`). It can read sudo policy through that group, but it has no sudo rights.

Run it by hand from the repository root:

```sh
mkdir -p /tmp/lab/mount && ssh-keygen -q -t ed25519 -N "" -f /tmp/lab/audit
cp /tmp/lab/audit.pub /tmp/lab/mount/
cd fork-lab/linux-host
OPENCYBER_LAB_KEY_DIR=/tmp/lab/mount docker compose -p ocl-manual -f compose.yaml up --build -d
OPENCYBER_LAB_KEY_DIR=/tmp/lab/mount docker compose -p ocl-manual -f compose.yaml down --volumes --remove-orphans --rmi local
```

The Windows form uses `$env:OPENCYBER_LAB_KEY_DIR` and a Windows path. Only the public key is mounted. The private key stays in a separate directory.

Egress: the hosts have no default route (`/proc/net/route`). The edge's `OUTPUT` policy is `DROP` (`iptables -S OUTPUT`). Build-time egress goes to the Debian mirrors, and runtime egress is denied except the declared SSH paths.

Teardown: `down --volumes --remove-orphans --rmi local` removes the containers, networks, volumes and the images the lab built. The base image stays in the Docker cache. The gated test asserts that no project resources remain.

## Verification

Unit and decision tests (no Docker):

```sh
cd packages/core
bun test test/plugin/fork-cyber-host.test.ts
```

Laboratory (Docker, OpenSSH client and `ssh-keygen`; set the variable to run it):

```powershell
$env:OPENCYBER_TEST_HOST_LAB = "1"
Set-Location packages/core
bun test test/plugin/fork-cyber-host-lab.test.ts
```

Without `OPENCYBER_TEST_HOST_LAB=1`, the laboratory cases report as skipped. The test starts the lab under a fresh compose project, uses ports 2201 and 2202 (override with `OPENCYBER_LAB_HARDENED_PORT` and `OPENCYBER_LAB_VULNERABLE_PORT`), and tears it down. It covers the hardened pass, the known-positive report, the privesc conditions, unchanged files after each audit, egress, and teardown.

The unit test that connects to a real loopback listener is skipped explicitly when no `ssh` client is on PATH.

## Limits

- The SUID baseline is the lab image's list. A real host needs its own baseline before `suid.unexpected` means anything.
- `sudo.nopasswd` is `unknown` when the account cannot read sudo policy. Granting the auditors group read access is a deployment decision.
- Host keys are trusted on first use per call. Pinning needs a manifest field, which is not built.
- `sshd_config` is read from the main file only. `Include` is not followed.
- `device` is not an accepted manifest target yet (OC-301 would add it). `cyber_host` uses `host` targets, enforced by the existing host and service scope.
- The key is written to disk during the call, in a private directory. JavaScript strings made while building the key are not zeroed.
- Windows hosts, the VM tier, and privileged reads are not covered.

## Not done

- `patch_inventory`: needs the pinned advisory module. Not present on `origin/custom` when this was written.
- Windows directory and Windows host laboratory: needs a Windows VM, which this machine cannot run.
- VM tier for Linux hosts beyond the two containers: needs a hypervisor.
- Host key pinning and a per-host SUID baseline: need manifest fields and an operator decision.
- Upstream test `packages/core/test/location-layer.test.ts` lists native cyber tools for F-014. It needs `cyber_host` added and FORK.md F-014 updated. Until then that upstream test fails.
- CI workflow for the laboratory: not added. The gated test runs only when the variable is set.
