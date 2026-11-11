export * as ForkCyberHost from "./host.js"

import { Effect, Schema } from "effect"
import { spawn } from "node:child_process"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir, userInfo } from "node:os"
import path from "node:path"
import { ForkCyberCredentialLease } from "./credential-lease.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberPolicy } from "./policy.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>

const Port = Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 65535 }))
const Label = Schema.String.check(Schema.isPattern(/^[a-z][a-z0-9-]{0,62}$/))
const Probe = Schema.Struct({
  action: Schema.Literals(["audit", "privesc_config"]),
  host: ForkCyberScope.Host,
  port: Schema.optional(Port),
  label: Label,
})
export const Action = Schema.Union([Schema.Struct({ action: Schema.Literal("procedures") }), Probe])
export type Probe = typeof Probe.Type

export type Assessment = {
  owner: string
  session: string
  agent: string
  mode: ForkCyberPolicy.Mode
  manifest: ForkCyberScope.Manifest
  keyFile: string
  execution: string
}

type Command = { line: string; exits: readonly number[] }

// Every remote command is a fixed string that only reads metadata or config. None redirects, pipes, runs a shell
// or takes input from the model. /etc/shadow is stat-ed, never read.
export const commands = {
  sshd_config: { line: "cat /etc/ssh/sshd_config", exits: [0] },
  login_defs: { line: "cat /etc/login.defs", exits: [0] },
  account_modes: { line: "stat -c '%a %U %G %n' /etc/passwd /etc/shadow", exits: [0] },
  suid_files: {
    line: "find /usr/bin /usr/sbin /usr/local/bin -xdev -perm -4000 -type f -printf '%m %u %p\\n'",
    exits: [0],
  },
  // grep exits 1 when no rule matches, which is a clear result rather than a failure.
  sudo_rules: { line: "grep -rhE NOPASSWD /etc/sudoers /etc/sudoers.d", exits: [0, 1] },
  file_capabilities: { line: "/sbin/getcap -r /usr/bin /usr/sbin /usr/local/bin", exits: [0] },
  cron_writable: { line: "find /etc/crontab /etc/cron.d -perm -0022 -printf '%m %u %p\\n'", exits: [0] },
} satisfies Record<string, Command>
export type CommandID = keyof typeof commands

const auditCommands = ["sshd_config", "login_defs", "account_modes"] as const satisfies readonly CommandID[]
const privescCommands = [
  "suid_files",
  "sudo_rules",
  "file_capabilities",
  "cron_writable",
] as const satisfies readonly CommandID[]

// The setuid programs the lab image ships. A real host needs its own baseline; this list names only the lab's.
const suidBaseline = new Set([
  "/usr/bin/chfn",
  "/usr/bin/chsh",
  "/usr/bin/gpasswd",
  "/usr/bin/mount",
  "/usr/bin/newgrp",
  "/usr/bin/passwd",
  "/usr/bin/su",
  "/usr/bin/sudo",
  "/usr/bin/umount",
])

const outputLimit = 256 * 1024
const remoteDeadline = 30_000

export const procedures = {
  module: "linux-host-v1",
  procedures: [
    "Declare the host login in the engagement: rules_of_engagement.credentials with kind host_login, its account, the host target, and the actions cyber_host.audit and cyber_host.privesc_config. Scope the host and SSH port.",
    "Run audit for configuration checks and privesc_config for privilege-escalation conditions. Each call takes one lease for one execution.",
    "Compare each observation with the documented baseline of the host. Keep the transcript artifact as evidence.",
    "Report a condition as a candidate. Exploitability needs a validation task with its own approval; this tool does not exploit anything.",
  ],
  checks: {
    audit: [
      "ssh.permit_root_login",
      "ssh.password_authentication",
      "ssh.permit_empty_passwords",
      "account.pass_max_days",
      "account.shadow_permissions",
      "account.passwd_permissions",
    ],
  },
  conditions: ["suid.unexpected", "sudo.nopasswd", "file.capabilities", "cron.group_or_world_writable"],
  limits: [
    "The account is read-only. Remote commands are fixed strings; no argument reaches the host from the model.",
    "sshd_config is read from the main file. Include directives are not followed, so a directive absent from the main file is unknown when Include is present.",
    "sudo policy is read only when the account can read it. Otherwise sudo.nopasswd is unknown, not clear.",
    "The SUID baseline is the lab image's list. Real hosts need their own baseline before unexpected SUID results mean anything.",
    "Host keys are trusted on first use for each call; no host key is pinned yet.",
    "patch_inventory is not implemented. It needs the pinned advisory module, which this workload does not contain.",
    "Windows hosts and privileged reads are not covered. Findings are observations and candidates, not confirmed vulnerabilities.",
  ],
}

// Scope and lease gates run before any SSH process starts. A refused request therefore produces no traffic.
export const run = Effect.fn("ForkCyberHost.run")(function* (store: Store, assessment: Assessment, input: Probe) {
  if (!ForkCyberRoles.allowed(assessment.agent, "cyber_host"))
    return yield* Effect.fail(new Error(`Phase ${assessment.agent} cannot execute cyber_host`))
  if (ForkCyberRoles.worker(assessment.agent)) yield* store.coordination.requireClaim(assessment)
  const host = ForkCyberScope.normalize(input.host)
  const port = input.port ?? 22
  yield* authorized(store, assessment, host, port)
  return yield* Effect.acquireUseRelease(
    ForkCyberCredentialLease.lease({
      store,
      keyFile: assessment.keyFile,
      owner: assessment.owner,
      session: assessment.session,
      agent: assessment.agent,
      mode: assessment.mode,
      label: input.label,
      action: `cyber_host.${input.action}`,
      target: { type: "host", value: host },
      execution: assessment.execution,
      now: Date.now(),
    }),
    (lease) => inspect(store, assessment, input, { host, port, lease }),
    (lease) => Effect.sync(() => lease.release()),
  )
})

const authorized = Effect.fn("ForkCyberHost.authorized")(function* (
  store: Store,
  assessment: Assessment,
  host: string,
  port: number,
) {
  const result = yield* Effect.try({
    try: () => ForkCyberScope.authorize(assessment.manifest, host, "tcp", port),
    catch: (error) => (error instanceof Error ? error : new Error(String(error))),
  }).pipe(Effect.result)
  if (result._tag === "Success") return
  yield* store.decision({
    owner: assessment.owner,
    session: assessment.session,
    agent: assessment.agent,
    tool: "cyber_host",
    mode: assessment.mode,
    risk: "R1",
    decision: "deny",
    reason: "outside_scope",
    target: host,
  })
  return yield* Effect.fail(result.failure)
})

type Target = { host: string; port: number; lease: ForkCyberCredentialLease.Lease }

const inspect = (store: Store, assessment: Assessment, input: Probe, target: Target) =>
  Effect.acquireUseRelease(
    Effect.tryPromise({
      try: () => mkdtemp(path.join(tmpdir(), "opencyber-host-")),
      catch: () => internal("The temporary key directory could not be created."),
    }),
    (dir) =>
      Effect.gen(function* () {
        const account = target.lease.account
        if (account === undefined)
          return yield* Effect.fail(
            new ForkCyberDiagnostics.Failure({
              category: "configuration",
              operation: "cyber_host",
              message: "The declared credential is not a host login.",
              target_started: false,
              effects: "not_started",
              recovery: "Declare the label with kind host_login and an account, then get that revision approved.",
            }),
          )
        const key = path.join(dir, "key")
        const bytes = Buffer.from(`${target.lease.value.toString("utf8").trimEnd()}\n`)
        yield* Effect.tryPromise({
          try: () => writeFile(key, bytes, { mode: 0o600, flag: "wx" }),
          catch: () => internal("The key file could not be written."),
        })
        bytes.fill(0)
        yield* restrict(key)
        const connection = {
          host: target.host,
          port: target.port,
          account,
          key,
          known: path.join(dir, "known_hosts"),
        }
        const ids = input.action === "audit" ? auditCommands : privescCommands
        const results = yield* Effect.forEach(ids, (id) => remote(connection, id))
        return yield* report(store, assessment, input, target, results)
      }),
    (dir) => Effect.tryPromise(() => rm(dir, { recursive: true, force: true })).pipe(Effect.ignore),
  )

// Stores the transcript as an execution artifact and returns the structured result. The key never reaches this point.
const report = Effect.fn("ForkCyberHost.report")(function* (
  store: Store,
  assessment: Assessment,
  input: Probe,
  target: Target,
  results: readonly Remote[],
) {
  const transcript = Buffer.from(
    results
      .map(
        (result) =>
          `$ ${commands[result.id].line}\n${result.stdout}${result.stderr ? `stderr: ${result.stderr}\n` : ""}`,
      )
      .join("\n"),
  )
  const stored = yield* store.artifact(
    assessment.owner,
    assessment.execution,
    "host_transcript",
    transcript,
    "text/plain",
  )
  const excerpt = ForkCyberKali.excerpt(transcript)
  const texts = new Map(results.map((result) => [result.id, usable(result)] as const))
  const base = {
    target: target.host,
    port: target.port,
    label: input.label,
    account: target.lease.account,
    transcript_artifact: stored[0]!.id,
    transcript_excerpt: excerpt.preview,
    next_offset: excerpt.next_offset,
    limitations: procedures.limits,
  }
  if (input.action === "audit") {
    const checks = auditChecks(texts)
    return { ...base, format: "opencyber-host-audit-v1", action: input.action, checks, summary: summary(checks) }
  }
  const conditions = privescConditions(texts)
  return {
    ...base,
    format: "opencyber-host-privesc-v1",
    action: input.action,
    conditions,
    summary: conditionSummary(conditions),
  }
})

type Check = { id: string; status: "pass" | "fail" | "unknown"; observed: string; expected: string }
type Condition = {
  id: string
  status: "condition_present" | "no_condition" | "unknown"
  count: number
  items: string[]
}
type Remote = { id: CommandID; code: number; stdout: string; stderr: string }

// A command whose exit code is outside its allowed set produces no text, so its checks report unknown.
function usable(result: Remote) {
  return commands[result.id].exits.includes(result.code) ? result.stdout : undefined
}

export function auditChecks(texts: Map<CommandID, string | undefined>): Check[] {
  const config = texts.get("sshd_config")
  const modes = texts.get("account_modes")
  return [
    sshdDirective(
      "ssh.permit_root_login",
      config,
      "PermitRootLogin",
      "prohibit-password",
      ["no", "prohibit-password", "without-password", "forced-commands-only"],
      "PermitRootLogin no, prohibit-password or forced-commands-only",
    ),
    sshdDirective(
      "ssh.password_authentication",
      config,
      "PasswordAuthentication",
      "yes",
      ["no"],
      "PasswordAuthentication no",
    ),
    sshdDirective(
      "ssh.permit_empty_passwords",
      config,
      "PermitEmptyPasswords",
      "no",
      ["no"],
      "PermitEmptyPasswords no",
    ),
    passMaxDays(texts.get("login_defs")),
    fileMode(
      "account.shadow_permissions",
      modes,
      "/etc/shadow",
      (mode) => (mode & 0o007) === 0,
      "no access for other users, for example 640 or 600",
    ),
    fileMode(
      "account.passwd_permissions",
      modes,
      "/etc/passwd",
      (mode) => (mode & 0o022) === 0,
      "not writable by group or other users",
    ),
  ]
}

export function privescConditions(texts: Map<CommandID, string | undefined>): Condition[] {
  return [
    condition("suid.unexpected", texts.get("suid_files"), (lines) =>
      lines.flatMap((line) => {
        const [mode = "", owner = "", ...file] = line.split(" ")
        const location = file.join(" ")
        return suidBaseline.has(location) ? [] : [`${location} (${mode} ${owner})`]
      }),
    ),
    condition("sudo.nopasswd", texts.get("sudo_rules"), (lines) => lines.filter((line) => !line.startsWith("#"))),
    condition("file.capabilities", texts.get("file_capabilities"), (lines) => lines),
    condition("cron.group_or_world_writable", texts.get("cron_writable"), (lines) => lines),
  ]
}

function condition(id: string, text: string | undefined, select: (lines: string[]) => string[]): Condition {
  if (text === undefined) return { id, status: "unknown", count: 0, items: [] }
  const lines = text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
  const items = select(lines)
  return {
    id,
    status: items.length > 0 ? "condition_present" : "no_condition",
    count: items.length,
    items: items.slice(0, 64).map((item) => item.slice(0, 200)),
  }
}

// OpenSSH applies the first value it reads. Directives after a Match line apply only to some users, so they are skipped.
function directive(config: string, key: string) {
  for (const line of config.split("\n")) {
    const [name = "", ...value] = line.trim().split(/\s+/)
    if (name.toLowerCase() === "match") return undefined
    if (name.toLowerCase() === key.toLowerCase()) return value.join(" ")
  }
  return undefined
}

function sshdDirective(
  id: string,
  config: string | undefined,
  key: string,
  fallback: string,
  allowed: readonly string[],
  expected: string,
): Check {
  if (config === undefined) return unknown(id, expected, `${key} could not be read.`)
  const value = directive(config, key)
  if (value === undefined && /^\s*include\s/im.test(config))
    return unknown(id, expected, `${key} is absent from the main file, which includes files this check does not read.`)
  const effective = value ?? fallback
  return {
    id,
    status: allowed.includes(effective) ? "pass" : "fail",
    observed: `${key} ${effective}${value === undefined ? " (default)" : ""}`,
    expected,
  }
}

function passMaxDays(text: string | undefined): Check {
  const id = "account.pass_max_days"
  const expected = "PASS_MAX_DAYS 365 or less"
  if (text === undefined) return unknown(id, expected, "/etc/login.defs could not be read.")
  const days = /^\s*PASS_MAX_DAYS\s+(\d+)/m.exec(text)?.[1]
  if (days === undefined) return unknown(id, expected, "PASS_MAX_DAYS is not set.")
  return { id, status: Number(days) <= 365 ? "pass" : "fail", observed: `PASS_MAX_DAYS ${days}`, expected }
}

function fileMode(
  id: string,
  modes: string | undefined,
  file: string,
  passes: (mode: number) => boolean,
  expected: string,
): Check {
  if (modes === undefined) return unknown(id, expected, "The file modes could not be read.")
  const row = modes.split("\n").find((line) => line.trim().endsWith(` ${file}`))
  if (row === undefined) return unknown(id, expected, `${file} was not reported.`)
  const [mode = "", owner = "", group = ""] = row.trim().split(/\s+/)
  return {
    id,
    status: passes(Number.parseInt(mode, 8)) ? "pass" : "fail",
    observed: `${file} mode ${mode} owner ${owner}:${group}`,
    expected,
  }
}

function unknown(id: string, expected: string, observed: string): Check {
  return { id, status: "unknown", observed, expected }
}

function summary(checks: readonly Check[]) {
  const count = (status: Check["status"]) => checks.filter((check) => check.status === status).length
  return `${count("pass")} pass, ${count("fail")} fail, ${count("unknown")} unknown.`
}

function conditionSummary(conditions: readonly Condition[]) {
  const count = (status: Condition["status"]) => conditions.filter((item) => item.status === status).length
  return `${count("condition_present")} condition(s) present, ${count("no_condition")} clear, ${count("unknown")} unknown.`
}

type Connection = { host: string; port: number; account: string; key: string; known: string }

// One SSH connection per fixed command. The key file lives only in this call's private directory.
const remote = Effect.fn("ForkCyberHost.remote")(function* (connection: Connection, id: CommandID) {
  const result = yield* execute(
    [
      "ssh",
      "-F",
      "none",
      "-i",
      connection.key,
      "-o",
      "BatchMode=yes",
      "-o",
      "IdentitiesOnly=yes",
      "-o",
      "IdentityAgent=none",
      "-o",
      "PasswordAuthentication=no",
      "-o",
      "KbdInteractiveAuthentication=no",
      "-o",
      "StrictHostKeyChecking=accept-new",
      // OpenSSH splits -o values on spaces, so the quoted form is required for paths with spaces.
      "-o",
      `UserKnownHostsFile "${connection.known}"`,
      "-o",
      "ConnectTimeout=10",
      "-o",
      "LogLevel=ERROR",
      "-p",
      String(connection.port),
      "-l",
      connection.account,
      "--",
      connection.host,
      commands[id].line,
    ],
    remoteDeadline,
  )
  if (result.code === 255) return yield* Effect.fail(connectionFailure(result.stderr))
  return { id, code: result.code ?? -1, stdout: result.stdout, stderr: result.stderr } satisfies Remote
})

function connectionFailure(stderr: string) {
  const rejected = /Permission denied/.test(stderr)
  return new ForkCyberDiagnostics.Failure({
    category: "transport",
    operation: "cyber_host",
    message: rejected
      ? "The host did not accept the leased key for this account."
      : "The host did not complete the SSH connection.",
    target_started: rejected,
    effects: "not_started",
    recovery: rejected
      ? "Check that the declared account exists and that the registered key is in its authorized keys. Re-register the label if the key changed."
      : "Confirm the host and port are reachable inside the recorded scope, then retry the same audit.",
    details: { reason: rejected ? "authentication_rejected" : "connection_failed" },
  })
}

// Windows ignores POSIX modes, and OpenSSH refuses a key other principals can read. Grant read access to this user only.
const restrict = (file: string) => {
  if (process.platform !== "win32") return Effect.void
  return execute(["icacls", file, "/inheritance:r", "/grant:r", `${userInfo().username}:(R)`], 10_000).pipe(
    Effect.flatMap((result) =>
      result.code === 0 ? Effect.void : Effect.fail(internal("The key file permissions could not be restricted.")),
    ),
  )
}

type Process = { code: number | null; stdout: string; stderr: string }

// The child is killed on deadline, on output overflow and on interruption. Output is bounded per process.
const execute = (argv: readonly string[], deadline: number) =>
  Effect.tryPromise({
    try: (signal) =>
      new Promise<Process>((resolve, reject) => {
        const [command = "", ...args] = argv
        const child = spawn(command, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] })
        const captured: Record<"stdout" | "stderr", Buffer[]> = { stdout: [], stderr: [] }
        const size = { total: 0 }
        const stop = (failure: ForkCyberDiagnostics.Failure) => {
          child.kill()
          reject(failure)
        }
        const timer = setTimeout(() => stop(internal("The SSH request exceeded its deadline.", "transport")), deadline)
        const abort = () => stop(internal("The SSH request was interrupted.", "interruption"))
        signal.addEventListener("abort", abort, { once: true })
        child.once("error", (error) => {
          clearTimeout(timer)
          signal.removeEventListener("abort", abort)
          reject(
            "code" in error && error.code === "ENOENT"
              ? new ForkCyberDiagnostics.Failure({
                  category: "configuration",
                  operation: "cyber_host",
                  message: `The ${command} client is not available.`,
                  target_started: false,
                  effects: "not_started",
                  recovery:
                    "Install the OpenSSH client and check that it is on PATH, then run cyber_capabilities with runtime.",
                })
              : internal("The SSH client failed to start."),
          )
        })
        for (const stream of ["stdout", "stderr"] as const)
          child[stream].on("data", (chunk: Buffer) => {
            size.total += chunk.length
            if (size.total > outputLimit) return stop(internal("Remote output exceeded 256 KiB.", "capture"))
            captured[stream].push(chunk)
          })
        child.once("close", (code) => {
          clearTimeout(timer)
          signal.removeEventListener("abort", abort)
          resolve({
            code,
            stdout: Buffer.concat(captured.stdout).toString("utf8"),
            stderr: Buffer.concat(captured.stderr).toString("utf8"),
          })
        })
      }),
    catch: (error) => (error instanceof ForkCyberDiagnostics.Failure ? error : internal(String(error))),
  })

function internal(message: string, kind: "transport" | "interruption" | "capture" | "internal" = "internal") {
  return new ForkCyberDiagnostics.Failure({
    category: kind,
    operation: "cyber_host",
    message,
    target_started: null,
    effects: "unknown",
  })
}
