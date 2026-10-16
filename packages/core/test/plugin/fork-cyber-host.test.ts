import { expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { Effect, Option, Schema } from "effect"
import { readFileSync } from "node:fs"
import path from "node:path"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberDiagnostics } from "@opencode/core/fork-cyber/diagnostics"
import { ForkCyberHost } from "@opencode/core/fork-cyber/host"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { definition } from "@opencode/core/tool/runtime"
import { tmpdirScoped } from "../fixture/tmpdir"

const owner = "owner-host"
const session = "session-host"
const agent = "primary"
const execution = "execution-host"
const now = Date.now()
const day = 86_400_000
const labRoot = path.resolve(import.meta.dir, "../../../../fork-lab/linux-host/host/variants")
const lab = (file: string) => readFileSync(path.join(labRoot, file), "utf8")

const decode = Schema.decodeUnknownOption(ForkCyberHost.Action)
const pick = <T extends { status: string }>(items: readonly T[], status: string) =>
  items.filter((item) => item.status === status)

const texts = (values: Partial<Record<ForkCyberHost.CommandID, string>>) =>
  new Map<ForkCyberHost.CommandID, string | undefined>(
    Object.entries(values).map(([id, value]) => [id as ForkCyberHost.CommandID, value]),
  )

// Real fixture values: the lab's own sshd_config files and the output shape of the fixed commands.
const hardenedAudit = texts({
  sshd_config: lab("hardened.sshd_config"),
  login_defs: "PASS_MAX_DAYS\t90\nPASS_MIN_DAYS\t0\n",
  account_modes: "644 root root /etc/passwd\n640 root shadow /etc/shadow\n",
})
const vulnerableAudit = texts({
  sshd_config: lab("vulnerable.sshd_config"),
  login_defs: "PASS_MAX_DAYS\t99999\n",
  account_modes: "644 root root /etc/passwd\n644 root shadow /etc/shadow\n",
})

test("decodes only the declared actions and strips fields the model cannot choose", () => {
  expect(decode({ action: "procedures" })._tag).toBe("Some")
  expect(decode({ action: "audit", host: "127.0.0.1", port: 2201, label: "lab-audit" })._tag).toBe("Some")
  expect(decode({ action: "privesc_config", host: "127.0.0.1", label: "lab-audit" })._tag).toBe("Some")
  for (const input of [
    { action: "exec", host: "127.0.0.1", label: "lab-audit" },
    { action: "patch_inventory", host: "127.0.0.1", label: "lab-audit" },
    { action: "audit", host: "http://127.0.0.1", label: "lab-audit" },
    { action: "audit", host: "127.0.0.1", port: 0, label: "lab-audit" },
    { action: "audit", host: "127.0.0.1", label: "Lab" },
  ])
    expect(decode(input)._tag).toBe("None")
  const decoded = Option.getOrThrow(
    decode({ action: "audit", host: "127.0.0.1", label: "lab-audit", command: "rm -rf /" }),
  )
  expect(Object.keys(decoded)).toEqual(["action", "host", "label"])
})

test("every remote command is a fixed read-only string", () => {
  const writes =
    /(^|\s)(rm|mv|cp|chmod|chown|tee|sed|dd|sh|bash|python3?|tar)(\s|$)|[;&|<>`]|\$\(|-exec|-delete|-ok\b|-fprint|-fls|\s-i\b/
  for (const command of Object.values(ForkCyberHost.commands)) {
    expect(command.line).not.toMatch(writes)
    expect(["cat", "stat", "find", "grep", "/sbin/getcap"]).toContain(command.line.split(" ")[0]!)
  }
  expect(Object.keys(ForkCyberHost.commands).sort()).toEqual([
    "account_modes",
    "cron_writable",
    "file_capabilities",
    "login_defs",
    "sshd_config",
    "sudo_rules",
    "suid_files",
  ])
})

test("procedures and the audit contract name only implemented checks", () => {
  expect(ForkCyberHost.procedures.checks.audit).toHaveLength(6)
  expect(ForkCyberHost.procedures.conditions).toHaveLength(4)
  expect(ForkCyberHost.procedures.limits.join(" ")).toContain("patch_inventory is not implemented")
})

test("risk declarations route audit and privesc_config to R1 and procedures to R0", () => {
  expect(
    ForkCyberDecision.decide({
      mode: "assessment",
      agent: "cyber-enum",
      tool: "cyber_host",
      input: { action: "audit", host: "127.0.0.1", label: "x" },
    }),
  ).toEqual({
    decision: "allow",
    reason: "allowed",
    risk: "R1",
  })
  expect(
    ForkCyberDecision.decide({
      mode: "assessment",
      agent: "cyber-enum",
      tool: "cyber_host",
      input: { action: "privesc_config", host: "127.0.0.1", label: "x" },
    }).risk,
  ).toBe("R1")
  expect(
    ForkCyberDecision.decide({
      mode: "assessment",
      agent: "cyber-enum",
      tool: "cyber_host",
      input: { action: "procedures" },
    }).risk,
  ).toBe("R0")
})

test("phase and mode rules keep host audits in enumeration and validation only", () => {
  const audit = { action: "audit", host: "127.0.0.1", label: "x" }
  expect(
    ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-enum", tool: "cyber_host", input: audit }).decision,
  ).toBe("allow")
  expect(
    ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-validate", tool: "cyber_host", input: audit })
      .decision,
  ).toBe("allow")
  expect(
    ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-recon", tool: "cyber_host", input: audit }),
  ).toEqual({
    decision: "deny",
    reason: "outside_role_or_mode",
  })
  expect(
    ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-exploit-net", tool: "cyber_host", input: audit })
      .decision,
  ).toBe("deny")
  expect(
    ForkCyberDecision.decide({ mode: "assessment", agent: "cyber-report", tool: "cyber_host", input: audit }).decision,
  ).toBe("deny")
  expect(ForkCyberDecision.decide({ mode: "review", agent: "cyber-enum", tool: "cyber_host", input: audit })).toEqual({
    decision: "deny",
    reason: "outside_role_or_mode",
  })
})

test("audit results: hardened fixtures pass and the known-positive fixture reports each misconfiguration", () => {
  const hardened = ForkCyberHost.auditChecks(hardenedAudit)
  expect(hardened.map((check) => check.status)).toEqual(["pass", "pass", "pass", "pass", "pass", "pass"])
  const vulnerable = ForkCyberHost.auditChecks(vulnerableAudit)
  expect(vulnerable.map((check) => [check.id, check.status])).toEqual([
    ["ssh.permit_root_login", "fail"],
    ["ssh.password_authentication", "fail"],
    ["ssh.permit_empty_passwords", "pass"],
    ["account.pass_max_days", "fail"],
    ["account.shadow_permissions", "fail"],
    ["account.passwd_permissions", "pass"],
  ])
  expect(vulnerable.find((check) => check.id === "ssh.permit_root_login")?.observed).toBe("PermitRootLogin yes")
})

test("a directive is read the way OpenSSH applies it: first match wins, Match blocks do not count, defaults apply", () => {
  // Everything after a Match line is conditional, so the global PasswordAuthentication must come first.
  const config = "PasswordAuthentication no\nMatch User someone\n  PermitRootLogin yes\n"
  const checks = ForkCyberHost.auditChecks(
    texts({
      sshd_config: config,
      login_defs: "PASS_MAX_DAYS 30\n",
      account_modes: "640 root shadow /etc/shadow\n644 root root /etc/passwd\n",
    }),
  )
  expect(checks.find((check) => check.id === "ssh.permit_root_login")).toMatchObject({
    status: "pass",
    observed: "PermitRootLogin prohibit-password (default)",
  })
  expect(checks.find((check) => check.id === "ssh.password_authentication")?.status).toBe("pass")
  const conditional = ForkCyberHost.auditChecks(
    texts({ sshd_config: "Match User someone\n  PasswordAuthentication no\n" }),
  )
  expect(conditional.find((check) => check.id === "ssh.password_authentication")).toMatchObject({
    status: "fail",
    observed: "PasswordAuthentication yes (default)",
  })
  const firstWins = ForkCyberHost.auditChecks(texts({ sshd_config: "PermitRootLogin no\nPermitRootLogin yes\n" }))
  expect(firstWins.find((check) => check.id === "ssh.permit_root_login")?.status).toBe("pass")
})

test("an included configuration and unreadable outputs report unknown instead of a pass", () => {
  const included = ForkCyberHost.auditChecks(texts({ sshd_config: "Include /etc/ssh/sshd_config.d/*.conf\n" }))
  expect(included.find((check) => check.id === "ssh.password_authentication")?.status).toBe("unknown")
  const missing = ForkCyberHost.auditChecks(texts({}))
  expect(missing.map((check) => check.status).every((status) => status === "unknown")).toBe(true)
  expect(missing.find((check) => check.id === "account.pass_max_days")?.observed).toBe(
    "/etc/login.defs could not be read.",
  )
})

test("privesc results report conditions, with the lab baseline and comments excluded", () => {
  const present = ForkCyberHost.privescConditions(
    texts({
      suid_files: "4755 root /usr/bin/passwd\n4755 root /usr/bin/sudo\n4755 root /usr/local/bin/backup-helper\n",
      sudo_rules: "# ops ALL=(ALL) NOPASSWD: ALL\nops ALL=(root) NOPASSWD: /usr/bin/tar\n",
      file_capabilities: "/usr/local/bin/backup-helper cap_dac_read_search=ep\n",
      cron_writable: "666 root /etc/cron.d/maint\n",
    }),
  )
  expect(present).toEqual([
    {
      id: "suid.unexpected",
      status: "condition_present",
      count: 1,
      items: ["/usr/local/bin/backup-helper (4755 root)"],
    },
    { id: "sudo.nopasswd", status: "condition_present", count: 1, items: ["ops ALL=(root) NOPASSWD: /usr/bin/tar"] },
    {
      id: "file.capabilities",
      status: "condition_present",
      count: 1,
      items: ["/usr/local/bin/backup-helper cap_dac_read_search=ep"],
    },
    {
      id: "cron.group_or_world_writable",
      status: "condition_present",
      count: 1,
      items: ["666 root /etc/cron.d/maint"],
    },
  ])
  const clear = ForkCyberHost.privescConditions(
    texts({ suid_files: "4755 root /usr/bin/su\n", sudo_rules: "", file_capabilities: "", cron_writable: "" }),
  )
  expect(pick(clear, "no_condition").map((item) => item.id)).toEqual([
    "suid.unexpected",
    "sudo.nopasswd",
    "file.capabilities",
    "cron.group_or_world_writable",
  ])
  expect(pick(ForkCyberHost.privescConditions(texts({})), "unknown")).toHaveLength(4)
})

// Zero-traffic checks. A real loopback listener counts every connection; a refused request must leave it at zero.
const listen = Effect.acquireRelease(
  Effect.sync(() => {
    const seen = { connections: 0 }
    const server = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        open(socket) {
          seen.connections++
          socket.end()
        },
        data() {},
        close() {},
      },
    })
    return { server, seen, port: server.port }
  }),
  ({ server }) => Effect.sync(() => server.stop(true)),
)

const environment = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const file = path.join(tmp.path, "evidence.sqlite")
  const keyFile = path.join(tmp.path, "state", "credential.key")
  const store = yield* ForkCyberStore.open(file)
  const key = yield* ForkCyberCredentials.loadKey(keyFile)
  yield* store.start({ id: execution, owner, session, tool: "cyber_host", agent, input: {} })
  return { file, keyFile, key, store }
})

type Env = Effect.Success<typeof environment>

const register = (env: Env, label: string, value: string) => {
  const binding = { owner, label, kind: "host_login" as const }
  return env.store.putCredential({
    ...binding,
    expires_at: now + day,
    created_at: now,
    ...ForkCyberCredentials.seal(env.key, binding, value),
  })
}

const manifest = (
  port: number,
  credentials: NonNullable<ForkCyberScope.Manifest["rules_of_engagement"]["credentials"]>,
): ForkCyberScope.Manifest => ({
  engagement: "lab",
  authorized_by: "operator",
  authorization_ref: "lab-plan",
  scope: { domains: [], cidrs: [], excluded: [], services: [{ target: "127.0.0.1", protocol: "tcp", ports: [port] }] },
  rules_of_engagement: { no_dos: true, max_rps: 1, window: "test", contact: "operator", credentials },
})

const declared = (label: string, action: string) => ({
  label,
  kind: "host_login" as const,
  read_only: true as const,
  account: "audit",
  targets: [{ type: "host" as const, value: "127.0.0.1" }],
  actions: [action],
})

const run = (
  env: Env,
  value: ForkCyberScope.Manifest,
  input: ForkCyberHost.Probe,
  mode: "assessment" | "review" = "assessment",
) =>
  ForkCyberHost.run(
    env.store,
    { owner, session, agent, mode, manifest: value, keyFile: env.keyFile, execution },
    input,
  ).pipe(Effect.result)

const decisions = (file: string) => {
  const db = new Database(file, { readonly: true })
  const rows = db
    .query<
      { decision: string; reason: string; tool: string },
      []
    >("SELECT decision, reason, tool FROM cyber_decision ORDER BY seq")
    .all()
  db.close()
  return rows
}

test("a request outside the authorized port makes no SSH connection", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        const listener = yield* listen
        yield* register(env, "lab-audit", "not-a-real-key")
        const value = manifest(listener.port + 1, [declared("lab-audit", "cyber_host.audit")])
        yield* env.store.approveManifest(owner, value, 0)
        const result = yield* run(env, value, {
          action: "audit",
          host: "127.0.0.1",
          port: listener.port,
          label: "lab-audit",
        })
        expect(result._tag).toBe("Failure")
        expect(result._tag === "Failure" && result.failure).toMatchObject({ diagnostic: { category: "outside_scope" } })
        expect(listener.seen.connections).toBe(0)
        expect(decisions(env.file)).toContainEqual(
          expect.objectContaining({ decision: "deny", reason: "outside_scope", tool: "cyber_host" }),
        )
      }),
    ),
  )
})

test("a request for a label the engagement does not declare for this action makes no SSH connection", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        const listener = yield* listen
        yield* register(env, "lab-audit", "not-a-real-key")
        const value = manifest(listener.port, [declared("lab-audit", "cyber_host.privesc_config")])
        yield* env.store.approveManifest(owner, value, 0)
        const result = yield* run(env, value, {
          action: "audit",
          host: "127.0.0.1",
          port: listener.port,
          label: "lab-audit",
        })
        expect(result._tag).toBe("Failure")
        expect(listener.seen.connections).toBe(0)
        expect(decisions(env.file)).toContainEqual(
          expect.objectContaining({ decision: "deny", reason: "not_declared" }),
        )
      }),
    ),
  )
})

test("a request above the mode ceiling makes no SSH connection even when declared and in scope", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        const listener = yield* listen
        yield* register(env, "lab-audit", "not-a-real-key")
        const value = manifest(listener.port, [declared("lab-audit", "cyber_host.audit")])
        yield* env.store.approveManifest(owner, value, 0)
        const result = yield* run(
          env,
          value,
          { action: "audit", host: "127.0.0.1", port: listener.port, label: "lab-audit" },
          "review",
        )
        expect(result._tag).toBe("Failure")
        expect(result._tag === "Failure" && result.failure).toMatchObject({
          diagnostic: { category: "refused_by_policy" },
        })
        expect(listener.seen.connections).toBe(0)
      }),
    ),
  )
})

test.skipIf(Bun.which("ssh") === null)(
  "an allowed request reaches the host, so the zero-traffic results above are not vacuous",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* environment
          const listener = yield* listen
          yield* register(env, "lab-audit", "not-a-real-key")
          const value = manifest(listener.port, [declared("lab-audit", "cyber_host.audit")])
          yield* env.store.approveManifest(owner, value, 0)
          const result = yield* run(env, value, {
            action: "audit",
            host: "127.0.0.1",
            port: listener.port,
            label: "lab-audit",
          })
          // The listener closes before any SSH banner, so the call ends as a connection failure, never as a result.
          expect(result._tag).toBe("Failure")
          expect(listener.seen.connections).toBeGreaterThan(0)
          expect(decisions(env.file)).toContainEqual(
            expect.objectContaining({ decision: "allow", reason: "credential_lease", tool: "cyber_host" }),
          )
        }),
      ),
    )
  },
  30_000,
)

test("the model-facing schema exposes the action discriminator and no command field", () => {
  const schema = definition({
    name: "cyber_host",
    description: "Host audit",
    input: ForkCyberHost.Action,
    execute: () => Effect.succeed({ content: "unused" }),
  }).inputSchema
  const text = JSON.stringify(schema)
  expect(text).toContain('"audit"')
  expect(text).toContain('"privesc_config"')
  expect(text).not.toContain('"command"')
})

test("host logins need an account on a host, and cyber_host actions need a host login", () => {
  const decodeManifest = Schema.decodeUnknownOption(ForkCyberScope.Manifest)
  const withCredential = (credential: unknown) => ({
    engagement: "lab",
    authorized_by: "operator",
    authorization_ref: "plan",
    scope: { domains: ["lab.test"], cidrs: [], excluded: [] },
    rules_of_engagement: { no_dos: true, max_rps: 1, window: "test", contact: "operator", credentials: [credential] },
  })
  const login = {
    label: "lab-audit",
    kind: "host_login",
    read_only: true,
    targets: [{ type: "host", value: "lab.test" }],
    actions: ["cyber_host.audit"],
    account: "audit",
  }
  expect(decodeManifest(withCredential(login))._tag).toBe("Some")
  expect(decodeManifest(withCredential({ ...login, account: undefined }))._tag).toBe("None")
  expect(decodeManifest(withCredential({ ...login, account: "Root Admin" }))._tag).toBe("None")
  expect(decodeManifest(withCredential({ ...login, targets: [{ type: "cidr", value: "10.0.0.0/24" }] }))._tag).toBe(
    "None",
  )
  expect(decodeManifest(withCredential({ ...login, kind: "directory_bind" }))._tag).toBe("None")
  expect(
    decodeManifest(
      withCredential({
        label: "ad-reader",
        kind: "directory_bind",
        read_only: true,
        targets: [{ type: "host", value: "lab.test" }],
        actions: ["cyber_services.version"],
      }),
    )._tag,
  ).toBe("Some")
})

test("a refusal carries a categorized diagnostic with recovery", () => {
  const failure = new ForkCyberDiagnostics.Failure({
    category: "scope",
    operation: "cyber_host",
    message: "outside",
    target_started: false,
    effects: "not_started",
  })
  expect(failure.diagnostic.category).toBe("outside_scope")
  expect(failure.diagnostic.recovery.length).toBeGreaterThan(0)
})
