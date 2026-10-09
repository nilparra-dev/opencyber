import { expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { Effect } from "effect"
import path from "node:path"
import { ForkCyberCredentialLease } from "@opencode/core/fork-cyber/credential-lease"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberDiagnostics } from "@opencode/core/fork-cyber/diagnostics"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const seeded = "seeded-lease-secret-9b2e"
const owner = "owner-a"
const now = Date.UTC(2026, 9, 9)
const day = 86_400_000

type Declaration = NonNullable<ForkCyberScope.Manifest["rules_of_engagement"]["credentials"]>[number]
type Env = {
  file: string
  keyFile: string
  key: Buffer
  store: Effect.Success<ReturnType<typeof ForkCyberStore.open>>
}

const declared = (overrides: Partial<Declaration> = {}): Declaration => ({
  label: "ad-reader",
  kind: "directory_bind",
  read_only: true,
  targets: [{ type: "host", value: "lab.test" }],
  actions: ["cyber_services.version"],
  ...overrides,
})

const engagement = (credentials: Declaration[]): ForkCyberScope.Manifest => ({
  engagement: "lab",
  authorized_by: "operator",
  authorization_ref: "lab-plan",
  scope: {
    domains: ["lab.test"],
    cidrs: ["10.0.0.0/24"],
    excluded: [],
    resources: ["arn:aws:s3:::lab-bucket"],
  },
  rules_of_engagement: { no_dos: true, max_rps: 1, window: "test", contact: "operator", credentials },
})

const environment = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const file = path.join(tmp.path, "evidence.sqlite")
  const keyFile = path.join(tmp.path, "state", "credential.key")
  const store = yield* ForkCyberStore.open(file)
  const key = yield* ForkCyberCredentials.loadKey(keyFile)
  return { file, keyFile, key, store } satisfies Env
})

const register = (env: Env, label = "ad-reader", expiresAt = now + day) => {
  const sealed = ForkCyberCredentials.seal(env.key, { owner, label, kind: "directory_bind" }, seeded)
  return env.store.putCredential({
    owner,
    label,
    kind: "directory_bind",
    expires_at: expiresAt,
    created_at: now,
    ...sealed,
  })
}

const approve = (env: Env, credentials: Declaration[]) => env.store.approveManifest(owner, engagement(credentials), 0)

const request = (
  env: Env,
  overrides: Partial<ForkCyberCredentialLease.Request> = {},
): ForkCyberCredentialLease.Request => ({
  store: env.store,
  keyFile: env.keyFile,
  owner,
  session: "session-1",
  agent: "cyber-enum",
  mode: "assessment",
  label: "ad-reader",
  action: "cyber_services.version",
  target: { type: "host", value: "lab.test" },
  execution: "execution-1",
  now,
  ...overrides,
})

// The category of a refusal, "granted" when the lease succeeds, and "store" when the store itself fails.
const outcome = (env: Env, overrides: Partial<ForkCyberCredentialLease.Request> = {}) =>
  Effect.gen(function* () {
    const result = yield* ForkCyberCredentialLease.lease(request(env, overrides)).pipe(Effect.result)
    if (result._tag === "Success") return "granted"
    return result.failure instanceof ForkCyberDiagnostics.Failure ? result.failure.diagnostic.category : "store"
  })

const leaseRows = (env: Env) => {
  const db = new Database(env.file, { readonly: true })
  const rows = db
    .query<{ outcome: string; reason: string; action: string; label: string; target: string }, []>(
      "SELECT outcome, reason, action, label, target FROM cyber_credential_lease ORDER BY seq",
    )
    .all()
  db.close()
  return rows
}

const decisionRows = (env: Env) => {
  const db = new Database(env.file, { readonly: true })
  const rows = db
    .query<{ tool: string; decision: string; reason: string; risk: string | null }, []>(
      "SELECT tool, decision, reason, risk FROM cyber_decision ORDER BY seq",
    )
    .all()
  db.close()
  return rows
}

test("grants a declared read-only lease, records it and zeroes the value on release", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        yield* register(env)
        yield* approve(env, [declared()])
        const lease = yield* ForkCyberCredentialLease.lease(request(env))
        expect(lease.value.toString("utf8")).toBe(seeded)
        lease.release()
        expect(lease.value.every((byte) => byte === 0)).toBe(true)
        expect(leaseRows(env)).toEqual([
          expect.objectContaining({
            outcome: "granted",
            reason: "declared",
            action: "cyber_services.version",
            label: "ad-reader",
            target: "host:lab.test",
          }),
        ])
        expect(decisionRows(env)).toEqual([
          expect.objectContaining({ tool: "cyber_services", decision: "allow", reason: "credential_lease", risk: "R1" }),
        ])
      }),
    ),
  )
})

test("refuses leases the engagement does not declare, and records each refusal", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        yield* register(env)
        expect(yield* outcome(env)).toBe("refused_by_policy")
        yield* approve(env, [declared()])
        expect(yield* outcome(env, { action: "cyber_services.scan" })).toBe("refused_by_policy")
        expect(yield* outcome(env, { target: { type: "host", value: "other.test" } })).toBe("refused_by_policy")
        expect(yield* outcome(env, { label: "other-label" })).toBe("refused_by_policy")
        expect(leaseRows(env).map((row) => row.reason)).toEqual([
          "not_declared",
          "not_declared",
          "not_declared",
          "not_declared",
        ])
        expect(leaseRows(env).every((row) => row.outcome === "refused")).toBe(true)
        expect(decisionRows(env).every((row) => row.decision === "deny")).toBe(true)
      }),
    ),
  )
})

test("refuses targets outside the recorded scope, write-capable actions and undeclared risk", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        yield* approve(env, [
          declared({
            label: "bucket-reader",
            kind: "cloud_key",
            targets: [{ type: "cloud_resource", value: "arn:aws:s3:::other-bucket" }],
          }),
          declared({ label: "writer", actions: ["cyber_local_validation"] }),
          declared({ label: "unclassified", actions: ["cyber_directory.ldap_enum"] }),
        ])
        expect(
          yield* outcome(env, {
            label: "bucket-reader",
            action: "cyber_services.version",
            target: { type: "cloud_resource", value: "arn:aws:s3:::other-bucket" },
          }),
        ).toBe("outside_scope")
        expect(yield* outcome(env, { label: "writer", action: "cyber_local_validation" })).toBe("refused_by_policy")
        expect(yield* outcome(env, { label: "unclassified", action: "cyber_directory.ldap_enum" })).toBe(
          "refused_by_policy",
        )
        expect(leaseRows(env).map((row) => row.reason)).toEqual(["outside_scope", "above_ceiling", "undeclared_action"])
      }),
    ),
  )
})

test("refuses unregistered, revoked and expired credentials", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        yield* approve(env, [declared(), declared({ label: "old-reader" })])
        expect(yield* outcome(env)).toBe("not_configured")
        yield* register(env)
        yield* env.store.revokeCredential(owner, "ad-reader", now)
        expect(yield* outcome(env)).toBe("refused_by_policy")
        yield* register(env, "old-reader", now)
        expect(yield* outcome(env, { label: "old-reader" })).toBe("refused_by_policy")
        expect(leaseRows(env).map((row) => row.reason)).toEqual(["not_configured", "revoked", "expired"])
      }),
    ),
  )
})

test("refuses a tool outside the agent's role even when its risk class is allowed", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        yield* register(env)
        yield* approve(env, [declared({ actions: ["cyber_code_review"] })])
        expect(yield* outcome(env, { agent: "cyber-report", action: "cyber_code_review" })).toBe("refused_by_policy")
        expect(leaseRows(env).map((row) => row.reason)).toEqual(["outside_role_or_mode"])
      }),
    ),
  )
})

test("reports a tool failure when the stored credential does not open with the current key", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* environment
        yield* register(env)
        yield* approve(env, [declared()])
        const other = path.join(path.dirname(env.file), "other", "credential.key")
        yield* ForkCyberCredentials.loadKey(other)
        expect(yield* outcome(env, { keyFile: other })).toBe("tool_failure")
        expect(leaseRows(env).map((row) => row.reason)).toEqual(["unreadable"])
      }),
    ),
  )
})
