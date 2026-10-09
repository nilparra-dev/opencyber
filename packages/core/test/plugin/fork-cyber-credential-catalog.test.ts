import { expect, test } from "bun:test"
import { Effect } from "effect"
import path from "node:path"
import { ForkCyberCredentialLease } from "@opencode/core/fork-cyber/credential-lease"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberRedaction } from "@opencode/core/fork-cyber/redaction"
import { ForkCyberRoles } from "@opencode/core/fork-cyber/roles"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const seeded = "seeded-catalog-secret-8a4f"
const owner = "owner-a"
const now = Date.UTC(2026, 9, 9)
const day = 86_400_000

type Declaration = NonNullable<ForkCyberScope.Manifest["rules_of_engagement"]["credentials"]>[number]

const declared = (label: string): Declaration => ({
  label,
  kind: "directory_bind",
  read_only: true,
  targets: [{ type: "host", value: "lab.test" }],
  actions: ["cyber_services.version"],
})

const engagement = (credentials: Declaration[]): ForkCyberScope.Manifest => ({
  engagement: "lab",
  authorized_by: "operator",
  authorization_ref: "lab-plan",
  scope: { domains: ["lab.test"], cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: 1, window: "test", contact: "operator", credentials },
})

test("lists declared credentials with their registration state and never a value", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        const key = yield* ForkCyberCredentials.loadKey(path.join(tmp.path, "state", "credential.key"))
        const register = (label: string, expiresAt: number) => {
          const sealed = ForkCyberCredentials.seal(key, { owner, label, kind: "directory_bind" }, seeded)
          return store.putCredential({
            owner,
            label,
            kind: "directory_bind",
            expires_at: expiresAt,
            created_at: now,
            ...sealed,
          })
        }
        yield* store.approveManifest(
          owner,
          engagement([
            declared("available-reader"),
            declared("unregistered-reader"),
            declared("revoked-reader"),
            declared("expired-reader"),
          ]),
          0,
        )
        yield* register("available-reader", now + day)
        yield* register("revoked-reader", now + day)
        yield* store.revokeCredential(owner, "revoked-reader", now)
        yield* register("expired-reader", now)

        const listed = yield* ForkCyberCredentialLease.catalog({ store, owner, now })
        expect(listed.map((item) => [item.label, item.status])).toEqual([
          ["available-reader", "available"],
          ["unregistered-reader", "not_registered"],
          ["revoked-reader", "revoked"],
          ["expired-reader", "expired"],
        ])
        expect(listed[0]?.expires_at).toBe(new Date(now + day).toISOString())
        expect(listed[1]?.expires_at).toBeNull()
        expect(listed[0]?.targets).toEqual([{ type: "host", value: "lab.test" }])
        expect(JSON.stringify(listed)).not.toContain(seeded)
        expect(yield* ForkCyberCredentialLease.catalog({ store, owner: "owner-b", now })).toEqual([])
      }),
    ),
  )
})

test("lists nothing when no approved engagement declares credentials", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        expect(yield* ForkCyberCredentialLease.catalog({ store, owner, now })).toEqual([])
      }),
    ),
  )
})

test("the list action is read-only, risk R0, and open to every cyber reader role", () => {
  expect(ForkCyberDecision.declaration("cyber_credentials")).toBe("R0")
  for (const agent of ["cyber-recon", "cyber-enum", "cyber-report", "cyber-validate"])
    expect(ForkCyberRoles.allowed(agent, "cyber_credentials")).toBe(true)
  expect(
    ForkCyberDecision.decide({
      mode: "assessment",
      agent: "cyber-enum",
      tool: "cyber_credentials",
      input: { action: "list" },
    }).decision,
  ).toBe("allow")
})

test("the redaction layer keeps labels, states, targets and dates of a listed declaration", () => {
  const entry = {
    label: "available-reader",
    kind: "directory_bind",
    read_only: true,
    targets: [{ type: "host", value: "lab.test" }],
    actions: ["cyber_services.version"],
    status: "available",
    expires_at: new Date(now + day).toISOString(),
  }
  const content = JSON.stringify({ declared: [entry], restrictions: "Values are never returned." })
  expect(JSON.parse(ForkCyberRedaction.text(content))).toEqual({ declared: [entry], restrictions: "Values are never returned." })
})
