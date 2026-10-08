import { expect, test } from "bun:test"
import { Effect } from "effect"
import path from "node:path"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const grant = {
  owner: "owner",
  id: "approval-1",
  action: "cyber_web_test.validate",
  target: "https://app.example.test/item",
  approver: "operator",
  approved_at: 1000,
  expires_at: 2000,
}

test("an approval covers its exact action and target only until it expires", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        yield* store.grantApproval(grant)
        const active = (input: Partial<typeof grant> & { now: number }) =>
          store.activeApproval({
            owner: input.owner ?? grant.owner,
            action: input.action ?? grant.action,
            target: input.target ?? grant.target,
            now: input.now,
          })

        expect(yield* active({ now: 1500 })).toEqual([{ id: "approval-1", approver: "operator", expires_at: 2000 }])
        expect(yield* active({ now: 2000 })).toEqual([])
        expect(yield* active({ now: 2500 })).toEqual([])
      }),
    ),
  )
})

test("an approval never covers another action, target or owner", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        yield* store.grantApproval(grant)
        const lookup = (input: { owner?: string; action?: string; target?: string }) =>
          store.activeApproval({
            owner: input.owner ?? grant.owner,
            action: input.action ?? grant.action,
            target: input.target ?? grant.target,
            now: 1500,
          })

        expect(yield* lookup({ action: "cyber_web_test.validate.ssrf" })).toEqual([])
        expect(yield* lookup({ action: "cyber_local_validation" })).toEqual([])
        expect(yield* lookup({ target: "https://app.example.test/other" })).toEqual([])
        expect(yield* lookup({ target: "https://app.example.test/item/" })).toEqual([])
        expect(yield* lookup({ owner: "another-owner" })).toEqual([])
      }),
    ),
  )
})

test("the most recent active approval for the same action and target is reported", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        yield* store.grantApproval(grant)
        yield* store.grantApproval({ ...grant, id: "approval-2", approved_at: 1200, expires_at: 3000 })
        const [row] = yield* store.activeApproval({ ...grant, now: 1500 })
        expect(row?.id).toBe("approval-2")
      }),
    ),
  )
})
