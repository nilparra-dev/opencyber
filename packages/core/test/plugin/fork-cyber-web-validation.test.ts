import { expect, test } from "bun:test"
import { Effect } from "effect"
import path from "node:path"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberWebValidation } from "@opencode/core/fork-cyber/web-validation"
import { tmpdirScoped } from "../fixture/tmpdir"

const manifest = {
  engagement: "web-lab",
  authorized_by: "operator",
  authorization_ref: "web-lab-plan",
  scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: 20, window: "test", contact: "operator" },
}
const actor = { owner: "owner", session: "child", agent: "cyber-validate", manifest }

// A laboratory with one vulnerable and one safe route per class, and one page that echoes everything.
function lab() {
  return Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const url = new URL(request.url)
      const next = url.searchParams.get("next") ?? "/"
      const name = url.searchParams.get("name") ?? ""
      if (url.pathname === "/redirect") return new Response(null, { status: 302, headers: { location: next } })
      if (url.pathname === "/safe-redirect" && next.startsWith("/") && !next.startsWith("//"))
        return new Response(null, { status: 302, headers: { location: next } })
      if (url.pathname === "/safe-redirect") return new Response("home")
      if (url.pathname === "/file")
        return name.includes("../") && name.endsWith("etc/hostname")
          ? new Response("lab-host-marker\n")
          : new Response("missing", { status: 404 })
      if (url.pathname === "/echo") return new Response(`static lab-host-marker page, value ${name}${next}`)
      return new Response("not found", { status: 404 })
    },
  })
}

const resolve = () => Effect.succeed({ owner: actor.owner, session: actor.session, agent: actor.agent, manifest })

const setup = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
  yield* store.coordination.run(actor, {
    action: "create",
    key: "web",
    asset: "127.0.0.1",
    procedure: "Validate one endpoint class",
    phase: "cyber-validate",
    hypothesis: "The parameter is attacker-controlled",
  })
  yield* store.coordination.run(actor, { action: "claim", key: "web", revision: 1 })
  return store
})

test("open redirect is reproduced only when the probe redirects to the canary and the control does not", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const url = `http://127.0.0.1:${server.port}`
        const vulnerable = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "open_redirect",
          url: `${url}/redirect`,
          parameter: "next",
        })
        expect(vulnerable).toMatchObject({
          validator: "cyber_web_test.validate.open_redirect",
          oracle: { result: "reproduced" },
          cleanup: "completed",
          effects: "known",
          pre_state: { control: { status: 302, location: "opencyber-control" } },
          action: { probe: { status: 302, location: `https://${ForkCyberWebValidation.CANARY_HOST}/opencyber` } },
        })
        expect(vulnerable.completion_evidence).toHaveLength(1)

        const safe = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "open_redirect",
          url: `${url}/safe-redirect`,
          parameter: "next",
        })
        expect(safe.oracle.result).toBe("not_reproduced")
      }),
    ),
  )
})

test("a page that echoes the canary in its body is not an open redirect", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const result = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "open_redirect",
          url: `http://127.0.0.1:${server.port}/echo`,
          parameter: "next",
        })
        expect(result.oracle.result).not.toBe("reproduced")
        expect(result.oracle.result).toBe("not_reproduced")
      }),
    ),
  )
})

test("path traversal is reproduced only when the marker appears in the probe and not in the control", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const url = `http://127.0.0.1:${server.port}/file`
        const vulnerable = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "path_traversal",
          url,
          parameter: "name",
          file: "etc/hostname",
          marker: "lab-host-marker",
        })
        expect(vulnerable.oracle.result).toBe("reproduced")

        const absent = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "path_traversal",
          url,
          parameter: "name",
          file: "etc/hostname",
          marker: "marker-the-file-does-not-hold",
        })
        expect(absent.oracle.result).toBe("not_reproduced")
      }),
    ),
  )
})

test("a marker present in every response is inconclusive, never a traversal", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const server = lab()
        yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
        const store = yield* setup
        const result = yield* ForkCyberWebValidation.run(store, resolve, {
          action: "validate",
          class: "path_traversal",
          url: `http://127.0.0.1:${server.port}/echo`,
          parameter: "name",
          file: "etc/hostname",
          marker: "lab-host-marker",
        })
        expect(result.oracle.result).toBe("inconclusive")
        expect(result.oracle.result).not.toBe("reproduced")
      }),
    ),
  )
})

test("validation needs a claimed cyber-validate task and refuses other roles before any request", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        const reconnaissance = () =>
          Effect.succeed({ owner: actor.owner, session: actor.session, agent: "cyber-recon", manifest })
        const denied = yield* ForkCyberWebValidation.run(store, reconnaissance, {
          action: "validate",
          class: "open_redirect",
          url: "http://127.0.0.1:9/redirect",
          parameter: "next",
        }).pipe(Effect.flip)
        expect(String(denied)).toContain("requires a claimed cyber-validate task")
      }),
    ),
  )
})
