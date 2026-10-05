import { expect, test } from "bun:test"
import { Effect } from "effect"
import path from "node:path"
import { ForkCyberBrowser } from "@opencode/core/fork-cyber/browser"
import { ForkCyberEnvironment } from "@opencode/core/fork-cyber/environment"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberWebPlan } from "@opencode/core/fork-cyber/web-plan"
import { tmpdirScoped } from "../fixture/tmpdir"

const executable = process.env.OPENCYBER_TEST_BROWSER
const browserTest = executable ? test : test.skip
const features = ["url_navigation", "storage", "csp"] as const
const page = `<title>Controlled SPA</title>
<label>URL <input id="url"></label><button id="navigate">Navigate</button><p id="navigation">url: untouched</p>
<label>Marker <input id="marker"></label><button id="store">Store</button><p id="storage"></p>
<button id="probe">Probe inline script</button><p id="csp">csp: untouched</p><script src="/app.js"></script>`
const application = `const element = id => document.getElementById(id);
element('storage').textContent = 'stored: ' + (localStorage.getItem('marker') ?? 'empty');
element('store').onclick = () => {
  localStorage.setItem('marker', element('marker').value);
  element('storage').textContent = 'stored: ' + localStorage.getItem('marker');
};
element('navigate').onclick = () => {
  const url = new URL(element('url').value, location.href);
  if (!['http:', 'https:'].includes(url.protocol) || url.origin !== location.origin) {
    element('navigation').textContent = 'url: rejected';
    return;
  }
  history.pushState({}, '', url.pathname);
  element('navigation').textContent = 'url: accepted ' + location.pathname;
};
element('probe').onclick = () => {
  element('csp').textContent = 'csp: blocked';
  const script = document.createElement('script');
  script.textContent = "document.getElementById('csp').textContent = 'csp: executed'";
  document.body.appendChild(script);
};`

const fixture = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
  const hits: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const url = new URL(request.url)
      hits.push(url.pathname)
      if (url.pathname === "/app.js")
        return new Response(application, { headers: { "Content-Type": "application/javascript" } })
      return new Response(page, {
        headers: {
          "Content-Type": "text/html",
          "Content-Security-Policy": `default-src 'self'; script-src 'self'${url.pathname === "/healthy" ? " 'unsafe-inline'" : ""}; object-src 'none'`,
        },
      })
    },
  })
  yield* Effect.addFinalizer(() => Effect.sync(() => server.stop(true)))
  const actor = {
    owner: "web-lab",
    session: "web-lab",
    agent: "build",
    manifest: {
      engagement: "controlled-spa",
      authorized_by: "operator",
      authorization_ref: "local-loopback-fixture",
      scope: ForkCyberScope.webService(server.url.href),
      rules_of_engagement: { no_dos: true, max_rps: 100, window: "test", contact: "fixture" },
    },
  }
  const captured = yield* ForkCyberHttp.run(store, () => Effect.succeed(actor), { url: `${server.url}spa` })
  return { tmp, store, actor, hits, url: server.url.origin, evidence: [captured[0]!.output] }
})

test("the SPA's static capture leaves every applicable dimension blocked when Chromium is absent", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const env = yield* fixture
        const config = yield* ForkCyberEnvironment.doctor(env.tmp.path)
        const plan = ForkCyberWebPlan.plan({ features, evidence: env.evidence }, config.browser.status)
        expect(plan.dimensions.map((dimension) => dimension.feature)).toEqual([...features])
        expect(plan.dimensions.every((dimension) => dimension.state === "blocked" && !dimension.runtime_verified)).toBe(
          true,
        )
        expect(plan.dimensions.every((dimension) => dimension.basis[0] === env.evidence[0])).toBe(true)
        expect((yield* env.store.readArtifact(env.actor.owner, env.evidence[0]!)).status).toBe("completed")
        expect(env.hits).toEqual(["/spa"])
        expect(
          (yield* env.store.executions(env.actor.owner)).some((execution) => execution.tool === "cyber_browser"),
        ).toBe(false)
      }),
    ),
  )
})

browserTest(
  "the same SPA records runtime URL, isolated storage and CSP observations with healthy controls",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const plan = ForkCyberWebPlan.plan({ features, evidence: env.evidence }, "ready")
          expect(plan.dimensions.every((dimension) => dimension.state === "pending_execution")).toBe(true)
          const browser = yield* ForkCyberBrowser.make(env.store)
          const run = (action: typeof ForkCyberBrowser.Action.Type) =>
            browser.run({ executable: executable! }, () => Effect.succeed(env.actor), action)
          yield* run({ action: "open", identity: "alice" })
          yield* run({ action: "navigate", identity: "alice", url: `${env.url}/spa` })
          yield* run({ action: "fill", identity: "alice", selector: "#url", value: `${env.url}/destination` })
          const allowed = yield* run({ action: "click", identity: "alice", selector: "#navigate" })
          expect(JSON.stringify(allowed.result)).toContain("url: accepted /destination")
          yield* run({ action: "fill", identity: "alice", selector: "#url", value: "javascript:void(0)" })
          const denied = yield* run({ action: "click", identity: "alice", selector: "#navigate" })
          expect(JSON.stringify(denied.result)).toContain("url: rejected")
          yield* run({ action: "fill", identity: "alice", selector: "#marker", value: "synthetic-alice-marker" })
          yield* run({ action: "click", identity: "alice", selector: "#store" })
          const persisted = yield* run({ action: "navigate", identity: "alice", url: `${env.url}/spa` })
          expect(JSON.stringify(persisted.result)).toContain("stored: synthetic-alice-marker")
          yield* run({ action: "open", identity: "bob" })
          const isolated = yield* run({ action: "navigate", identity: "bob", url: `${env.url}/spa` })
          expect(JSON.stringify(isolated.result)).toContain("stored: empty")
          expect(JSON.stringify(isolated.result)).not.toContain("synthetic-alice-marker")
          const blocked = yield* run({ action: "click", identity: "alice", selector: "#probe" })
          expect(JSON.stringify(blocked.result)).toContain("csp: blocked")
          expect(JSON.stringify(blocked.result)).not.toContain("csp: executed")
          yield* run({ action: "navigate", identity: "alice", url: `${env.url}/healthy` })
          const healthy = yield* run({ action: "click", identity: "alice", selector: "#probe" })
          expect(JSON.stringify(healthy.result)).toContain("csp: executed")
          for (const observation of [allowed, denied, persisted, isolated, blocked, healthy]) {
            expect(observation.action_status).toBe("completed")
            expect(observation.issues).toEqual([])
            expect(observation.completion_evidence).toHaveLength(1)
            expect((yield* env.store.readArtifact(env.actor.owner, observation.completion_evidence[0]!)).status).toBe(
              "completed",
            )
          }
          // Observations prove only these controlled interactions; the initial plan never upgrades itself.
          expect(plan.dimensions.every((dimension) => !dimension.runtime_verified)).toBe(true)
          expect(env.hits.every((pathname) => ["/spa", "/app.js", "/favicon.ico", "/healthy"].includes(pathname))).toBe(
            true,
          )
        }),
      ),
    )
  },
  60000,
)
