import { expect, test } from "bun:test"
import { Effect, Schema, Scope } from "effect"
import path from "node:path"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberDiscovery } from "@opencode/core/fork-cyber/discovery"
import { ForkCyberDns } from "@opencode/core/fork-cyber/dns"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { lab } from "../fixture/fork-cyber-http-lab"
import { ForkCyberServicesLab } from "../fixture/fork-cyber-services/lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip

const network = {
  connections_per_second: 10,
  packets_per_second: 1000,
  bytes_per_job: 1024 * 1024,
  bytes_total: 10 * 1024 * 1024,
  duration_ms: 60000,
}

// Kali network policy resolves every declared name before a job starts, so the sweep test declares no names.
const scope = (
  overrides: {
    cidrs?: string[]
    domains?: string[]
    excluded?: string[]
    passive?: boolean
    derived?: boolean
    budgets?: boolean
  } = {},
) =>
  Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
    engagement: "discovery-test",
    authorized_by: "operator",
    authorization_ref: "fixture",
    scope: {
      domains: overrides.domains ?? ["127.0.0.1", "example.test", "app.example.test"],
      cidrs: overrides.cidrs ?? [],
      excluded: overrides.excluded ?? ["blocked.example.test"],
    },
    rules_of_engagement: {
      no_dos: true,
      max_rps: 10,
      window: "test",
      contact: "operator",
      passive_osint: overrides.passive ?? false,
      network: overrides.budgets === false ? undefined : network,
    },
    derived: overrides.derived,
  })

// The primary agent needs no task claim, so these tests exercise the scope and decision rules directly.
const assessment = (manifest = scope()) => ({ owner: "owner", session: "session", agent: "build", manifest })

const withStore = <A>(body: (store: ForkCyberHttp.Store, profile: string) => Effect.Effect<A, unknown, Scope.Scope>) =>
  Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "discovery.sqlite"))
        return yield* body(store, tmp.path)
      }),
    ),
  )

const kaliConfig = Schema.decodeUnknownSync(ForkCyberKali.Config)({
  image: `sha256:${"0".repeat(64)}`,
  network: { kind: "scoped", name: "discovery-test" },
})

test("discovery actions are typed, passive_dns keeps every cyber_dns record type, and sweeps are IPv4 /24 to /32", () => {
  const valid = Schema.is(ForkCyberDiscovery.Action)
  for (const type of ForkCyberDns.Action.fields.type.literals)
    expect(valid({ action: "passive_dns", host: "app.example.test", type })).toBe(true)
  expect(valid({ action: "certificates", domain: "example.test" })).toBe(true)
  expect(valid({ action: "host_sweep", cidr: "10.20.30.0/29" })).toBe(true)
  expect(valid({ action: "fingerprint", url: "https://app.example.test/login" })).toBe(true)
  expect(valid({ action: "passive_dns", host: "app.example.test", type: "PTR" })).toBe(false)
  expect(valid({ action: "certificates", domain: "10.0.0.1" })).toBe(false)
  expect(valid({ action: "host_sweep", cidr: "10.20.30.0/23" })).toBe(false)
  expect(valid({ action: "host_sweep", cidr: "fd00::/64" })).toBe(false)
  expect(valid({ action: "host_sweep", cidr: "app.example.test" })).toBe(false)
  expect(valid({ action: "fingerprint", url: "ftp://app.example.test/" })).toBe(false)
  expect(valid({ action: "fingerprint", url: "not a url" })).toBe(false)
})

test("discovery decisions keep certificates and passive DNS at R0 and active actions at R1", () => {
  const decide = (input: unknown) =>
    ForkCyberDecision.decide({ mode: "development", agent: "build", tool: "cyber_discover", input })
  expect(decide({ action: "passive_dns", host: "app.example.test", type: "A" })).toMatchObject({ risk: "R0" })
  expect(decide({ action: "certificates", domain: "example.test" })).toMatchObject({ risk: "R0" })
  expect(decide({ action: "host_sweep", cidr: "10.20.30.0/29" })).toMatchObject({ risk: "R1" })
  expect(decide({ action: "fingerprint", url: "https://app.example.test/" })).toMatchObject({ risk: "R1" })
})

test("certificate lookups are refused without the declaration or outside scope, before any request", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const undeclared = assessment()
      expect(
        String(yield* ForkCyberDiscovery.certificates(store, undeclared, "app.example.test").pipe(Effect.flip)),
      ).toContain("passive OSINT")
      const declared = assessment(scope({ passive: true }))
      expect(String(yield* ForkCyberDiscovery.certificates(store, declared, "other.test").pipe(Effect.flip))).toContain(
        "outside scope",
      )
      expect(
        String(yield* ForkCyberDiscovery.certificates(store, declared, "blocked.example.test").pipe(Effect.flip)),
      ).toContain("outside scope")
      expect(yield* store.executions("owner")).toEqual([])
    }),
  )
})

test("certificate transparency names are filtered to the domain, and only declared names are marked in scope", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      let requested = ""
      const source = yield* lab((request, response) => {
        requested = request.url ?? ""
        response.writeHead(200, { "content-type": "application/json" })
        response.end(
          JSON.stringify([
            { name_value: "app.example.test\n*.api.example.test" },
            { name_value: "example.test\nunrelated.test" },
            { name_value: "blocked.example.test" },
          ]),
        )
      })
      const result = yield* ForkCyberDiscovery.certificates(
        store,
        assessment(scope({ passive: true })),
        "example.test",
        source.url,
      )
      expect(decodeURIComponent(requested)).toContain("q=%.example.test")
      expect(requested).toContain("output=json")
      expect(result.capture.names).toEqual([
        "api.example.test",
        "app.example.test",
        "blocked.example.test",
        "example.test",
      ])
      expect(result.capture.declared_in_scope).toEqual(["app.example.test", "example.test"])
      expect((yield* store.executions("owner")).map((row) => row.status)).toEqual(["completed"])
      expect(result.artifacts.some((item) => item.kind === "discovery.certificates")).toBe(true)
    }),
  )
})

test("a failed certificate source is recorded as an error execution, not a completed lookup", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const source = yield* lab((_request, response) => {
        response.writeHead(500)
        response.end("unavailable")
      })
      expect(
        String(
          yield* ForkCyberDiscovery.certificates(
            store,
            assessment(scope({ passive: true })),
            "example.test",
            source.url,
          ).pipe(Effect.flip),
        ),
      ).toContain("HTTP 500")
      expect((yield* store.executions("owner")).map((row) => row.status)).toEqual(["error"])
    }),
  )
})

test("fingerprint reads only in-scope URLs and reports hints without cookie values", async () => {
  await withStore((store) =>
    Effect.gen(function* () {
      const outside = yield* ForkCyberDiscovery.fingerprint(
        store,
        () => Effect.succeed(assessment()),
        "https://outside.example.net/",
      ).pipe(Effect.flip)
      expect(String(outside)).toContain("outside the recorded scope")
      // The HTTP engine records the refused attempt as an error. No completed capture exists for it.
      expect((yield* store.executions("owner")).map((row) => row.status)).toEqual(["error"])

      const site = yield* lab((_request, response) => {
        response.writeHead(200, {
          "content-type": "text/html",
          server: "nginx/1.25.3",
          "x-powered-by": "PHP/8.2",
          "set-cookie": "PHPSESSID=session-secret-value; path=/",
        })
        response.end(
          '<html><head><meta name="generator" content="WordPress 6.4"></head><body><link href="/wp-content/theme.css"></body></html>',
        )
      })
      const result = yield* ForkCyberDiscovery.fingerprint(store, () => Effect.succeed(assessment()), site.url)
      const names = result.technologies.map((hint) => `${hint.evidence}=${hint.name}`)
      expect(names).toEqual([
        "header:server=nginx/1.25.3",
        "header:x-powered-by=PHP/8.2",
        "cookie:PHPSESSID=PHP",
        "body:meta-generator=WordPress 6.4",
        "body:path=WordPress",
      ])
      expect(JSON.stringify(result)).not.toContain("session-secret-value")
    }),
  )
})

test("host sweeps are refused before Docker for unscoped networks, undeclared ranges, exclusions and derived scope", async () => {
  await withStore((store, profile) =>
    Effect.gen(function* () {
      const none = Schema.decodeUnknownSync(ForkCyberKali.Config)({
        image: `sha256:${"0".repeat(64)}`,
        network: { kind: "none" },
      })
      const sweep = (
        actor = assessment(scope({ cidrs: ["10.20.30.0/29"] })),
        config = kaliConfig,
        cidr = "10.20.30.0/29",
      ) => ForkCyberDiscovery.sweep(store, profile, config, actor, { action: "host_sweep", cidr }).pipe(Effect.flip)
      expect(String(yield* sweep(undefined, none))).toContain("scoped Kali network")
      expect(String(yield* sweep(assessment(scope()), kaliConfig))).toContain("not declared in scope")
      expect(String(yield* sweep(undefined, kaliConfig, "10.20.31.0/29"))).toContain("not declared in scope")
      const excluded = assessment({
        ...scope({ cidrs: ["10.20.30.0/29"] }),
        scope: { ...scope().scope, cidrs: ["10.20.30.0/29"], excluded: ["10.20.30.3"] },
      })
      expect(String(yield* sweep(excluded))).toContain("overlaps an exclusion")
      expect(String(yield* sweep(assessment(scope({ cidrs: ["10.20.30.0/29"], derived: true }))))).toContain(
        "explicit engagement",
      )
      expect(String(yield* sweep(assessment(scope({ cidrs: ["10.20.30.0/29"], budgets: false }))))).toContain(
        "network budgets",
      )
      expect(yield* store.executions("owner")).toEqual([])
    }),
  )
})

dockerTest(
  "real Nmap sweep reports the live container and not an unused address inside a declared range",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "sweep.sqlite"))
          const octet = 20 + Math.floor(Math.random() * 200)
          const subnet = `10.${octet}.0.0/29`
          const live = `10.${octet}.0.2`
          const name = `opencyber-sweep-${crypto.randomUUID()}`
          yield* ForkCyberServicesLab.docker(["network", "create", "--internal", "--subnet", subnet, name])
          yield* Effect.addFinalizer(() => ForkCyberServicesLab.docker(["network", "rm", name]).pipe(Effect.orDie))
          const container = yield* ForkCyberServicesLab.docker([
            "run",
            "-d",
            "--rm",
            "--network",
            name,
            "--ip",
            live,
            "--entrypoint",
            "sleep",
            image!,
            "600",
          ])
          yield* Effect.addFinalizer(() => ForkCyberServicesLab.docker(["rm", "-f", container]).pipe(Effect.orDie))
          const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({
            image: image!,
            network: { kind: "scoped", name },
          })
          const declared = assessment(scope({ cidrs: [subnet], domains: [], excluded: [] }))
          const result = yield* ForkCyberDiscovery.sweep(store, tmp.path, config, declared, {
            action: "host_sweep",
            cidr: subnet,
          })
          const capture = result.capture!
          expect(capture.addresses).toBe(8)
          expect(capture.hosts_up).toContain(live)
          expect(capture.hosts_up).not.toContain(`10.${octet}.0.6`)
          expect(capture.up_count).toBe(capture.hosts_up.length)
          expect(capture.down_count).toBe(8 - capture.up_count)
        }),
      ),
    )
  },
  180000,
)
