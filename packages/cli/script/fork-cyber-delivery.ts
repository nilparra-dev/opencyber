import { Database } from "bun:sqlite"
import { Effect, Schema } from "effect"
import { mkdir, mkdtemp } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { ForkCyberServicesLab } from "../../core/test/fixture/fork-cyber-services/lab"
import { ForkCyberSurfacesLab } from "../../core/test/fixture/fork-cyber-surfaces/lab"
import { ForkCyberServiceValidation } from "../../core/src/fork-cyber/service-validation"
import { cyberProfile } from "../src/fork-cyber-profile"

// Deterministic CLI integration smoke. The local protocol fixture supplies tool calls, not model evaluations.
const binary = process.argv[2]
const image = process.env.OPENCYBER_TEST_KALI_IMAGE
if (!binary || !image) throw new Error("Expected a CLI binary and OPENCYBER_TEST_KALI_IMAGE")
const root = await mkdtemp(path.join(tmpdir(), "opencyber-delivery-"))
await mkdir(path.join(root, "tmp"), { recursive: true })
const project = path.join(root, "project")
await mkdir(project, { recursive: true })
const model = "fixture/fixture"
const surfaces = process.argv.includes("--surfaces")
const inventorySteps = [
  "engagement",
  "cyber_tasks",
  "cyber_tasks",
  "cyber_services",
  "findings",
  "cyber_tasks",
  "cyber_coverage",
]
const steps = surfaces
  ? [...inventorySteps.slice(0, 5), "cyber_surface", "cyber_surface", "findings", ...inventorySteps.slice(5)]
  : inventorySteps
let step = 0
const Scan = Schema.Struct({ execution: Schema.String })

await Effect.runPromise(
  Effect.scoped(
    Effect.gen(function* () {
      const lab = yield* surfaces ? ForkCyberSurfacesLab.open(image) : ForkCyberServicesLab.open(image)
      yield* Effect.promise(() =>
        Bun.write(
          path.join(project, ".opencode", "cyber", "scope.jsonc"),
          JSON.stringify(
            surfaces
              ? {
                  ...ForkCyberSurfacesLab.assessment.manifest,
                  scope: {
                    domains: [],
                    cidrs: [],
                    excluded: [],
                    services: [{ target: "target", protocol: "tcp", ports: [8001, 8443, 8444] }],
                  },
                }
              : ForkCyberServicesLab.assessment.manifest,
          ),
        ),
      )
      yield* Effect.promise(() =>
        Bun.write(path.join(root, "config", "opencode", "opencyber-kali.jsonc"), JSON.stringify(lab.config)),
      )
      const llm = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        async fetch(request) {
          const body = Schema.decodeUnknownSync(
            Schema.Struct({ messages: Schema.Array(Schema.Struct({ role: Schema.String, content: Schema.Unknown })) }),
          )(await request.json())
          using archive = new Database(path.join(root, "data", "opencode", "opencyber", "evidence.sqlite"), {
            readonly: true,
          })
          if (
            step >= 4 &&
            !archive.query("SELECT id FROM execution WHERE tool = 'cyber_services' AND status = 'completed'").get()
          )
            throw new Error(`TCP inventory did not complete: ${JSON.stringify(body.messages.at(-1))}`)
          const output =
            step >= 4
              ? Schema.decodeUnknownSync(Schema.Struct({ id: Schema.String, data: Schema.String }))(
                  archive
                    .query(
                      "SELECT id, data FROM artifact WHERE kind = 'output' AND execution IN (SELECT id FROM execution WHERE tool = 'cyber_services' AND status = 'completed') ORDER BY rowid DESC LIMIT 1",
                    )
                    .get(),
                )
              : undefined
          const scan = output
            ? {
                evidence: output.id,
                ...Schema.decodeUnknownSync(Schema.fromJsonString(Scan))(Buffer.from(output.data, "base64").toString()),
              }
            : undefined
          const tls =
            surfaces && step >= 7
              ? Schema.decodeUnknownSync(Schema.Array(Schema.Struct({ id: Schema.String, data: Schema.String })))(
                  archive
                    .query(
                      "SELECT a.id, a.data FROM artifact a JOIN execution e ON e.id = a.execution AND e.owner = a.owner WHERE a.kind = 'output' AND e.tool = 'cyber_surface' AND e.status = 'completed' ORDER BY e.started_at, e.id",
                    )
                    .all(),
                )
              : []
          if (surfaces && step >= 7) {
            const reports = tls.map(
              (item) =>
                Schema.decodeUnknownSync(
                  Schema.fromJsonString(
                    Schema.Struct({ capture: Schema.Struct({ report: ForkCyberServiceValidation.Report }) }),
                  ),
                )(Buffer.from(item.data, "base64").toString()).capture.report,
            )
            if (
              reports.length !== 2 ||
              reports[0]?.protocol !== "tls" ||
              reports[1]?.protocol !== "tls" ||
              !reports[0].versions.some((row) => row.version === "TLSv1" && row.accepted) ||
              reports[1].versions.some((row) => row.version === "TLSv1" && row.accepted) ||
              !reports[1].versions.some((row) => row.version === "TLSv1.2" && row.accepted)
            )
              throw new Error("CLI TLS validation or healthy control failed")
          }
          const evidence = [...(scan ? [scan.evidence] : []), ...tls.map((item) => item.id)]
          const inventoryInputs = [
            {},
            {
              action: "create",
              key: "delivery",
              asset: surfaces ? "target:8444,8443,8001" : "target:8000,8001",
              procedure: surfaces ? "TCP inventory and TLS controls" : "TCP inventory",
              phase: surfaces ? "cyber-validate" : "cyber-enum",
              hypothesis: surfaces
                ? "TLSv1 succeeds on 8444; the healthy 8443 control requires modern TLS"
                : "Only 8000 listens",
            },
            { action: "claim", key: "delivery", revision: 1 },
            { action: "scan", host: "target", ports: surfaces ? [8444, 8001] : [8000, 8001] },
            {
              write: {
                id: "reachable-service",
                revision: 0,
                title: "Fixture TCP listener",
                status: "candidate",
                rationale: "Reachable listener; protocol impact remains pending",
                evidence,
              },
            },
            {
              action: "complete",
              key: "delivery",
              revision: 2,
              outcome: "supported",
              rationale: "Open and closed controls reproduced",
              evidence,
            },
            {},
          ]
          const inputs = surfaces
            ? [
                ...inventoryInputs.slice(0, 5),
                { module: "tls", action: "probe", host: "target", port: 8444 },
                { module: "tls", action: "probe", host: "target", port: 8443 },
                {
                  write: {
                    id: "reachable-service",
                    revision: 1,
                    title: "Fixture legacy TLS",
                    status: "confirmed",
                    rationale: "Actual TLSv1 handshake succeeds; healthy control negotiates TLSv1.2",
                    evidence,
                  },
                },
                ...inventoryInputs.slice(5),
              ]
            : inventoryInputs
          const tool = steps[step]
          step++
          const delta = tool
            ? {
                role: "assistant",
                tool_calls: [
                  {
                    index: 0,
                    id: `call_${step}`,
                    type: "function",
                    function: { name: tool, arguments: JSON.stringify(inputs[step - 1]) },
                  },
                ],
              }
            : { role: "assistant", content: "Delivery workflow completed with recorded evidence." }
          const chunks = [
            { id: `fixture_${step}`, choices: [{ index: 0, delta, finish_reason: null }] },
            { choices: [{ index: 0, delta: {}, finish_reason: tool ? "tool_calls" : "stop" }] },
            { choices: [], usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 } },
          ]
          if (!body.messages.length || step > steps.length + 1)
            throw new Error("CLI protocol fixture exceeded its bounded sequence")
          return new Response(
            chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join("") + "data: [DONE]\n\n",
            { headers: { "content-type": "text/event-stream" } },
          )
        },
      })
      yield* Effect.addFinalizer(() => Effect.promise(() => llm.stop(true)))
      yield* Effect.promise(() =>
        Bun.write(
          path.join(root, "config", "opencode", "opencode.json"),
          JSON.stringify({
            update: "disable",
            share: "disabled",
            model,
            providers: {
              fixture: {
                package: "@opencode/ai/providers/openai-compatible",
                settings: { baseURL: `${llm.url}v1`, apiKey: "fixture-only" },
                models: {
                  fixture: {
                    name: "Local protocol fixture",
                    capabilities: { tools: true, input: ["text"], output: ["text"] },
                    limit: { context: 100000, output: 1000 },
                  },
                },
              },
            },
            agents: {
              build: {
                steps: 12,
                permissions: [
                  { action: "*", resource: "*", effect: "deny" },
                  ...steps.map((action) => ({ action, resource: "*", effect: "allow" })),
                ],
              },
            },
          }),
        ),
      )
      yield* Effect.promise(() => Bun.write(path.join(root, "models.json"), "{}"))
      const child = Bun.spawn(
        [
          path.resolve(binary),
          "run",
          "--standalone",
          "--format",
          "json",
          "--model",
          model,
          "--title",
          "Local delivery smoke",
          "Run the fixture workflow.",
        ],
        {
          cwd: project,
          env: {
            ...cyberProfile(root, process.env),
            // CLI Location selection reads PWD; spawn's cwd does not update it.
            PWD: project,
            OPENCODE_TEST_HOME: root,
            OPENCODE_DISABLE_AUTOUPDATE: "1",
            OPENCODE_MODELS_PATH: path.join(root, "models.json"),
          },
          stdout: "pipe",
          stderr: "pipe",
        },
      )
      yield* Effect.addFinalizer(() => Effect.sync(() => child.kill()))
      const [code, stdout, stderr] = yield* Effect.promise(() =>
        Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]),
      ).pipe(Effect.timeout(120000))
      yield* Effect.promise(() => Bun.write(path.join(root, "stdout.jsonl"), stdout))
      yield* Effect.promise(() => Bun.write(path.join(root, "stderr.txt"), stderr))
      if (code !== 0) {
        console.error(stdout, stderr)
        throw new Error(`CLI exited ${code}; inspect ${root}`)
      }
      using archive = new Database(path.join(root, "data", "opencode", "opencyber", "evidence.sqlite"), {
        readonly: true,
      })
      const task = Schema.decodeUnknownSync(Schema.Struct({ status: Schema.String }))(
        archive.query("SELECT status FROM cyber_task WHERE key = 'delivery'").get(),
      )
      const execution = Schema.decodeUnknownSync(Schema.Struct({ status: Schema.String }))(
        archive.query("SELECT status FROM execution WHERE tool = 'cyber_services'").get(),
      )
      const finding = Schema.decodeUnknownSync(Schema.Struct({ status: Schema.String, revision: Schema.Number }))(
        archive.query("SELECT status, revision FROM finding WHERE id = 'reachable-service'").get(),
      )
      if (
        task.status !== "completed" ||
        execution.status !== "completed" ||
        finding.status !== (surfaces ? "confirmed" : "candidate") ||
        finding.revision !== (surfaces ? 2 : 1) ||
        step !== steps.length + 1
      )
        throw new Error(`Delivery acceptance failed; inspect ${root}`)
      console.log(`CLI ${surfaces ? "TCP and TLS" : "TCP"} workflow passed; artifacts retained at ${root}`)
    }),
  ),
)
