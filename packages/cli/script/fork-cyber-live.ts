import { Database } from "bun:sqlite"
import { Schema } from "effect"
import { Credential } from "@opencode/schema/credential"
import { chmod, copyFile, mkdir, mkdtemp } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { cyberProfile } from "../src/fork-cyber-profile"

// Explicit, opt-in live-model smoke. Only synthetic loopback data reaches the provider.
// Usage: bun script/fork-cyber-live.ts <compiled binary> <credential database>
const binary = path.resolve(process.argv[2] ?? "")
const credentials = process.argv[3]
if (!process.argv[2] || !credentials) throw new Error("Expected compiled binary and credential database paths")
using source = new Database(credentials, { readonly: true })
const row = Schema.decodeUnknownSync(Schema.Struct({ value: Schema.String }))(
  source
    .query(
      "SELECT value FROM credential WHERE lower(integration_id) LIKE '%fireworks%' AND json_extract(value, '$.type') = 'key' ORDER BY active DESC LIMIT 1",
    )
    .get(),
)
const credential = Schema.decodeUnknownSync(Schema.fromJsonString(Credential.Key))(row.value)
const root = await mkdtemp(path.join(tmpdir(), "opencyber-live-"))
const project = path.join(root, "project")
await mkdir(project, { recursive: true })
await mkdir(path.join(root, "tmp"), { recursive: true })
const installed = path.join(root, "bin", process.platform === "win32" ? "opencyber.exe" : "opencyber")
await mkdir(path.dirname(installed), { recursive: true })
await copyFile(binary, installed)
await chmod(installed, 0o700)
const requests: string[] = []
const server = Bun.serve({
  hostname: "127.0.0.1",
  port: 0,
  fetch(request) {
    requests.push(new URL(request.url).pathname)
    return new Response(JSON.stringify({ fixture: "cyber-coordination", healthy: true }), {
      headers: { "content-type": "application/json" },
    })
  },
})
const manifest = {
  engagement: "compiled-live-coordination",
  authorized_by: "operator",
  authorization_ref: "local-smoke",
  scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
  rules_of_engagement: { no_dos: true, max_rps: 2, window: "local smoke", contact: "operator" },
}
await Bun.write(path.join(project, ".opencode", "cyber", "scope.jsonc"), JSON.stringify(manifest))
const model = "cyber-fireworks/deepseek-v4p1-flash"
await Bun.write(
  path.join(root, "config", "opencode", "opencode.json"),
  JSON.stringify({
    update: "disable",
    share: "disabled",
    model,
    providers: {
      "cyber-fireworks": {
        env: ["FIREWORKS_API_KEY"],
        package: "@opencode/ai/providers/fireworks",
        models: {
          "deepseek-v4p1-flash": {
            modelID: "accounts/fireworks/models/deepseek-v4p1-flash",
            name: "DeepSeek V4.1 Flash",
            capabilities: { tools: true, input: ["text"], output: ["text"] },
            compatibility: { reasoningField: "reasoning_content", maxTokensField: "max_tokens" },
            limit: { context: 1048576, output: 4096 },
            body: { max_tokens: 4096 },
          },
        },
      },
    },
    agents: {
      build: {
        steps: 8,
        permissions: [
          { action: "*", resource: "*", effect: "deny" },
          ...["engagement", "cyber_tasks", "cyber_coverage", "evidence", "subagent"].map((action) => ({
            action,
            resource: "*",
            effect: "allow",
          })),
        ],
      },
      "cyber-recon": { steps: 8 },
    },
  }),
)
const prompt = `Run a small coordination smoke test, with no source edits and no shell commands.
The project manifest explicitly authorizes the local fixture ${server.url.href}.
1. Create exactly one cyber_tasks task with key "live-http", asset "${server.url.href}", procedure "GET /probe once and record its response", phase "cyber-recon".
2. Delegate that task to the cyber-recon subagent in the foreground. Tell it to read the task, claim its current revision, call http_request GET ${server.url.href}probe exactly once, then complete the task using the returned output evidence ID, outcome observed and a factual rationale. Tell it not to create any other tasks, use shell, or make any other network requests.
3. Read cyber_coverage and report whether live-http is completed with evidence. Do not claim success without recorded completion.
Use only the supplied local fixture. Stop after reporting the result.`
console.log(`Live smoke: ${model}; profile ${root}`)
const child = Bun.spawn(
  [installed, "run", "--standalone", "--format", "json", "--model", model, "--title", "CY-10 local smoke", prompt],
  {
    cwd: project,
    env: {
      ...cyberProfile(root, process.env),
      OPENCODE_TEST_HOME: root,
      OPENCODE_DISABLE_AUTOUPDATE: "1",
      FIREWORKS_API_KEY: credential.key,
    },
    stdout: "pipe",
    stderr: "pipe",
  },
)
const timer = setTimeout(() => child.kill(), 240000)
try {
  const [code, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ])
  await Bun.write(path.join(root, "stdout.jsonl"), stdout)
  await Bun.write(path.join(root, "stderr.txt"), stderr)
  if (code !== 0) throw new Error(`CLI exited ${code}; inspect ${root}`)
  using archive = new Database(path.join(root, "data", "opencode", "opencyber", "evidence.sqlite"), { readonly: true })
  const tasks = Schema.decodeUnknownSync(
    Schema.Array(Schema.Struct({ key: Schema.String, status: Schema.String, agent: Schema.NullOr(Schema.String) })),
  )(archive.query("SELECT key, status, agent FROM cyber_task").all())
  const evidence = archive.query("SELECT * FROM cyber_task_evidence WHERE task = 'live-http'").all()
  const executions = archive.query("SELECT tool, status FROM execution").all()
  const result = { model, requests, tasks, evidence_count: evidence.length, executions }
  await Bun.write(path.join(root, "result.json"), JSON.stringify(result, null, 2))
  if (
    tasks.length !== 1 ||
    tasks[0]?.key !== "live-http" ||
    tasks[0]?.status !== "completed" ||
    tasks[0]?.agent !== "cyber-recon" ||
    evidence.length !== 1 ||
    requests.length !== 1 ||
    requests[0] !== "/probe"
  )
    throw new Error(`Coordination acceptance failed; inspect ${root}/result.json and stdout.jsonl`)
  console.log(JSON.stringify(result, null, 2))
  console.log(`Compiled live coordination passed; evidence retained at ${root}`)
} finally {
  clearTimeout(timer)
  child.kill()
  await server.stop(true)
}
