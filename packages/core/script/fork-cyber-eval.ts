// Willingness eval: runs every task in the fork-cyber suite against a live model
// through the real CLI and reports how often the model refuses under the
// operator/engagement layer.
//
//   cd packages/core && bun run script/fork-cyber-eval.ts <provider/model> [timeoutSeconds]
//
// The CLI runs in the repository root so the .opencode/plugin/fork-cyber entry is
// active and the engagement layer is in effect. The report lands in reports/,
// which stays local (F-012).

import { ForkCyberEvalSuite } from "../src/fork-cyber/eval-suite.js"
import { ForkCyberRefusal } from "../src/fork-cyber/refusal.js"
import { Schema } from "effect"
import path from "path"

const model = process.argv[2]
if (!model) {
  console.error("usage: (cd packages/core &&) bun run script/fork-cyber-eval.ts <provider/model> [timeoutSeconds]")
  process.exit(1)
}
const timeoutMs = (Number(process.argv[3]) || 180) * 1000
const root = path.resolve(import.meta.dir, "../../..")
// CYBER_EVAL_LABEL distinguishes A/B runs of the same model (e.g. an adapter tweak).
const label = process.env.CYBER_EVAL_LABEL?.trim()
const suffix = label ? `-${label.replace(/[^a-z0-9.-]/gi, "_")}` : ""
const out = path.join(root, "reports", `cyber-eval-${model.replace(/[^a-z0-9.-]/gi, "_")}${suffix}.md`)
const decode = Schema.decodeUnknownOption(Schema.fromJsonString(Schema.Unknown))

const rows: Array<{ id: string; refusal: boolean; chars: number; seconds: number; errors: string[] }> = []
for (const task of ForkCyberEvalSuite.tasks) {
  const started = Date.now()
  const proc = Bun.spawn(
    [
      "bun",
      "run",
      "--cwd",
      "packages/cli",
      "src/index.ts",
      "run",
      "--auto",
      "--format",
      "json",
      "--model",
      model,
      task.prompt,
    ],
    { cwd: root, stdout: "pipe", stderr: "pipe" },
  )
  const timer = setTimeout(() => proc.kill(), timeoutMs)
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  const exitCode = await proc.exited
  clearTimeout(timer)
  const parsed = collect(stdout)
  const text = parsed.text
  const refusal = ForkCyberRefusal.isRefusal(text)
  const seconds = Math.round((Date.now() - started) / 1000)
  rows.push({
    id: task.id,
    refusal,
    chars: text.length,
    seconds,
    errors: [
      ...parsed.errors,
      ...(exitCode === 0 ? [] : [`exit ${exitCode}`]),
      ...(stderr.trim() ? [truncate(stderr)] : []),
    ],
  })
  console.error(`${refusal ? "REFUSAL" : "ok"}      ${task.id} (${text.length} chars, ${seconds}s)`)
}

const refusals = rows.filter((row) => row.refusal).length
const rate = ((refusals / rows.length) * 100).toFixed(1)
const report = [
  `# Cyber willingness eval — ${model}${label ? ` (${label})` : ""}`,
  "",
  `Tasks: ${rows.length} · refusals: ${refusals} (${rate}%)`,
  "",
  "| task | result | chars | seconds | notes |",
  "|---|---|---|---|---|",
  ...rows.map(
    (row) =>
      `| ${row.id} | ${row.refusal ? "refusal" : "ok"} | ${row.chars} | ${row.seconds} | ${row.errors.join("; ").replaceAll("|", "\\|")} |`,
  ),
  "",
].join("\n")
await Bun.write(out, report)
console.error(`refusal rate: ${rate}% (${refusals}/${rows.length}) → ${out}`)

// The CLI emits one JSON event per line; the assistant text arrives as `text`
// events. Anything unparseable is ignored instead of failing the whole run.
function collect(stdout: string) {
  const chunks: string[] = []
  const errors: string[] = []
  for (const line of stdout.split(/\r?\n/)) {
    if (!line.trim()) continue
    const event = decode(line)
    if (event._tag === "None") continue
    if (!isRecord(event.value)) continue
    if (event.value.type === "text" && isRecord(event.value.part) && typeof event.value.part.text === "string") {
      chunks.push(event.value.part.text)
    }
    if (event.value.type === "error" && isRecord(event.value.error) && typeof event.value.error.message === "string") {
      errors.push(event.value.error.message)
    }
  }
  return { text: chunks.join(""), errors }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}

function truncate(value: string) {
  return value.trim().slice(0, 200)
}
