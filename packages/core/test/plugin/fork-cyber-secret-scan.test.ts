import { expect, test } from "bun:test"
import { Effect } from "effect"
import path from "node:path"
import { ForkCyberCodeReview } from "@opencode/core/fork-cyber/code-review"
import { ForkCyberSecretScan } from "@opencode/core/fork-cyber/secret-scan"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

// Synthetic values in the documented shapes. None contains a placeholder marker, so each must be found.
const awsKey = "AKIAQ7XK2M4NB9VT3RZ8"
const githubToken = `ghp_${"q7Zx".repeat(10)}`
const password = "hunter2hunter2"

test("each credential pattern is found with its rule, line and a masked preview", () => {
  const text = [
    "const a = 1",
    `const key = "${awsKey}"`,
    `const token = "${githubToken}"`,
    `const db = { password: "${password}" }`,
    "-----BEGIN RSA PRIVATE KEY-----",
  ].join("\n")
  const findings = ForkCyberSecretScan.scan([{ file: "src/config.ts", text }])
  expect(findings.map((finding) => [finding.rule, finding.line])).toEqual([
    ["aws_access_key_id", 2],
    ["github_token", 3],
    ["credential_assignment", 4],
    ["private_key_block", 5],
  ])
  expect(findings.every((finding) => finding.file === "src/config.ts")).toBe(true)
})

test("findings never contain the value, only four leading characters and its length", () => {
  const findings = ForkCyberSecretScan.scan([{ file: "a.ts", text: `key = "${awsKey}"` }])
  const serialized = JSON.stringify(findings)
  expect(serialized).not.toContain(awsKey)
  expect(serialized).not.toContain(awsKey.slice(4))
  expect(findings[0]?.preview.startsWith("AKIA")).toBe(true)
  expect(findings[0]?.preview).toContain(`${awsKey.length} characters`)
})

test("the fingerprint identifies a repeated credential without naming it", () => {
  const findings = ForkCyberSecretScan.scan([
    { file: "a.ts", text: `k = "${awsKey}"` },
    { file: "b.ts", text: `k = "${awsKey}"` },
    { file: "c.ts", text: `k = "AKIAOTHERVALUE123456"` },
  ])
  expect(findings[0]?.fingerprint).toBe(findings[1]?.fingerprint)
  expect(findings[0]?.fingerprint).not.toBe(findings[2]?.fingerprint)
  expect(findings[0]?.fingerprint).toHaveLength(16)
})

test("placeholders and interpolation are not reported as credentials", () => {
  const text = [
    `password = "changeme-placeholder"`,
    `password = "your_password_here"`,
    `token = "\${TOKEN_FROM_ENV}"`,
    `api_key = "<api-key-value>"`,
    `key = "AKIAEXAMPLEEXAMPLE00"`,
  ].join("\n")
  expect(ForkCyberSecretScan.scan([{ file: "docs.md", text }])).toEqual([])
})

test("secrets action reports redacted findings from explicit files and keeps the value out of the output", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        yield* Effect.promise(() =>
          Bun.write(
            path.join(tmp.path, "config.ts"),
            `export const key = "${awsKey}"\nexport const password = "${password}"\n`,
          ),
        )
        const result = yield* ForkCyberCodeReview.run(
          store,
          { owner: "owner", session: "session", agent: "build", directory: tmp.path, permission: () => Effect.void },
          { action: "secrets", files: ["config.ts"] },
        )
        expect("findings" in result && result.findings?.map((finding) => finding.rule).sort()).toEqual([
          "aws_access_key_id",
          "credential_assignment",
        ])
        expect("coverage" in result && result.coverage).toContain("does not prove")
        expect(JSON.stringify(result)).not.toContain(awsKey)
        expect(JSON.stringify(result)).not.toContain(password)
      }),
    ),
  )
})
