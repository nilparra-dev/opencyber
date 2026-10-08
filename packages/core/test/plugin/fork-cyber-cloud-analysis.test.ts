import { expect, test } from "bun:test"
import { Effect } from "effect"
import path from "node:path"
import { ForkCyberCloudAnalysis } from "@opencode/core/fork-cyber/cloud-analysis"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { lab } from "../fixture/fork-cyber-http-lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const page = { offset: 0, limit: 50 }
const policy = JSON.stringify({
  Version: "2012-10-17",
  Statement: [
    { Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::reports/*" },
    { Effect: "Allow", Action: "*", Resource: "*" },
    { Effect: "Allow", Action: ["ec2:*"], Resource: "arn:aws:ec2:eu-west-1:123:instance/i-1" },
    { Effect: "Deny", Action: "*", Resource: "*" },
    { Effect: "Allow", NotAction: "iam:*", Resource: "arn:aws:s3:::bucket" },
    { Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::pub/*", Principal: "*" },
    { Effect: "Allow", Action: "s3:GetObject", Resource: "arn:aws:s3:::pub/*", Principal: { AWS: "*" } },
    { Effect: "Allow", Action: "iam:CreateAccessKey", Resource: "*" },
    { Effect: "Allow", Action: "sts:AssumeRole", Resource: "arn:aws:iam::123:role/deploy" },
  ],
})

test("iam analysis points each finding at its statement and ignores deny statements", () => {
  const result = ForkCyberCloudAnalysis.iamAnalyze(policy, page)
  expect(result).toMatchObject({ format: "iam_policy", statement_count: 9, finding_count: 8, next_offset: null })
  expect(result?.findings.map((finding) => [finding.flag, finding.pointer])).toEqual([
    ["wildcard_action", "/Statement/1/Action"],
    ["wildcard_resource", "/Statement/1/Resource"],
    ["wildcard_action", "/Statement/2/Action"],
    ["not_action_allow", "/Statement/4/NotAction"],
    ["public_principal", "/Statement/5/Principal"],
    ["public_principal", "/Statement/6/Principal"],
    ["wildcard_resource", "/Statement/7/Resource"],
    ["privilege_escalation_candidate", "/Statement/7/Action"],
  ])
  expect(result?.findings.some((finding) => finding.pointer.startsWith("/Statement/3/"))).toBe(false)
  expect(result?.findings.some((finding) => finding.pointer.startsWith("/Statement/0/"))).toBe(false)
  // sts:AssumeRole scoped to one role is not a candidate: its resource is specific.
  expect(result?.findings.some((finding) => finding.pointer.startsWith("/Statement/8/"))).toBe(false)
})

test("a single statement document is analyzed with a document-level pointer", () => {
  const result = ForkCyberCloudAnalysis.iamAnalyze(
    JSON.stringify({ Statement: { Effect: "Allow", Action: "*", Resource: "*" } }),
    page,
  )
  expect(result?.findings.map((finding) => [finding.flag, finding.pointer])).toEqual([
    ["wildcard_action", "/Statement/Action"],
    ["wildcard_resource", "/Statement/Resource"],
  ])
})

test("service-wide wildcards and public principals inside an AWS list are both reported", () => {
  const result = ForkCyberCloudAnalysis.iamAnalyze(
    JSON.stringify({
      Statement: [
        {
          Effect: "Allow",
          Action: "s3:*",
          Resource: "arn:aws:s3:::b",
          Principal: { AWS: ["arn:aws:iam::1:root", "*"] },
        },
      ],
    }),
    page,
  )
  expect(result?.findings.map((finding) => finding.flag)).toEqual(["wildcard_action", "public_principal"])
})

test("findings are paginated and a document that is not a policy is refused", () => {
  const first = ForkCyberCloudAnalysis.iamAnalyze(policy, { offset: 0, limit: 4 })
  expect(first?.findings).toHaveLength(4)
  expect(first?.next_offset).toBe(4)
  expect(first?.findings.map((finding) => finding.pointer)).toEqual([
    "/Statement/1/Action",
    "/Statement/1/Resource",
    "/Statement/2/Action",
    "/Statement/4/NotAction",
  ])
  const second = ForkCyberCloudAnalysis.iamAnalyze(policy, { offset: 4, limit: 4 })
  expect(second?.findings).toHaveLength(4)
  expect(ForkCyberCloudAnalysis.iamAnalyze("<html>", page)).toBeUndefined()
  expect(ForkCyberCloudAnalysis.iamAnalyze(JSON.stringify({ Version: "2012-10-17" }), page)).toBeUndefined()
})

test("the analysis reads an imported policy artifact and records the execution offline", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "cloud.sqlite"))
        const server = yield* lab((_request, response) => {
          response.writeHead(200, { "content-type": "application/json" })
          response.end(policy)
        })
        const resolve = () =>
          Effect.succeed({
            owner: "owner",
            session: "session",
            agent: "build",
            manifest: {
              engagement: "cloud-analysis",
              authorized_by: "operator",
              authorization_ref: "fixture",
              scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
              rules_of_engagement: { no_dos: true, max_rps: 100, window: "test", contact: "operator" },
            },
          })
        const hops = yield* ForkCyberHttp.run(store, resolve, { url: `${server.url}/policy.json` })
        const result = yield* ForkCyberCloudAnalysis.runIamAnalyze(
          store,
          { owner: "owner", session: "session", agent: "build" },
          { action: "iam_analyze", artifact: hops[0]!.capture.response_body },
        )
        const output = JSON.parse(result.content) as { finding_count: number; execution: string; provenance?: unknown }
        expect(output.finding_count).toBe(8)
        const executions = yield* store.executions("owner")
        expect(executions.find((execution) => execution.id === output.execution)?.tool).toBe("cyber_cloud")
        expect(yield* store.readArtifact("owner", hops[0]!.capture.response_body).pipe(Effect.map(() => true))).toBe(
          true,
        )
      }),
    ),
  )
})
