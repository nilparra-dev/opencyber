import { expect, test } from "bun:test"
import { Schema } from "effect"
import { compileFunction } from "node:vm"

// Exercise the exact script shipped to github-script. Only the remote API is substituted.
const workflow = Schema.decodeUnknownSync(
  Schema.Struct({
    jobs: Schema.Struct({
      recover: Schema.Struct({
        steps: Schema.Array(Schema.Struct({ with: Schema.Struct({ script: Schema.String }) })),
      }),
    }),
  }),
)(
  Bun.YAML.parse(
    await Bun.file(new URL("../../../.github/workflows/fork-runner-recovery.yml", import.meta.url)).text(),
  ),
)
const execute = compileFunction(`return (async () => {${workflow.jobs.recover.steps[0].with.script}})()`, [
  "github",
  "context",
  "core",
])

// The cancelled plan and skipped dependants match release run 37362712044, attempt 1.
const snapshot = {
  workflow: "fork-release.yml",
  run: {
    id: 37362712044,
    status: "completed",
    conclusion: "failure",
    head_sha: "a869de175a8108b9fd95c63bde08c88d9985592d",
    run_attempt: 1,
    html_url: "https://github.com/nilparra-dev/opencyber/actions/runs/37362712044",
  },
  jobs: [
    {
      conclusion: "cancelled",
      steps: new Array<unknown>(),
      check_run_url: "https://api.github.com/repos/nilparra-dev/opencyber/check-runs/111940888004",
    },
    { conclusion: "skipped", steps: new Array<unknown>(), check_run_url: "" },
    { conclusion: "skipped", steps: new Array<unknown>(), check_run_url: "" },
  ],
  annotations: [
    {
      annotation_level: "failure",
      message: "The job was not acquired by Runner of type hosted even after multiple attempts",
    },
    { annotation_level: "notice", message: "The ubuntu-latest label will migrate to Ubuntu 26" },
  ],
}

async function recover(
  input: Partial<Pick<typeof snapshot, "workflow" | "run">> & {
    jobs?: readonly { conclusion: string; steps: readonly unknown[]; check_run_url: string }[]
    annotations?: readonly (typeof snapshot.annotations)[number][]
  } = {},
) {
  const data = { ...snapshot, ...input }
  const reruns: { owner: string; repo: string; run_id: number }[] = []
  const reads: unknown[] = []
  const warnings: string[] = []
  const notices: string[] = []
  await execute(
    {
      rest: {
        repos: { getBranch: async () => ({ data: { commit: { sha: snapshot.run.head_sha } } }) },
        actions: {
          listWorkflowRuns: async (request: { workflow_id: string }) => ({
            data: { workflow_runs: request.workflow_id === data.workflow ? [snapshot.run] : [] },
          }),
          getWorkflowRun: async () => ({ data: data.run }),
          listJobsForWorkflowRunAttempt: () => data.jobs,
          reRunWorkflow: async (request: (typeof reruns)[number]) => reruns.push(request),
        },
        checks: { listAnnotations: () => data.annotations },
      },
      paginate: async (method: () => typeof data.jobs | typeof data.annotations, request: unknown) => {
        reads.push(request)
        return method()
      },
    },
    { repo: { owner: "nilparra-dev", repo: "opencyber" } },
    { warning: (message: string) => warnings.push(message), notice: (message: string) => notices.push(message) },
  )
  return { reruns, reads, warnings, notices }
}

test.each(["fork-release.yml", "fork-sync.yml"])("recovers runner acquisition failures in %s", async (workflow) => {
  const result = await recover({ workflow })
  expect(result.reruns).toEqual([{ owner: "nilparra-dev", repo: "opencyber", run_id: snapshot.run.id }])
  expect(result.reads).toContainEqual({
    owner: "nilparra-dev",
    repo: "opencyber",
    run_id: snapshot.run.id,
    attempt_number: 1,
    per_page: 100,
  })
  expect(result.reads).toContainEqual({
    owner: "nilparra-dev",
    repo: "opencyber",
    check_run_id: 111940888004,
    per_page: 100,
  })
  expect(result.notices[0]).toContain("attempt 2/3 on the same commit")
})

test("uses the current run attempt and stops after two automatic retries", async () => {
  const result = await recover({ run: { ...snapshot.run, run_attempt: 2 } })
  expect(result.reruns).toHaveLength(1)
  expect(result.reads[0]).toMatchObject({ attempt_number: 2 })
  expect(result.notices[0]).toContain("attempt 3/3")
  const exhausted = await recover({ run: { ...snapshot.run, run_attempt: 3 } })
  expect(exhausted.reruns).toEqual([])
  expect(exhausted.warnings[0]).toContain(snapshot.run.html_url)
})

test.each([
  { status: "in_progress", conclusion: "failure" },
  { status: "completed", conclusion: "success" },
  { status: "completed", conclusion: "cancelled" },
])("ignores superseded or active runs: %p", async (state) => {
  expect((await recover({ run: { ...snapshot.run, ...state } })).reruns).toEqual([])
})

test("does not publish an older commit after custom advances", async () => {
  expect((await recover({ run: { ...snapshot.run, head_sha: "older-commit" } })).reruns).toEqual([])
})

test("does not repeat a publication or any other step that started", async () => {
  const result = await recover({
    jobs: [
      ...snapshot.jobs,
      { conclusion: "cancelled", steps: [{ name: "Create release", conclusion: "success" }], check_run_url: "" },
    ],
  })
  expect(result.reruns).toEqual([])
  expect(result.reads).toHaveLength(1)
})

test("does not retry tests or workflow errors even alongside a runner failure", async () => {
  const result = await recover({
    jobs: [...snapshot.jobs, { conclusion: "failure", steps: [], check_run_url: "" }],
  })
  expect(result.reruns).toEqual([])
})

test.each([{ jobs: [] }, { jobs: [{ conclusion: "skipped", steps: [], check_run_url: "" }] }])(
  "requires a cancelled job rather than an empty or entirely skipped run: %p",
  async (input) => {
    expect((await recover(input)).reruns).toEqual([])
  },
)

test.each([
  { annotations: [] },
  { annotations: [{ annotation_level: "failure", message: "Billing limit exceeded" }] },
  { annotations: [{ annotation_level: "notice", message: snapshot.annotations[0].message }] },
])("requires the precise infrastructure failure annotation: %p", async (input) => {
  expect((await recover(input)).reruns).toEqual([])
})
