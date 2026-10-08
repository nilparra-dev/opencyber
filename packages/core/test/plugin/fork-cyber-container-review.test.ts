import { expect, test } from "bun:test"
import { Effect } from "effect"
import path from "node:path"
import { ForkCyberContainerReview } from "@opencode/core/fork-cyber/container-review"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { lab } from "../fixture/fork-cyber-http-lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const digest = "a".repeat(64)
const weakDockerfile = [
  "FROM node:latest AS build",
  "RUN curl -fsSL https://example.test/install.sh | sh",
  "ADD https://example.test/app.tar.gz /app/",
  "ENV API_KEY=supersecretvalue123",
  "EXPOSE 22",
].join("\n")
const hardenedDockerfile = [`FROM node:22-alpine@sha256:${digest}`, "USER app", "HEALTHCHECK CMD true"].join("\n")
const weakInspect = JSON.stringify([
  {
    Config: { User: "", Env: ["PATH=/usr/bin", "API_TOKEN=abc123xyz789"] },
    HostConfig: {
      Privileged: true,
      NetworkMode: "host",
      CapAdd: ["SYS_ADMIN"],
      Binds: ["/var/run/docker.sock:/var/run/docker.sock"],
      SecurityOpt: ["seccomp=unconfined"],
      ReadonlyRootfs: false,
    },
  },
])
const hardenedInspect = JSON.stringify([
  {
    Config: { User: "10001", Env: ["PATH=/usr/bin"] },
    HostConfig: { Privileged: false, NetworkMode: "bridge", CapAdd: null, Binds: null, ReadonlyRootfs: true },
  },
])

test("dockerfile lint reports the weak pattern at its line and never reports a secret value", () => {
  const result = ForkCyberContainerReview.dockerfileLint(weakDockerfile)
  expect(result.findings.map((finding) => [finding.rule, finding.line ?? null])).toEqual([
    ["mutable_base_image", 1],
    ["latest_base_image", 1],
    ["pipe_to_shell", 2],
    ["remote_add", 3],
    ["secret_in_build_definition", 4],
    ["ssh_exposed", 5],
    ["runs_as_root", null],
    ["no_healthcheck", null],
  ])
  expect(JSON.stringify(result)).not.toContain("supersecretvalue123")
})

test("a digest-pinned, non-root Dockerfile with a healthcheck has no findings", () => {
  expect(ForkCyberContainerReview.dockerfileLint(hardenedDockerfile).findings).toEqual([])
})

test("runtime review reports the weak configuration and never reports a credential value", () => {
  const result = ForkCyberContainerReview.runtimeReview(weakInspect)
  expect(result?.findings.map((finding) => finding.rule)).toEqual([
    "privileged",
    "host_network",
    "docker_socket_mount",
    "added_capabilities",
    "unconfined_profile",
    "writable_root_filesystem",
    "runs_as_root",
    "credential_environment",
  ])
  expect(JSON.stringify(result)).not.toContain("abc123xyz789")
})

test("a hardened container configuration has no runtime findings", () => {
  expect(ForkCyberContainerReview.runtimeReview(hardenedInspect)?.findings).toEqual([])
})

test("runtime review refuses documents that are not docker inspect exports", () => {
  expect(ForkCyberContainerReview.runtimeReview("FROM alpine")).toBeUndefined()
  expect(ForkCyberContainerReview.runtimeReview(JSON.stringify([]))).toBeUndefined()
})

test("a captured Dockerfile is reviewed from its artifact and the execution is recorded offline", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "container.sqlite"))
        const server = yield* lab((_request, response) => {
          response.writeHead(200, { "content-type": "text/plain" })
          response.end(weakDockerfile)
        })
        const resolve = () =>
          Effect.succeed({
            owner: "owner",
            session: "session",
            agent: "build",
            manifest: {
              engagement: "container-review",
              authorized_by: "operator",
              authorization_ref: "fixture",
              scope: { domains: ["127.0.0.1"], cidrs: [], excluded: [] },
              rules_of_engagement: { no_dos: true, max_rps: 100, window: "test", contact: "operator" },
            },
          })
        const hops = yield* ForkCyberHttp.run(store, resolve, { url: `${server.url}/Dockerfile` })
        const result = yield* ForkCyberContainerReview.runReview(
          store,
          { owner: "owner", session: "session", agent: "build" },
          { action: "dockerfile_lint", artifact: hops[0]!.capture.response_body },
        )
        const output = JSON.parse(result.content) as { execution: string; findings: unknown[] }
        expect(output.findings.length).toBe(8)
        const execution = (yield* store.executions("owner")).find((row) => row.id === output.execution)
        expect(execution?.tool).toBe("cyber_container")
      }),
    ),
  )
})
