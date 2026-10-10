import { expect, test } from "bun:test"
import { Effect, Schedule } from "effect"
import { writeFile } from "node:fs/promises"
import path from "node:path"
import { ForkCyberDatabaseAuth } from "@opencode/core/fork-cyber/database-auth"
import { tmpdirScoped } from "../fixture/tmpdir"

// The probe script runs in the Kali image in production. These tests run it on the host Python so that the classes
// can be checked against a real Redis without a scoped network. Set OPENCYBER_TEST_PYTHON when python3 is not on PATH.
const python = process.env.OPENCYBER_TEST_PYTHON ?? "python3"
const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip
// Redis 7.2 pinned by digest, so the lab does not move under the test.
const redis = "redis@sha256:29e8589c3f9ba699b5f7aa4b3c7733c58852a3626439e619aa0ee78de08c6ca0"
const valid = "lab-valid-password"

const docker = (args: string[]) =>
  Effect.tryPromise(async () => {
    const child = Bun.spawn(["docker", ...args], { stdout: "pipe", stderr: "pipe" })
    const [stdout, stderr, code] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ])
    if (code !== 0) throw new Error(stderr)
    return stdout.trim()
  })

// Redis logs this line once it accepts connections; the port is published before that.
const ready = (id: string) =>
  docker(["logs", id]).pipe(
    Effect.filterOrFail((logs) => logs.includes("Ready to accept connections"), () => new Error("Redis is starting")),
    Effect.retry({ times: 100, schedule: Schedule.spaced(100) }),
  )

// A Redis on loopback, published on a random port and removed when the scope ends.
const startRedis = (command: string[]) =>
  Effect.gen(function* () {
    const id = yield* docker(["run", "-d", "--rm", "-p", "127.0.0.1::6379", redis, ...command])
    yield* Effect.addFinalizer(() => docker(["rm", "-f", id]).pipe(Effect.orDie))
    yield* ready(id)
    const published = yield* docker(["port", id, "6379"])
    return Number(published.split(":").at(-1))
  })

const probe = (directory: string, port: number, secret: string) =>
  Effect.tryPromise(async () => {
    const credential = path.join(directory, "credential")
    await writeFile(credential, secret)
    const child = Bun.spawn(
      [
        python,
        "-I",
        "-c",
        ForkCyberDatabaseAuth.PROBE,
        JSON.stringify({ engine: "redis", host: "127.0.0.1", port, timeout: 5, credential }),
      ],
      { cwd: directory, stdout: "pipe", stderr: "pipe" },
    )
    const [stdout, stderr, code] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ])
    const report = await Bun.file(path.join(directory, "auth.json")).text()
    return { code, stdout, stderr, report: JSON.parse(report) as { state: string } }
  })

dockerTest("the redis probe classifies valid, wrong, absent and closed services without printing the value", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const locked = yield* startRedis(["redis-server", "--requirepass", valid])
        const open = yield* startRedis([])
        const accepted = yield* probe(tmp.path, locked, valid)
        const rejected = yield* probe(tmp.path, locked, "wrong-password")
        const notRequired = yield* probe(tmp.path, open, valid)
        const closed = yield* probe(tmp.path, 1, valid)
        expect([accepted.report.state, rejected.report.state, notRequired.report.state, closed.report.state]).toEqual([
          "accepted",
          "rejected",
          "not_required",
          "closed",
        ])
        for (const result of [accepted, rejected, notRequired, closed]) {
          expect(result.code).toBe(0)
          expect(result.stdout + result.stderr).not.toContain(valid)
          expect(JSON.stringify(result.report)).not.toContain(valid)
        }
      }),
    ),
  )
}, 120000)
