import { expect, test } from "bun:test"
import { Cause, Effect, Exit, Fiber, Schema } from "effect"
import path from "node:path"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const assessment = {
  owner: "owner",
  session: "session",
  agent: "build",
  manifest: {
    engagement: "docker-lab",
    authorized_by: "operator",
    authorization_ref: "offline-fixture",
    scope: { domains: [], cidrs: [], excluded: [] },
    rules_of_engagement: {
      no_dos: true,
      max_rps: 1,
      window: "test",
      contact: "operator",
      network: {
        connections_per_second: 100,
        packets_per_second: 10000,
        bytes_per_job: 1024 * 1024,
        bytes_total: 10 * 1024 * 1024,
        duration_ms: 60000,
      },
    },
  },
}
const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip
const decode = Schema.decodeUnknownSync(ForkCyberKali.Config)

test("Kali configuration requires an immutable image and bounded resources; transfer names cannot escape /work", () => {
  const config = { image: `sha256:${"a".repeat(64)}`, network: { kind: "none" } } satisfies ForkCyberKali.Config
  expect(decode(config)).toEqual(config)
  expect(() => decode({ ...config, image: "opencyber-kali:latest" })).toThrow()
  expect(() => decode({ ...config, memory_mb: 0 })).toThrow()
  expect(() => decode({ ...config, network: { kind: "operator-managed", name: "audit" } })).toThrow()
  expect(() =>
    decode({ ...config, network: { kind: "operator-managed", name: "audit", control_ref: "old policy" } }),
  ).toThrow()
  const run = Schema.decodeUnknownSync(ForkCyberKali.Run)
  expect(() => run({ argv: [] })).toThrow()
  expect(() => run({ argv: ["true"], outputs: ["../evidence.sqlite"] })).toThrow()
  expect(() => run({ argv: ["true"], outputs: ["/tmp/file"] })).toThrow()
  expect(() => run({ argv: ["true"], timeout_ms: 900001 })).toThrow()
})

const fixture = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
  const manager = ForkCyberKali.manager(store, tmp.path, decode({ image, network: { kind: "none" } }))
  yield* Effect.addFinalizer(() => manager.cleanup(assessment.owner).pipe(Effect.orDie))
  return { store, manager, profile: tmp.path }
})

dockerTest(
  "real Kali preserves binary input/output and inventory after container deletion and store reopening",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const { store, manager, profile } = yield* fixture
          yield* store.start({ ...assessment, id: "seed", tool: "fixture", input: {} })
          const bytes = Buffer.from([0, 255, 13, 10, 128])
          const input = (yield* store.artifact(
            assessment.owner,
            "seed",
            "input",
            bytes,
            "application/octet-stream",
          ))[0]!.id
          yield* store.finish(assessment.owner, "seed", "completed", {})
          const result = yield* manager.run(assessment, {
            argv: ["sh", "-c", "cp source.bin result.bin; printf 'captured'; printf 'diagnostic' >&2"],
            inputs: [{ name: "source.bin", artifact: input }],
            outputs: ["result.bin"],
          })
          expect(result.exit_code).toBe(0)
          expect((yield* store.readArtifact(assessment.owner, result.stdout)).bytes.toString()).toBe("captured")
          expect((yield* store.readArtifact(assessment.owner, result.stderr)).bytes.toString()).toBe("diagnostic")
          expect(yield* manager.status(assessment.owner)).toEqual([])
          const reopened = yield* ForkCyberStore.open(path.join(profile, "evidence.sqlite"))
          expect((yield* reopened.readArtifact(assessment.owner, result.files![0]!.artifact)).bytes).toEqual(bytes)
          expect(
            (yield* reopened.artifacts(assessment.owner, result.execution)).some(
              (item) => item.kind === "kali.inventory",
            ),
          ).toBe(true)
          expect(Exit.isFailure(yield* reopened.readArtifact("other", result.stdout).pipe(Effect.exit))).toBe(true)
          const next = yield* manager.run(assessment, { argv: ["test", "!", "-e", "/work/source.bin"] })
          expect(next.exit_code).toBe(0)
        }),
      ),
    )
  },
  120000,
)

dockerTest(
  "real Kali denies external networking, host mounts, root writes and inherited provider credentials",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const { store, manager } = yield* fixture
          const script = `import os,socket,json
assert os.getuid()==1000
assert not os.path.exists('/var/run/docker.sock')
assert not any(k in os.environ for k in ['ANTHROPIC_API_KEY','OPENAI_API_KEY'])
assert os.statvfs('/work').f_blocks*os.statvfs('/work').f_frsize<=128*1024*1024
assert socket.if_nameindex()==[(1,'lo')]
assert open('/sys/fs/cgroup/memory.max').read().strip()=='536870912'
assert open('/sys/fs/cgroup/memory.swap.max').read().strip()=='0'
assert open('/sys/fs/cgroup/pids.max').read().strip()=='128'
assert open('/sys/fs/cgroup/cpu.max').read().strip()=='100000 100000'
try:
 open('/root-write','w')
 raise AssertionError('writable root')
except OSError: pass
s=socket.socket();s.settimeout(0.2)
assert s.connect_ex(('192.0.2.1',80))!=0
print('isolated')`
          const result = yield* manager.run(assessment, { argv: ["python3", "-c", script] })
          expect(result.exit_code).toBe(0)
          expect((yield* store.readArtifact(assessment.owner, result.stdout)).bytes.toString().trim()).toBe("isolated")
        }),
      ),
    )
  },
  120000,
)

const docker = (args: string[]) =>
  Effect.tryPromise(async () => {
    const process = Bun.spawn(["docker", ...args], { stdout: "pipe", stderr: "pipe" })
    const [stdout, stderr, code] = await Promise.all([
      new Response(process.stdout).text(),
      new Response(process.stderr).text(),
      process.exited,
    ])
    if (code !== 0) throw new Error(stderr)
    return stdout.trim()
  })

dockerTest(
  "scoped networking reaches an isolated fixture; stop cancels work without deleting another engagement",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const network = `opencyber-test-${crypto.randomUUID()}`
          yield* docker(["network", "create", "--internal", network])
          yield* Effect.addFinalizer(() => docker(["network", "rm", network]).pipe(Effect.orDie))
          const target = yield* docker([
            "run",
            "-d",
            "--rm",
            "--network",
            network,
            "--network-alias",
            "target",
            "--entrypoint",
            "python3",
            image!,
            "-m",
            "http.server",
            "8000",
            "--directory",
            "/opt/opencyber",
          ])
          yield* Effect.addFinalizer(() => docker(["rm", "-f", target]).pipe(Effect.orDie))
          const connected = ForkCyberKali.manager(
            env.store,
            env.profile,
            decode({
              image,
              network: { kind: "scoped", name: network },
            }),
          )
          const result = yield* connected.run(
            {
              ...assessment,
              manifest: { ...assessment.manifest, scope: { domains: ["target"], cidrs: [], excluded: [] } },
            },
            {
              argv: [
                "curl",
                "--fail",
                "--silent",
                "--retry",
                "3",
                "--retry-connrefused",
                "http://target:8000/packages.txt",
              ],
            },
          )
          expect(result.exit_code).toBe(0)
          expect((yield* env.store.readArtifact(assessment.owner, result.stdout)).bytes.toString()).toContain("nmap")
          const job = yield* connected.run(assessment, { argv: ["sleep", "30"] }).pipe(Effect.forkChild)
          yield* Effect.gen(function* () {
            while (
              !(yield* connected.status(assessment.owner)).some((item) => item.kind === "environment" && item.running)
            )
              yield* Effect.sleep(100)
          }).pipe(Effect.timeout(20000))
          expect((yield* connected.cleanup("another-owner")).removed).toEqual([])
          // A second client can inspect the environment while stop and the job finalizer remove it.
          yield* Effect.all(
            [
              connected.cleanup(assessment.owner),
              ...Array.from({ length: 8 }, () => env.manager.status(assessment.owner)),
            ],
            { concurrency: "unbounded" },
          )
          const stopped = yield* Fiber.await(job)
          expect(Exit.isFailure(stopped) && !Cause.hasDies(stopped.cause)).toBe(true)
          expect(yield* connected.status(assessment.owner)).toEqual([])
          expect((yield* env.store.executions(assessment.owner)).every((item) => item.status !== "running")).toBe(true)
          expect((yield* env.store.readArtifact(assessment.owner, result.stdout)).bytes.length).toBeGreaterThan(0)
        }),
      ),
    )
  },
  120000,
)

dockerTest(
  "real Kali timeout and output limits kill the environment and preserve partial evidence",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const { store, manager } = yield* fixture
          expect(
            Exit.isFailure(
              yield* manager
                .run(assessment, {
                  argv: ["sh", "-c", "printf 'before-timeout'; sleep 30"],
                  timeout_ms: 300,
                })
                .pipe(Effect.exit),
            ),
          ).toBe(true)
          expect(yield* manager.status(assessment.owner)).toEqual([])
          expect((yield* store.executions(assessment.owner))[0]!.status).toBe("error")
          expect(
            Exit.isFailure(
              yield* manager
                .run(assessment, {
                  argv: ["python3", "-c", "import sys; sys.stdout.buffer.write(b'x'*3000000)"],
                })
                .pipe(Effect.exit),
            ),
          ).toBe(true)
          expect(yield* manager.status(assessment.owner)).toEqual([])
          const archive = yield* store.exportArchive(assessment.owner)
          expect(archive.artifacts.some((artifact) => artifact.bytes === 2 * 1024 * 1024)).toBe(true)
        }),
      ),
    )
  },
  120000,
)

dockerTest(
  "real Kali rejects concurrent clients and cancellation removes descendants",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const { store, manager, profile } = yield* fixture
          const job = yield* manager.run(assessment, { argv: ["sh", "-c", "sleep 30 & wait"] }).pipe(Effect.forkChild)
          // Wait for the actual container, not a guessed startup delay.
          yield* Effect.gen(function* () {
            while (
              !(yield* manager.status(assessment.owner)).some((item) => item.kind === "environment" && item.running)
            )
              yield* Effect.sleep(100)
          }).pipe(Effect.timeout(20000))
          const other = ForkCyberKali.manager(store, profile, decode({ image, network: { kind: "none" } }))
          expect(Exit.isFailure(yield* other.run(assessment, { argv: ["true"] }).pipe(Effect.exit))).toBe(true)
          expect(yield* manager.status("another-engagement")).toEqual([])
          yield* Fiber.interrupt(job)
          expect(yield* manager.status(assessment.owner)).toEqual([])
          expect((yield* store.executions(assessment.owner)).every((execution) => execution.status === "error")).toBe(
            true,
          )
        }),
      ),
    )
  },
  120000,
)

dockerTest(
  "real Kali rejects symlink exports and archives nonzero exits as errors",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const { store, manager } = yield* fixture
          const result = yield* manager.run(assessment, { argv: ["sh", "-c", "echo failure >&2; exit 7"] })
          expect(result.exit_code).toBe(7)
          expect((yield* store.executions(assessment.owner))[0]!.status).toBe("error")
          expect(
            Exit.isFailure(
              yield* manager
                .run(assessment, {
                  argv: ["ln", "-s", "/etc/passwd", "/work/leak"],
                  outputs: ["leak"],
                })
                .pipe(Effect.exit),
            ),
          ).toBe(true)
          expect(yield* manager.status(assessment.owner)).toEqual([])
        }),
      ),
    )
  },
  120000,
)
