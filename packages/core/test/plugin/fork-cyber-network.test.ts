import { expect, test } from "bun:test"
import { Database } from "bun:sqlite"
import { Effect, Exit, Schema } from "effect"
import path from "node:path"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip
const budget = {
  connections_per_second: 100,
  packets_per_second: 10000,
  bytes_per_job: 1024 * 1024,
  bytes_total: 20 * 1024 * 1024,
  duration_ms: 15000,
}
const assessment = {
  owner: "owner",
  session: "session",
  agent: "build",
  manifest: {
    engagement: "network-lab",
    authorized_by: "operator",
    authorization_ref: "local-fixture",
    scope: { domains: ["target", "blocked"], cidrs: [], excluded: ["blocked"] },
    rules_of_engagement: { no_dos: true, max_rps: 1, window: "fixture", contact: "operator", network: budget },
  },
}

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

const fixture = Effect.gen(function* () {
  const tmp = yield* tmpdirScoped()
  const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
  const network = `opencyber-network-${crypto.randomUUID()}`
  yield* docker([
    "network",
    "create",
    "--internal",
    "--ipv6",
    "--subnet",
    `fd42:${crypto.randomUUID().slice(0, 4)}::/64`,
    network,
  ])
  yield* Effect.addFinalizer(() => docker(["network", "rm", network]).pipe(Effect.orDie))
  const targets = yield* Effect.forEach(["target", "blocked"], (host) =>
    Effect.gen(function* () {
      const container = yield* docker([
        "run",
        "-d",
        "--rm",
        "--network",
        network,
        "--network-alias",
        host,
        "--entrypoint",
        "python3",
        image!,
        "-u",
        "-c",
        SERVER,
      ])
      yield* Effect.addFinalizer(() => docker(["rm", "-f", container]).pipe(Effect.orDie))
      yield* docker([
        "exec",
        container,
        "python3",
        "-c",
        "import socket,time\nfor i in range(100):\n s=socket.socket();s.settimeout(.1)\n if s.connect_ex(('127.0.0.1',8000))==0: break\n time.sleep(.05)\nelse: raise RuntimeError('fixture not ready')",
      ])
      const addresses = (yield* docker([
        "inspect",
        "--format",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.GlobalIPv6Address}}{{end}}",
        container,
      ])).split(" ")
      return { container, ipv4: addresses[0]!, ipv6: addresses[1]! }
    }),
  )
  const manager = ForkCyberKali.manager(
    store,
    tmp.path,
    Schema.decodeUnknownSync(ForkCyberKali.Config)({ image, network: { kind: "scoped", name: network } }),
  )
  yield* Effect.addFinalizer(() => manager.cleanup(assessment.owner).pipe(Effect.orDie))
  return { manager, store, targets }
})

test("schema 3 migration retains evidence and installs an empty persistent network budget", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        yield* Effect.scoped(
          Effect.gen(function* () {
            const store = yield* ForkCyberStore.open(file)
            yield* store.append("owner", "existing phase 6 evidence")
          }),
        )
        using database = new Database(file)
        database.run("DROP TABLE network_budget")
        database.run("PRAGMA user_version = 3")
        const migrated = yield* ForkCyberStore.open(file)
        expect((yield* migrated.notes("owner"))[0]?.content).toBe("existing phase 6 evidence")
        expect(yield* migrated.reserveNetwork("owner", 100, 100)).toBe(100)
        expect(database.query("PRAGMA user_version").get()).toEqual({ user_version: 7 })
      }),
    ),
  )
})

dockerTest(
  "CIDR scope honors exclusions and the manifest bounds raw job duration",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const scoped = {
            ...assessment,
            manifest: {
              ...assessment.manifest,
              scope: {
                domains: [],
                cidrs: ["0.0.0.0/0", "::/0"],
                excluded: [`${env.targets[1]!.ipv4}/32`, `${env.targets[1]!.ipv6}/128`],
              },
            },
          }
          const result = yield* env.manager.run(scoped, {
            argv: [
              "python3",
              "-c",
              `import socket,sys
for host,allowed in [(sys.argv[1],True),(sys.argv[2],False)]:
 s=socket.socket();s.settimeout(.3)
 assert (s.connect_ex((host,8000))==0)==allowed
 s.close()
print('CIDR verified')`,
              env.targets[0]!.ipv4,
              env.targets[1]!.ipv4,
            ],
          })
          expect(result.exit_code).toBe(0)
          const limited = {
            ...assessment,
            manifest: {
              ...assessment.manifest,
              rules_of_engagement: {
                ...assessment.manifest.rules_of_engagement,
                network: { ...budget, duration_ms: 300 },
              },
            },
          }
          expect(
            String(
              yield* env.manager
                .run(limited, { argv: ["sh", "-c", "printf 'started'; sleep 10"], timeout_ms: 10000 })
                .pipe(Effect.flip),
            ),
          ).toContain("timed out")
          expect(yield* env.manager.status("owner")).toEqual([])
        }),
      ),
    )
  },
  120000,
)

test("network limits require explicit positive integral quantities", () => {
  const decode = Schema.decodeUnknownSync(ForkCyberScope.Manifest)
  expect(decode(assessment.manifest)).toEqual(assessment.manifest)
  for (const field of Object.keys(budget))
    for (const value of [0, -1, 0.5, Infinity])
      expect(() =>
        decode({
          ...assessment.manifest,
          rules_of_engagement: { ...assessment.manifest.rules_of_engagement, network: { ...budget, [field]: value } },
        }),
      ).toThrow()
})

test("network reservations are shared across clients, survive reopening and cannot exceed the engagement total", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "evidence.sqlite")
        const first = yield* ForkCyberStore.open(file)
        const second = yield* ForkCyberStore.open(file)
        const attempts = yield* Effect.forEach(
          Array.from({ length: 8 }, (_, index) => index),
          (index) => (index % 2 ? first : second).reserveNetwork("owner", 100, 300).pipe(Effect.exit),
          { concurrency: 8 },
        )
        expect(attempts.filter(Exit.isSuccess)).toHaveLength(3)
        const reopened = yield* ForkCyberStore.open(file)
        expect(Exit.isFailure(yield* reopened.reserveNetwork("owner", 1, 300).pipe(Effect.exit))).toBe(true)
        expect(yield* reopened.reserveNetwork("other", 300, 300)).toBe(300)
        expect((yield* reopened.exportArchive("owner")).network_budget).toEqual([
          { owner: "owner", reserved_bytes: 300 },
        ])
        yield* reopened.purge("owner")
        expect((yield* reopened.exportArchive("owner")).network_budget).toEqual([])
        expect((yield* reopened.exportArchive("other")).network_budget).toEqual([
          { owner: "other", reserved_bytes: 300 },
        ])
      }),
    ),
  )
})

dockerTest(
  "scoped processes reach allowed IPv4/IPv6 but not exclusions, redirects, DNS or firewall controls",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const result = yield* env.manager.run(assessment, {
            argv: [
              "python3",
              "-c",
              PROBE,
              env.targets[0]!.ipv4,
              env.targets[0]!.ipv6,
              env.targets[1]!.ipv4,
              env.targets[1]!.ipv6,
            ],
          })
          expect((yield* env.store.readArtifact("owner", result.stderr)).bytes.toString()).toBe("")
          expect(result.exit_code).toBe(0)
          expect((yield* env.store.readArtifact("owner", result.stdout)).bytes.toString()).toContain(
            "boundaries verified",
          )
          expect(yield* docker(["exec", env.targets[1]!.container, "cat", "/tmp/requests"])).toBe("")
          const artifacts = yield* env.store.artifacts("owner", result.execution)
          expect(artifacts.some((item) => item.kind === "kali.network.policy")).toBe(true)
          expect(artifacts.some((item) => item.kind === "kali.network.counters")).toBe(true)
          expect(yield* env.manager.status("owner")).toEqual([])
        }),
      ),
    )
  },
  120000,
)

dockerTest(
  "byte quota limits a raw TCP download and the next job cannot reset the reserved total",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const limited = {
            ...assessment,
            manifest: {
              ...assessment.manifest,
              rules_of_engagement: {
                ...assessment.manifest.rules_of_engagement,
                network: { ...budget, bytes_per_job: 8192, bytes_total: 8192 },
              },
            },
          }
          const result = yield* env.manager.run(limited, {
            argv: [
              "python3",
              "-c",
              `import socket
s=socket.create_connection(('target',8000),timeout=1)
s.sendall(b'GET /large HTTP/1.0\\r\\nHost: target\\r\\n\\r\\n')
size=0
try:
 while True:
  data=s.recv(65536)
  if not data: break
  size+=len(data)
except TimeoutError: pass
assert size<8192,size
print('quota verified')`,
            ],
          })
          expect(result.exit_code).toBe(0)
          expect((yield* env.store.readArtifact("owner", result.stdout)).bytes.toString()).toContain("quota verified")
          expect(String(yield* env.manager.run(limited, { argv: ["true"] }).pipe(Effect.flip))).toContain(
            "budget exhausted",
          )
          expect(yield* env.manager.status("owner")).toEqual([])
        }),
      ),
    )
  },
  120000,
)

dockerTest(
  "connection and packet limits constrain concurrent raw clients",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const env = yield* fixture
          const limited = {
            ...assessment,
            manifest: {
              ...assessment.manifest,
              rules_of_engagement: {
                ...assessment.manifest.rules_of_engagement,
                network: { ...budget, connections_per_second: 1 },
              },
            },
          }
          const result = yield* env.manager.run(limited, {
            argv: [
              "python3",
              "-c",
              `import concurrent.futures,socket
def probe(i):
 s=socket.socket();s.settimeout(.3)
 result=s.connect_ex(('target',8000));s.close();return result==0
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool: count=sum(pool.map(probe,range(12)))
assert 1<=count<=2,count
print('connection rate verified')`,
            ],
          })
          expect((yield* env.store.readArtifact("owner", result.stderr)).bytes.toString()).toBe("")
          expect(result.exit_code).toBe(0)
          const packets = {
            ...assessment,
            manifest: {
              ...assessment.manifest,
              rules_of_engagement: {
                ...assessment.manifest.rules_of_engagement,
                network: { ...budget, packets_per_second: 2 },
              },
            },
          }
          const flood = yield* env.manager.run(packets, {
            argv: [
              "python3",
              "-c",
              "import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\nfor i in range(100):\n try: s.sendto(b'probe',('target',8001))\n except OSError: pass",
            ],
          })
          expect(flood.exit_code).toBe(0)
          const received = Number(
            yield* docker([
              "exec",
              env.targets[0]!.container,
              "python3",
              "-c",
              "print(len(open('/tmp/udp','rb').readlines()))",
            ]),
          )
          expect(received).toBeGreaterThan(0)
          expect(received).toBeLessThanOrEqual(2)
        }),
      ),
    )
  },
  120000,
)

const SERVER = `import http.server,socket,threading
open('/tmp/requests','w').close();open('/tmp/udp','w').close()
def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',8001))
 while True:
  s.recvfrom(65536)
  with open('/tmp/udp','a') as f: f.write('packet\\n')
threading.Thread(target=udp,daemon=True).start()
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  with open('/tmp/requests','a') as f: f.write(self.path+'\\n')
  self.send_response(302 if self.path=='/redirect' else 200)
  if self.path=='/redirect': self.send_header('Location','http://blocked:8000/denied')
  self.end_headers()
  try: self.wfile.write(b'x'*(4194304 if self.path=='/large' else 1))
  except OSError: pass
 def log_message(self,*args): pass
class Server(http.server.ThreadingHTTPServer): address_family=socket.AF_INET6
Server(('::',8000),Handler).serve_forever()
`

const PROBE = `import socket,subprocess,sys
def curl(url): return subprocess.run(['curl','--noproxy','*','--fail','--silent','--max-time','2','-L',url],capture_output=True).returncode
assert curl('http://target:8000/allowed')==0
assert curl('http://'+sys.argv[1]+':8000/ipv4')==0
assert curl('http://['+sys.argv[2]+']:8000/ipv6')==0
for host in ['blocked',sys.argv[3],'['+sys.argv[4]+']','[::ffff:'+sys.argv[3]+']','192.0.2.1']:
 assert curl('http://'+host+':8000/denied')!=0,host
assert curl('http://target:8000/redirect')!=0
assert subprocess.run(['nft','flush','ruleset'],capture_output=True).returncode!=0
assert subprocess.run(['dig','@127.0.0.11','target','+time=1','+tries=1'],capture_output=True).returncode!=0
print('boundaries verified')
`
