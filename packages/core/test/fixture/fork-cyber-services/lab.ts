export * as ForkCyberServicesLab from "./lab.js"

import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../tmpdir"

export const assessment = {
  owner: "services-lab",
  session: "services-lab",
  agent: "cyber-enum",
  manifest: {
    engagement: "tcp-services-lab",
    authorized_by: "operator",
    authorization_ref: "internal-docker-fixture",
    scope: { domains: ["target"], cidrs: [], excluded: ["127.0.0.1"] },
    rules_of_engagement: {
      no_dos: true,
      max_rps: 1,
      window: "fixture",
      contact: "operator",
      network: {
        connections_per_second: 10,
        packets_per_second: 1000,
        bytes_per_job: 1024 * 1024,
        bytes_total: 10 * 1024 * 1024,
        duration_ms: 15000,
      },
    },
  },
}

export const docker = (args: string[], stdin?: string) =>
  Effect.tryPromise(async () => {
    const child = Bun.spawn(["docker", ...args], {
      stdin: stdin === undefined ? "ignore" : Buffer.from(stdin),
      stdout: "pipe",
      stderr: "pipe",
    })
    const [stdout, stderr, code] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ])
    if (code !== 0) throw new Error(stderr)
    return stdout.trim()
  })

export const open = (image: string) =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped("opencyber-services-")
    const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
    const network = `opencyber-services-${crypto.randomUUID()}`
    yield* docker([
      "network",
      "create",
      "--internal",
      "--ipv6",
      "--subnet",
      `fd43:${crypto.randomUUID().slice(0, 4)}::/64`,
      network,
    ])
    yield* Effect.addFinalizer(() => docker(["network", "rm", network]).pipe(Effect.orDie))
    const container = yield* docker([
      "run",
      "-d",
      "--rm",
      "--network",
      network,
      "--network-alias",
      "target",
      "--entrypoint",
      "python3",
      image,
      "-u",
      "-c",
      `import socket
server=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
server.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
server.bind(('::',8000));server.listen()
while True:
    client,_=server.accept()
    with client:
        client.sendall(b'OpenCyber synthetic management listener\\n')
`,
    ])
    yield* Effect.addFinalizer(() => docker(["rm", "-f", container]).pipe(Effect.orDie))
    yield* docker([
      "exec",
      container,
      "python3",
      "-I",
      "-c",
      `import socket,time
for _ in range(100):
    try:
        with socket.create_connection(('127.0.0.1',8000),.1) as client:
            assert b'synthetic management' in client.recv(128)
        break
    except OSError: time.sleep(.05)
else: raise RuntimeError('Service lab did not start')
`,
    ])
    const addresses = (yield* docker([
      "inspect",
      "--format",
      "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.GlobalIPv6Address}}{{end}}",
      container,
    ])).split(" ")
    const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({ image, network: { kind: "scoped", name: network } })
    const manager = ForkCyberKali.manager(store, tmp.path, config)
    yield* Effect.addFinalizer(() => manager.cleanup(assessment.owner).pipe(Effect.orDie))
    yield* store.coordination.run(
      { ...assessment, agent: "build" },
      {
        action: "create",
        key: "management-exposure",
        asset: "target:8000,8001",
        procedure: "TCP connect inventory",
        phase: "cyber-enum",
        hypothesis: "The synthetic management listener is reachable; the closed control is not",
      },
    )
    yield* store.coordination.run(assessment, { action: "claim", key: "management-exposure", revision: 1 })
    return { store, config, profile: tmp.path, ipv4: addresses[0]!, ipv6: addresses[1]! }
  })
