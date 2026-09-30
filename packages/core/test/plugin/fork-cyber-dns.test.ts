import { expect } from "bun:test"
import { Effect } from "effect"
import { createSocket } from "node:dgram"
import path from "node:path"
import { ForkCyberDns } from "@opencode/core/fork-cyber/dns"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"
import { it } from "../lib/effect"

const resolver = Effect.acquireRelease(
  Effect.promise(
    () =>
      new Promise<ReturnType<typeof createSocket>>((resolve) => {
        const socket = createSocket("udp4")
        socket.on("message", (request, peer) => {
          const labels: string[] = []
          let end = 12
          while (request[end]) {
            labels.push(request.subarray(end + 1, end + 1 + request[end]!).toString())
            end += request[end]! + 1
          }
          end += 5
          const host = labels.join(".")
          if (host === "timeout.test") return
          const header = Buffer.alloc(12)
          request.copy(header, 0, 0, 2)
          header.writeUInt16BE(host === "missing.test" ? 0x8183 : 0x8180, 2)
          header.writeUInt16BE(1, 4)
          const answer =
            host === "present.test"
              ? Buffer.concat([
                  Buffer.from([0xc0, 0x0c, 0x01, 0x01, 0, 1, 0, 0, 0, 60]),
                  Buffer.from([0, 22, 0, 5]),
                  Buffer.from("issuefixture-ca.test"),
                ])
              : Buffer.alloc(0)
          header.writeUInt16BE(answer.length ? 1 : 0, 6)
          socket.send(Buffer.concat([header, request.subarray(12, end), answer]), peer.port, peer.address)
        })
        socket.bind(0, "127.0.0.1", () => resolve(socket))
      }),
  ),
  (socket) => Effect.promise(() => new Promise<void>((resolve) => socket.close(() => resolve()))),
)

it.live(
  "bounded DNS fixture distinguishes CAA, empty records, NXDOMAIN, timeout and unauthorized hosts",
  () =>
    Effect.gen(function* () {
      const tmp = yield* tmpdirScoped()
      const store = yield* ForkCyberStore.open(path.join(tmp.path, "dns.sqlite"))
      const socket = yield* resolver
      const address = socket.address()
      const assessment = {
        owner: "dns",
        session: "dns",
        agent: "build",
        manifest: {
          engagement: "dns",
          authorized_by: "operator",
          authorization_ref: "local-udp-fixture",
          scope: { domains: ["present.test", "empty.test", "missing.test", "timeout.test"], cidrs: [], excluded: [] },
          rules_of_engagement: { no_dos: true, max_rps: 1, window: "fixture", contact: "operator" },
        },
      }
      const servers = [`127.0.0.1:${address.port}`]
      const present = yield* ForkCyberDns.run(store, assessment, { host: "present.test", type: "CAA" }, servers)
      expect(present.capture).toMatchObject({
        status: "present",
        records: [{ critical: 0, issue: "fixture-ca.test" }],
        ttl: "unavailable_from_resolver_api",
      })
      expect(
        (yield* ForkCyberDns.run(store, assessment, { host: "empty.test", type: "CAA" }, servers)).capture.status,
      ).toBe("no_records")
      expect(
        (yield* ForkCyberDns.run(store, assessment, { host: "missing.test", type: "CAA" }, servers)).capture.status,
      ).toBe("nxdomain")
      expect(
        (yield* ForkCyberDns.run(store, assessment, { host: "timeout.test", type: "CAA" }, servers)).capture.status,
      ).toBe("timeout")
      const denied = yield* ForkCyberDns.run(
        store,
        assessment,
        { host: "unauthorized.test", type: "CAA" },
        servers,
      ).pipe(Effect.result)
      expect(denied._tag).toBe("Failure")
      expect(yield* store.executions("dns")).toHaveLength(4)
    }),
  10000,
)
