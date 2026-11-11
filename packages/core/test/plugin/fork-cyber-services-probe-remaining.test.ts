import { expect, test } from "bun:test"
import { Effect, Schedule, Schema } from "effect"
import path from "node:path"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberServices } from "@opencode/core/fork-cyber/services"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberServicesLab } from "../fixture/fork-cyber-services/lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const mongoImage = process.env.OPENCYBER_TEST_MONGO_IMAGE
const dockerTest = image ? test : test.skip
const mongoTest = image && mongoImage ? test : test.skip

const scope = (overrides: { cidrs?: string[]; excluded?: string[] } = {}) =>
  Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
    engagement: "services-probe-remaining-test",
    authorized_by: "operator",
    authorization_ref: "fixture",
    scope: { domains: [], cidrs: overrides.cidrs ?? ["10.20.50.0/29"], excluded: overrides.excluded ?? [] },
    rules_of_engagement: {
      no_dos: true,
      max_rps: 10,
      window: "test",
      contact: "operator",
      // Each job reserves its full byte allowance, so the lab budget covers the retries below.
      network: {
        connections_per_second: 10,
        packets_per_second: 1000,
        bytes_per_job: 1024 * 1024,
        bytes_total: 64 * 1024 * 1024,
        duration_ms: 60000,
      },
    },
  })

const scoped = Schema.decodeUnknownSync(ForkCyberKali.Config)({
  image: `sha256:${"0".repeat(64)}`,
  network: { kind: "scoped", name: "services-probe-remaining-test" },
})

test("the remaining probe checks are typed; anonymous FTP login is not an accepted check", () => {
  const valid = Schema.is(ForkCyberServices.Action)
  expect(
    ["ldap_root_dse", "smb_signing", "nfs_exports", "mongodb_build_info"].map((check) =>
      valid({ action: "probe", host: "10.20.50.2", port: 389, check }),
    ),
  ).toEqual([true, true, true, true])
  expect(valid({ action: "probe", host: "10.20.50.2", port: 21, check: "ftp_anonymous" })).toBe(false)
  expect(ForkCyberServices.procedures.probe.implemented).toEqual([
    "redis_info",
    "elasticsearch_root",
    "ldap_root_dse",
    "smb_signing",
    "nfs_exports",
    "mongodb_build_info",
  ])
  expect(ForkCyberServices.procedures.probe.not_implemented).toEqual(["ftp_anonymous"])
})

test("every remaining probe check is a scoped R1 action in the decision function", () => {
  const decide = (check: string) =>
    ForkCyberDecision.decide({
      mode: "development",
      agent: "build",
      tool: "cyber_services",
      input: { action: "probe", host: "10.20.50.2", port: 389, check },
    })
  const checks = ["ldap_root_dse", "smb_signing", "nfs_exports", "mongodb_build_info"]
  checks.forEach((check) => expect(decide(check)).toMatchObject({ risk: "R1" }))
})

test("refused remaining probes name their reason and start no Kali job", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
        const actor = { owner: "owner", session: "session", agent: "build", manifest: scope() }
        const probe = (who: typeof actor, host: string, family?: "ipv4" | "ipv6") =>
          ForkCyberServices.probe(store, tmp.path, scoped, who, {
            action: "probe",
            host,
            port: 1389,
            check: "ldap_root_dse",
            family,
          }).pipe(Effect.flip)
        expect(String(yield* probe(actor, "10.20.51.2"))).toContain("outside the recorded scope")
        expect(
          String(yield* probe({ ...actor, manifest: scope({ excluded: ["10.20.50.3"] }) }, "10.20.50.3")),
        ).toContain("excluded")
        expect(String(yield* probe(actor, "10.20.50.2", "ipv6"))).toContain("address family")
        expect(yield* store.executions("owner")).toEqual([])
      }),
    ),
  )
})

dockerTest(
  "synthetic LDAP, SMB and NFS responders report their known states",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "remaining.sqlite"))
          const octet = 20 + Math.floor(Math.random() * 200)
          const subnet = `10.${octet}.0.0/29`
          const live = `10.${octet}.0.2`
          const name = `opencyber-probes-remaining-${crypto.randomUUID()}`
          yield* ForkCyberServicesLab.docker(["network", "create", "--internal", "--subnet", subnet, name])
          yield* Effect.addFinalizer(() => ForkCyberServicesLab.docker(["network", "rm", name]).pipe(Effect.orDie))
          const container = yield* ForkCyberServicesLab.docker([
            "run",
            "-d",
            "--rm",
            "--network",
            name,
            "--ip",
            live,
            "--entrypoint",
            "python3",
            image!,
            "-u",
            "-c",
            LAB,
          ])
          yield* Effect.addFinalizer(() => ForkCyberServicesLab.docker(["rm", "-f", container]).pipe(Effect.orDie))
          // The lab process needs a moment to bind its listeners after the container starts.
          yield* Effect.promise(() => Bun.sleep(1500))
          const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({
            image: image!,
            network: { kind: "scoped", name },
          })
          const actor = { owner: "owner", session: "session", agent: "build", manifest: scope({ cidrs: [subnet] }) }
          const check = (port: number, which: "ldap_root_dse" | "smb_signing" | "nfs_exports") =>
            ForkCyberServices.probe(store, tmp.path, config, actor, {
              action: "probe",
              host: live,
              port,
              check: which,
            }).pipe(Effect.map((result) => result.capture!))

          const ldapOpen = yield* check(1389, "ldap_root_dse")
          expect(ldapOpen.state).toBe("answered")
          expect(ldapOpen.fields).toEqual({
            vendor_name: "OpenCyber lab",
            vendor_version: "1.0",
            supported_ldap_version: "3",
            naming_contexts: 1,
          })
          expect(ldapOpen.ran).toEqual(["ldap_root_dse"])
          expect(ldapOpen.not_run).toContain("ftp_anonymous")
          const ldapRestricted = yield* check(1390, "ldap_root_dse")
          expect(ldapRestricted.state).toBe("auth_required")
          expect(ldapRestricted.fields).toEqual({ result_code: 8 })

          const smbEnabled = yield* check(1445, "smb_signing")
          expect(smbEnabled.state).toBe("answered")
          expect(smbEnabled.fields).toEqual({ dialect: 528, signing: "enabled" })
          expect((yield* check(1446, "smb_signing")).fields).toEqual({ dialect: 528, signing: "required" })

          const nfsExported = yield* check(20048, "nfs_exports")
          expect(nfsExported.state).toBe("answered")
          expect(nfsExported.fields).toEqual({ export_count: 1, exports: "/srv/export" })
          expect((yield* check(20049, "nfs_exports")).fields).toEqual({ export_count: 0, exports: "" })

          // No listener on this port: the control reports a refused connection, not a service.
          expect((yield* check(1391, "ldap_root_dse")).state).toBe("closed")
        }),
      ),
    )
  },
  240000,
)

mongoTest(
  "a real MongoDB server reports its build version; a port without a listener reports closed",
  async () => {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped()
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "mongo.sqlite"))
          const octet = 20 + Math.floor(Math.random() * 200)
          const subnet = `10.${octet}.0.0/29`
          const live = `10.${octet}.0.3`
          const name = `opencyber-probes-mongo-${crypto.randomUUID()}`
          yield* ForkCyberServicesLab.docker(["network", "create", "--internal", "--subnet", subnet, name])
          yield* Effect.addFinalizer(() => ForkCyberServicesLab.docker(["network", "rm", name]).pipe(Effect.orDie))
          const container = yield* ForkCyberServicesLab.docker([
            "run",
            "-d",
            "--rm",
            "--network",
            name,
            "--ip",
            live,
            mongoImage!,
          ])
          yield* Effect.addFinalizer(() => ForkCyberServicesLab.docker(["rm", "-f", container]).pipe(Effect.orDie))
          const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({
            image: image!,
            network: { kind: "scoped", name },
          })
          const actor = { owner: "owner", session: "session", agent: "build", manifest: scope({ cidrs: [subnet] }) }
          const check = (port: number) =>
            ForkCyberServices.probe(store, tmp.path, config, actor, {
              action: "probe",
              host: live,
              port,
              check: "mongodb_build_info",
            }).pipe(Effect.map((result) => result.capture!))
          // mongod takes a few seconds to bind; retry until it answers, within the lab budget.
          const mongo = yield* check(27017).pipe(
            Effect.flatMap((capture) =>
              capture.state === "answered" ? Effect.succeed(capture) : Effect.fail(new Error(capture.state)),
            ),
            Effect.retry({ times: 20, schedule: Schedule.spaced(1000) }),
          )
          expect(mongo.state).toBe("answered")
          expect(mongo.fields.version).toMatch(/^7\.0\./)
          expect((yield* check(27018)).state).toBe("closed")
        }),
      ),
    )
  },
  240000,
)

// Three synthetic protocol responders for the fixture, built from the LDAP, SMB2 and ONC RPC (MOUNT v3) reply layouts.
// Ports are above 1024 because the Kali workload runs as a non-root user. Each listener answers one request and closes.
const LAB = `import socket,threading
def be(value,count=4): return value.to_bytes(count,'big')
def le(value,count): return value.to_bytes(count,'little')
def ber(tag,content):
    size=len(content)
    if size<128: return bytes([tag,size])+content
    count=(size.bit_length()+7)//8
    return bytes([tag,128|count])+size.to_bytes(count,'big')+content
def ldap_answer(attributes,code):
    messages=b''
    if attributes is not None:
        partials=b''.join(ber(48,ber(4,name.encode())+ber(49,b''.join(ber(4,value.encode()) for value in values))) for name,values in attributes)
        messages+=ber(48,ber(2,bytes([1]))+ber(100,ber(4,b'')+ber(48,partials)))
    messages+=ber(48,ber(2,bytes([1]))+ber(101,ber(10,bytes([code]))+ber(4,b'')+ber(4,b'')))
    return messages
LDAP_OPEN=[('namingContexts',['dc=lab,dc=test']),('supportedLDAPVersion',['3']),('vendorName',['OpenCyber lab']),('vendorVersion',['1.0'])]
def smb_answer(mode):
    header=bytes([254])+b'SMB'+le(64,2)+bytes(2)+bytes(4)+le(0,2)+le(1,2)+le(1,4)+bytes(4)+bytes(8)+bytes(4)+bytes(4)+bytes(8)+bytes(16)
    body=le(65,2)+le(mode,2)+le(528,2)+bytes(2)+bytes(16)+bytes(4)+bytes(4)+bytes(4)+bytes(4)+bytes(8)+bytes(8)+bytes(2)+bytes(2)+bytes(4)+bytes(1)
    message=header+body
    return bytes([0])+len(message).to_bytes(3,'big')+message
def xstr(text):
    raw=text.encode()
    return be(len(raw))+raw+bytes((-len(raw))%4)
def nfs_answer(xid,exports):
    reply=be(xid)+be(1)+be(0)+be(0)+be(0)+be(0)+exports
    return be(2147483648|len(reply))+reply
NFS_ONE_EXPORT=be(1)+xstr('/srv/export')+be(1)+xstr('*')+be(0)+be(0)
NFS_NONE=be(0)
def serve(port,answer):
    listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    listener.bind(('0.0.0.0',port))
    listener.listen(16)
    while True:
        conn,_=listener.accept()
        threading.Thread(target=handle,args=(conn,answer),daemon=True).start()
def handle(conn,answer):
    with conn:
        try: request=conn.recv(4096)
        except OSError: return
        conn.sendall(answer(request))
ANSWERS={
    1389:lambda request: ldap_answer(LDAP_OPEN,0),
    1390:lambda request: ldap_answer(None,8),
    1445:lambda request: smb_answer(1),
    1446:lambda request: smb_answer(3),
    20048:lambda request: nfs_answer(int.from_bytes(request[4:8],'big'),NFS_ONE_EXPORT),
    20049:lambda request: nfs_answer(int.from_bytes(request[4:8],'big'),NFS_NONE),
}
for port,answer in ANSWERS.items():
    threading.Thread(target=serve,args=(port,answer),daemon=True).start()
threading.Event().wait()
`
