export * as ForkCyberDatabaseAuth from "./database-auth.js"

import { Effect, Schema } from "effect"
import { randomUUID } from "node:crypto"
import { ForkCyberCredentialLease } from "./credential-lease.js"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberPolicy } from "./policy.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>

type Assessment = {
  owner: string
  session: string
  agent: string
  mode: ForkCyberPolicy.Mode
  manifest: ForkCyberScope.Manifest
}

export const Engine = Schema.Literals(["redis", "elasticsearch"])
export type Engine = typeof Engine.Type

// The label names a credential the engagement declares for this host. Redis takes the value as its AUTH password;
// Elasticsearch takes `user:password` as HTTP basic credentials. The value reaches the job as a file, never in argv.
export const Input = Schema.Struct({
  engine: Engine,
  host: ForkCyberScope.Host,
  port: Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 65535 })),
  label: Schema.String.check(Schema.isPattern(/^[a-z][a-z0-9-]{0,62}$/)),
  timeout_ms: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1000, maximum: 30000 }))),
})
export type Input = typeof Input.Type

export const Report = Schema.Struct({
  engine: Engine,
  port: Schema.Number,
  state: Schema.Literals(["accepted", "rejected", "not_required", "error", "closed", "no_response"]),
})
export type Report = typeof Report.Type

// Exactly one authentication attempt per call. The script sends one unauthenticated request first for
// Elasticsearch, which is not an attempt; a service that answers without credentials is `not_required`.
export const PROBE = `import base64,json,socket,sys
args=json.loads(sys.argv[1])
secret=open(args['credential'],'rb').read()
host=args['host']
def connect():
    return socket.create_connection((host,args['port']),timeout=args['timeout'])
def read_all(sock,limit=65536):
    data=b''
    while len(data)<limit:
        chunk=sock.recv(4096)
        if not chunk: break
        data+=chunk
    return data
def redis():
    with connect() as sock:
        sock.sendall(b'*2\\r\\n$4\\r\\nAUTH\\r\\n$%d\\r\\n' % len(secret) + secret + b'\\r\\n')
        reply=sock.recv(4096)
    if reply.startswith(b'+OK'): return 'accepted'
    if reply.startswith(b'-WRONGPASS') or b'invalid password' in reply: return 'rejected'
    if b'no password is set' in reply or b'without any password configured' in reply: return 'not_required'
    return 'error'
def status(headers):
    with connect() as sock:
        sock.sendall(('GET / HTTP/1.1\\r\\nHost: %s\\r\\nAccept: application/json\\r\\nConnection: close\\r\\n%s\\r\\n' % (host,headers)).encode())
        head=read_all(sock).split(b'\\r\\n',1)[0]
    parts=head.split(b' ')
    return int(parts[1]) if head.startswith(b'HTTP/') and len(parts)>1 and parts[1].isdigit() else None
def elastic():
    if status('')==200: return 'not_required'
    token=base64.b64encode(secret).decode()
    code=status('Authorization: Basic %s\\r\\n' % token)
    if code==200: return 'accepted'
    if code in (401,403): return 'rejected'
    return 'error'
out={'engine':args['engine'],'port':args['port']}
try:
    out['state']=redis() if args['engine']=='redis' else elastic()
except ConnectionRefusedError:
    out['state']='closed'
except socket.timeout:
    out['state']='no_response'
except OSError:
    out['state']='error'
open('auth.json','w').write(json.dumps(out))
`

export const run = Effect.fn("ForkCyberDatabaseAuth.run")(function* (input: {
  store: Store
  profile: string
  keyFile: string
  config: ForkCyberKali.Config
  assessment: Assessment
  request: Input
  now: number
}) {
  const { assessment, request } = input
  if (!ForkCyberRoles.allowed(assessment.agent, "cyber_database"))
    return yield* Effect.fail(new Error(`Phase ${assessment.agent} cannot execute cyber_database`))
  if (ForkCyberRoles.worker(assessment.agent)) yield* input.store.coordination.requireClaim(assessment)
  if (input.config.network.kind !== "scoped") return yield* Effect.fail(new Error("Auth tests require a scoped Kali network"))
  const budget = assessment.manifest.rules_of_engagement.network
  if (!budget) return yield* Effect.fail(new Error("Auth tests require explicit network budgets"))
  const host = ForkCyberScope.normalize(request.host)
  yield* Effect.try(() => ForkCyberScope.authorize(assessment.manifest, host, "tcp", request.port)).pipe(
    Effect.mapError((error) => new Error(String(error.cause))),
  )
  const timeout = Math.min(request.timeout_ms ?? 10000, input.config.timeout_ms ?? 300000, budget.duration_ms)
  const name = `credential-${randomUUID()}`
  const lease = yield* ForkCyberCredentialLease.lease({
    store: input.store,
    keyFile: input.keyFile,
    owner: assessment.owner,
    session: assessment.session,
    agent: assessment.agent,
    mode: assessment.mode,
    label: request.label,
    action: "cyber_database.auth_test",
    target: { type: "host", value: host },
    execution: name,
    now: input.now,
  })
  return yield* ForkCyberKali.manager(input.store, input.profile, input.config)
    .run(
      assessment,
      {
        argv: [
          "python3",
          "-I",
          "-c",
          PROBE,
          JSON.stringify({
            engine: request.engine,
            host,
            port: request.port,
            timeout: timeout / 1000,
            credential: `/work/${name}`,
          }),
        ],
        timeout_ms: timeout,
        outputs: ["auth.json"],
      },
      {
        tool: "cyber_database",
        parse: (result) =>
          Effect.gen(function* () {
            const file = result.files.find((item) => item.name === "auth.json")
            if (result.exit_code !== 0 || file === undefined)
              return yield* Effect.fail(new Error(`Auth probe failed (exit ${result.exit_code})`))
            const bytes = yield* input.store.readArtifact(assessment.owner, file.artifact)
            return yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Report))(bytes.bytes.toString()).pipe(
              Effect.mapError((error) => new Error(String(error))),
            )
          }),
      },
      [{ name, value: lease.value }],
    )
    .pipe(Effect.ensuring(Effect.sync(() => lease.release())))
})
