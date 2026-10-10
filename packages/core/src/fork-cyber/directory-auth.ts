export * as ForkCyberDirectoryAuth from "./directory-auth.js"

import { Effect, Schema } from "effect"
import { randomUUID } from "node:crypto"
import { ForkCyberCredentialLease } from "./credential-lease.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
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

const Label = Schema.String.check(Schema.isPattern(/^[a-z][a-z0-9-]{0,62}$/))
const Port = Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 65535 }))
const ArtifactID = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(128))

// One directory account per call, named by a label the engagement declares for this host. The value stays in the lease.
export const AuthTest = Schema.Struct({
  action: Schema.Literal("auth_test"),
  label: Label,
  host: ForkCyberScope.Host,
  port: Schema.optional(Port),
  timeout_ms: Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1000, maximum: 30000 }))),
})
export type AuthTest = typeof AuthTest.Type

// Hashes and a wordlist are operator-supplied artifacts of this engagement. Each hash is tested offline, one job each.
export const Crack = Schema.Struct({
  action: Schema.Literal("crack"),
  format: Schema.Literals(["nt", "raw-md5"]),
  hashes: ArtifactID,
  wordlist: ArtifactID,
  timeout_ms: Schema.optional(
    Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1000, maximum: 300000 })),
  ),
})
export type Crack = typeof Crack.Type

export const Action = Schema.Union([AuthTest, Crack])
export type Action = typeof Action.Type

const johnFormat = { nt: "NT", "raw-md5": "Raw-MD5" } as const
// Bounds for one crack job. Each hash runs john once against the wordlist, so the count bounds the job's time.
const maximumHashes = 16
const maximumHashBytes = 256

// Exactly one LDAP simple bind per call. The password comes from the file the lease wrote, never from argv. A
// successful bind with an empty password is an anonymous bind, so an empty value is an error, not an acceptance.
export const AUTH_PROBE = `import json,socket,sys
args=json.loads(sys.argv[1])
password=open(args['credential'],'rb').read()
def length(size):
    if size<128: return bytes([size])
    body=size.to_bytes((size.bit_length()+7)//8,'big')
    return bytes([128+len(body)])+body
def tlv(tag,value):
    return bytes([tag])+length(len(value))+value
def element(data,offset=0):
    start=offset+2
    size=data[offset+1]
    if size>=128:
        count=size-128
        size=int.from_bytes(data[start:start+count],'big')
        start+=count
    return data[offset],data[start:start+size],start+size
def complete(data):
    if len(data)<2: return False
    size=data[1]
    start=2
    if size>=128:
        count=size-128
        if len(data)<2+count: return False
        size=int.from_bytes(data[2:2+count],'big')
        start=2+count
    return len(data)>=start+size
def classify(code,diagnostic):
    if code==0: return 'accepted'
    if code==49: return 'locked' if b'data 775' in diagnostic else 'rejected'
    return 'error'
def bind():
    request=tlv(48,tlv(2,bytes([1]))+tlv(96,tlv(2,bytes([3]))+tlv(4,args['account'].encode())+tlv(128,password)))
    with socket.create_connection((args['host'],args['port']),timeout=args['timeout']) as sock:
        sock.sendall(request)
        data=b''
        while not complete(data):
            chunk=sock.recv(4096)
            if not chunk: break
            data+=chunk
    _,message,_=element(data)
    _,_,offset=element(message)
    tag,response,_=element(message,offset)
    if tag!=97: raise ValueError('not a bind response')
    _,code,offset=element(response)
    _,_,offset=element(response,offset)
    _,diagnostic,_=element(response,offset)
    return int.from_bytes(code,'big'),diagnostic
result={'state':'error'}
if len(password)>0:
    try:
        code,diagnostic=bind()
        result={'state':classify(code,diagnostic),'result_code':code}
    except ConnectionRefusedError:
        result={'state':'closed'}
    except socket.timeout:
        result={'state':'no_response'}
    except (ValueError,IndexError,OSError):
        result={'state':'error'}
open('auth.json','w').write(json.dumps(result))
`

// One john run per hash, each against the same wordlist. Output of john is captured and never printed, so cracked
// plaintext cannot reach stdout, stderr or an artifact. The pot file lives in the job's /work and goes with the job.
export const CRACK_PROBE = `import json,os,shutil,subprocess,sys
args=json.loads(sys.argv[1])
if shutil.which('john') is None:
    json.dump({'state':'not_configured','results':[]},open('crack.json','w'))
    sys.exit(0)
lines=[line for line in open('hashes').read().splitlines() if line.strip()]
results=[]
for index,line in enumerate(lines):
    open('one.txt','w').write(line+'\\n')
    base=['john','--format='+args['format'],'--pot=pot.txt','--session=session']
    subprocess.run(base+['--wordlist=words','one.txt'],capture_output=True,stdin=subprocess.DEVNULL,timeout=args['timeout'])
    shown=subprocess.run(base+['--show','one.txt'],capture_output=True,stdin=subprocess.DEVNULL,timeout=args['timeout'])
    results.append({'index':index,'cracked':b'1 password hash cracked' in shown.stdout})
    os.remove('one.txt')
json.dump({'state':'completed','results':results},open('crack.json','w'))
`

const AuthReport = Schema.Struct({
  state: Schema.Literals(["accepted", "rejected", "locked", "closed", "no_response", "error"]),
  result_code: Schema.optional(Schema.Number),
})
const CrackReport = Schema.Struct({
  state: Schema.Literals(["completed", "not_configured"]),
  results: Schema.Array(Schema.Struct({ index: Schema.Number, cracked: Schema.Boolean })),
})

const operation = "cyber_directory"

export const authTest = Effect.fn("ForkCyberDirectoryAuth.authTest")(function* (input: {
  store: Store
  profile: string
  keyFile: string
  config: ForkCyberKali.Config
  assessment: Assessment
  request: AuthTest
  now: number
}) {
  const { assessment, request, store } = input
  if (!ForkCyberRoles.allowed(assessment.agent, operation))
    return yield* Effect.fail(new Error(`Phase ${assessment.agent} cannot execute ${operation}`))
  if (ForkCyberRoles.worker(assessment.agent)) yield* store.coordination.requireClaim(assessment)
  if (input.config.network.kind !== "scoped")
    return yield* Effect.fail(new Error("Auth tests require a scoped Kali network"))
  const budget = assessment.manifest.rules_of_engagement.network
  if (!budget) return yield* Effect.fail(new Error("Auth tests require explicit network budgets"))
  const host = ForkCyberScope.normalize(request.host)
  const port = request.port ?? 389
  yield* Effect.try(() => ForkCyberScope.authorize(assessment.manifest, host, "tcp", port)).pipe(
    Effect.mapError((error) => new Error(String(error.cause))),
  )
  const declared = assessment.manifest.rules_of_engagement.credentials?.find((item) => item.label === request.label)
  if (declared !== undefined && (declared.kind !== "directory_bind" || declared.account === undefined))
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation,
        message: "The label is not a directory_bind credential with a declared account",
        target_started: false,
        effects: "not_started",
        recovery:
          "Declare the directory account for this label in the engagement, get that revision approved, then retry.",
      }),
    )
  const timeout = Math.min(request.timeout_ms ?? 10000, input.config.timeout_ms ?? 300000, budget.duration_ms)
  const name = `credential-${randomUUID()}`
  // The lease records the attempt, refusals included, before any value leaves storage.
  const lease = yield* ForkCyberCredentialLease.lease({
    store,
    keyFile: input.keyFile,
    owner: assessment.owner,
    session: assessment.session,
    agent: assessment.agent,
    mode: assessment.mode,
    label: request.label,
    action: "cyber_directory.auth_test",
    target: { type: "host", value: host },
    execution: name,
    now: input.now,
  })
  return yield* Effect.gen(function* () {
    const account = declared?.account
    if (account === undefined) return yield* Effect.fail(new Error("A granted lease needs a declared account"))
    const result = yield* ForkCyberKali.manager(store, input.profile, input.config).run(
      assessment,
      {
        argv: [
          "python3",
          "-I",
          "-c",
          AUTH_PROBE,
          JSON.stringify({ account, host, port, timeout: timeout / 1000, credential: `/work/${name}` }),
        ],
        timeout_ms: timeout,
        outputs: ["auth.json"],
      },
      {
        tool: operation,
        parse: (job) =>
          Effect.gen(function* () {
            const file = job.files.find((item) => item.name === "auth.json")
            if (job.exit_code !== 0 || file === undefined)
              return yield* Effect.fail(new Error(`Auth probe failed (exit ${job.exit_code})`))
            const bytes = yield* store.readArtifact(assessment.owner, file.artifact)
            return yield* Schema.decodeUnknownEffect(Schema.fromJsonString(AuthReport))(bytes.bytes.toString()).pipe(
              Effect.mapError((error) => new Error(String(error))),
            )
          }),
      },
      [{ name, value: lease.value }],
    )
    const state = result.capture!.state
    return {
      format: "opencyber-directory-auth-v1",
      action: "auth_test",
      summary: `Label ${request.label} on ${host}:${port} returned ${state}. The password was not returned.`,
      label: request.label,
      target: host,
      port,
      state,
      execution: result.execution,
      evidence: result.evidence,
      completion_evidence: result.completion_evidence,
      artifacts: result.artifacts.map((item) => item.id),
    }
  }).pipe(Effect.ensuring(Effect.sync(() => lease.release())))
})

export const crack = Effect.fn("ForkCyberDirectoryAuth.crack")(function* (input: {
  store: Store
  profile: string
  config: ForkCyberKali.Config
  assessment: Assessment
  request: Crack
}) {
  const { assessment, request, store } = input
  if (!ForkCyberRoles.allowed(assessment.agent, operation))
    return yield* Effect.fail(new Error(`Phase ${assessment.agent} cannot execute ${operation}`))
  if (ForkCyberRoles.worker(assessment.agent)) yield* store.coordination.requireClaim(assessment)
  const hashes = yield* supplied(store, assessment.owner, request.hashes, "operator.hashes")
  yield* supplied(store, assessment.owner, request.wordlist, "operator.wordlist")
  const lines = hashes.bytes
    .toString("utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0)
  if (lines.length === 0 || lines.length > maximumHashes || lines.some((line) => line.length > maximumHashBytes))
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation,
        message: `The hash set must hold 1 to ${maximumHashes} hashes of at most ${maximumHashBytes} characters`,
        target_started: false,
        effects: "not_started",
        recovery: "Split the hash set into batches of at most 16 hashes, then retry each batch.",
      }),
    )
  const timeout = Math.min(request.timeout_ms ?? 60000, input.config.timeout_ms ?? 300000)
  const result = yield* ForkCyberKali.manager(store, input.profile, input.config).run(
    assessment,
    {
      network: "none",
      argv: [
        "python3",
        "-I",
        "-c",
        CRACK_PROBE,
        JSON.stringify({ format: johnFormat[request.format], timeout: timeout / 1000 }),
      ],
      timeout_ms: timeout,
      inputs: [
        { name: "hashes", artifact: request.hashes },
        { name: "words", artifact: request.wordlist },
      ],
      outputs: ["crack.json"],
    },
    {
      tool: operation,
      parse: (job) =>
        Effect.gen(function* () {
          const file = job.files.find((item) => item.name === "crack.json")
          if (job.exit_code !== 0 || file === undefined)
            return yield* Effect.fail(new Error(`Crack job failed (exit ${job.exit_code})`))
          const bytes = yield* store.readArtifact(assessment.owner, file.artifact)
          const report = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(CrackReport))(
            bytes.bytes.toString(),
          ).pipe(Effect.mapError((error) => new Error(String(error))))
          return report
        }),
    },
  )
  const report = result.capture!
  // Raised after the job returns: a failure inside the job would reach the caller as a generic execution error.
  if (report.state === "not_configured")
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "configuration",
        operation,
        message: "The Kali image has no john binary",
        target_started: false,
        effects: "not_started",
        recovery:
          "The fork-kali image does not include john yet. Crack actions stay unavailable until an image with a pinned john build is deployed.",
      }),
    )
  const results = report.results
  const cracked = results.filter((item) => item.cracked).length
  return {
    format: "opencyber-directory-crack-v1",
    action: "crack",
    summary: `${cracked} of ${results.length} supplied hashes were recovered. Plaintext is withheld.`,
    hashes: results.length,
    cracked,
    results: results.map((item) => ({ index: item.index, status: item.cracked ? "cracked" : "not_cracked" })),
    // Recovered plaintext never leaves the job. Retrieving it is an operator decision (fork-cyber-directory-auth.md).
    plaintext: "withheld",
    execution: result.execution,
    evidence: result.evidence,
    completion_evidence: result.completion_evidence,
    artifacts: result.artifacts.map((item) => item.id),
  }
})

// A supplied artifact is one an operator import recorded under its own kind. Tools cannot create these kinds.
const supplied = Effect.fn("ForkCyberDirectoryAuth.supplied")(function* (
  store: Store,
  owner: string,
  id: string,
  kind: string,
) {
  const artifact = yield* store.readArtifact(owner, id)
  if (artifact.kind === kind) return artifact
  return yield* Effect.fail(
    new ForkCyberDiagnostics.Failure({
      category: "input",
      operation,
      message: `Artifact ${id} is not a supplied ${kind} artifact of this engagement`,
      target_started: false,
      effects: "not_started",
      recovery: "Use only artifacts the operator supplied for this engagement. Tool output cannot be cracked.",
    }),
  )
})
