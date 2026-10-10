export * as ForkCyberDirectory from "./directory.js"

import { Effect, Schema } from "effect"
import { randomUUID } from "node:crypto"
import { ForkCyberCredentialLease } from "./credential-lease.js"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberPagination } from "./pagination.js"
import { ForkCyberPolicy } from "./policy.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
type Assessment = { owner: string; session: string; agent: string; manifest: ForkCyberScope.Manifest }

const integer = (minimum: number, maximum: number) =>
  Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum, maximum }))
// A distinguished name or search base. Control characters are refused so a DN cannot carry a line break into the probe.
const Dn = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(512), Schema.isPattern(/^[^\u0000-\u001f]+$/))
const Label = Schema.String.check(Schema.isPattern(/^[a-z][a-z0-9-]{0,62}$/))
const Artifact = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256))
const Connection = {
  host: ForkCyberScope.Host,
  port: Schema.optional(integer(1, 65535)),
  // A registered label whose value is `bind DN`, a line feed and the password. Only the label is model-visible.
  credential: Schema.optional(Label),
  timeout_ms: Schema.optional(integer(1000, 30000)),
}

export const Action = Schema.Union([
  Schema.Struct({ action: Schema.Literal("procedures") }),
  Schema.Struct({ action: Schema.Literal("ldap_enum"), ...Connection, base_dn: Schema.optional(Dn) }),
  Schema.Struct({ action: Schema.Literal("password_policy"), ...Connection, base_dn: Dn }),
  Schema.Struct({
    action: Schema.Literal("collect"),
    ...Connection,
    base_dn: Dn,
    max_entries: Schema.optional(integer(1, 500)),
  }),
  Schema.Struct({
    action: Schema.Literal("kerberos_config"),
    artifact: Artifact,
    offset: Schema.optional(integer(0, 100000)),
  }),
  Schema.Struct({
    action: Schema.Literal("adcs_templates"),
    artifact: Artifact,
    offset: Schema.optional(integer(0, 100000)),
  }),
])
export type Action = typeof Action.Type
export type Live = Extract<Action, { action: "ldap_enum" | "password_policy" | "collect" }>
export type Offline = Extract<Action, { action: "kerberos_config" | "adcs_templates" }>

export const procedures = {
  module: "directory-v1",
  procedures: [
    "Start with ldap_enum without a credential: it reads the rootDSE, attempts an anonymous bind and reports what an anonymous session can see.",
    "A credential is a registered label. Declare it in rules_of_engagement.credentials with read_only true, the host as target and the action cyber_directory.<action>, then register it with script/fork-cyber-credential.ts. Its value is the bind DN, a line feed and the password.",
    "A credential is sent only after StartTLS succeeds. A server that does not offer StartTLS is not sent the credential, and its report says so.",
    "password_policy and collect read under base_dn. collect requests only an allowlisted attribute set; credential attributes are never requested.",
    "kerberos_config and adcs_templates review an exported JSON array offline (R0). Export the attributes named in the action's limits; findings are candidates for the directory owner to confirm.",
  ],
}

// Attributes that carry credential material. collect's allowlist must never contain one of them (tested).
export const credentialAttributes = [
  "userPassword",
  "unicodePwd",
  "sambaNTPassword",
  "sambaLMPassword",
  "krbPrincipalKey",
  "supplementalCredentials",
  "unixUserPassword",
  "ms-Mcs-AdmPwd",
  "msDS-KeyCredentialLink",
  "pwdHistory",
]
const collectAttributes = [
  "objectClass",
  "cn",
  "sn",
  "givenName",
  "uid",
  "mail",
  "displayName",
  "memberOf",
  "member",
  "sAMAccountName",
  "userAccountControl",
  "servicePrincipalName",
  "distinguishedName",
  "whenCreated",
]
const policyAttributes = [
  "cn",
  "pwdAttribute",
  "pwdMinLength",
  "pwdLockout",
  "pwdMaxFailure",
  "pwdLockoutDuration",
  "pwdInHistory",
  "pwdMaxAge",
  "pwdCheckQuality",
  "pwdMustChange",
  "pwdAllowUserChange",
]

// Review thresholds of this fork, not a published baseline. A value below them is a candidate for review.
const minimumLength = 12
const maximumFailures = 10
const userClasses = ["person", "organizationalperson", "inetorgperson", "posixaccount", "user"]
const clientEkus = ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.4", "2.5.29.37.0"]

const Attributes = Schema.Record(Schema.String, Schema.Array(Schema.String))
const Entry = Schema.Struct({ dn: Schema.String, attributes: Attributes })
const Search = Schema.NullOr(
  Schema.Struct({
    base: Schema.NullOr(Schema.String),
    result: Schema.NullOr(Schema.Number),
    state: Schema.Literals(["returned", "truncated", "refused", "no_base", "error", "no_naming_context"]),
    entries: Schema.Array(Entry),
  }),
)
const Bind = Schema.Struct({ result: Schema.Number, state: Schema.Literals(["accepted", "rejected", "refused"]) })
export const Report = Schema.Struct({
  port: Schema.Number,
  state: Schema.Literals(["connected", "closed", "no_response", "error"]),
  rootdse: Schema.NullOr(
    Schema.Struct({
      naming_contexts: Schema.Array(Schema.String),
      supported_extensions: Schema.Array(Schema.String),
      sasl_mechanisms: Schema.Array(Schema.String),
      starttls: Schema.Boolean,
    }),
  ),
  anonymous: Schema.NullOr(Schema.Struct({ bind: Bind, search: Search })),
  credential: Schema.NullOr(
    Schema.Struct({
      tls: Schema.Literals(["starttls", "unavailable", "refused"]),
      bind: Schema.NullOr(Bind),
      search: Search,
    }),
  ),
})
type Report = typeof Report.Type

// The probe speaks only four LDAP operations: BindRequest (0x60), SearchRequest (0x63), UnbindRequest (0x42) and the
// StartTLS ExtendedRequest (0x77). `send` refuses any other operation, so no add, modify, delete or rename can be sent.
export const PROBE = `import json,socket,ssl,sys
args=json.loads(sys.argv[1])
ALLOWED={0x60,0x63,0x42,0x77}
MAX=8388608
STARTTLS='1.3.6.1.4.1.1466.20037'
ROOT=['namingContexts','supportedExtension','supportedSASLMechanisms']
SEARCH_STATES={0:'returned',4:'truncated',32:'no_base',48:'refused',50:'refused',53:'refused'}
ids=[0]
def length(n):
    if n<128: return bytes([n])
    raw=n.to_bytes((n.bit_length()+7)//8,'big')
    return bytes([128|len(raw)])+raw
def tlv(tag,body): return bytes([tag])+length(len(body))+body
def integer(n): return tlv(2,n.to_bytes((n.bit_length()+8)//8,'big',signed=True))
def parse(data):
    items=[]
    i=0
    while i<len(data):
        tag=data[i]
        first=data[i+1]
        i+=2
        if first&128:
            count=first&127
            size=int.from_bytes(data[i:i+count],'big')
            i+=count
        else: size=first
        if i+size>len(data): raise ValueError('truncated')
        items.append((tag,data[i:i+size]))
        i+=size
    return items
def value(body): return int.from_bytes(parse(body)[0][1],'big',signed=True)
def connect(): return socket.create_connection((args['host'],args['port']),timeout=args['timeout'])
def recv_exact(sock,n):
    data=b''
    while len(data)<n:
        chunk=sock.recv(n-len(data))
        if not chunk: raise EOFError('closed')
        data+=chunk
    return data
def receive(sock):
    tag,first=recv_exact(sock,2)
    if first&128:
        count=first&127
        if not 0<count<=4: raise ValueError('length')
        size=int.from_bytes(recv_exact(sock,count),'big')
    else: size=first
    if tag!=48 or size>MAX: raise ValueError('message')
    items=parse(recv_exact(sock,size))
    return items[1][0],items[1][1]
def send(sock,op,body):
    if op not in ALLOWED: raise PermissionError('operation not permitted')
    ids[0]+=1
    sock.sendall(tlv(48,integer(ids[0])+tlv(op,body)))
def bind(sock,name,password):
    send(sock,0x60,integer(3)+tlv(4,name)+tlv(128,password))
    op,body=receive(sock)
    if op!=0x61: raise ValueError('bind response')
    return value(body)
def unbind(sock): send(sock,0x42,b'')
def filt(attr,val):
    if val=='*': return tlv(135,attr.encode())
    return tlv(163,tlv(4,attr.encode())+tlv(4,val.encode()))
def search(sock,base,s):
    body=(tlv(4,base.encode())+tlv(10,bytes([s['scope']]))+tlv(10,bytes([0]))+integer(s['size'])
          +integer(args['timeout'])+tlv(1,bytes([0]))+filt(s['filter'][0],s['filter'][1])
          +tlv(48,b''.join(tlv(4,a.encode()) for a in s['attributes'])))
    send(sock,0x63,body)
    entries=[]
    while True:
        op,body=receive(sock)
        if op==0x64:
            items=parse(body)
            found={}
            for _,pair_bytes in parse(items[1][1]):
                pair=parse(pair_bytes)
                found[pair[0][1].decode('utf-8','replace')]=[v.decode('utf-8','replace') for _,v in parse(pair[1][1])]
            entries.append({'dn':items[0][1].decode('utf-8','replace'),'attributes':found})
        elif op==0x65: return value(body),entries
        elif op!=0x73: raise ValueError('search response')
def searched(sock,base,s):
    code,entries=search(sock,base,s)
    state=SEARCH_STATES.get(code,'error')
    return {'base':base,'result':code,'state':state,'entries':entries if state in ('returned','truncated') else []}
def scoped(sock,contexts):
    s=args['search']
    base=s['base'] or (contexts[0] if contexts else None)
    if base is None: return {'base':None,'result':None,'state':'no_naming_context','entries':[]}
    return searched(sock,base,s)
def state_of(code):
    if code==0: return 'accepted'
    if code==49: return 'rejected'
    return 'refused'
def root():
    with connect() as sock:
        _,entries=search(sock,'',{'scope':0,'filter':['objectClass','*'],'attributes':ROOT,'size':1})
        unbind(sock)
    found=entries[0]['attributes'] if entries else {}
    extensions=found.get('supportedExtension',[])
    return {'naming_contexts':found.get('namingContexts',[]),'supported_extensions':extensions,'sasl_mechanisms':found.get('supportedSASLMechanisms',[]),'starttls':STARTTLS in extensions}
def anonymous(contexts):
    with connect() as sock:
        code=bind(sock,b'',b'')
        found=scoped(sock,contexts)
        unbind(sock)
    return {'bind':{'result':code,'state':state_of(code)},'search':found}
def credential(contexts,starttls):
    if not starttls: return {'tls':'unavailable','bind':None,'search':None}
    name,password=open(args['credential'],'rb').read().split(bytes([10]),1)
    with connect() as sock:
        send(sock,0x77,tlv(128,STARTTLS.encode()))
        _,body=receive(sock)
        if value(body)!=0: return {'tls':'refused','bind':None,'search':None}
        context=ssl.create_default_context()
        context.check_hostname=False
        context.verify_mode=ssl.CERT_NONE
        with context.wrap_socket(sock,server_hostname=args['host']) as tls:
            code=bind(tls,name,password)
            found=scoped(tls,contexts) if code==0 else None
            unbind(tls)
    return {'tls':'starttls','bind':{'result':code,'state':state_of(code)},'search':found}
out={'port':args['port'],'state':'connected','rootdse':None,'anonymous':None,'credential':None}
try:
    out['rootdse']=root()
    contexts=out['rootdse']['naming_contexts']
    if args['anonymous']: out['anonymous']=anonymous(contexts)
    if args['credential']: out['credential']=credential(contexts,out['rootdse']['starttls'])
except ConnectionRefusedError: out['state']='closed'
except socket.timeout: out['state']='no_response'
except (OSError,EOFError,ValueError,IndexError,PermissionError): out['state']='error'
open('directory.json','w').write(json.dumps(out))
`

export const live = Effect.fn("ForkCyberDirectory.live")(function* (input: {
  store: Store
  profile: string
  keyFile: string
  mode: ForkCyberPolicy.Mode
  config: ForkCyberKali.Config
  assessment: Assessment
  request: Live
  now: number
}) {
  const { assessment, request } = input
  if (ForkCyberRoles.worker(assessment.agent)) yield* input.store.coordination.requireClaim(assessment)
  if (input.config.network.kind !== "scoped")
    return yield* Effect.fail(new Error("Directory checks require a scoped Kali network"))
  const budget = assessment.manifest.rules_of_engagement.network
  if (!budget) return yield* Effect.fail(new Error("Directory checks require explicit network budgets"))
  const host = ForkCyberScope.normalize(request.host)
  const port = request.port ?? 389
  yield* Effect.try({
    try: () => ForkCyberScope.authorize(assessment.manifest, host, "tcp", port),
    catch: (error) => (error instanceof ForkCyberDiagnostics.Failure ? error : new Error(String(error))),
  })
  const timeout = Math.min(request.timeout_ms ?? 10000, input.config.timeout_ms ?? 300000, budget.duration_ms)
  const name = `directory-${randomUUID()}`
  // The lease is taken before the Kali job exists, so a refused lease starts no container and sends no traffic.
  const lease =
    request.credential === undefined
      ? undefined
      : yield* ForkCyberCredentialLease.lease({
          store: input.store,
          keyFile: input.keyFile,
          owner: assessment.owner,
          session: assessment.session,
          agent: assessment.agent,
          mode: input.mode,
          label: request.credential,
          action: `cyber_directory.${request.action}`,
          target: { type: "host", value: host },
          execution: name,
          now: input.now,
        })
  return yield* Effect.gen(function* () {
    if (lease !== undefined && lease.value.indexOf(10) < 0)
      return yield* Effect.fail(
        new ForkCyberDiagnostics.Failure({
          category: "configuration",
          operation: "credential_lease",
          message: "The registered directory credential is not a bind DN, a line feed and a password.",
          target_started: false,
          effects: "not_started",
        }),
      )
    const args = probeArguments({
      request,
      host,
      port,
      timeout: Math.max(1, Math.ceil(timeout / 1000)),
      credential: lease === undefined ? undefined : `/work/${name}`,
    })
    return yield* ForkCyberKali.manager(input.store, input.profile, input.config).run(
      assessment,
      {
        argv: ["python3", "-I", "-c", PROBE, JSON.stringify(args)],
        timeout_ms: timeout,
        outputs: ["directory.json"],
      },
      {
        tool: "cyber_directory",
        parse: (result) =>
          Effect.gen(function* () {
            const file = result.files.find((item) => item.name === "directory.json")
            if (result.exit_code !== 0 || file === undefined)
              return yield* Effect.fail(new Error(`Directory probe failed (exit ${result.exit_code})`))
            const bytes = yield* input.store.readArtifact(assessment.owner, file.artifact)
            const report = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Report))(
              bytes.bytes.toString(),
            ).pipe(Effect.mapError((error) => new Error(String(error))))
            if (report.state === "closed" || report.state === "no_response")
              return yield* Effect.fail(
                new ForkCyberDiagnostics.Failure({
                  category: "transport",
                  operation: "directory_probe",
                  message: `The directory service did not accept the connection (${report.state}).`,
                  target_started: true,
                  effects: "not_started",
                }),
              )
            return interpret({ request, host, port, report, artifact: file.artifact })
          }),
      },
      lease === undefined ? [] : [{ name, value: lease.value }],
    )
  }).pipe(Effect.ensuring(Effect.sync(() => lease?.release())))
})

export const offline = Effect.fn("ForkCyberDirectory.offline")(function* (input: {
  store: Store
  assessment: Assessment
  request: Offline
}) {
  const raw = yield* input.store.readArtifact(input.assessment.owner, input.request.artifact)
  if (raw.bytes.length > 2 * 1024 * 1024) return yield* Effect.fail(new Error("Directory export exceeds 2 MiB"))
  const offset = input.request.offset ?? 0
  if (input.request.action === "kerberos_config") {
    const accounts = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Accounts))(raw.bytes.toString()).pipe(
      Effect.mapError((error) => new Error(String(error))),
    )
    return kerberos(accounts, input.request.artifact, offset)
  }
  const templates = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Templates))(raw.bytes.toString()).pipe(
    Effect.mapError((error) => new Error(String(error))),
  )
  return adcs(templates, input.request.artifact, offset)
})

// The arguments of one probe run. A credential is used only when the request names one, and the anonymous identity is
// always tried for ldap_enum because exposure is what it measures.
export function probeArguments(input: {
  request: Live
  host: string
  port: number
  timeout: number
  credential?: string
}) {
  return {
    host: input.host,
    port: input.port,
    timeout: input.timeout,
    anonymous: input.request.action === "ldap_enum" || input.request.credential === undefined,
    credential: input.credential ?? null,
    search: searchOf(input.request),
  }
}

function searchOf(request: Live) {
  if (request.action === "ldap_enum")
    return {
      base: request.base_dn ?? null,
      scope: 2,
      filter: ["objectClass", "*"],
      attributes: ["objectClass"],
      size: 25,
    }
  if (request.action === "password_policy")
    return {
      base: request.base_dn,
      scope: 2,
      filter: ["objectClass", "pwdPolicy"],
      attributes: policyAttributes,
      size: 50,
    }
  return {
    base: request.base_dn,
    scope: 2,
    filter: ["objectClass", "*"],
    attributes: collectAttributes,
    size: request.max_entries ?? 100,
  }
}

// Classifies one probe report. Exported so the laboratory runs the same classification as the Kali job.
export function interpret(input: { request: Live; host: string; port: number; report: Report; artifact: string }) {
  const { report, request } = input
  const identities = {
    anonymous: report.anonymous?.bind.state ?? "not_attempted",
    credential: report.credential === null ? "not_attempted" : (report.credential.bind?.state ?? report.credential.tls),
  }
  const base = {
    format: "opencyber-directory-v1",
    action: request.action,
    target: { host: input.host, port: input.port },
    probe_state: report.state,
    identities,
    report_artifact: input.artifact,
    limitations: limitations(request.action),
  }
  if (request.action === "ldap_enum") return { ...base, ...enumeration(report) }
  if (request.action === "password_policy") return { ...base, ...policies(report, request.base_dn) }
  return { ...base, ...collection(report, request.max_entries ?? 100) }
}

function enumeration(report: Report) {
  const anonymous = report.anonymous?.search ?? null
  const credential = report.credential?.search ?? null
  const contexts = report.rootdse?.naming_contexts ?? []
  return {
    summary: `Anonymous bind ${report.anonymous?.bind.state ?? "not attempted"}; anonymous read ${visibility(anonymous)}.`,
    findings: [
      { id: "anonymous_bind", state: anonymousBindState(report) },
      { id: "anonymous_read", state: visibility(anonymous) },
      { id: "starttls", state: report.rootdse?.starttls ? "offered" : "not_offered" },
      { id: "naming_contexts", state: contexts.length > 0 ? "disclosed" : "not_disclosed" },
      ...(report.credential === null
        ? []
        : [
            { id: "credential_bind", state: report.credential.bind?.state ?? report.credential.tls },
            { id: "credential_read", state: visibility(credential) },
          ]),
    ],
    fields: {
      naming_contexts: contexts,
      sasl_mechanisms: report.rootdse?.sasl_mechanisms ?? [],
      anonymous_entries: anonymous?.entries.length ?? 0,
      anonymous_user_objects: userEntries(anonymous?.entries ?? []).length,
      anonymous_truncated: anonymous?.state === "truncated",
    },
  }
}

function policies(report: Report, base: string) {
  const search = report.credential?.search ?? report.anonymous?.search ?? null
  const reviewed = (search?.entries ?? []).map((entry) => ({
    dn: entry.dn,
    attributes: Object.fromEntries(
      policyAttributes.flatMap((name) => (entry.attributes[name] ? [[name, entry.attributes[name]]] : [])),
    ),
    review: policyReview(entry.attributes),
  }))
  return {
    summary: `${reviewed.length} password policy object(s) under ${base}; ${reviewed.filter((item) => item.review.length > 0).length} with review candidates.`,
    fields: {
      state: search?.state ?? "not_attempted",
      policies: reviewed.slice(0, 25),
      policies_total: reviewed.length,
    },
    findings: reviewed.flatMap((item) => item.review.map((id) => ({ id, dn: item.dn, state: "candidate" }))),
  }
}

function policyReview(attributes: Record<string, readonly string[]>) {
  const first = (name: string) => attributes[name]?.[0]
  const minimum = first("pwdMinLength")
  const lockout = first("pwdLockout")?.toUpperCase()
  const failures = Number(first("pwdMaxFailure") ?? "0")
  return [
    ...(minimum === undefined
      ? ["minimum_length_not_set"]
      : Number(minimum) < minimumLength
        ? ["minimum_length_below_12"]
        : []),
    ...(lockout !== "TRUE"
      ? ["lockout_disabled"]
      : failures === 0 || failures > maximumFailures
        ? ["lockout_threshold_above_10"]
        : []),
    ...(first("pwdCheckQuality") === "0" ? ["quality_check_disabled"] : []),
  ]
}

function collection(report: Report, limit: number) {
  const search = report.credential?.search ?? report.anonymous?.search ?? null
  const entries = search?.entries ?? []
  return {
    summary: `${entries.length} entr${entries.length === 1 ? "y" : "ies"} returned (limit ${limit}); the artifact holds the full collection.`,
    fields: {
      state: search?.state ?? "not_attempted",
      entries_total: entries.length,
      truncated: search?.state === "truncated",
      preview: entries.slice(0, 25),
    },
    findings: [],
  }
}

function anonymousBindState(report: Report) {
  if (report.anonymous === null) return "not_assessed"
  return report.anonymous.bind.state === "accepted" ? "exposed" : "not_exposed"
}

function visibility(
  search: { state: string; entries: readonly { attributes: Record<string, readonly string[]> }[] } | null,
) {
  if (search === null) return "not_attempted"
  if (search.state === "no_base") return "base_not_visible"
  if (search.state !== "returned" && search.state !== "truncated") return search.state
  if (userEntries(search.entries).length > 0) return "user_objects_visible"
  return search.entries.length > 0 ? "other_entries_visible" : "no_entries_visible"
}

function userEntries(entries: readonly { attributes: Record<string, readonly string[]> }[]) {
  return entries.filter((entry) =>
    (entry.attributes.objectClass ?? []).some((name) => userClasses.includes(name.toLowerCase())),
  )
}

const Account = Schema.Struct({
  sAMAccountName: Schema.String,
  userAccountControl: Schema.optional(Schema.Number),
  servicePrincipalName: Schema.optional(Schema.Union([Schema.String, Schema.Array(Schema.String)])),
  "msDS-SupportedEncryptionTypes": Schema.optional(Schema.Number),
})
const Accounts = Schema.Array(Account).check(Schema.isMaxLength(10000))
const Template = Schema.Struct({
  name: Schema.String,
  "msPKI-Certificate-Name-Flag": Schema.optional(Schema.Number),
  "msPKI-Enrollment-Flag": Schema.optional(Schema.Number),
  "msPKI-RA-Signature": Schema.optional(Schema.Number),
  pKIExtendedKeyUsage: Schema.optional(Schema.Union([Schema.String, Schema.Array(Schema.String)])),
})
const Templates = Schema.Array(Template).check(Schema.isMaxLength(2000))

// UF_DONT_REQUIRE_PREAUTH; SPNs on accounts that are not computers; AES bits (0x08, 0x10) absent from the types.
function kerberos(accounts: readonly (typeof Account.Type)[], artifact: string, offset: number) {
  const rows = accounts.flatMap((account) => {
    const spns = [account.servicePrincipalName ?? []].flat()
    const computer = account.sAMAccountName.endsWith("$")
    return [
      ...((account.userAccountControl ?? 0) & 0x400000
        ? [{ account: account.sAMAccountName, finding: "no_preauth_required" }]
        : []),
      ...(spns.length > 0 && !computer ? [{ account: account.sAMAccountName, finding: "spn_on_user_account" }] : []),
      ...(account["msDS-SupportedEncryptionTypes"] !== undefined &&
      (account["msDS-SupportedEncryptionTypes"] & 0x18) === 0
        ? [{ account: account.sAMAccountName, finding: "no_aes_encryption_types" }]
        : []),
    ]
  })
  // ForkCyberPagination.page expects rows already positioned at the offset, as the store's SQL pages are.
  const page = ForkCyberPagination.page(rows.slice(offset), offset)
  return {
    format: "opencyber-directory-v1",
    action: "kerberos_config",
    summary: `${accounts.length} account(s) reviewed; ${rows.length} candidate row(s).`,
    fields: {
      counts: {
        no_preauth_required: rows.filter((row) => row.finding === "no_preauth_required").length,
        spn_on_user_account: rows.filter((row) => row.finding === "spn_on_user_account").length,
        no_aes_encryption_types: rows.filter((row) => row.finding === "no_aes_encryption_types").length,
      },
      items: page.items,
      offset: page.offset,
      next_offset: page.next_offset,
    },
    source_artifact: artifact,
    limitations: limitations("kerberos_config"),
  }
}

// CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (name flag 0x1) and CT_FLAG_PEND_ALL_REQUESTS (enrollment flag 0x2).
function adcs(templates: readonly (typeof Template.Type)[], artifact: string, offset: number) {
  const rows = templates.map((template) => {
    const missing = [
      template["msPKI-Certificate-Name-Flag"] === undefined ? "msPKI-Certificate-Name-Flag" : undefined,
      template["msPKI-Enrollment-Flag"] === undefined ? "msPKI-Enrollment-Flag" : undefined,
      template.pKIExtendedKeyUsage === undefined ? "pKIExtendedKeyUsage" : undefined,
    ].filter((item): item is string => item !== undefined)
    if (missing.length > 0) return { template: template.name, state: "incomplete", missing }
    const nameFlag = template["msPKI-Certificate-Name-Flag"] ?? 0
    const enrollmentFlag = template["msPKI-Enrollment-Flag"] ?? 0
    const ekus = [template.pKIExtendedKeyUsage ?? []].flat()
    const clientCapable = ekus.length === 0 || ekus.some((eku) => clientEkus.includes(eku))
    const enrolleeSubject = (nameFlag & 0x1) !== 0
    const managerApproval = (enrollmentFlag & 0x2) !== 0
    const signatures = template["msPKI-RA-Signature"] ?? 0
    const candidate = enrolleeSubject && clientCapable && !managerApproval && signatures === 0
    return {
      template: template.name,
      state: candidate ? "candidate" : "not_flagged",
      enrollee_supplies_subject: enrolleeSubject,
      client_capable_eku: clientCapable,
      manager_approval: managerApproval,
      authorized_signatures: signatures,
    }
  })
  const page = ForkCyberPagination.page(rows.slice(offset), offset)
  return {
    format: "opencyber-directory-v1",
    action: "adcs_templates",
    summary: `${templates.length} template(s) reviewed; ${rows.filter((row) => row.state === "candidate").length} candidate(s).`,
    fields: {
      items: page.items,
      offset: page.offset,
      next_offset: page.next_offset,
    },
    source_artifact: artifact,
    limitations: limitations("adcs_templates"),
  }
}

const common = [
  "Credentials are never returned. A credential bind runs only after StartTLS; the server certificate is not verified, so a credential bind does not establish the server's identity.",
  "Findings are configuration candidates. Confirm each one with the directory owner before reporting it as a finding.",
]
function limitations(action: Action["action"]) {
  if (action === "ldap_enum")
    return [
      ...common,
      "One search per identity, bounded to 25 entries. Visibility depends on the ACLs the service applies to that identity.",
      "No write operation is sent: the probe speaks bind, search, unbind and StartTLS only.",
    ]
  if (action === "password_policy")
    return [
      ...common,
      "Reads pwdPolicy objects only (ppolicy-style). Active Directory domain policy attributes are not read; they need the Windows laboratory (OC-301).",
    ]
  if (action === "collect")
    return [
      ...common,
      "Requests an allowlisted attribute set; credential attributes are never requested. The preview holds 25 entries; the artifact holds the whole bounded collection. Paged reads of artifacts are not implemented.",
    ]
  if (action === "kerberos_config")
    return [
      ...common,
      "Input is a JSON array of account objects with AD attribute names (sAMAccountName, userAccountControl, servicePrincipalName, msDS-SupportedEncryptionTypes). No ticket is requested and nothing is cracked.",
    ]
  if (action === "adcs_templates")
    return [
      ...common,
      "Input is a JSON array of template objects with AD attribute names. Enrollment rights and template ACLs are not in the export and are not evaluated, so a candidate is a pattern, not an exploitable path.",
    ]
  return common
}
