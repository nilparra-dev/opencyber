export * as ForkCyberDiscovery from "./discovery.js"

import { Effect, Exit, Schema } from "effect"
import { isIP } from "node:net"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberDns } from "./dns.js"
import { ForkCyberHttp } from "./http.js"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberScope } from "./scope.js"

// Operator infrastructure, never a target-supplied argument. Tests pass a local endpoint.
const CERTIFICATE_SOURCE = "https://crt.sh/"
const CERTIFICATE_BYTES = 2 * 1024 * 1024
const CERTIFICATE_TIMEOUT_MS = 15000
const NAME_LIMIT = 200
const FINGERPRINT_BYTES = 1024 * 1024

const integer = (minimum: number, maximum: number) =>
  Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum, maximum }))

// A prefix shorter than /24 would sweep more than 256 addresses in one job.
function sweepable(value: string) {
  const [address = "", prefix = ""] = ForkCyberScope.normalize(value).split("/")
  return isIP(address) === 4 && Number(prefix) >= 24 && Number(prefix) <= 32
}
const SweepRange = ForkCyberScope.Cidr.check(
  Schema.makeFilter<string>((value) => sweepable(value) || "Expected an IPv4 CIDR with a prefix from /24 to /32"),
)
const HttpUrl = Schema.String.check(
  Schema.isMaxLength(2048),
  Schema.makeFilter<string>((value) => (URL.canParse(value) && /^https?:/.test(value)) || "Expected an HTTP(S) URL"),
)

export const Action = Schema.Union([
  Schema.Struct({
    action: Schema.Literal("passive_dns"),
    host: ForkCyberScope.Host,
    // The same record types cyber_dns supported, so absorbing it removes no coverage.
    type: ForkCyberDns.Action.fields.type,
  }),
  Schema.Struct({ action: Schema.Literal("certificates"), domain: ForkCyberScope.Domain }),
  Schema.Struct({ action: Schema.Literal("host_sweep"), cidr: SweepRange }),
  Schema.Struct({ action: Schema.Literal("fingerprint"), url: HttpUrl }),
])
export type Action = typeof Action.Type
export type HostSweep = Extract<Action, { action: "host_sweep" }>

export function target(input: Action) {
  if (input.action === "passive_dns") return input.host
  if (input.action === "certificates") return input.domain
  if (input.action === "host_sweep") return input.cidr
  return input.url
}

// Every action except host_sweep, which needs a scoped Kali network and goes through `sweep`.
export const run = Effect.fn("ForkCyberDiscovery.run")(function* (
  store: ForkCyberHttp.Store,
  resolve: () => Effect.Effect<ForkCyberHttp.Assessment, Error>,
  input: Exclude<Action, HostSweep>,
  source = CERTIFICATE_SOURCE,
) {
  if (input.action === "passive_dns") return yield* ForkCyberDns.run(store, yield* resolve(), input)
  if (input.action === "fingerprint") return yield* fingerprint(store, resolve, input.url)
  return yield* certificates(store, yield* resolve(), input.domain, source)
})

export const sweep = Effect.fn("ForkCyberDiscovery.sweep")(function* (
  store: ForkCyberHttp.Store,
  profile: string,
  configuration: ForkCyberKali.Config,
  assessment: ForkCyberHttp.Assessment,
  input: HostSweep,
) {
  const range = ForkCyberScope.normalize(input.cidr)
  const budget = assessment.manifest.rules_of_engagement.network
  if (configuration.network.kind !== "scoped")
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "configuration",
        operation: "cyber_discover",
        message: "Host sweeps require a scoped Kali network",
        target_started: false,
        effects: "not_started",
      }),
    )
  if (assessment.manifest.derived || !budget)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "scope",
        operation: "cyber_discover",
        message: "Host sweeps require an explicit engagement with network budgets",
        target_started: false,
        effects: "not_started",
        recovery: "Record the operator's engagement scope and network budgets before sweeping.",
      }),
    )
  if (
    !assessment.manifest.scope.cidrs.some((entry) => ForkCyberScope.normalize(entry) === range) ||
    assessment.manifest.scope.excluded.some((entry) => overlaps(range, entry))
  )
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "scope",
        operation: "cyber_discover",
        message: "Host sweep range is not declared in scope or overlaps an exclusion",
        target_started: false,
        effects: "not_started",
        recovery:
          "Sweep only a range declared exactly in the engagement scope. Sub-ranges and hosts are not inferred from it.",
      }),
    )
  const timeout = Math.min(60000, configuration.timeout_ms ?? 300000, budget.duration_ms)
  const argv = [
    "/usr/lib/nmap/nmap",
    "--unprivileged",
    "-sn",
    "-n",
    "--max-parallelism",
    "1",
    "--max-retries",
    "1",
    "--scan-delay",
    `${Math.ceil(1000 / budget.connections_per_second)}ms`,
    "--host-timeout",
    `${timeout}ms`,
    "-oX",
    "sweep.xml",
    range,
  ]
  // Nmap reports every address in the range, including the network and broadcast addresses.
  const addresses = 2 ** (32 - Number(range.split("/")[1]))
  return yield* ForkCyberKali.manager(store, profile, configuration).run(
    assessment,
    {
      argv: ["python3", "-I", "-c", SWEEP, JSON.stringify(argv)],
      timeout_ms: timeout,
      outputs: ["sweep.xml", "sweep.json"],
    },
    {
      tool: "cyber_discover",
      parse: (result) =>
        Effect.gen(function* () {
          if (result.exit_code !== 0)
            return yield* Effect.fail(new Error(`Nmap host sweep failed (exit ${result.exit_code})`))
          const report = result.files.find((file) => file.name === "sweep.json")!
          const raw = result.files.find((file) => file.name === "sweep.xml")!
          const bytes = yield* store.readArtifact(assessment.owner, report.artifact)
          const parsed = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(SweepReport))(
            bytes.bytes.toString(),
          ).pipe(Effect.mapError((error) => new Error(String(error))))
          if (
            parsed.target !== range ||
            parsed.scanned !== addresses ||
            parsed.addresses !== addresses ||
            parsed.hosts.length !== parsed.up
          )
            return yield* Effect.fail(new Error("Nmap report does not match the requested range"))
          return {
            format: "opencyber-host-sweep-v1",
            target: range,
            addresses,
            hosts_up: parsed.hosts,
            up_count: parsed.up,
            down_count: addresses - parsed.up,
            xml_artifact: raw.artifact,
            report_artifact: report.artifact,
            limitations: sweepLimitations,
          }
        }),
    },
  )
})

const SweepReport = Schema.Struct({
  scanner: Schema.Literal("nmap"),
  version: Schema.String.check(Schema.isMaxLength(64)),
  target: Schema.String,
  addresses: integer(1, 256),
  scanned: integer(1, 256),
  up: integer(0, 256),
  hosts: Schema.Array(Schema.String.check(Schema.makeFilter<string>((value) => isIP(value) === 4 || "Expected IPv4"))),
})

const sweepLimitations = [
  "Unprivileged discovery uses TCP connect probes. A host that neither accepts nor resets those probes is reported down, so filtering can hide live hosts.",
  "Results describe reachability from this network position at this time only.",
]

// A sweep overlaps an exclusion when either range contains the other's base address.
function overlaps(range: string, entry: string) {
  const value = ForkCyberScope.normalize(entry)
  const base = value.split("/")[0]!
  if (!isIP(base)) return false
  return ForkCyberScope.matches(base, range) || ForkCyberScope.matches(range.split("/")[0]!, value)
}

export const certificates = Effect.fn("ForkCyberDiscovery.certificates")(function* (
  store: ForkCyberHttp.Store,
  assessment: ForkCyberHttp.Assessment,
  value: string,
  source = CERTIFICATE_SOURCE,
) {
  const domain = ForkCyberScope.normalize(value)
  const manifest = assessment.manifest
  if (
    manifest.derived ||
    manifest.scope.excluded.some((entry) => ForkCyberScope.matches(domain, entry)) ||
    !manifest.scope.domains.some((entry) => ForkCyberScope.matches(domain, entry))
  )
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "scope",
        operation: "cyber_discover",
        message: "Certificate lookup domain is outside scope or excluded",
        target_started: false,
        effects: "not_started",
        recovery: "Use a domain declared in the engagement scope. Discovered names are not added to scope.",
      }),
    )
  // The declaration is checked before any request. Without it the lookup is refused, not attempted.
  if (manifest.rules_of_engagement.passive_osint !== true)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "capability",
        operation: "cyber_discover",
        message: "Certificate transparency lookups require passive OSINT declared in the engagement",
        target_started: false,
        effects: "not_started",
        recovery:
          "Use passive_dns for in-scope names. Record passive OSINT only when the operator permits third-party lookups.",
      }),
    )
  const id = crypto.randomUUID()
  yield* store.start({
    ...assessment,
    id,
    tool: "cyber_discover",
    input: { action: "certificates", domain },
    provenance: { operation_class: "acquisition", transport: "certificate_transparency", source },
  })
  const observed = yield* fetchCertificates(domain, source).pipe(Effect.exit)
  if (Exit.isFailure(observed)) {
    yield* store.finish(
      assessment.owner,
      id,
      "error",
      { message: "Certificate lookup failed", effects: "unknown" },
      Exit.hasInterrupts(observed) ? "interrupted" : undefined,
    )
    return yield* Effect.failCause(observed.cause)
  }
  const names = [
    ...new Set(
      observed.value.entries
        .flatMap((entry) => entry.name_value.split("\n"))
        .map((name) => ForkCyberScope.normalize(name).replace(/^\*\./, "")),
    ),
  ]
    .filter((name) => Schema.is(ForkCyberScope.Domain)(name) && (name === domain || name.endsWith(`.${domain}`)))
    .toSorted()
  const artifact = yield* store.artifact(
    assessment.owner,
    id,
    "discovery.certificates",
    observed.value.bytes,
    "application/json",
  )
  const capture = {
    domain,
    source: "certificate_transparency",
    entries: observed.value.entries.length,
    name_count: names.length,
    names: names.slice(0, NAME_LIMIT),
    truncated: names.length > NAME_LIMIT,
    declared_in_scope: names.filter((name) =>
      manifest.scope.domains.some((entry) => ForkCyberScope.matches(name, entry)),
    ),
    raw_artifact: artifact[0]!.id,
    limitations: [
      "Names are candidates from public certificate transparency records. They are not added to scope and do not show that a service is reachable.",
      "Wildcard entries are reported without the wildcard label.",
    ],
  }
  const output = yield* store.finish(assessment.owner, id, "completed", capture)
  return {
    execution: id,
    evidence: output[0]!.id,
    completion_evidence: [output[0]!.id],
    capture,
    artifacts: yield* store.artifacts(assessment.owner, id),
  }
})

const CertificateEntries = Schema.Array(Schema.Struct({ name_value: Schema.String }))

const fetchCertificates = Effect.fn("ForkCyberDiscovery.fetchCertificates")(function* (domain: string, source: string) {
  const url = new URL(source)
  url.searchParams.set("q", `%.${domain}`)
  url.searchParams.set("output", "json")
  const response = yield* Effect.tryPromise({
    try: (signal) =>
      fetch(url, { redirect: "error", signal: AbortSignal.any([signal, AbortSignal.timeout(CERTIFICATE_TIMEOUT_MS)]) }),
    catch: () =>
      new ForkCyberDiagnostics.Failure({
        category: "transport",
        operation: "cyber_discover",
        message: "Certificate transparency source did not answer",
        target_started: true,
        effects: "unknown",
      }),
  })
  if (!response.ok)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "transport",
        operation: "cyber_discover",
        message: `Certificate transparency source returned HTTP ${response.status}`,
        target_started: true,
        effects: "unknown",
      }),
    )
  const bytes = yield* Effect.tryPromise({
    try: () => readBounded(response, CERTIFICATE_BYTES),
    catch: () =>
      new ForkCyberDiagnostics.Failure({
        category: "capture",
        operation: "cyber_discover",
        message: "Certificate transparency response exceeds 2 MiB or was interrupted",
        target_started: true,
        effects: "unknown",
      }),
  })
  const entries = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(CertificateEntries))(
    bytes.toString("utf8"),
  ).pipe(
    Effect.mapError(
      () =>
        new ForkCyberDiagnostics.Failure({
          category: "capture",
          operation: "cyber_discover",
          message: "Certificate transparency response is not the expected JSON",
          target_started: true,
          effects: "unknown",
        }),
    ),
  )
  return { bytes, entries }
})

// Stops reading as soon as the limit is exceeded, so a large response cannot exhaust memory.
async function readBounded(response: Response, limit: number) {
  const reader = response.body?.getReader()
  if (!reader) return Buffer.alloc(0)
  const chunks: Buffer[] = []
  let size = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) return Buffer.concat(chunks)
    size += value.byteLength
    if (size > limit) {
      await reader.cancel()
      throw new Error("Response exceeds the limit")
    }
    chunks.push(Buffer.from(value))
  }
}

const cookieTechnologies: Record<string, string> = {
  PHPSESSID: "PHP",
  JSESSIONID: "Java servlet container",
  "ASP.NET_SessionId": "ASP.NET",
  laravel_session: "Laravel",
  csrftoken: "Django",
}
const bodyPaths: [RegExp, string][] = [
  [/\/wp-content\//, "WordPress"],
  [/\/_next\//, "Next.js"],
  [/\/sites\/default\/files\//, "Drupal"],
]
const generatorTag = /<meta\s[^>]*name=["']generator["'][^>]*content=["']([^"']{1,128})["']/i

export const fingerprint = Effect.fn("ForkCyberDiscovery.fingerprint")(function* (
  store: ForkCyberHttp.Store,
  resolve: () => Effect.Effect<ForkCyberHttp.Assessment, Error>,
  value: string,
) {
  const owner = (yield* resolve()).owner
  const hops = yield* ForkCyberHttp.run(store, resolve, { url: value, method: "GET" })
  const last = hops[hops.length - 1]!.capture
  const body = (yield* store.readArtifact(owner, last.response_body)).bytes
    .subarray(0, FINGERPRINT_BYTES)
    .toString("utf8")
  // rawHeaders are flat name/value pairs, so the even positions are names.
  const headers = last.headers.flatMap((name, index) =>
    index % 2 === 0 ? [[name.toLowerCase(), last.headers[index + 1] ?? ""] as const] : [],
  )
  const header = (name: string) => headers.find(([key]) => key === name)?.[1]
  // Only cookie names leave the response. Their values can be session secrets.
  const cookies = headers.flatMap(([key, setCookie]) => {
    if (key !== "set-cookie") return []
    const name = setCookie.split("=")[0]!.trim()
    return Object.hasOwn(cookieTechnologies, name)
      ? [{ name: cookieTechnologies[name]!, evidence: `cookie:${name}` }]
      : []
  })
  const server = header("server")
  const poweredBy = header("x-powered-by")
  const generator = body.match(generatorTag)?.[1]
  return {
    url: value,
    final_url: last.url,
    status: last.status,
    redirects: hops.length - 1,
    execution: last.execution,
    technologies: [
      ...(server ? [{ name: server.slice(0, 128), evidence: "header:server" }] : []),
      ...(poweredBy ? [{ name: poweredBy.slice(0, 128), evidence: "header:x-powered-by" }] : []),
      ...cookies,
      ...(generator ? [{ name: generator, evidence: "body:meta-generator" }] : []),
      ...bodyPaths.flatMap(([pattern, name]) => (pattern.test(body) ? [{ name, evidence: "body:path" }] : [])),
    ],
    limitations: [
      "Hints come from one response and its redirects. They are heuristics: they do not verify a version or show that a weakness exists.",
    ],
  }
})

const SWEEP = `import ipaddress,json,pathlib,subprocess,sys
from xml.etree import ElementTree
def parse(raw,cidr):
    if len(raw)>2*1024*1024 or b'<!ENTITY' in raw or b'<!DOCTYPE' in raw.replace(b'<!DOCTYPE nmaprun>',b''):
        raise ValueError('Unsupported or oversized Nmap XML')
    root=ElementTree.fromstring(raw)
    if root.tag!='nmaprun' or root.get('scanner')!='nmap':
        raise ValueError('Expected a Nmap report')
    finished=root.findall('runstats/finished')
    stats=root.findall('runstats/hosts')
    if len(finished)!=1 or finished[0].get('exit')!='success' or len(stats)!=1:
        raise ValueError('Nmap report is incomplete or unsuccessful')
    network=ipaddress.ip_network(cidr)
    total=int(stats[0].attrib['total'])
    up=int(stats[0].attrib['up'])
    hosts=[]
    for host in root.findall('host'):
        state=host.find('status').attrib['state']
        found=[row.attrib['addr'] for row in host.findall('address') if row.get('addrtype')=='ipv4']
        if len(found)!=1 or ipaddress.ip_address(found[0]) not in network:
            raise ValueError('Host outside the requested range')
        if state=='up':
            hosts.append(found[0])
    if total!=network.num_addresses or len(hosts)!=up:
        raise ValueError('Host states do not match Nmap totals')
    return {'scanner':'nmap','version':root.attrib['version'],'target':cidr,'addresses':total,'scanned':total,'up':up,'hosts':sorted(hosts,key=ipaddress.ip_address)}
subprocess.run(json.loads(sys.argv[1]),stdout=subprocess.DEVNULL,check=True)
with open('sweep.json','w') as output:
    json.dump(parse(pathlib.Path('sweep.xml').read_bytes(),json.loads(sys.argv[1])[-1]),output)
`
