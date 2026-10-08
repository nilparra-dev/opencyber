export * as ForkCyberServices from "./services.js"

import { Effect, Schema } from "effect"
import { BlockList, isIP } from "node:net"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

const integer = (minimum: number, maximum: number) =>
  Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum, maximum }))
const text = Schema.String.check(Schema.isMaxLength(1024))
const state = Schema.Literals(["open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"])
const Targets = {
  host: ForkCyberScope.Host,
  ports: Schema.Array(integer(1, 65535)).check(Schema.isMinLength(1), Schema.isMaxLength(32)),
  family: Schema.optional(Schema.Literals(["ipv4", "ipv6"])),
  timeout_ms: Schema.optional(integer(1000, 120000)),
}
export const Action = Schema.Union([
  Schema.Struct({ action: Schema.Literal("procedures") }),
  Schema.Struct({ action: Schema.Literal("scan"), ...Targets }),
  Schema.Struct({ action: Schema.Literal("version"), ...Targets }),
  // UDP needs raw sockets. This workload has none, so the action reports not_configured instead of failing silently.
  Schema.Struct({ action: Schema.Literal("udp_top"), host: ForkCyberScope.Host }),
  Schema.Struct({
    action: Schema.Literal("probe"),
    host: ForkCyberScope.Host,
    port: integer(1, 65535),
    check: Schema.Literals(["redis_info", "elasticsearch_root"]),
    family: Schema.optional(Schema.Literals(["ipv4", "ipv6"])),
    timeout_ms: Schema.optional(integer(1000, 30000)),
  }),
])
export type Action = typeof Action.Type
export type Probe = Extract<Action, { action: "probe" }>
export const Report = Schema.Struct({
  scanner: Schema.Literal("nmap"),
  version: text,
  started_at: text,
  finished_at: text,
  address: Schema.String.check(Schema.makeFilter<string>((value) => isIP(value) !== 0 || "Expected an IP")),
  host_state: Schema.Literals(["up", "down"]),
  scanned_ports: Schema.Array(integer(1, 65535)).check(Schema.isMinLength(1), Schema.isMaxLength(32)),
  ports: Schema.Array(
    Schema.Struct({
      port: integer(1, 65535),
      state,
      reason: text,
      service: Schema.optional(
        Schema.Struct({
          name: text,
          method: Schema.Literals(["table", "probed"]),
          confidence: integer(0, 10),
          product: Schema.optional(text),
          version: Schema.optional(text),
          extrainfo: Schema.optional(text),
        }),
      ),
    }),
  ).check(Schema.isMaxLength(32)),
  extra_ports: Schema.Array(Schema.Struct({ state, count: integer(1, 32) })).check(Schema.isMaxLength(6)),
})
type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
type Assessment = {
  owner: string
  session: string
  agent: string
  manifest: ForkCyberScope.Manifest
}

export const procedures = {
  module: "tcp-services-v1",
  procedures: [
    "Claim a cyber-recon or cyber-enum task for one explicit host, TCP ports and an exposure hypothesis.",
    "Scan only the assigned ports using cyber_services. Retrieve the XML, normalized capture and network-policy artifacts with evidence.",
    "Distinguish open, closed, filtered and unreported ports. Table-derived service names are guesses. Probed names from version come from light version detection and are still observations.",
    "Compare the observation with the expected deployment and a known closed or restricted control. An open port alone is not a vulnerability.",
    "Record exposure candidates with completed output evidence. Have validation reproduce any authentication or impact claim with a protocol-specific procedure.",
    "Complete the task with its own output evidence and report untested hosts, ports, address families and protocols.",
  ],
  limits: [
    "One exact host, one address family and at most 32 explicit TCP ports per job. Hostnames use the first pinned address selected by Nmap, not every DNS address.",
    "Connect scans establish TCP connections. version adds light version detection without scripts. No raw packets, host discovery, reverse DNS, NSE scripts or arbitrary scanner options. UDP is not configured in this workload.",
    "Nmap port states describe this observation path. Filtering, network budgets and firewalls can change results; closed or filtered does not establish security.",
    "Collapsed XML port groups remain aggregate counts. Missing per-port records are unreported, never silently classified as closed.",
    "Requires an explicit engagement, scoped Kali network and separate connection, packet, byte and duration budgets. Free-text windows and no_dos are operator constraints.",
  ],
  probe: {
    // Each probe sends one unauthenticated request per call and no credentials.
    implemented: ["redis_info", "elasticsearch_root"],
    // Not run yet. Anonymous FTP login is excluded because it is an authentication attempt.
    not_implemented: ["ftp_anonymous", "ldap_root_dse", "smb_signing", "nfs_exports", "mongodb_build_info"],
    limits: [
      "One port and one check per call, within the same scope and connection budgets as scans. Checks not listed as implemented were not run.",
      "A probe reports what the service answered to one request. It does not establish a vulnerability.",
    ],
  },
}

// probe has its own function so the scan result type stays exact for callers.
export const run = Effect.fn("ForkCyberServices.run")(function* (
  store: Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: Assessment,
  input: Exclude<Action, Probe>,
) {
  const role = assessment.agent
  if (!ForkCyberRoles.allowed(role, "cyber_services"))
    return yield* Effect.fail(new Error(`Phase ${role} cannot execute cyber_services`))
  if (input.action === "procedures") return procedures
  if (ForkCyberRoles.worker(assessment.agent)) yield* store.coordination.requireClaim(assessment)
  if (input.action === "udp_top")
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "configuration",
        operation: "cyber_services",
        message: "UDP top-port scans need raw sockets, which the Kali workload does not have",
        target_started: false,
        effects: "not_started",
        recovery:
          "Use scan for TCP inventory. UDP checks need an operator-approved profile that grants NET_RAW; this workload does not.",
      }),
    )
  const host = ForkCyberScope.normalize(input.host)
  const ports = [...new Set(input.ports)].toSorted((a, b) => a - b)
  yield* Effect.try(() => {
    if (config.network.kind !== "scoped") throw new Error("TCP scans require a scoped Kali network")
    if (assessment.manifest.derived) throw new Error("TCP scans require explicit engagement scope")
    if (assessment.manifest.scope.excluded.some((entry) => matches(host, entry)))
      throw new Error("TCP destination is excluded")
    ports.forEach((port) => ForkCyberScope.authorize(assessment.manifest, host, "tcp", port))
    if (isIP(host) && (isIP(host) === 6) !== (input.family === "ipv6"))
      throw new Error("The target IP must match the selected address family")
  }).pipe(Effect.mapError((error) => new Error(String(error.cause))))
  const budget = assessment.manifest.rules_of_engagement.network
  if (!budget) return yield* Effect.fail(new Error("TCP scans require explicit network budgets"))
  const timeout = Math.min(input.timeout_ms ?? 30000, config.timeout_ms ?? 300000, budget.duration_ms)
  const argv = [
    "/usr/lib/nmap/nmap",
    "--unprivileged",
    "-sT",
    "-Pn",
    "-n",
    "--disable-arp-ping",
    "-vv",
    "--reason",
    "--max-parallelism",
    "1",
    "--max-retries",
    "1",
    "--scan-delay",
    `${Math.ceil(1000 / budget.connections_per_second)}ms`,
    "--host-timeout",
    `${timeout}ms`,
    "-p",
    ports.join(","),
    "-oX",
    "services.xml",
    ...(input.family === "ipv6" ? ["-6"] : []),
    // Light version detection: no NSE scripts, and fewer probes than the default intensity.
    ...(input.action === "version" ? ["-sV", "--version-light"] : []),
    host,
  ]
  return yield* ForkCyberKali.manager(store, profile, config).run(
    assessment,
    {
      argv: ["python3", "-I", "-c", SCAN, JSON.stringify(argv)],
      timeout_ms: timeout,
      outputs: ["services.xml", "services.json"],
    },
    {
      tool: "cyber_services",
      parse: (result) =>
        Effect.gen(function* () {
          if (result.exit_code !== 0)
            return yield* Effect.fail(new Error(`Nmap capture failed (exit ${result.exit_code})`))
          const report = result.files.find((file) => file.name === "services.json")!
          const raw = result.files.find((file) => file.name === "services.xml")!
          const bytes = yield* store.readArtifact(assessment.owner, report.artifact)
          const parsed = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Report))(bytes.bytes.toString()).pipe(
            Effect.mapError((error) => new Error(String(error))),
          )
          if (
            parsed.scanned_ports.join(",") !== ports.join(",") ||
            parsed.ports.some((entry) => !ports.includes(entry.port)) ||
            new Set(parsed.ports.map((entry) => entry.port)).size !== parsed.ports.length ||
            parsed.ports.length + parsed.extra_ports.reduce((total, group) => total + group.count, 0) !==
              ports.length ||
            isIP(parsed.address) !== (input.family === "ipv6" ? 6 : 4) ||
            (isIP(host) !== 0 && !matches(parsed.address, host))
          )
            return yield* Effect.fail(new Error("Nmap report does not match the requested ports and address family"))
          const xml = yield* store.readArtifact(assessment.owner, raw.artifact)
          return {
            format: "opencyber-tcp-services-v1",
            action: input.action,
            target: host,
            family: input.family ?? "ipv4",
            ...parsed,
            unreported_ports: ports.filter((port) => !parsed.ports.some((entry) => entry.port === port)),
            xml_excerpt: ForkCyberKali.excerpt(xml.bytes),
            xml_artifact: raw.artifact,
            report_artifact: report.artifact,
            limitations: procedures.limits,
          }
        }),
    },
  )
})

export const probe = Effect.fn("ForkCyberServices.probe")(function* (
  store: Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: Assessment,
  input: Probe,
) {
  if (!ForkCyberRoles.allowed(assessment.agent, "cyber_services"))
    return yield* Effect.fail(new Error(`Phase ${assessment.agent} cannot execute cyber_services`))
  if (ForkCyberRoles.worker(assessment.agent)) yield* store.coordination.requireClaim(assessment)
  const host = ForkCyberScope.normalize(input.host)
  yield* Effect.try(() => {
    if (config.network.kind !== "scoped") throw new Error("Service probes require a scoped Kali network")
    if (assessment.manifest.derived) throw new Error("Service probes require explicit engagement scope")
    if (assessment.manifest.scope.excluded.some((entry) => matches(host, entry)))
      throw new Error("TCP destination is excluded")
    ForkCyberScope.authorize(assessment.manifest, host, "tcp", input.port)
    if (isIP(host) && (isIP(host) === 6) !== (input.family === "ipv6"))
      throw new Error("The target IP must match the selected address family")
  }).pipe(Effect.mapError((error) => new Error(String(error.cause))))
  const budget = assessment.manifest.rules_of_engagement.network
  if (!budget) return yield* Effect.fail(new Error("Service probes require explicit network budgets"))
  const timeout = Math.min(input.timeout_ms ?? 10000, config.timeout_ms ?? 300000, budget.duration_ms)
  const family = input.family ?? "ipv4"
  return yield* ForkCyberKali.manager(store, profile, config).run(
    assessment,
    {
      argv: [
        "python3",
        "-I",
        "-c",
        PROBE,
        JSON.stringify({ check: input.check, host, port: input.port, timeout: timeout / 1000 }),
      ],
      timeout_ms: timeout,
      outputs: ["probe.json"],
    },
    {
      tool: "cyber_services",
      parse: (result) =>
        Effect.gen(function* () {
          if (result.exit_code !== 0)
            return yield* Effect.fail(new Error(`Service probe failed (exit ${result.exit_code})`))
          const report = result.files.find((file) => file.name === "probe.json")!
          const bytes = yield* store.readArtifact(assessment.owner, report.artifact)
          const parsed = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(ProbeReport))(
            bytes.bytes.toString(),
          ).pipe(Effect.mapError((error) => new Error(String(error))))
          if (parsed.check !== input.check || parsed.port !== input.port)
            return yield* Effect.fail(new Error("Probe report does not match the request"))
          return {
            format: "opencyber-service-probe-v1",
            action: input.action,
            target: host,
            family,
            port: input.port,
            ran: [input.check],
            not_run: procedures.probe.not_implemented,
            state: parsed.state,
            fields: parsed.fields,
            report_artifact: report.artifact,
            limitations: procedures.probe.limits,
          }
        }),
    },
  )
})

const ProbeReport = Schema.Struct({
  check: Schema.Literals(["redis_info", "elasticsearch_root"]),
  port: integer(1, 65535),
  state: Schema.Literals(["answered", "auth_required", "closed", "no_response", "unexpected", "error"]),
  fields: Schema.Record(
    Schema.String.check(Schema.isMaxLength(64)),
    Schema.NullOr(Schema.Union([Schema.String.check(Schema.isMaxLength(256)), Schema.Number])),
  ),
})

function matches(host: string, entry: string) {
  const target = ForkCyberScope.normalize(entry)
  if (!target.includes("/")) {
    if (!isIP(host) || !isIP(target)) return host === target
    const list = new BlockList()
    list.addAddress(target, isIP(target) === 4 ? "ipv4" : "ipv6")
    return list.check(host, isIP(host) === 4 ? "ipv4" : "ipv6")
  }
  if (!isIP(host)) return false
  const list = new BlockList()
  list.addSubnet(target.split("/")[0]!, Number(target.split("/")[1]), target.includes(":") ? "ipv6" : "ipv4")
  return list.check(host, isIP(host) === 4 ? "ipv4" : "ipv6")
}

// ElementTree parses only the scanner's local report. Entities and external declarations are unsupported.
export const PARSER = `import json
from xml.etree import ElementTree
def parse(raw):
    if len(raw)>2*1024*1024 or b'<!ENTITY' in raw or b'<!DOCTYPE' in raw.replace(b'<!DOCTYPE nmaprun>',b''):
        raise ValueError('Unsupported or oversized Nmap XML')
    root=ElementTree.fromstring(raw)
    if root.tag!='nmaprun' or root.get('scanner')!='nmap':
        raise ValueError('Expected a Nmap report')
    finished=root.findall('runstats/finished')
    hosts=root.findall('host')
    scans=root.findall('scaninfo')
    if len(finished)!=1 or finished[0].get('exit')!='success' or len(hosts)!=1 or len(scans)!=1:
        raise ValueError('Nmap report is incomplete or unsuccessful')
    scan=scans[0]
    if scan.get('type')!='connect' or scan.get('protocol')!='tcp':
        raise ValueError('Expected a TCP connect scan')
    scanned=[]
    for item in scan.attrib['services'].split(','):
        span=item.split('-')
        start=int(span[0]); end=int(span[-1])
        if len(span)>2 or not 1<=start<=end<=65535 or end-start>=32:
            raise ValueError('Unsupported port range')
        scanned.extend(range(start,end+1))
        if len(scanned)>32: raise ValueError('Too many ports')
    if len(set(scanned))!=len(scanned) or int(scan.attrib['numservices'])!=len(scanned):
        raise ValueError('Inconsistent scan coverage')
    host=hosts[0]
    addresses=[row for row in host.findall('address') if row.get('addrtype') in ('ipv4','ipv6')]
    if len(addresses)!=1: raise ValueError('Expected one scanned address')
    ports=[]
    for row in host.findall('ports/port'):
        if row.get('protocol')!='tcp' or len(row.findall('state'))!=1:
            raise ValueError('Unsupported port observation')
        status=row.find('state')
        entry={'port':int(row.attrib['portid']),'state':status.attrib['state'],'reason':status.get('reason','')}
        service=row.find('service')
        if service is not None:
            entry['service']={'name':service.attrib['name'],'method':service.attrib['method'],'confidence':int(service.attrib['conf'])}
            for key in ('product','version','extrainfo'):
                if service.get(key): entry['service'][key]=service.attrib[key][:1024]
        ports.append(entry)
    return {'scanner':'nmap','version':root.attrib['version'],'started_at':root.attrib['start'],
        'finished_at':finished[0].attrib['time'],'address':addresses[0].attrib['addr'],
        'host_state':host.find('status').attrib['state'],'scanned_ports':sorted(scanned),'ports':ports,
        'extra_ports':[{'state':row.attrib['state'],'count':int(row.attrib['count'])} for row in host.findall('ports/extraports')]}
`
const SCAN = `${PARSER}
import pathlib,subprocess,sys
subprocess.run(json.loads(sys.argv[1]),stdout=subprocess.DEVNULL,check=True)
with open('services.json','w') as output:
    json.dump(parse(pathlib.Path('services.xml').read_bytes()),output)
`

// Each check sends one unauthenticated request and reads a bounded reply. Nothing is retried or followed.
const PROBE = `import json,socket,sys
args=json.loads(sys.argv[1])
def read_all(sock,limit=65536):
    data=b''
    while len(data)<limit:
        chunk=sock.recv(4096)
        if not chunk: break
        data+=chunk
    return data
def redis_info(sock,host):
    sock.sendall(b'INFO server\\r\\n')
    reply=sock.recv(4096)
    if reply.startswith(b'-'):
        return ('auth_required' if b'NOAUTH' in reply else 'error'),{}
    version=None
    for line in reply.decode('utf8','replace').splitlines():
        if line.startswith('redis_version:'): version=line.split(':',1)[1].strip()[:64]
    return ('answered' if version else 'unexpected'),{'redis_version':version}
def elasticsearch_root(sock,host):
    sock.sendall(('GET / HTTP/1.1\\r\\nHost: %s\\r\\nAccept: application/json\\r\\nConnection: close\\r\\n\\r\\n' % host).encode())
    head,_,body=read_all(sock).partition(b'\\r\\n\\r\\n')
    parts=head.split(b' ')
    status=int(parts[1]) if head.startswith(b'HTTP/') and len(parts)>1 and parts[1].isdigit() else None
    if status in (401,403): return 'auth_required',{'http_status':status}
    try: document=json.loads(body.decode('utf8'))
    except ValueError: return 'unexpected',{'http_status':status}
    version=document.get('version') if isinstance(document,dict) else None
    number=version.get('number') if isinstance(version,dict) else None
    return ('answered' if number else 'unexpected'),{'http_status':status,'elasticsearch_version':None if number is None else str(number)[:64]}
CHECKS={'redis_info':redis_info,'elasticsearch_root':elasticsearch_root}
out={'check':args['check'],'port':args['port']}
try:
    sock=socket.create_connection((args['host'],args['port']),timeout=args['timeout'])
except ConnectionRefusedError:
    out.update(state='closed',fields={})
except socket.timeout:
    out.update(state='no_response',fields={})
else:
    with sock:
        try:
            state,fields=CHECKS[args['check']](sock,args['host'])
        except socket.timeout:
            state,fields='no_response',{}
        out.update(state=state,fields=fields)
with open('probe.json','w') as output:
    json.dump(out,output)
`
