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
const probeChecks = [
  "redis_info",
  "elasticsearch_root",
  "ldap_root_dse",
  "smb_signing",
  "nfs_exports",
  "mongodb_build_info",
] as const
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
    check: Schema.Literals(probeChecks),
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
    implemented: probeChecks,
    // Not run. Anonymous FTP login is excluded because it is an authentication attempt.
    not_implemented: ["ftp_anonymous"],
    limits: [
      "One port and one check per call, within the same scope and connection budgets as scans. Checks not listed as implemented were not run.",
      "A probe reports what the service answered to one request. It does not establish a vulnerability.",
      "ldap_root_dse reads the anonymous root DSE over plaintext LDAP without StartTLS. smb_signing negotiates SMB 2 and 3 only and reports a SMB1-only server as unexpected. nfs_exports must target the mountd TCP port; it does not query the portmapper.",
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
  check: Schema.Literals(probeChecks),
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
// Checks parse replies strictly: truncated or unexpected bytes raise ValueError, reported as unexpected.
const PROBE = `import json,socket,struct,sys
args=json.loads(sys.argv[1])
def read_all(sock,limit=65536):
    data=b''
    while len(data)<limit:
        chunk=sock.recv(4096)
        if not chunk: break
        data+=chunk
    return data
def read_exact(sock,count):
    data=b''
    while len(data)<count:
        chunk=sock.recv(count-len(data))
        if not chunk: raise ValueError('Connection closed')
        data+=chunk
    return data
def take(data,pos,count):
    if pos<0 or count<0 or pos+count>len(data): raise ValueError('Truncated reply')
    return data[pos:pos+count]
def le(value,count): return value.to_bytes(count,'little')
def be(value,count=4): return value.to_bytes(count,'big')
def le_read(data,pos,count=4,signed=False): return int.from_bytes(take(data,pos,count),'little',signed=signed)
def be_read(data,pos,count=4): return int.from_bytes(take(data,pos,count),'big')
def pad(size): return (-size)%4
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
def ber(tag,content):
    size=len(content)
    if size<128: return bytes([tag,size])+content
    count=(size.bit_length()+7)//8
    return bytes([tag,128|count])+size.to_bytes(count,'big')+content
def ber_items(data):
    items=[]
    pos=0
    while pos<len(data):
        tag=take(data,pos,1)[0]
        first=take(data,pos+1,1)[0]
        count=first&127 if first&128 else 0
        if (first&128 and count==0) or count>4: raise ValueError('Unsupported BER length')
        size=be_read(data,pos+2,count) if count else first
        start=pos+2+count
        items.append((tag,take(data,start,size)))
        pos=start+size
    return items
def ber_read(sock):
    head=read_exact(sock,2)
    raw=head
    size=head[1]
    if head[1]&128:
        count=head[1]&127
        if count==0 or count>4: raise ValueError('Unsupported BER length')
        extra=read_exact(sock,count)
        raw+=extra
        size=int.from_bytes(extra,'big')
    if size>65536: raise ValueError('Oversized LDAP message')
    return ber_items(raw+read_exact(sock,size))[0]
def ldap_result(code,entry):
    if code in (8,50): return 'auth_required',{'result_code':code}
    if code!=0 or entry is None: return 'unexpected',{'result_code':code}
    attributes={}
    for _,partial in ber_items(ber_items(entry)[1][1]):
        name,values=ber_items(partial)
        attributes[name[1].decode('utf8','replace')]=[value[1].decode('utf8','replace') for value in ber_items(values[1])]
    def first(name):
        values=attributes.get(name,[])
        return values[0][:200] if values else None
    return 'answered',{'vendor_name':first('vendorName'),'vendor_version':first('vendorVersion'),'supported_ldap_version':first('supportedLDAPVersion'),'naming_contexts':len(attributes.get('namingContexts',[]))}
def ldap_root_dse(sock,host):
    attributes=b''.join(ber(4,name.encode()) for name in ('namingContexts','supportedLDAPVersion','vendorName','vendorVersion'))
    search=ber(99,ber(4,b'')+ber(10,bytes(1))+ber(10,bytes(1))+ber(2,bytes(1))+ber(2,bytes(1))+ber(1,bytes(1))+ber(135,b'objectClass')+ber(48,attributes))
    sock.sendall(ber(48,ber(2,bytes([1]))+search))
    entry=None
    for _ in range(16):
        tag,body=ber_read(sock)
        if tag!=48: raise ValueError('Expected an LDAP message')
        operation,content=ber_items(body)[1]
        if operation==100: entry=content
        if operation==101: return ldap_result(int.from_bytes(ber_items(content)[0][1],'big'),entry)
    raise ValueError('Too many LDAP messages')
def smb_negotiate():
    header=bytes([254])+b'SMB'+le(64,2)+bytes(2)+bytes(4)+le(0,2)+le(1,2)+bytes(4)+bytes(4)+bytes(8)+bytes(4)+bytes(4)+bytes(8)+bytes(16)
    body=le(36,2)+le(4,2)+le(1,2)+bytes(2)+bytes(4)+bytes(16)+bytes(8)+b''.join(le(dialect,2) for dialect in (514,528,768,770))
    message=header+body
    return bytes([0])+len(message).to_bytes(3,'big')+message
def smb_signing(sock,host):
    sock.sendall(smb_negotiate())
    frame=read_exact(sock,4)
    if frame[0]!=0: raise ValueError('Unexpected NetBIOS frame')
    reply=read_exact(sock,be_read(frame,1,3))
    if take(reply,0,4)==bytes([255])+b'SMB': return 'unexpected',{'smb_protocol':'smb1'}
    if take(reply,0,4)!=bytes([254])+b'SMB': raise ValueError('Expected an SMB2 reply')
    status=le_read(reply,8)
    if status!=0: return 'unexpected',{'smb_status':status}
    mode=le_read(reply,66,2)
    signing='required' if mode&2 else ('enabled' if mode&1 else 'disabled')
    return 'answered',{'dialect':le_read(reply,68,2),'signing':signing}
def xdr_string(data,pos):
    size=be_read(data,pos)
    return take(data,pos+4,size).decode('utf8','replace'),pos+4+size+pad(size)
def xdr_optional(data,pos,item):
    values=[]
    while True:
        flag=be_read(data,pos)
        pos+=4
        if flag==0: return values,pos
        if flag!=1: raise ValueError('Unsupported XDR optional value')
        value,pos=item(data,pos)
        values.append(value)
def export_node(data,pos):
    directory,pos=xdr_string(data,pos)
    _,pos=xdr_optional(data,pos,xdr_string)
    return directory,pos
def nfs_exports(sock,host):
    call=be(1)+be(0)+be(2)+be(100005)+be(3)+be(5)+bytes(16)
    sock.sendall(be(2147483648|len(call))+call)
    mark=be_read(read_exact(sock,4),0)
    if (mark&2147483648)==0 or (mark&2147483647)>65536: raise ValueError('Unsupported RPC record')
    reply=read_exact(sock,mark&2147483647)
    if be_read(reply,4)!=1: raise ValueError('Expected an RPC reply')
    if be_read(reply,8)==1:
        reject=be_read(reply,12)
        return ('auth_required' if reject==1 else 'unexpected'),{'reject_stat':reject}
    if be_read(reply,8)!=0: raise ValueError('Unsupported RPC reply status')
    verifier=be_read(reply,16)
    accept_at=20+verifier+pad(verifier)
    accept=be_read(reply,accept_at)
    if accept!=0: return 'unexpected',{'accept_stat':accept}
    exports,_=xdr_optional(reply,accept_at+4,export_node)
    return 'answered',{'export_count':len(exports),'exports':';'.join(exports)[:200]}
BSON_FIXED={7:12,8:1,9:8,10:0,17:8,18:8}
def bson_values(data):
    if le_read(data,0)!=len(data) or take(data,len(data)-1,1)!=bytes(1): raise ValueError('Malformed BSON document')
    values={}
    pos=4
    while take(data,pos,1)!=bytes(1):
        kind=take(data,pos,1)[0]
        end=data.index(bytes(1),pos+1)
        name=data[pos+1:end].decode('utf8','replace')
        pos=end+1
        if kind==2:
            size=le_read(data,pos)
            values[name]=take(data,pos+4,size-1).decode('utf8','replace')
            pos+=4+size
        elif kind in (3,4):
            pos+=le_read(data,pos)
        elif kind==5:
            pos+=5+le_read(data,pos)
        elif kind==1:
            values[name]=struct.unpack('<d',take(data,pos,8))[0]
            pos+=8
        elif kind==16:
            values[name]=le_read(data,pos,4,True)
            pos+=4
        elif kind in BSON_FIXED: pos+=BSON_FIXED[kind]
        else: raise ValueError('Unsupported BSON type')
    return values
def mongodb_build_info(sock,host):
    command=bytes([16])+b'buildInfo'+bytes([0])+le(1,4)+bytes([2])+b'$db'+bytes([0])+le(6,4)+b'admin'+bytes([0])
    document=le(len(command)+5,4)+command+bytes([0])
    sock.sendall(le(21+len(document),4)+le(1,4)+bytes(4)+le(2013,4)+bytes(4)+bytes([0])+document)
    header=read_exact(sock,16)
    size=le_read(header,0)
    if le_read(header,12)!=2013 or size<21 or size>65536: raise ValueError('Expected an OP_MSG reply')
    body=read_exact(sock,size-16)
    if take(body,4,1)!=bytes(1): raise ValueError('Unsupported OP_MSG section')
    values=bson_values(body[5:])
    if values.get('ok')==1 and isinstance(values.get('version'),str): return 'answered',{'version':values['version'][:64]}
    if values.get('code')==13: return 'auth_required',{'code':13}
    return 'unexpected',{}
CHECKS={'redis_info':redis_info,'elasticsearch_root':elasticsearch_root,'ldap_root_dse':ldap_root_dse,'smb_signing':smb_signing,'nfs_exports':nfs_exports,'mongodb_build_info':mongodb_build_info}
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
        except ValueError:
            state,fields='unexpected',{}
        out.update(state=state,fields=fields)
with open('probe.json','w') as output:
    json.dump(out,output)
`
