export * as ForkCyberArtifactValidation from "./artifact-validation.js"

import { Effect, Schema } from "effect"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberSurface } from "./surface.js"

export const Action = Schema.Union([
  Schema.Struct({
    module: Schema.Literal("mobile"),
    action: Schema.Literal("apk"),
    artifact: ForkCyberSurface.Artifact,
  }),
  Schema.Struct({
    module: Schema.Literal("wireless"),
    action: Schema.Literal("pcap"),
    artifact: ForkCyberSurface.Artifact,
    bssid: Schema.String.check(Schema.isPattern(/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/)),
  }),
  Schema.Struct({
    module: Schema.Literal("binary"),
    action: Schema.Literal("elf"),
    artifact: ForkCyberSurface.Artifact,
  }),
  Schema.Struct({
    module: Schema.Literal("binary"),
    action: Schema.Literal("execute"),
    artifact: ForkCyberSurface.Artifact,
    stdin: Schema.String.check(Schema.isMaxLength(1024)),
  }),
])

export const Report = Schema.Union([
  Schema.Struct({
    module: Schema.Literal("mobile"),
    package: Schema.String,
    application: Schema.Record(Schema.String, Schema.Union([Schema.String, Schema.Boolean, Schema.Number])),
    components: Schema.Array(
      Schema.Struct({
        kind: Schema.String,
        attributes: Schema.Record(Schema.String, Schema.Union([Schema.String, Schema.Boolean, Schema.Number])),
      }),
    ).check(Schema.isMaxLength(256)),
    candidates: Schema.Array(Schema.String),
    execution_tested: Schema.Literal(false),
  }),
  Schema.Struct({
    module: Schema.Literal("wireless"),
    bssid: Schema.String,
    beacons: Schema.Array(
      Schema.Struct({
        ssid: Schema.String,
        security: Schema.Literals(["open", "rsn", "legacy_or_unknown"]),
        cipher_suites: Schema.Array(Schema.String),
        record: Schema.Number,
      }),
    ).check(Schema.isMaxLength(128)),
    records_read: Schema.Number,
    unsupported_frames: Schema.Number,
  }),
  Schema.Struct({
    module: Schema.Literal("binary"),
    action: Schema.Literal("elf"),
    class: Schema.Literals([32, 64]),
    machine: Schema.Number,
    type: Schema.Number,
    executable_stack: Schema.Union([Schema.Boolean, Schema.Null]),
    needed: Schema.Array(Schema.String),
    readelf: Schema.String.check(Schema.isMaxLength(65536)),
  }),
  Schema.Struct({
    module: Schema.Literal("binary"),
    action: Schema.Literal("execute"),
    exit_code: Schema.NullOr(Schema.Number),
    timed_out: Schema.Boolean,
    stdout_base64: Schema.String,
    stderr_base64: Schema.String,
  }),
])

export const procedures = {
  mobile: {
    module: "android-apk-v1",
    procedures: [
      "Import one authorized project APK with cyber_surface.import, then inspect its artifact with apk.",
      "Parse the compiled Android manifest, package, explicit application flags and component permissions. Treat debuggable, cleartext and exported attributes as candidates.",
      "Compare a deliberately debuggable package with a release control. Retrieve original APK and manifest evidence. Validate reachable behavior on an authorized emulator before claiming application impact.",
      "Record candidates, complete the task and list untested runtime, native, signing and platform behavior.",
    ],
    limits: [
      "Static Android APK manifest workflow. No iOS, emulator, device, signature verification or application execution.",
      "Missing attributes remain missing. Exported components can be intentional; manifest observations do not prove exploitable access.",
    ],
  },
  binary: {
    module: "elf-v1",
    procedures: [
      "Import one explicit ELF artifact and run elf for class, architecture, dependencies and stack metadata. Never use ldd on an untrusted executable.",
      "For a controlled reproducer, use execute with explicit stdin. It runs only the artifact, without command arguments, in a fresh network-disabled Kali workspace.",
      "Compare a reproducible failing input and a healthy binary with the same input. Retrieve raw program output, exit status, timeout and environment inventory.",
      "A crash is a fault candidate. Prove the security consequence separately, then record findings and complete the task with its output evidence.",
    ],
    limits: [
      "ELF on the Kali host architecture only; no PE, Mach-O, emulation, fuzzing or kernel isolation guarantee.",
      "Docker isolation shares the host kernel. Each execution has a two-second child deadline; unsupported architecture and loader errors are operational errors, not vulnerability findings.",
      "Static hardening metadata does not establish exploitability. A timeout is distinct from a crash.",
    ],
  },
  wireless: {
    module: "wireless-beacons-v1",
    procedures: [
      "Capture beacons in an authorized radio lab, then import the explicit PCAP file. No adapter operation is performed by this module.",
      "Select the authorized BSSID explicitly. Parse IEEE 802.11 beacon security advertisements from raw 802.11 or radiotap PCAP.",
      "Compare an open beacon capture with an RSN control for the same laboratory BSSID. Review advertised cipher suites and preserve the source capture.",
      "Record observed exposure candidates. Validate radio reachability and association on a real adapter before reporting wireless impact. List unsupported frames and uncaptured traffic.",
    ],
    limits: [
      "Offline classic PCAP only; no PCAPNG, live capture, injection, deauthentication, key recovery or association.",
      "An RSN advertisement is not proof of secure configuration or authentication. Synthetic captures verify decoding, not radio behavior.",
    ],
  },
}

export const run = Effect.fn(function* (
  store: ForkCyberSurface.Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: ForkCyberSurface.Assessment,
  input: typeof Action.Type,
) {
  if (config.network.kind !== "none")
    return yield* Effect.fail(new Error("Artifact analysis requires network-disabled Kali"))
  const source = yield* store.readArtifact(assessment.owner, input.artifact)
  if (source.bytes.length > 16 * 1024 * 1024) return yield* Effect.fail(new Error("Artifact analysis exceeds 16 MiB"))
  const program = input.module === "mobile" ? APK : input.module === "wireless" ? PCAP : ELF
  return yield* ForkCyberSurface.job(
    store,
    profile,
    input.action === "execute" ? { ...config, executable_work: true } : config,
    assessment,
    input.module,
    {
      argv: ["python3", "-I", "-c", program, JSON.stringify(input)],
      inputs: [{ name: "input.bin", artifact: input.artifact }],
      outputs: ["analysis.raw", "report.json"],
      timeout_ms: 15000,
    },
    Report,
  )
})

export const APK = `import pathlib,zipfile,struct,json,sys
with zipfile.ZipFile('input.bin') as archive:
    entries=archive.infolist()
    if len(entries)>4096 or len({row.filename for row in entries})!=len(entries): raise ValueError('Unsupported APK entries')
    item=archive.getinfo('AndroidManifest.xml')
    if item.file_size>2*1024*1024: raise ValueError('Android manifest exceeds 2 MiB')
    raw=archive.read(item)
pathlib.Path('analysis.raw').write_bytes(raw)
def u16(offset): return struct.unpack_from('<H',raw,offset)[0]
def u32(offset): return struct.unpack_from('<I',raw,offset)[0]
if len(raw)<8 or u16(0)!=3 or u16(2)!=8 or u32(4)!=len(raw): raise ValueError('Expected compiled Android binary XML')
strings=[]; position=8; application={}; components=[]; package=None; stack=[]; application_seen=False
def string(index):
    if index==0xffffffff: return ''
    if index>=len(strings): raise ValueError('Invalid Android string reference')
    return strings[index]
while position<len(raw):
    if position+8>len(raw): raise ValueError('Truncated XML chunk')
    kind=u16(position); header=u16(position+2); size=u32(position+4)
    if size<header or header<8 or position+size>len(raw): raise ValueError('Invalid XML chunk length')
    end=position+size
    if kind==1:
        if strings or header<28: raise ValueError('Unsupported Android string pool')
        count=u32(position+8); flags=u32(position+16); start=u32(position+20)
        if count>8192 or header+count*4>size or start<header+count*4: raise ValueError('Oversized Android string pool')
        for index in range(count):
            cursor=position+start+u32(position+header+index*4)
            def length(cursor,wide):
                if cursor+(2 if wide else 1)>end: raise ValueError('Invalid string length')
                first=u16(cursor) if wide else raw[cursor]; cursor+=2 if wide else 1
                flag=0x8000 if wide else 0x80
                if first&flag:
                    if cursor+(2 if wide else 1)>end: raise ValueError('Truncated string length')
                    second=u16(cursor) if wide else raw[cursor]; cursor+=2 if wide else 1
                    first=((first&~flag)<<(16 if wide else 8))|second
                return first,cursor
            if flags&0x100:
                _,cursor=length(cursor,False); count_bytes,cursor=length(cursor,False); width=1; encoding='utf-8'
            else:
                characters,cursor=length(cursor,True); count_bytes=characters*2; width=2; encoding='utf-16le'
            if cursor+count_bytes+width>end or raw[cursor+count_bytes:cursor+count_bytes+width]!=b'\\x00'*width: raise ValueError('Truncated Android string')
            strings.append(raw[cursor:cursor+count_bytes].decode(encoding))
    elif kind==0x102:
        if header!=16 or size<36: raise ValueError('Invalid Android element')
        if u32(position+16)!=0xffffffff: raise ValueError('Namespaced Android elements are unsupported')
        name=string(u32(position+20)); start=u16(position+24); width=u16(position+26); count=u16(position+28)
        if width!=20 or count>256 or start<20 or 16+start+count*width>size: raise ValueError('Invalid Android attributes')
        attributes={}
        for index in range(count):
            cursor=position+16+start+index*width; namespace=string(u32(cursor)); name_attr=string(u32(cursor+4))
            key=name_attr if namespace=='http://schemas.android.com/apk/res/android' or (namespace=='' and name_attr=='package') else '{'+namespace+'}'+name_attr
            literal=u32(cursor+8); value_type=raw[cursor+15]; data=u32(cursor+16)
            if u16(cursor+12)!=8 or raw[cursor+14]!=0: raise ValueError('Invalid Android typed value')
            if key in attributes: raise ValueError('Ambiguous Android attribute names')
            attributes[key]=string(literal) if literal!=0xffffffff else (string(data) if value_type==3 else bool(data) if value_type==0x12 else data)
        if name=='manifest':
            if package is not None or stack: raise ValueError('Duplicate Android manifest')
            package=attributes.get('package')
        if name=='application':
            if application_seen or stack!=['manifest']: raise ValueError('Invalid Android application element')
            application_seen=True; application=attributes
        if name in ('activity','activity-alias','service','receiver','provider'):
            components.append({'kind':name,'attributes':attributes})
        stack.append(name)
        if len(stack)>64 or len(components)>256: raise ValueError('Android manifest exceeds structural limits')
    elif kind==0x103:
        if header!=16 or size<24 or not stack or stack.pop()!=string(u32(position+20)): raise ValueError('Unbalanced Android manifest')
    position=end
if stack or not isinstance(package,str) or not package: raise ValueError('Incomplete Android manifest')
candidates=[]
if application.get('debuggable') is True: candidates.append('explicit-debuggable')
if application.get('usesCleartextTraffic') is True: candidates.append('explicit-cleartext')
for row in components:
    if row['attributes'].get('exported') is True and not row['attributes'].get('permission') and not application.get('permission'):
        candidates.append('exported-without-permission:'+str(row['attributes'].get('name','unknown')))
pathlib.Path('report.json').write_text(json.dumps({'module':'mobile','package':package,'application':application,'components':components,'candidates':candidates,'execution_tested':False}))
`

export const PCAP = `import pathlib,struct,json,sys
p=json.loads(sys.argv[1]); raw=pathlib.Path('input.bin').read_bytes()
pathlib.Path('analysis.raw').write_bytes(raw)
if len(raw)>2*1024*1024 or len(raw)<24: raise ValueError('PCAP requires 24 bytes to 2 MiB')
magic=raw[:4]
if magic not in (b'\\xd4\\xc3\\xb2\\xa1',b'\\xa1\\xb2\\xc3\\xd4',b'\\x4d\\x3c\\xb2\\xa1',b'\\xa1\\xb2\\x3c\\x4d'): raise ValueError('Unsupported PCAP format')
order='<' if magic in (b'\\xd4\\xc3\\xb2\\xa1',b'\\x4d\\x3c\\xb2\\xa1') else '>'
major,minor,zone,sig,snap,link=struct.unpack_from(order+'HHIIII',raw,4)
if (major,minor)!=(2,4) or link not in (105,127) or not 1<=snap<=65535: raise ValueError('Unsupported PCAP header')
position=24; records=0; unsupported=0; beacons=[]
while position<len(raw):
    if records>=4096 or position+16>len(raw): raise ValueError('Oversized or truncated PCAP')
    seconds,fraction,size,original=struct.unpack_from(order+'IIII',raw,position); position+=16
    if size>snap or size>original or position+size>len(raw): raise ValueError('Truncated PCAP record')
    packet=raw[position:position+size]; position+=size; records+=1
    if link==127:
        if len(packet)<8 or packet[0]!=0: raise ValueError('Invalid radiotap header')
        header=struct.unpack_from('<H',packet,2)[0]
        if not 8<=header<=len(packet): raise ValueError('Truncated radiotap header')
        packet=packet[header:]
    if len(packet)<24: raise ValueError('Truncated 802.11 frame')
    if packet[0]!=0x80: unsupported+=1; continue
    if len(packet)<36: raise ValueError('Truncated beacon')
    bssid=':'.join(format(byte,'02x') for byte in packet[16:22])
    if bssid!=p['bssid']: continue
    privacy=bool(struct.unpack_from('<H',packet,34)[0]&0x10); cursor=36; ssid=None; suites=[]; rsn=False
    while cursor<len(packet):
        if cursor+2>len(packet): raise ValueError('Truncated beacon element')
        kind,size=packet[cursor:cursor+2]; cursor+=2
        if cursor+size>len(packet): raise ValueError('Truncated beacon element value')
        data=packet[cursor:cursor+size]; cursor+=size
        if kind==0:
            if ssid is not None or size>32: raise ValueError('Invalid SSID')
            ssid=data.decode('utf-8',errors='replace')
        if kind==48:
            if rsn or len(data)<12 or struct.unpack_from('<H',data)[0]!=1: raise ValueError('Invalid RSN element')
            rsn=True; suites=[data[2:6].hex()]; count=struct.unpack_from('<H',data,6)[0]
            if count<1 or count>16 or 8+4*count+2>len(data): raise ValueError('Truncated RSN cipher list')
            suites.extend(data[8+4*index:12+4*index].hex() for index in range(count))
            offset=8+4*count; akms=struct.unpack_from('<H',data,offset)[0]
            if akms<1 or akms>16 or offset+2+4*akms>len(data): raise ValueError('Truncated RSN authentication list')
    if ssid is None: raise ValueError('Beacon has no SSID')
    beacons.append({'ssid':ssid,'security':'rsn' if rsn else 'legacy_or_unknown' if privacy else 'open','cipher_suites':suites,'record':records})
    if len(beacons)>128: raise ValueError('Too many matching beacons')
if not beacons: raise ValueError('No matching BSSID beacons; coverage is incomplete')
pathlib.Path('analysis.raw').write_bytes(raw)
pathlib.Path('report.json').write_text(json.dumps({'module':'wireless','bssid':p['bssid'],'beacons':beacons,'records_read':records,'unsupported_frames':unsupported}))
`

export const ELF = `import pathlib,struct,json,sys,subprocess,base64,os
p=json.loads(sys.argv[1]); raw=pathlib.Path('input.bin').read_bytes()
if len(raw)<64 or raw[:4]!=b'\\x7fELF' or raw[4] not in (1,2) or raw[5] not in (1,2) or raw[6]!=1: raise ValueError('Unsupported or truncated ELF')
if p['action']=='elf':
    result=subprocess.run(['readelf','--wide','--file-header','--program-headers','--dynamic','input.bin'],capture_output=True,check=True,timeout=3)
    text=result.stdout.decode('utf-8'); order='<' if raw[5]==1 else '>'; kind,machine=struct.unpack_from(order+'HH',raw,16)
    stack=[row for row in text.splitlines() if 'GNU_STACK' in row]
    needed=[row.split('[',1)[1].split(']',1)[0] for row in text.splitlines() if '(NEEDED)' in row and '[' in row]
    report={'module':'binary','action':'elf','class':32 if raw[4]==1 else 64,'machine':machine,'type':kind,'executable_stack':('E' in stack[0].split()[-2]) if stack else None,'needed':needed,'readelf':text}
    pathlib.Path('analysis.raw').write_bytes(result.stdout)
else:
    os.chmod('input.bin',0o700)
    # File-backed output prevents a noisy executable from exhausting the capture process memory.
    with open('program.stdout','wb') as out,open('program.stderr','wb') as err:
        child=subprocess.Popen(['/work/input.bin'],stdin=subprocess.PIPE,stdout=out,stderr=err,env={'PATH':'/usr/bin:/bin','HOME':'/work','LANG':'C'})
        try:
            child.communicate(p['stdin'].encode(),timeout=2); timed_out=False
        except subprocess.TimeoutExpired:
            child.kill(); child.communicate(); timed_out=True
    with open('program.stdout','rb') as source: out=source.read(65536)
    with open('program.stderr','rb') as source: err=source.read(65536)
    report={'module':'binary','action':'execute','exit_code':None if timed_out else child.returncode,'timed_out':timed_out,'stdout_base64':base64.b64encode(out).decode(),'stderr_base64':base64.b64encode(err).decode()}
    pathlib.Path('analysis.raw').write_bytes(out+b'\\n---stderr---\\n'+err)
pathlib.Path('report.json').write_text(json.dumps(report))
`
