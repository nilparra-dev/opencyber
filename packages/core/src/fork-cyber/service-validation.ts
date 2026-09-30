export * as ForkCyberServiceValidation from "./service-validation.js"

import { Effect, Schema } from "effect"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberSurface } from "./surface.js"

export const Action = Schema.Struct({
  action: Schema.Literal("probe"),
  module: Schema.Literals(["tls", "ssh"]),
  host: ForkCyberScope.Host,
  port: ForkCyberSurface.Port,
})
export const Report = Schema.Union([
  Schema.Struct({
    protocol: Schema.Literal("tls"),
    versions: Schema.Array(
      Schema.Struct({ version: Schema.String, accepted: Schema.Boolean, error: Schema.optional(Schema.String) }),
    ),
    certificate_sha256: Schema.String,
    certificate_not_before: Schema.Number,
    certificate_not_after: Schema.Number,
    certificate_time_valid: Schema.Boolean,
    trust_verified: Schema.Literal(false),
  }),
  Schema.Struct({
    protocol: Schema.Literal("ssh"),
    banner: Schema.String.check(Schema.isMaxLength(255)),
    algorithms: Schema.Record(Schema.String, Schema.Array(Schema.String).check(Schema.isMaxLength(128))),
    legacy_algorithms: Schema.Array(Schema.String),
    authentication_tested: Schema.Literal(false),
  }),
])
export const procedures = {
  module: "tls-ssh-v1",
  procedures: [
    "Claim a validation task for one explicit TCP endpoint. Inventory its port first; probe the actual protocol with cyber_surface.",
    "TLS performs four bounded handshakes. Inspect accepted legacy versions and certificate validity dates. Trust, hostname verification and cipher coverage remain pending.",
    "SSH reads an SSH-2.0 identification and a complete KEXINIT packet. Review advertised algorithms against deployment requirements; no login or host-key authentication is attempted.",
    "Repeat a candidate against a healthy control, retrieve raw artifacts, and record a finding only for the reproduced property. Complete the task with output evidence.",
  ],
  limits: [
    "No exploit, credential guessing, TLS trust verdict, CVE inference or automatic finding confirmation.",
    "A rejected handshake may be a network or client compatibility error. It never proves that the server excludes that version.",
  ],
}

export const run = Effect.fn(function* (
  store: ForkCyberSurface.Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: ForkCyberSurface.Assessment,
  input: typeof Action.Type,
) {
  yield* Effect.try(() => ForkCyberSurface.network(config, assessment, input.host, input.port))
  return yield* ForkCyberSurface.job(
    store,
    profile,
    config,
    assessment,
    input.module,
    {
      argv: ["python3", "-I", "-c", PROBE, JSON.stringify(input)],
      timeout_ms: 30000,
      outputs: ["protocol.raw", "report.json"],
    },
    Report,
  )
})

export const PROBE = `import socket,ssl,struct,json,sys,pathlib,hashlib,subprocess,datetime,time
p=json.loads(sys.argv[1]); host=p['host']; port=p['port']
raw=bytearray()
pathlib.Path('protocol.raw').write_bytes(raw)
if p['module']=='tls':
    versions=[]; cert=None
    for name,version in [('TLSv1',ssl.TLSVersion.TLSv1),('TLSv1.1',ssl.TLSVersion.TLSv1_1),('TLSv1.2',ssl.TLSVersion.TLSv1_2),('TLSv1.3',ssl.TLSVersion.TLSv1_3)]:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); context.check_hostname=False; context.verify_mode=ssl.CERT_NONE
        context.minimum_version=version; context.maximum_version=version; context.set_ciphers('ALL:@SECLEVEL=0')
        try:
            with socket.create_connection((host,port),3) as tcp:
                with context.wrap_socket(tcp,server_hostname=host) as conn:
                    cert=conn.getpeercert(binary_form=True); versions.append({'version':name,'accepted':True})
        except (OSError,ssl.SSLError) as error:
            versions.append({'version':name,'accepted':False,'error':str(error)[:1024]})
    if cert is None: raise ValueError('No TLS handshake succeeded; service identification is incomplete')
    raw.extend(cert)
    dates=subprocess.run(['openssl','x509','-inform','DER','-noout','-dates'],input=cert,capture_output=True,check=True).stdout.decode().splitlines()
    values={row.split('=',1)[0]:datetime.datetime.strptime(row.split('=',1)[1],'%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc).timestamp() for row in dates}
    report={'protocol':'tls','versions':versions,'certificate_sha256':hashlib.sha256(cert).hexdigest(),
        'certificate_not_before':values['notBefore'],'certificate_not_after':values['notAfter'],
        'certificate_time_valid':values['notBefore']<=time.time()<=values['notAfter'],'trust_verified':False}
else:
    def exact(conn,length):
        result=bytearray()
        while len(result)<length:
            chunk=conn.recv(length-len(result))
            if not chunk: raise ValueError('Truncated SSH packet')
            result.extend(chunk)
        raw.extend(result); pathlib.Path('protocol.raw').write_bytes(raw); return bytes(result)
    with socket.create_connection((host,port),3) as conn:
        conn.sendall(b'SSH-2.0-OpenCyber_probe\\r\\n')
        banner=b''
        for _ in range(16):
            line=bytearray()
            while not line.endswith(b'\\n') and len(line)<255: line.extend(exact(conn,1))
            if not line.endswith(b'\\n'): raise ValueError('Oversized SSH identification')
            if line.startswith(b'SSH-'): banner=bytes(line).rstrip(b'\\r\\n'); break
        if not banner.startswith(b'SSH-2.0-'): raise ValueError('Expected SSH-2.0 identification')
        length=struct.unpack('!I',exact(conn,4))[0]
        if not 32<=length<=35000 or (length+4)%8: raise ValueError('Invalid SSH packet length')
        packet=exact(conn,length); padding=packet[0]
        if padding<4 or padding>=length-1: raise ValueError('Invalid SSH padding')
        payload=packet[1:-padding]
        if payload[0]!=20: raise ValueError('Expected SSH KEXINIT')
        position=17; algorithms={}
        for key in ['kex','host_key','encryption_client','encryption_server','mac_client','mac_server','compression_client','compression_server','language_client','language_server']:
            if position+4>len(payload): raise ValueError('Truncated SSH name-list')
            size=struct.unpack('!I',payload[position:position+4])[0]; position+=4
            if size>8192 or position+size>len(payload): raise ValueError('Oversized SSH name-list')
            names=payload[position:position+size].decode('ascii'); position+=size
            algorithms[key]=names.split(',') if names else []
            if len(algorithms[key])>128: raise ValueError('Too many SSH algorithms')
        if position+5!=len(payload) or payload[position] not in (0,1) or payload[position+1:]!=b'\\x00'*4: raise ValueError('Invalid KEXINIT trailer')
    legacy={'diffie-hellman-group1-sha1','ssh-dss','3des-cbc','arcfour','hmac-md5'}
    report={'protocol':'ssh','banner':banner.decode('ascii'),'algorithms':algorithms,
        'legacy_algorithms':sorted(legacy.intersection(name for names in algorithms.values() for name in names)), 'authentication_tested':False}
pathlib.Path('protocol.raw').write_bytes(raw)
pathlib.Path('report.json').write_text(json.dumps(report))
`
