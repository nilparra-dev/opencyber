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
      Schema.Struct({
        version: Schema.String,
        accepted: Schema.Boolean,
        state: Schema.optional(
          Schema.Literals([
            "negotiated",
            "client_unsupported",
            "server_rejected",
            "connectivity_error",
            "unknown_failure",
          ]),
        ),
        negotiated: Schema.optional(Schema.String),
        cipher: Schema.optional(Schema.String),
        error: Schema.optional(Schema.String),
      }),
    ),
    certificate_sha256: Schema.String,
    certificate_not_before: Schema.Number,
    certificate_not_after: Schema.Number,
    certificate_time_valid: Schema.Boolean,
    trust_verified: Schema.NullOr(Schema.Boolean),
    chain: Schema.optional(
      Schema.Struct({
        status: Schema.Literals(["verified", "rejected", "unknown"]),
        error: Schema.optional(Schema.String),
        certificate_sha256: Schema.optional(Schema.String),
      }),
    ),
    hostname: Schema.optional(
      Schema.Struct({
        expected: Schema.String,
        status: Schema.Literals(["verified", "rejected", "unknown"]),
        exit_code: Schema.Number,
      }),
    ),
    sni: Schema.optional(Schema.NullOr(Schema.String)),
    trust_source: Schema.optional(Schema.String),
    cipher_coverage: Schema.optional(Schema.Literal("negotiated_samples_only")),
    processes: Schema.optional(
      Schema.Array(Schema.Struct({ name: Schema.String, exit_code: Schema.Number, stderr: Schema.String })),
    ),
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
    "TLS performs bounded version handshakes, a separate chain verification against the container trust store, and an explicit certificate hostname/IP check. Inspect each state, SNI and trust source. Cipher coverage is limited to negotiated samples.",
    "SSH reads an SSH-2.0 identification and a complete KEXINIT packet. Review advertised algorithms against deployment requirements; no login or host-key authentication is attempted.",
    "Repeat a candidate against a healthy control, retrieve raw artifacts, and record a finding only for the reproduced property. Complete the task with output evidence.",
  ],
  limits: [
    "No exploit, credential guessing, exhaustive cipher inventory, CVE inference or automatic finding confirmation.",
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

export const PROBE = `import socket,ssl,struct,json,sys,pathlib,hashlib,subprocess,datetime,time,ipaddress
p=json.loads(sys.argv[1]); host=p['host']; port=p['port']
raw=bytearray()
pathlib.Path('protocol.raw').write_bytes(raw)
if p['module']=='tls':
    versions=[]; cert=None
    for name,version in [('TLSv1',ssl.TLSVersion.TLSv1),('TLSv1.1',ssl.TLSVersion.TLSv1_1),('TLSv1.2',ssl.TLSVersion.TLSv1_2),('TLSv1.3',ssl.TLSVersion.TLSv1_3)]:
        try:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); context.check_hostname=False; context.verify_mode=ssl.CERT_NONE
            context.minimum_version=version; context.maximum_version=version; context.set_ciphers('ALL:@SECLEVEL=0')
            with socket.create_connection((host,port),3) as tcp:
                with context.wrap_socket(tcp,server_hostname=host) as conn:
                    cert=conn.getpeercert(binary_form=True); versions.append({'version':name,'accepted':True,'state':'negotiated','negotiated':conn.version(),'cipher':conn.cipher()[0]})
        except (OSError,ssl.SSLError) as error:
            reason=getattr(error,'reason','')
            state='client_unsupported' if reason in ['NO_PROTOCOLS_AVAILABLE','NO_CIPHERS_AVAILABLE','UNSUPPORTED_PROTOCOL'] else 'server_rejected' if reason=='TLSV1_ALERT_PROTOCOL_VERSION' else 'unknown_failure' if isinstance(error,ssl.SSLError) else 'connectivity_error'
            versions.append({'version':name,'accepted':False,'state':state,'error':str(error)[:1024]})
    if cert is None: raise ValueError('No TLS handshake succeeded; service identification is incomplete')
    raw.extend(cert)
    dates_process=subprocess.run(['openssl','x509','-inform','DER','-noout','-dates'],input=cert,capture_output=True,timeout=3)
    if dates_process.returncode: raise ValueError('Certificate date parsing failed: '+dates_process.stderr.decode()[:1024])
    dates=dates_process.stdout.decode().splitlines()
    values={row.split('=',1)[0]:datetime.datetime.strptime(row.split('=',1)[1],'%b %d %H:%M:%S %Y %Z').replace(tzinfo=datetime.timezone.utc).timestamp() for row in dates}
    chain={'status':'unknown'}
    try:
        context=ssl.create_default_context(); context.check_hostname=False
        with socket.create_connection((host,port),3) as tcp:
            with context.wrap_socket(tcp,server_hostname=host) as conn:
                chain={'status':'verified','certificate_sha256':hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest()}
    except ssl.SSLCertVerificationError as error: chain={'status':'rejected','error':str(error)[:1024]}
    except (OSError,ssl.SSLError) as error: chain={'status':'unknown','error':str(error)[:1024]}
    try: ipaddress.ip_address(host); flag='-verify_ip'
    except ValueError: flag='-verify_hostname'
    pathlib.Path('certificate.pem').write_text(ssl.DER_cert_to_PEM_cert(cert))
    # x509 -checkhost can exit zero on mismatch. Verify identity against the captured
    # leaf as its own trust anchor, independently of the live chain and date checks.
    hostname=subprocess.run(['openssl','verify','-no_check_time','-partial_chain','-trusted','certificate.pem',flag,host,'certificate.pem'],capture_output=True,timeout=3)
    mismatch=any(code in hostname.stderr.decode() for code in ['error 62 at','error 64 at'])
    report={'protocol':'tls','versions':versions,'certificate_sha256':hashlib.sha256(cert).hexdigest(),
        'certificate_not_before':values['notBefore'],'certificate_not_after':values['notAfter'],
        'certificate_time_valid':values['notBefore']<=time.time()<=values['notAfter'],
        'trust_verified':True if chain['status']=='verified' else False if chain['status']=='rejected' else None,'chain':chain,
        'hostname':{'expected':host,'status':'verified' if hostname.returncode==0 else 'rejected' if mismatch else 'unknown','exit_code':hostname.returncode},
        'sni':None if flag=='-verify_ip' else host,'trust_source':str(ssl.get_default_verify_paths()),'cipher_coverage':'negotiated_samples_only',
        'processes':[{'name':'openssl-dates','exit_code':dates_process.returncode,'stderr':dates_process.stderr.decode()[:1024]}, {'name':'openssl-hostname','exit_code':hostname.returncode,'stderr':hostname.stderr.decode()[:1024]}]}
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
