export * as ForkCyberSurfacesLab from "./lab.js"

import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberServicesLab } from "../fork-cyber-services/lab"
import { tmpdirScoped } from "../tmpdir"

export const assessment = {
  ...ForkCyberServicesLab.assessment,
  owner: "surface-lab",
  session: "surface-lab",
  agent: "build",
  manifest: {
    ...ForkCyberServicesLab.assessment.manifest,
    scope: {
      domains: [],
      cidrs: [],
      excluded: [],
      services: [{ target: "target", protocol: "tcp" as const, ports: [8000, 8443, 8444, 2222, 2223, 1502] }],
    },
    rules_of_engagement: {
      ...ForkCyberServicesLab.assessment.manifest.rules_of_engagement,
      network: {
        ...ForkCyberServicesLab.assessment.manifest.rules_of_engagement.network,
        bytes_total: 100 * 1024 * 1024,
        duration_ms: 30000,
      },
    },
  },
}
export const open = (image: string) =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped("opencyber-surfaces-")
    const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
    const network = `opencyber-surfaces-${crypto.randomUUID()}`
    yield* ForkCyberServicesLab.docker(["network", "create", "--internal", network])
    yield* Effect.addFinalizer(() => ForkCyberServicesLab.docker(["network", "rm", network]).pipe(Effect.orDie))
    const container = yield* ForkCyberServicesLab.docker([
      "run",
      "-d",
      "--rm",
      "--user",
      "0:0",
      "--network",
      network,
      "--network-alias",
      "target",
      "--entrypoint",
      "python3",
      image,
      "-u",
      "-c",
      SERVER,
    ])
    yield* Effect.addFinalizer(() => ForkCyberServicesLab.docker(["rm", "-f", container]).pipe(Effect.orDie))
    yield* ForkCyberServicesLab.docker([
      "exec",
      container,
      "python3",
      "-I",
      "-c",
      `import socket,time
for attempt in range(200):
    try:
        for port in [8000,8443,8444,2222,2223,1502]:
            with socket.create_connection(('127.0.0.1',port),.2): pass
        break
    except OSError: time.sleep(.05)
else: raise RuntimeError('Surface services failed to start')`,
    ])
    const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({ image, network: { kind: "scoped", name: network } })
    const offline = Schema.decodeUnknownSync(ForkCyberKali.Config)({ image, network: { kind: "none" } })
    yield* Effect.addFinalizer(() =>
      ForkCyberKali.manager(store, tmp.path, config).cleanup(assessment.owner).pipe(Effect.orDie),
    )
    yield* Effect.addFinalizer(() =>
      ForkCyberKali.manager(store, tmp.path, offline).cleanup(assessment.owner).pipe(Effect.orDie),
    )
    return { store, config, offline, profile: tmp.path, container }
  })

export const SERVER = `import socket,ssl,subprocess,pathlib,threading,struct,time
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout','key.pem','-out','cert.pem','-subj','/CN=target','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f','ssh_key'],check=True)
pathlib.Path('/run/sshd').mkdir(exist_ok=True)
for port,legacy in [(2222,False),(2223,True)]:
    args=['/usr/sbin/sshd','-D','-e','-f','/dev/null','-h','/work/ssh_key','-p',str(port),'-o','ListenAddress=0.0.0.0','-o','PidFile=/work/ssh'+str(port)+'.pid']
    if legacy: args+=['-o','KexAlgorithms=diffie-hellman-group1-sha1']
    subprocess.Popen(args)
def listener(port,handler):
    server=socket.socket(); server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); server.bind(('0.0.0.0',port)); server.listen()
    while True:
        conn,_=server.accept()
        def serve(conn):
            with conn:
                try: handler(conn)
                except (OSError,ValueError): pass
        threading.Thread(target=serve,args=(conn,),daemon=True).start()
for port,legacy in [(8443,False),(8444,True)]:
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain('cert.pem','key.pem')
    context.minimum_version=ssl.TLSVersion.TLSv1 if legacy else ssl.TLSVersion.TLSv1_2
    context.maximum_version=ssl.TLSVersion.TLSv1 if legacy else ssl.TLSVersion.TLSv1_3
    context.set_ciphers('ALL:@SECLEVEL=0')
    def tls(conn,context=context):
        with context.wrap_socket(conn,server_side=True) as secured: secured.recv(1)
    threading.Thread(target=listener,args=(port,tls),daemon=True).start()
def management(conn): conn.sendall(b'fixture-management\\n')
threading.Thread(target=listener,args=(8000,management),daemon=True).start()
def modbus(conn):
    raw=b''
    while len(raw)<12:
        chunk=conn.recv(12-len(raw))
        if not chunk: return
        raw+=chunk
    tid,protocol,length,unit,function,address,count=struct.unpack('!HHHBBHH',raw)
    if protocol!=0 or length!=6 or function!=3 or count!=1: return
    if address==98: tid^=1
    body=bytes([3,2])+struct.pack('!H',4242) if address==0 else bytes([0x83,2])
    conn.sendall(struct.pack('!HHHB',tid,0,len(body)+1,unit)+body)
threading.Thread(target=listener,args=(1502,modbus),daemon=True).start()
while True: time.sleep(10)
`

export const BUILD_ARTIFACTS = `import pathlib,subprocess,json,base64,struct,zipfile
source=pathlib.Path('program.c'); source.write_text('#include <stdio.h>\\n#include <signal.h>\\nint main(void){int c=getchar();if(c==88)raise(SIGSEGV);puts("healthy");return 0;}')
subprocess.run(['gcc','program.c','-o','fault'],check=True)
source.write_text('#include <stdio.h>\\nint main(void){getchar();puts("healthy");return 0;}')
subprocess.run(['gcc','program.c','-o','healthy'],check=True)
source.write_text('#include <unistd.h>\\nint main(void){sleep(5);return 0;}')
subprocess.run(['gcc','program.c','-o','hang'],check=True)
for name,debug in [('debug',True),('release',False)]:
    pathlib.Path('AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="local.fixture"><uses-sdk android:minSdkVersion="23" android:targetSdkVersion="28"/><application android:debuggable="'+str(debug).lower()+'" android:usesCleartextTraffic="'+str(debug).lower()+'"/></manifest>')
    subprocess.run(['aapt','package','-f','-M','AndroidManifest.xml','-I','/usr/share/android-framework-res/framework-res.apk','-F',name+'.apk'],check=True)
with zipfile.ZipFile('debug.apk') as source:
    with zipfile.ZipFile('invalid.apk','w') as invalid: invalid.writestr('AndroidManifest.xml',source.read('AndroidManifest.xml')[:-4])
    manifest=source.read('AndroidManifest.xml')
    for encoding in ('utf-8','utf-16le'):
        manifest=manifest.replace('http://schemas.android.com/apk/res/android'.encode(encoding),'http://schemas.android.com/apk/res/fixture'.encode(encoding))
    with zipfile.ZipFile('foreign.apk','w') as foreign: foreign.writestr('AndroidManifest.xml',manifest)
for name,rsn in [('open',False),('rsn',True)]:
    frame=bytes([0x80,0])+b'\\x00'*2+b'\\xff'*6+bytes.fromhex('020000000001')*2+b'\\x00'*2+b'\\x00'*8+struct.pack('<HH',100,0x10 if rsn else 0)+bytes([0,3])+b'lab'
    if rsn:
        element=struct.pack('<H',1)+bytes.fromhex('000fac04')+struct.pack('<H',1)+bytes.fromhex('000fac04')+struct.pack('<H',1)+bytes.fromhex('000fac02')
        frame+=bytes([48,len(element)])+element
    capture=bytes.fromhex('d4c3b2a1')+struct.pack('<HHIIII',2,4,0,0,65535,105)+struct.pack('<IIII',1,0,len(frame),len(frame))+frame
    pathlib.Path(name+'.pcap').write_bytes(capture)
pathlib.Path('invalid.pcap').write_bytes(pathlib.Path('rsn.pcap').read_bytes()[:-1])
names=['fault','healthy','hang','debug.apk','release.apk','invalid.apk','foreign.apk','open.pcap','rsn.pcap','invalid.pcap']
print(json.dumps({name:base64.b64encode(pathlib.Path(name).read_bytes()).decode() for name in names}))
`
