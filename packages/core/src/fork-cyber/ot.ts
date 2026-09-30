export * as ForkCyberOt from "./ot.js"

import { Effect, Schema } from "effect"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberSurface } from "./surface.js"

const integer = (maximum: number) => Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 0, maximum }))
export const Action = Schema.Struct({
  module: Schema.Literal("ot"),
  action: Schema.Literal("modbus"),
  environment: Schema.Literal("simulator"),
  host: ForkCyberScope.Host,
  port: ForkCyberSurface.Port,
  unit: integer(247),
  address: integer(65535),
  count: Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 1, maximum: 16 })),
})
export const Report = Schema.Union([
  Schema.Struct({
    protocol: Schema.Literal("modbus-tcp"),
    kind: Schema.Literal("registers"),
    unit: integer(247),
    values: Schema.Array(integer(65535)).check(Schema.isMinLength(1), Schema.isMaxLength(16)),
  }),
  Schema.Struct({
    protocol: Schema.Literal("modbus-tcp"),
    kind: Schema.Literal("exception"),
    unit: integer(247),
    code: integer(255),
  }),
])
export const procedures = {
  module: "modbus-simulator-v1",
  procedures: [
    "Use an authorized Modbus TCP simulator only. Record one service endpoint, unit, holding-register address and count in the task.",
    "Run one function-03 read with at most 16 registers. Compare a readable test register with an illegal-address exception control.",
    "Inspect the validated MBAP transaction, unit, function and byte count. Retrieve the raw response and policy artifacts.",
    "Report simulator reachability and register-read exposure. No process control or physical consequence is established. Complete the task and list untested units, functions and devices.",
  ],
  limits: [
    "Simulator workflow only. The environment field is an operator assertion, not device identification.",
    "No writes, diagnostics, broadcast operations, device discovery or production OT validation. A readable simulator register is not automatically a vulnerability.",
  ],
}
export const run = Effect.fn(function* (
  store: ForkCyberSurface.Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: ForkCyberSurface.Assessment,
  input: typeof Action.Type,
) {
  if (input.address + input.count > 65536)
    return yield* Effect.fail(new Error("Modbus register range exceeds address space"))
  yield* Effect.try(() => ForkCyberSurface.network(config, assessment, input.host, input.port))
  return yield* ForkCyberSurface.job(
    store,
    profile,
    config,
    assessment,
    "ot",
    {
      argv: ["python3", "-I", "-c", PROBE, JSON.stringify(input)],
      outputs: ["protocol.raw", "report.json"],
      timeout_ms: 10000,
    },
    Report,
  )
})
export const PROBE = `import socket,struct,json,sys,pathlib
p=json.loads(sys.argv[1]); transaction=0x4359
pathlib.Path('protocol.raw').write_bytes(b'')
request=struct.pack('!HHHBBHH',transaction,0,6,p['unit'],3,p['address'],p['count'])
def exact(conn,count):
    data=bytearray()
    while len(data)<count:
        chunk=conn.recv(count-len(data))
        if not chunk: raise ValueError('Truncated Modbus response')
        data.extend(chunk)
    return bytes(data)
with socket.create_connection((p['host'],p['port']),3) as conn:
    conn.sendall(request); header=exact(conn,7); pathlib.Path('protocol.raw').write_bytes(header); tid,protocol,length,unit=struct.unpack('!HHHB',header)
    if tid!=transaction or protocol!=0 or unit!=p['unit'] or not 3<=length<=35: raise ValueError('Invalid Modbus MBAP response')
    body=exact(conn,length-1)
pathlib.Path('protocol.raw').write_bytes(header+body)
if body[0]==0x83:
    if len(body)!=2 or body[1]==0: raise ValueError('Invalid Modbus exception')
    report={'protocol':'modbus-tcp','kind':'exception','unit':unit,'code':body[1]}
else:
    if body[0]!=3 or body[1]!=p['count']*2 or len(body)!=2+body[1]: raise ValueError('Invalid Modbus register count')
    report={'protocol':'modbus-tcp','kind':'registers','unit':unit,'values':list(struct.unpack('!'+'H'*p['count'],body[2:]))}
pathlib.Path('report.json').write_text(json.dumps(report))
`
