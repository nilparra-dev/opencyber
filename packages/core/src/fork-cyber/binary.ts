export * as ForkCyberBinary from "./binary.js"

import { Effect, Schema } from "effect"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberKali } from "./kali.js"
import { ForkCyberPagination } from "./pagination.js"
import { ForkCyberRoles } from "./roles.js"
import { ForkCyberScope } from "./scope.js"
import { ForkCyberStore } from "./store.js"

const artifact = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(256))
const offset = Schema.optional(Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 0, maximum: 8192 })))

export const Action = Schema.Union([
  Schema.Struct({ action: Schema.Literal("pe"), artifact, offset }),
  Schema.Struct({ action: Schema.Literal("firmware"), artifact, offset }),
])
export type Action = typeof Action.Type

type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
type Assessment = { owner: string; session: string; agent: string; manifest: ForkCyberScope.Manifest }

const text = Schema.String.check(Schema.isMaxLength(512))
const count = Schema.Number.check(Schema.isInt(), Schema.isBetween({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }))
const digest = (length: number) => Schema.String.check(Schema.isPattern(new RegExp(`^[a-f0-9]{${length}}$`)))
const PeTool = Schema.Struct({ name: Schema.Literal("pefile"), version: text })
const FirmwareTool = Schema.Struct({ name: Schema.Literal("binwalk"), version: text })
const Section = Schema.Struct({
  name: text,
  virtual_address: count,
  virtual_size: count,
  raw_size: count,
  raw_pointer: count,
  characteristics: count,
  readable: Schema.Boolean,
  writable: Schema.Boolean,
  executable: Schema.Boolean,
  entropy: Schema.Number,
  sha256: digest(64),
})
const Import = Schema.Struct({ dll: text, name: Schema.optional(text), ordinal: Schema.optional(count) })
const Anomaly = Schema.Struct({
  rule: Schema.Literals([
    "writable_executable_section",
    "high_entropy_section",
    "empty_raw_section",
    "entry_point_outside_sections",
    "no_import_directory",
    "overlay_data",
    "checksum_mismatch",
  ]),
  section: Schema.optional(text),
  detail: text,
})
const PeReport = Schema.Union([
  Schema.Struct({
    tool: PeTool,
    sha256: digest(64),
    bytes: count,
    parsed: Schema.Literal(false),
    reason: text,
  }),
  Schema.Struct({
    tool: PeTool,
    sha256: digest(64),
    bytes: count,
    parsed: Schema.Literal(true),
    headers: Schema.Struct({
      machine: count,
      timestamp: count,
      characteristics: count,
      subsystem: count,
      entry_point: count,
      image_base: count,
      checksum: count,
      dll: Schema.Boolean,
    }),
    sections_total: count,
    sections: Schema.Array(Section).check(Schema.isMaxLength(96)),
    imports: Schema.Array(Import).check(Schema.isMaxLength(4096)),
    imports_truncated: Schema.Boolean,
    overlay_bytes: count,
    anomalies: Schema.Array(Anomaly).check(Schema.isMaxLength(256)),
    warnings: Schema.Array(text).check(Schema.isMaxLength(64)),
  }),
])
const FirmwareReport = Schema.Struct({
  tool: FirmwareTool,
  sha256: digest(64),
  bytes: count,
  components: Schema.Array(Schema.Struct({ offset: count, description: text })).check(Schema.isMaxLength(4096)),
  components_truncated: Schema.Boolean,
  extracted: Schema.Array(
    Schema.Struct({ path: Schema.String.check(Schema.isMaxLength(1024)), bytes: count, sha256: digest(64) }),
  ).check(Schema.isMaxLength(4096)),
  extracted_truncated: Schema.Boolean,
  symlinks_skipped: count,
})

const PE_LIMITATIONS = [
  "The sample is never executed. The job runs with network disabled and no inherited credentials.",
  "pefile parses the headers, sections, import directory and overlay. Resources, Authenticode signatures, delay imports, exports and .NET metadata are not analyzed.",
  "Anomalies are candidates for review. Packers, installers and minimal programs can produce them, and no anomaly is a verdict.",
  "At most 96 sections and 4096 imports are read. Imports are paged 200 at a time with next_offset. The full report is in report_artifact.",
]
const FIRMWARE_LIMITATIONS = [
  "binwalk signature matches are components, not verified contents. An empty result does not prove that the image has no code or data.",
  "Extraction is single level. Nested archives are not recursively extracted. Extraction utilities run inside the network-disabled container, bounded to 256 files of at most 4 MiB on a 128 MiB work mount.",
  "Extracted content is hashed and never returned. Use report_artifact for the complete manifest.",
  "binwalk 2.x is past upstream end of life. Its version is recorded in tool.version; a move to binwalk 3 needs its own pinned install and license review.",
]

export const run = Effect.fn("ForkCyberBinary.run")(function* (
  store: Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: Assessment,
  input: Action,
) {
  if (!ForkCyberRoles.allowed(assessment.agent, "cyber_binary"))
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "capability",
        operation: "cyber_binary",
        message: `Phase ${assessment.agent} cannot execute cyber_binary`,
        target_started: false,
        effects: "not_started",
      }),
    )
  if (ForkCyberRoles.worker(assessment.agent)) yield* store.coordination.requireClaim(assessment)
  const source = yield* store.readArtifact(assessment.owner, input.artifact).pipe(
    Effect.mapError(
      () =>
        new ForkCyberDiagnostics.Failure({
          category: "input",
          operation: "cyber_binary",
          message: "The artifact could not be read from this engagement",
          target_started: false,
          effects: "not_started",
          recovery:
            "Import the sample with cyber_surface (module binary, action import) and pass the artifact ID it returns.",
        }),
    ),
  )
  if (source.bytes.length > ForkCyberKali.INPUT_LIMIT)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "cyber_binary",
        message: "Binary analysis inputs larger than 2 MiB are not analyzed",
        target_started: false,
        effects: "not_started",
        recovery: "Select a smaller artifact, or analyze the component that carries the code of interest.",
      }),
    )
  if (input.action === "pe") return yield* analyzePe(store, profile, config, assessment, input, source.sha256)
  return yield* analyzeFirmware(store, profile, config, assessment, input, source.sha256)
})

const analyzePe = Effect.fn(function* (
  store: Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: Assessment,
  input: Extract<Action, { action: "pe" }>,
  sha256: string,
) {
  const result = yield* job(store, profile, config, assessment, input, {
    argv: ["python3", "-I", "-c", PE_ANALYSIS],
    timeout_ms: 30000,
    report: PeReport,
  })
  const report = result.capture.report
  if (report.sha256 !== sha256) return yield* Effect.fail(new Error("PE report does not match the analyzed artifact"))
  if (!report.parsed)
    return yield* Effect.fail(
      new ForkCyberDiagnostics.Failure({
        category: "input",
        operation: "cyber_binary",
        message: `pefile could not analyze the artifact: ${report.reason}`,
        target_started: false,
        effects: "known",
        recovery:
          "Select an artifact that holds a Windows PE file (MZ header and PE signature). Other formats need a different action.",
        details: { execution: result.execution },
      }),
    )
  const offset = input.offset ?? 0
  const page = ForkCyberPagination.page(report.imports.slice(offset), offset, 200)
  return {
    ...result,
    capture: {
      format: "opencyber-pe-analysis-v1" as const,
      action: input.action,
      artifact: input.artifact,
      sha256: report.sha256,
      bytes: report.bytes,
      tool: report.tool,
      headers: report.headers,
      sections_total: report.sections_total,
      sections: report.sections,
      imports: page.items,
      imports_observed: report.imports.length,
      imports_truncated: report.imports_truncated,
      offset: page.offset,
      next_offset: page.next_offset,
      overlay_bytes: report.overlay_bytes,
      anomalies: report.anomalies,
      warnings: report.warnings,
      report_artifact: result.capture.report_artifact,
      limitations: PE_LIMITATIONS,
    },
  }
})

const analyzeFirmware = Effect.fn(function* (
  store: Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: Assessment,
  input: Extract<Action, { action: "firmware" }>,
  sha256: string,
) {
  const result = yield* job(store, profile, config, assessment, input, {
    argv: ["python3", "-I", "-c", FIRMWARE_ANALYSIS],
    timeout_ms: 120000,
    report: FirmwareReport,
  })
  const report = result.capture.report
  if (report.sha256 !== sha256)
    return yield* Effect.fail(new Error("Firmware report does not match the analyzed artifact"))
  const rows = [
    ...report.components.map((item) => ({
      kind: "signature" as const,
      offset: item.offset,
      description: item.description,
    })),
    ...report.extracted.map((item) => ({
      kind: "extracted" as const,
      path: item.path,
      bytes: item.bytes,
      sha256: item.sha256,
    })),
  ]
  const offset = input.offset ?? 0
  const page = ForkCyberPagination.page(rows.slice(offset), offset, 200)
  return {
    ...result,
    capture: {
      format: "opencyber-firmware-analysis-v1" as const,
      action: input.action,
      artifact: input.artifact,
      sha256: report.sha256,
      bytes: report.bytes,
      tool: report.tool,
      signatures_observed: report.components.length,
      signatures_truncated: report.components_truncated,
      extracted_observed: report.extracted.length,
      extracted_truncated: report.extracted_truncated,
      symlinks_skipped: report.symlinks_skipped,
      entries: page.items,
      offset: page.offset,
      next_offset: page.next_offset,
      report_artifact: result.capture.report_artifact,
      limitations: FIRMWARE_LIMITATIONS,
    },
  }
})

// One offline job. The artifact is the only input, the network is disabled, and the report is parsed by its schema.
const job = <A>(
  store: Store,
  profile: string,
  config: ForkCyberKali.Config,
  assessment: Assessment,
  input: Action,
  spec: { argv: string[]; timeout_ms: number; report: Schema.Codec<A, unknown> },
) =>
  Effect.gen(function* () {
    const result = yield* ForkCyberKali.manager(store, profile, config).run(
      assessment,
      {
        network: "none",
        argv: spec.argv,
        timeout_ms: spec.timeout_ms,
        inputs: [{ name: "input.bin", artifact: input.artifact }],
        outputs: ["report.json"],
      },
      {
        tool: "cyber_binary",
        parse: (captured) =>
          Effect.gen(function* () {
            if (captured.exit_code !== 0)
              return yield* Effect.fail(new Error(`Binary analysis failed (exit ${captured.exit_code})`))
            const file = captured.files.find((item) => item.name === "report.json")
            if (!file) return yield* Effect.fail(new Error("Binary analysis did not produce report.json"))
            const raw = yield* store.readArtifact(assessment.owner, file.artifact)
            const report = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(spec.report))(
              raw.bytes.toString(),
            ).pipe(Effect.mapError((error) => new Error(String(error))))
            return { report, report_artifact: file.artifact }
          }),
      },
    )
    if (!result.capture) return yield* Effect.fail(new Error("Binary analysis did not return its parsed report"))
    return { ...result, capture: result.capture }
  })

// The scripts are fixed. The model supplies only the artifact and a page offset.
const PE_ANALYSIS = `import hashlib,json,pathlib
import pefile
raw=pathlib.Path('input.bin').read_bytes()
def text(value):
    if isinstance(value,bytes): value=value.rstrip(bytes(1)).decode('utf-8','replace')
    return str(value)[:512]
def analyze(pe):
    oh=pe.OPTIONAL_HEADER; fh=pe.FILE_HEADER
    sections=[]
    for s in pe.sections[:96]:
        chars=s.Characteristics; body=s.get_data()
        sections.append({'name':text(s.Name),'virtual_address':s.VirtualAddress,'virtual_size':s.Misc_VirtualSize,'raw_size':s.SizeOfRawData,'raw_pointer':s.PointerToRawData,'characteristics':chars,'readable':bool(chars&0x40000000),'writable':bool(chars&0x80000000),'executable':bool(chars&0x20000000),'entropy':round(s.get_entropy(),4),'sha256':hashlib.sha256(body).hexdigest()})
    imports=[]; truncated=False
    for entry in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[]):
        for item in entry.imports:
            if len(imports)==4096: truncated=True; break
            row={'dll':text(entry.dll)}
            if item.name is None: row['ordinal']=item.ordinal
            else: row['name']=text(item.name)
            imports.append(row)
    anomalies=[]
    def add(rule,detail,section=None):
        row={'rule':rule,'detail':detail}
        if section is not None: row['section']=section
        anomalies.append(row)
    for s in sections:
        if s['writable'] and s['executable']: add('writable_executable_section','The section is writable and executable. Self-modifying or unpacking code looks like this.',s['name'])
        if s['entropy']>=7.2: add('high_entropy_section','The section entropy is high. Compressed or encrypted data looks like this.',s['name'])
        if s['raw_size']==0 and s['virtual_size']>0: add('empty_raw_section','The section has a virtual size but no raw data. Loaders often fill such sections at run time.',s['name'])
    if pe.get_section_by_rva(oh.AddressOfEntryPoint) is None: add('entry_point_outside_sections','The entry point is not inside any section.')
    if not hasattr(pe,'DIRECTORY_ENTRY_IMPORT'): add('no_import_directory','The import directory is absent. Packed or minimal programs often look like this.')
    overlay=pe.get_overlay_data_start_offset()
    overlay_bytes=0 if overlay is None else len(raw)-overlay
    if overlay_bytes: add('overlay_data','Data follows the last section. Installers and appended payloads often use an overlay.')
    if oh.CheckSum and oh.CheckSum!=pe.generate_checksum(): add('checksum_mismatch','The stored checksum differs from the computed value.')
    return {'headers':{'machine':fh.Machine,'timestamp':fh.TimeDateStamp,'characteristics':fh.Characteristics,'subsystem':oh.Subsystem,'entry_point':oh.AddressOfEntryPoint,'image_base':oh.ImageBase,'checksum':oh.CheckSum,'dll':bool(fh.Characteristics&0x2000)},'sections_total':len(pe.sections),'sections':sections,'imports':imports,'imports_truncated':truncated,'overlay_bytes':overlay_bytes,'anomalies':anomalies,'warnings':[text(item) for item in pe.get_warnings()][:64]}
base={'tool':{'name':'pefile','version':pefile.__version__},'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
try:
    report=dict(base,parsed=True,**analyze(pefile.PE(data=raw)))
except Exception as error:
    report=dict(base,parsed=False,reason=text(type(error).__name__+': '+str(error)))
pathlib.Path('report.json').write_text(json.dumps(report,separators=(',',':')))
`

const FIRMWARE_ANALYSIS = `import csv,hashlib,json,os,pathlib,subprocess
import binwalk
raw=pathlib.Path('input.bin').read_bytes()
subprocess.run(['binwalk','--quiet','--extract','--directory=extract','--count=256','--size=4194304','--csv','--log=scan.csv','input.bin'],check=True)
with open('scan.csv',newline='') as source: rows=list(csv.DictReader(source))
components=[{'offset':int(row['DECIMAL']),'description':row['DESCRIPTION'][:512]} for row in rows[:4096]]
def digest(path):
    hashing=hashlib.sha256(); size=0
    with open(path,'rb') as source:
        for chunk in iter(lambda: source.read(65536),b''):
            hashing.update(chunk); size+=len(chunk)
    return size,hashing.hexdigest()
extracted=[]; symlinks=0; truncated=False
for root,dirs,files in os.walk('extract'):
    symlinks+=sum(os.path.islink(os.path.join(root,name)) for name in dirs)
    for name in sorted(files):
        path=os.path.join(root,name)
        if os.path.islink(path):
            symlinks+=1
            continue
        if len(extracted)==4096:
            truncated=True
            continue
        size,sha=digest(path)
        extracted.append({'path':os.path.relpath(path,'extract')[:1024],'bytes':size,'sha256':sha})
pathlib.Path('report.json').write_text(json.dumps({'tool':{'name':'binwalk','version':binwalk.__version__},'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'components':components,'components_truncated':len(rows)>4096,'extracted':extracted,'extracted_truncated':truncated,'symlinks_skipped':symlinks},separators=(',',':')))
`
