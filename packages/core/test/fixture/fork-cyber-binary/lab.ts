export * as ForkCyberBinaryLab from "./lab.js"

import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberSurface } from "@opencode/core/fork-cyber/surface"
import { ForkCyberServicesLab } from "../fork-cyber-services/lab"
import { tmpdirScoped } from "../tmpdir"

export const assessment = {
  owner: "binary-lab",
  session: "binary-lab",
  agent: "build",
  manifest: ForkCyberServicesLab.assessment.manifest,
}

export type Import = { dll: string; functions: readonly string[] }

// Known contents: .text (code), .idata (imports) and .data. Each option changes one property for a negative or anomaly.
export const KNOWN_IMPORTS: readonly Import[] = [
  { dll: "kernel32.dll", functions: ["CreateFileW", "ReadFile"] },
  { dll: "user32.dll", functions: ["MessageBoxA"] },
]

const FILE_ALIGNMENT = 0x200
const SECTION_ALIGNMENT = 0x1000
const align = (value: number, unit: number) => Math.ceil(value / unit) * unit

// A PE32 (i386) image that pefile must parse: DOS header, PE headers, section table, file-aligned bodies.
// It is built from code, so it is reproducible and never executed. The entry point is the first byte of .text.
export function pe32(options: { imports: readonly Import[]; writableExecutable?: boolean }) {
  const code = Buffer.alloc(0x10, 0xcc)
  code.set([0xb8, 0, 0, 0, 0, 0xc3])
  const sections: { name: string; characteristics: number; data: Buffer; rva: number }[] = [
    {
      name: ".text",
      characteristics: options.writableExecutable ? 0xe0000020 : 0x60000020,
      data: code,
      rva: 0x1000,
    },
  ]
  const directory = { rva: 0, size: 0 }
  if (options.imports.length > 0) {
    const table = importTable(options.imports, 0x2000)
    sections.push({ name: ".idata", characteristics: 0x40000040, data: table.data, rva: 0x2000 })
    directory.rva = 0x2000
    directory.size = table.descriptors
  }
  const previous = sections.at(-1)!
  const data = Buffer.alloc(0x20, 0)
  data.write("opencyber fixture data", 0, "ascii")
  sections.push({
    name: ".data",
    characteristics: 0xc0000040,
    data,
    rva: previous.rva + align(previous.data.length, SECTION_ALIGNMENT),
  })

  const headersSize = 0x40 + 4 + 20 + 224 + 40 * sections.length
  if (headersSize > FILE_ALIGNMENT) throw new Error("Too many sections for one header block")
  const raw = sections.map((section) => align(section.data.length, FILE_ALIGNMENT))
  const out = Buffer.alloc(FILE_ALIGNMENT + raw.reduce((sum, size) => sum + size, 0))
  out.write("MZ", 0, "ascii")
  out.writeUInt32LE(0x40, 0x3c)

  const pe = 0x40
  out.write("PE\0\0", pe, "ascii")
  const coff = pe + 4
  out.writeUInt16LE(0x14c, coff)
  out.writeUInt16LE(sections.length, coff + 2)
  out.writeUInt32LE(1700000000, coff + 4)
  out.writeUInt16LE(224, coff + 16)
  out.writeUInt16LE(0x102, coff + 18)

  const optional = coff + 20
  const codeSections = sections.filter((section) => section.characteristics & 0x20000000)
  const initializedSections = sections.filter((section) => !(section.characteristics & 0x20000000))
  const sizeOf = (rows: typeof sections) =>
    rows.reduce((sum, section) => sum + align(section.data.length, FILE_ALIGNMENT), 0)
  const lastSection = sections.at(-1)!
  out.writeUInt16LE(0x10b, optional)
  out.writeUInt32LE(sizeOf(codeSections), optional + 4)
  out.writeUInt32LE(sizeOf(initializedSections), optional + 8)
  out.writeUInt32LE(0x1000, optional + 16)
  out.writeUInt32LE(0x1000, optional + 20)
  out.writeUInt32LE(initializedSections[0]?.rva ?? 0, optional + 24)
  out.writeUInt32LE(0x400000, optional + 28)
  out.writeUInt32LE(SECTION_ALIGNMENT, optional + 32)
  out.writeUInt32LE(FILE_ALIGNMENT, optional + 36)
  out.writeUInt16LE(4, optional + 40)
  out.writeUInt16LE(4, optional + 48)
  out.writeUInt32LE(lastSection.rva + align(lastSection.data.length, SECTION_ALIGNMENT), optional + 56)
  out.writeUInt32LE(FILE_ALIGNMENT, optional + 60)
  out.writeUInt16LE(3, optional + 68)
  out.writeUInt16LE(0x100, optional + 70)
  out.writeUInt32LE(0x100000, optional + 72)
  out.writeUInt32LE(0x1000, optional + 76)
  out.writeUInt32LE(0x100000, optional + 80)
  out.writeUInt32LE(0x1000, optional + 84)
  out.writeUInt32LE(16, optional + 92)
  out.writeUInt32LE(directory.rva, optional + 96 + 8)
  out.writeUInt32LE(directory.size, optional + 96 + 12)

  sections.forEach((section, index) => {
    const header = optional + 224 + index * 40
    out.write(section.name, header, "ascii")
    out.writeUInt32LE(section.data.length, header + 8)
    out.writeUInt32LE(section.rva, header + 12)
    out.writeUInt32LE(raw[index]!, header + 16)
    const at = FILE_ALIGNMENT + raw.slice(0, index).reduce((sum, size) => sum + size, 0)
    out.writeUInt32LE(at, header + 20)
    out.writeUInt32LE(section.characteristics, header + 36)
    section.data.copy(out, at)
  })
  return out
}

// Import directory: descriptors, then per-DLL lookup and address tables, then hint/name entries and DLL names.
function importTable(imports: readonly Import[], base: number) {
  const descriptors = (imports.length + 1) * 20
  let cursor = descriptors
  const layout = imports.map((item) => {
    const thunks = (item.functions.length + 1) * 4
    const lookup = cursor
    cursor += thunks
    const address = cursor
    cursor += thunks
    return { ...item, lookup, address }
  })
  const hints = layout.map((item) =>
    item.functions.map((name) => {
      const at = cursor
      cursor += align(2 + name.length + 1, 2)
      return { name, at }
    }),
  )
  const names = layout.map((item) => {
    const at = cursor
    cursor += align(item.dll.length + 1, 2)
    return at
  })
  const data = Buffer.alloc(cursor)
  layout.forEach((item, index) => {
    const row = index * 20
    data.writeUInt32LE(base + item.lookup, row)
    data.writeUInt32LE(base + names[index]!, row + 12)
    data.writeUInt32LE(base + item.address, row + 16)
    data.write(item.dll, names[index]!, "ascii")
    hints[index]!.forEach((hint, position) => {
      data.writeUInt32LE(base + hint.at, item.lookup + position * 4)
      data.writeUInt32LE(base + hint.at, item.address + position * 4)
      data.writeUInt16LE(position, hint.at)
      data.write(hint.name, hint.at + 2, "ascii")
    })
  })
  return { data, descriptors }
}

// A gzip member at offset 256 inside zero padding. Its payload is the known extraction result.
export const FIRMWARE_PAYLOAD = Buffer.from("opencyber known firmware payload\n")
export function firmware(payload: Buffer = FIRMWARE_PAYLOAD) {
  return Buffer.concat([Buffer.alloc(256, 0), Buffer.from(Bun.gzipSync(new Uint8Array(payload))), Buffer.alloc(512, 0)])
}

export const open = (image: string) =>
  Effect.gen(function* () {
    const tmp = yield* tmpdirScoped("opencyber-binary-")
    const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
    const config = Schema.decodeUnknownSync(ForkCyberKali.Config)({ image, network: { kind: "none" } })
    yield* Effect.addFinalizer(() =>
      ForkCyberKali.manager(store, tmp.path, config).cleanup(assessment.owner).pipe(Effect.orDie),
    )
    return { store, config, profile: tmp.path }
  })

// Writes the bytes into the lab profile and imports them through the surface boundary, as an operator would.
export const importSample = (env: { store: ForkCyberSurface.Store; profile: string }, file: string, bytes: Buffer) =>
  Effect.gen(function* () {
    yield* Effect.promise(() => Bun.write(path.join(env.profile, file), new Uint8Array(bytes)))
    const imported = yield* ForkCyberSurface.importFile(
      env.store,
      { ...assessment, directory: env.profile, permission: () => Effect.void },
      "binary",
      { action: "import", file },
    )
    return imported.capture.artifact
  })
