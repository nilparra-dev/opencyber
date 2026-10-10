import { describe, expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import path from "node:path"
import { ForkCyberBinary } from "@opencode/core/fork-cyber/binary"
import { ForkCyberDecision } from "@opencode/core/fork-cyber/decision"
import { ForkCyberDiagnostics } from "@opencode/core/fork-cyber/diagnostics"
import { ForkCyberKali } from "@opencode/core/fork-cyber/kali"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { ForkCyberBinaryLab } from "../fixture/fork-cyber-binary/lab"
import { tmpdirScoped } from "../fixture/tmpdir"

const image = process.env.OPENCYBER_TEST_KALI_IMAGE
const dockerTest = image ? test : test.skip
const { assessment, KNOWN_IMPORTS, pe32, firmware, FIRMWARE_PAYLOAD } = ForkCyberBinaryLab

type Run = Effect.Success<ReturnType<typeof ForkCyberBinary.run>>
const peCapture = (result: Run) => {
  if (result.capture.format !== "opencyber-pe-analysis-v1") throw new Error("Expected a PE analysis")
  return result.capture
}
const firmwareCapture = (result: Run) => {
  if (result.capture.format !== "opencyber-firmware-analysis-v1") throw new Error("Expected a firmware analysis")
  return result.capture
}

const decode = Schema.decodeUnknownOption(ForkCyberBinary.Action)
const verdict = (agent: string, input: unknown) =>
  ForkCyberDecision.decide({ mode: "review", agent, tool: "cyber_binary", input })
const offline = Schema.decodeUnknownSync(ForkCyberKali.Config)({
  image: `sha256:${"0".repeat(64)}`,
  network: { kind: "none" },
})

describe("cyber_binary contract", () => {
  test("the action discriminator accepts only pe and firmware, with a bounded page offset", () => {
    expect(decode({ action: "pe", artifact: "artifact-1" })._tag).toBe("Some")
    expect(decode({ action: "firmware", artifact: "artifact-1", offset: 200 })._tag).toBe("Some")
    for (const input of [
      { action: "dynamic", artifact: "artifact-1" },
      { action: "procedures", artifact: "artifact-1" },
      { action: "pe" },
      { action: "pe", artifact: "artifact-1", offset: -1 },
      { action: "firmware", artifact: "artifact-1", offset: 8193 },
    ])
      expect(decode(input)._tag).toBe("None")
  })

  test("pe and firmware are R0; roles decide which phases may run them", () => {
    expect(ForkCyberDecision.actionID("cyber_binary", { action: "pe", artifact: "a" })).toBe("cyber_binary.pe")
    expect(ForkCyberDecision.declaration("cyber_binary")).toEqual({ pe: "R0", firmware: "R0" })
    expect(verdict("cyber-code-review", { action: "pe", artifact: "a" })).toEqual({
      decision: "allow",
      reason: "allowed",
      risk: "R0",
    })
    expect(verdict("cyber-recon", { action: "firmware", artifact: "a" }).decision).toBe("allow")
    expect(verdict("cyber-report", { action: "pe", artifact: "a" })).toEqual({
      decision: "deny",
      reason: "outside_role_or_mode",
    })
    expect(verdict("cyber-postex", { action: "pe", artifact: "a" }).decision).toBe("deny")
  })

  test("an undeclared action is denied by the decision function", () => {
    expect(verdict("cyber-code-review", { action: "dynamic", artifact: "a" })).toEqual({
      decision: "deny",
      reason: "undeclared_action",
    })
  })

  test("the fixture PE has the declared signature, section names and import directory", () => {
    const bytes = pe32({ imports: KNOWN_IMPORTS })
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    expect(String.fromCharCode(bytes[0]!, bytes[1]!)).toBe("MZ")
    const header = view.getUint32(0x3c, true)
    expect(String.fromCharCode(...bytes.subarray(header, header + 4))).toBe("PE\0\0")
    const count = view.getUint16(header + 6, true)
    const table = header + 4 + 20 + 224
    const names = Array.from({ length: count }, (_, index) =>
      String.fromCharCode(...bytes.subarray(table + index * 40, table + index * 40 + 8)).replace(/\0+$/, ""),
    )
    expect(names).toEqual([".text", ".idata", ".data"])
    expect(view.getUint32(header + 4 + 20 + 96 + 8, true)).toBe(0x2000)
  })

  test("a refused role runs no Kali job and records no execution", () =>
    Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped("opencyber-binary-refused-")
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
          const before = yield* store.executions(assessment.owner)
          const error = yield* ForkCyberBinary.run(
            store,
            tmp.path,
            offline,
            { ...assessment, agent: "cyber-report" },
            { action: "pe", artifact: "missing" },
          ).pipe(Effect.flip)
          expect(error).toBeInstanceOf(ForkCyberDiagnostics.Failure)
          expect((error as ForkCyberDiagnostics.Failure).diagnostic.category).toBe("refused_by_policy")
          expect(yield* store.executions(assessment.owner)).toEqual(before)
        }),
      ),
    ))

  test("an artifact outside this engagement is an invalid input before any Kali job", () =>
    Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const tmp = yield* tmpdirScoped("opencyber-binary-missing-")
          const store = yield* ForkCyberStore.open(path.join(tmp.path, "evidence.sqlite"))
          const error = yield* ForkCyberBinary.run(store, tmp.path, offline, assessment, {
            action: "pe",
            artifact: "00000000-0000-4000-8000-000000000000",
          }).pipe(Effect.flip)
          expect((error as ForkCyberDiagnostics.Failure).diagnostic.category).toBe("invalid_input")
        }),
      ),
    ))
})

describe("cyber_binary laboratory (Docker)", () => {
  dockerTest(
    "pe reports known sections, imports, hashes and pefile version for a synthetic PE",
    () =>
      Effect.runPromise(
        Effect.scoped(
          Effect.gen(function* () {
            const env = yield* ForkCyberBinaryLab.open(image!)
            const bytes = pe32({ imports: KNOWN_IMPORTS })
            const artifact = yield* ForkCyberBinaryLab.importSample(env, "known.exe", bytes)
            const result = yield* ForkCyberBinary.run(env.store, env.profile, env.config, assessment, {
              action: "pe",
              artifact,
            })
            const capture = peCapture(result)
            expect(capture.tool.name).toBe("pefile")
            expect(capture.tool.version).toMatch(/^\d{4}\.\d+\.\d+$/)
            expect(capture.sha256).toBe(ForkCyberStore.digest(bytes))
            expect(capture.sections.map((section) => section.name)).toEqual([".text", ".idata", ".data"])
            expect(capture.sections[0]).toMatchObject({ executable: true, writable: false, readable: true })
            expect(capture.sections[2]).toMatchObject({ executable: false, writable: true })
            expect(capture.imports.map((row) => [row.dll, row.name])).toEqual([
              ["kernel32.dll", "CreateFileW"],
              ["kernel32.dll", "ReadFile"],
              ["user32.dll", "MessageBoxA"],
            ])
            expect(capture.imports_observed).toBe(3)
            expect(capture.anomalies).toEqual([])
            expect(capture.headers.entry_point).toBe(0x1000)
            expect(capture.report_artifact).toBeTruthy()
            expect(result.evidence).toBeTruthy()
          }),
        ),
      ),
    120000,
  )

  dockerTest(
    "pe negative: a PE without imports reports the missing import directory as a candidate only",
    () =>
      Effect.runPromise(
        Effect.scoped(
          Effect.gen(function* () {
            const env = yield* ForkCyberBinaryLab.open(image!)
            const artifact = yield* ForkCyberBinaryLab.importSample(env, "none.exe", pe32({ imports: [] }))
            const capture = peCapture(
              yield* ForkCyberBinary.run(env.store, env.profile, env.config, assessment, { action: "pe", artifact }),
            )
            expect(capture.sections.map((section) => section.name)).toEqual([".text", ".data"])
            expect(capture.imports).toEqual([])
            expect(capture.anomalies.map((row) => row.rule)).toEqual(["no_import_directory"])
          }),
        ),
      ),
    120000,
  )

  dockerTest(
    "pe anomaly: writable and executable code is reported with its section",
    () =>
      Effect.runPromise(
        Effect.scoped(
          Effect.gen(function* () {
            const env = yield* ForkCyberBinaryLab.open(image!)
            const artifact = yield* ForkCyberBinaryLab.importSample(
              env,
              "wx.exe",
              pe32({ imports: KNOWN_IMPORTS, writableExecutable: true }),
            )
            const capture = peCapture(
              yield* ForkCyberBinary.run(env.store, env.profile, env.config, assessment, { action: "pe", artifact }),
            )
            expect(capture.anomalies).toContainEqual(
              expect.objectContaining({ rule: "writable_executable_section", section: ".text" }),
            )
          }),
        ),
      ),
    120000,
  )

  dockerTest(
    "pe pages imports with next_offset beyond the first 200 rows",
    () =>
      Effect.runPromise(
        Effect.scoped(
          Effect.gen(function* () {
            const env = yield* ForkCyberBinaryLab.open(image!)
            const functions = Array.from({ length: 260 }, (_, index) => `Function${index}`)
            const artifact = yield* ForkCyberBinaryLab.importSample(
              env,
              "many.exe",
              pe32({ imports: [{ dll: "big.dll", functions }] }),
            )
            const first = peCapture(
              yield* ForkCyberBinary.run(env.store, env.profile, env.config, assessment, { action: "pe", artifact }),
            )
            expect(first.imports).toHaveLength(200)
            expect(first.imports_observed).toBe(260)
            expect(first.next_offset).toBe(200)
            const second = peCapture(
              yield* ForkCyberBinary.run(env.store, env.profile, env.config, assessment, {
                action: "pe",
                artifact,
                offset: 200,
              }),
            )
            expect(second.imports.map((row) => row.name)).toEqual(functions.slice(200))
            expect(second.next_offset).toBeNull()
          }),
        ),
      ),
    120000,
  )

  dockerTest(
    "pe rejects a non-PE artifact as invalid input",
    () =>
      Effect.runPromise(
        Effect.scoped(
          Effect.gen(function* () {
            const env = yield* ForkCyberBinaryLab.open(image!)
            const artifact = yield* ForkCyberBinaryLab.importSample(
              env,
              "text.txt",
              Buffer.from("this is not a portable executable\n"),
            )
            const error = yield* ForkCyberBinary.run(env.store, env.profile, env.config, assessment, {
              action: "pe",
              artifact,
            }).pipe(Effect.flip)
            expect(error).toBeInstanceOf(ForkCyberDiagnostics.Failure)
            const diagnostic = (error as ForkCyberDiagnostics.Failure).diagnostic
            expect(diagnostic.category).toBe("invalid_input")
            expect(diagnostic.message).toContain("pefile could not analyze")
          }),
        ),
      ),
    120000,
  )

  dockerTest(
    "firmware reports a known gzip component and the hash of its extracted payload, with no network",
    () =>
      Effect.runPromise(
        Effect.scoped(
          Effect.gen(function* () {
            const env = yield* ForkCyberBinaryLab.open(image!)
            const artifact = yield* ForkCyberBinaryLab.importSample(env, "fw.bin", firmware())
            const result = yield* ForkCyberBinary.run(env.store, env.profile, env.config, assessment, {
              action: "firmware",
              artifact,
            })
            const capture = firmwareCapture(result)
            expect(result.network).toMatchObject({ kind: "none" })
            expect(capture.tool.name).toBe("binwalk")
            expect(capture.signatures_observed).toBe(1)
            const signature = capture.entries.find((row) => row.kind === "signature")
            expect(signature).toMatchObject({
              kind: "signature",
              offset: 256,
              description: expect.stringMatching(/^gzip compressed data/),
            })
            // Extracted names follow the carved offset, so the payload is identified by its hash and size.
            const payload = capture.entries.find(
              (row) => row.kind === "extracted" && row.sha256 === ForkCyberStore.digest(FIRMWARE_PAYLOAD),
            )
            expect(payload).toMatchObject({ kind: "extracted", bytes: FIRMWARE_PAYLOAD.length })
          }),
        ),
      ),
    180000,
  )

  dockerTest(
    "firmware negative: an image without signatures reports no components and no extracted files",
    () =>
      Effect.runPromise(
        Effect.scoped(
          Effect.gen(function* () {
            const env = yield* ForkCyberBinaryLab.open(image!)
            const artifact = yield* ForkCyberBinaryLab.importSample(
              env,
              "empty.bin",
              Buffer.from("opencyber negative control\n".repeat(128)),
            )
            const capture = firmwareCapture(
              yield* ForkCyberBinary.run(env.store, env.profile, env.config, assessment, {
                action: "firmware",
                artifact,
              }),
            )
            expect(capture.signatures_observed).toBe(0)
            expect(capture.extracted_observed).toBe(0)
            expect(capture.entries).toEqual([])
            expect(capture.next_offset).toBeNull()
          }),
        ),
      ),
    180000,
  )
})
