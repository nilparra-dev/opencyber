import { expect, test } from "bun:test"
import { Effect } from "effect"
import path from "node:path"
import { ForkCyberAdvisory } from "@opencode/core/fork-cyber/advisory"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"
import { tmpdirScoped } from "../fixture/tmpdir"

const fixture = path.resolve(import.meta.dir, "../fixture/fork-cyber-advisory")
const snapshotFile = path.join(fixture, "snapshot.json")

const digestOf = (bytes: Uint8Array) => ForkCyberStore.digest(bytes)
const fixtureDigest = digestOf(await Bun.file(snapshotFile).bytes())

test("versions order by numeric core, rank prereleases below their release and ignore build metadata", () => {
  expect(ForkCyberAdvisory.compare("1.10.0", "1.9.9")).toBe(1)
  expect(ForkCyberAdvisory.compare("1.0.0-rc.1", "1.0.0")).toBe(-1)
  expect(ForkCyberAdvisory.compare("1.0.0-alpha.2", "1.0.0-alpha.10")).toBe(-1)
  expect(ForkCyberAdvisory.compare("1.0.0-alpha", "1.0.0-alpha.1")).toBe(-1)
  expect(ForkCyberAdvisory.compare("1.0.0+build.5", "1.0.0")).toBe(0)
  expect(ForkCyberAdvisory.compare("1.2", "1.2.0")).toBe(0)
})

test("versions that are not plain dotted numbers are not compared", () => {
  expect(ForkCyberAdvisory.compare("0.9.1rc1", "0.9.1")).toBeUndefined()
  expect(ForkCyberAdvisory.compare("1.0.0", "latest")).toBeUndefined()
  expect(ForkCyberAdvisory.satisfies("0.9.1rc1", "<2.0.0")).toBe(false)
})

test("a range is a conjunction of comparators with exact boundaries", () => {
  expect(ForkCyberAdvisory.satisfies("1.0.0", ">=1.0.0 <1.4.3")).toBe(true)
  expect(ForkCyberAdvisory.satisfies("1.4.2", ">=1.0.0 <1.4.3")).toBe(true)
  expect(ForkCyberAdvisory.satisfies("1.4.3", ">=1.0.0 <1.4.3")).toBe(false)
  expect(ForkCyberAdvisory.satisfies("0.9.9", ">=1.0.0 <1.4.3")).toBe(false)
  expect(ForkCyberAdvisory.satisfies("1.4.3", "<=1.4.3")).toBe(true)
  expect(ForkCyberAdvisory.satisfies("1.4.3", "=1.4.3")).toBe(true)
  expect(ForkCyberAdvisory.satisfies("1.4.3", "==1.4.3")).toBe(true)
  expect(ForkCyberAdvisory.satisfies("1.4.3", ">1.4.3")).toBe(false)
})

test("a snapshot loads only when its bytes match the pinned digest", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const loaded = yield* ForkCyberAdvisory.load(snapshotFile, fixtureDigest)
        expect(loaded).toMatchObject({
          format: "opencyber-advisory-snapshot-v1",
          source: "opencyber-test-fixture",
          snapshot_version: "test-fixture-1",
          sha256: fixtureDigest,
        })
        expect(ForkCyberAdvisory.identity(loaded)).toEqual({
          source: "opencyber-test-fixture",
          snapshot_version: "test-fixture-1",
          sha256: fixtureDigest,
          records: 2,
        })
        const wrong = yield* ForkCyberAdvisory.load(snapshotFile, "0".repeat(64)).pipe(Effect.result)
        expect(wrong._tag).toBe("Failure")
        if (wrong._tag === "Failure") {
          expect(wrong.failure.diagnostic.category).toBe("not_configured")
          expect(wrong.failure.message).toContain("does not match its pinned SHA-256 digest")
        }
      }),
    ),
  )
})

test("a snapshot with a range outside the comparator grammar is refused at load", async () => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const tmp = yield* tmpdirScoped()
        const file = path.join(tmp.path, "snapshot.json")
        const document = JSON.parse(yield* Effect.promise(() => Bun.file(snapshotFile).text()))
        document.records[0].range = ">=1.0.0 || <2.0.0"
        yield* Effect.promise(() => Bun.write(file, JSON.stringify(document)))
        const digest = digestOf(yield* Effect.promise(() => Bun.file(file).bytes()))
        const result = yield* ForkCyberAdvisory.load(file, digest).pipe(Effect.result)
        expect(result._tag).toBe("Failure")
        if (result._tag === "Failure")
          expect(result.failure.message).toContain("not a valid opencyber advisory snapshot")
      }),
    ),
  )
})

test("configuration names the two variables and refuses a malformed digest", async () => {
  const missing = await Effect.runPromise(ForkCyberAdvisory.configured({}).pipe(Effect.result))
  expect(missing._tag).toBe("Failure")
  if (missing._tag === "Failure") {
    expect(missing.failure.diagnostic.category).toBe("not_configured")
    expect(missing.failure.diagnostic.recovery).toContain("OPENCYBER_ADVISORY_SNAPSHOT")
    expect(missing.failure.diagnostic.recovery).toContain("OPENCYBER_ADVISORY_SHA256")
  }
  const malformed = await Effect.runPromise(
    ForkCyberAdvisory.configured({ OPENCYBER_ADVISORY_SNAPSHOT: snapshotFile, OPENCYBER_ADVISORY_SHA256: "ABC" }).pipe(
      Effect.result,
    ),
  )
  expect(malformed._tag).toBe("Failure")
  if (malformed._tag === "Failure") expect(malformed.failure.message).toContain("64-character lowercase")
})

test("matching separates vulnerable and fixed versions, normalizes PyPI names and reports unevaluable entries", async () => {
  const snapshot = await Effect.runPromise(ForkCyberAdvisory.load(snapshotFile, fixtureDigest))
  const result = ForkCyberAdvisory.match(snapshot, [
    { ecosystem: "npm", name: "ocfx-parser", version: "1.4.2" },
    { ecosystem: "npm", name: "ocfx-parser", version: "1.4.3" },
    { ecosystem: "PyPI", name: "OCFX_Py", version: "0.9.0" },
    { ecosystem: "PyPI", name: "ocfx-py", version: "0.9.1" },
    { ecosystem: "deb", name: "libssl3", version: "3.0.11-1" },
    { ecosystem: "npm", name: "ocfx-parser", version: "1.4.2rc1" },
  ])
  expect(result.evaluated).toBe(4)
  expect(result.findings.map((finding) => [finding.id, finding.package, finding.version, finding.fixed])).toEqual([
    ["OCFX-TEST-0001", "ocfx-parser", "1.4.2", "1.4.3"],
    ["OCFX-TEST-0002", "OCFX_Py", "0.9.0", "0.9.1"],
  ])
  expect(result.unevaluated).toEqual([
    { ecosystem: "deb", package: "libssl3", version: "3.0.11-1", reason: "unsupported_ecosystem" },
    { ecosystem: "npm", package: "ocfx-parser", version: "1.4.2rc1", reason: "unparsed_version" },
  ])
})

test("result pages hold fifty items and state the next offset only when more remain", () => {
  const long = Array.from({ length: 120 }, (_, index) => index)
  expect(ForkCyberAdvisory.page(long)).toEqual({ items: long.slice(0, 50), next_offset: 50 })
  expect(ForkCyberAdvisory.page([1, 2, 3])).toEqual({ items: [1, 2, 3], next_offset: null })
})
