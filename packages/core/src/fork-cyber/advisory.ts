export * as ForkCyberAdvisory from "./advisory.js"

import { Effect, Schema } from "effect"
import { ForkCyberDiagnostics } from "./diagnostics.js"
import { ForkCyberStore } from "./store.js"

// A pinned, versioned advisory snapshot for offline matching (fork-cyber-toolset.md, D7 and D8). The operator names the
// file and its SHA-256 digest; the digest is checked before any record is read. Results carry the snapshot identity.
const format = "opencyber-advisory-snapshot-v1"
const ecosystems = ["npm", "PyPI"] as const
export type Environment = Readonly<Record<string, string | undefined>>

const text = (maximum: number) => Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(maximum))
const comparator = /^(<=|>=|==|<|>|=)?(.+)$/
const version = /^(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/
const Range = text(200).check(
  Schema.makeFilter<string>(
    (value) =>
      value.split(" ").every((part) => version.test(part.match(comparator)?.[2] ?? "")) ||
      "Expected space-separated comparators such as >=1.0.0 <1.4.3",
  ),
)
const Entry = Schema.Struct({
  ecosystem: Schema.Literals(ecosystems),
  package: text(214),
  range: Range,
  id: text(100),
  severity: Schema.Literals(["critical", "high", "medium", "low", "unknown"]),
  summary: text(500),
  fixed: Schema.optional(text(128)),
})
const Snapshot = Schema.Struct({
  format: Schema.Literal(format),
  source: text(200),
  snapshot_version: text(100),
  records: Schema.Array(Entry).check(Schema.isMaxLength(20000)),
})
export type Loaded = typeof Snapshot.Type & { sha256: string }
export type Package = { ecosystem: string; name: string; version: string }

const Digest = Schema.String.check(Schema.isPattern(/^[a-f0-9]{64}$/))
const variables = { file: "OPENCYBER_ADVISORY_SNAPSHOT", digest: "OPENCYBER_ADVISORY_SHA256" } as const

export function configured(environment: Environment) {
  return Effect.suspend(() => {
    const file = environment[variables.file]
    const digest = environment[variables.digest]
    if (file === undefined || digest === undefined)
      return Effect.fail(
        failure(
          "No pinned advisory snapshot is configured.",
          `Set ${variables.file} to the snapshot file and ${variables.digest} to its SHA-256 digest, then retry.`,
        ),
      )
    if (!Schema.is(Digest)(digest))
      return Effect.fail(failure(`${variables.digest} must be a 64-character lowercase SHA-256 digest.`))
    return load(file, digest)
  })
}

export const load = Effect.fn("ForkCyberAdvisory.load")(function* (file: string, pinned: string) {
  const bytes = yield* Effect.tryPromise({
    try: () => Bun.file(file).bytes(),
    catch: () => failure("The advisory snapshot file cannot be read."),
  })
  const sha256 = ForkCyberStore.digest(bytes)
  if (sha256 !== pinned)
    return yield* Effect.fail(failure("The advisory snapshot does not match its pinned SHA-256 digest."))
  const snapshot = yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Snapshot))(
    Buffer.from(bytes).toString("utf8"),
  ).pipe(Effect.mapError(() => failure("The advisory snapshot is not a valid opencyber advisory snapshot.")))
  return { ...snapshot, sha256 }
})

// Version order over the dotted numeric core, then prerelease identifiers. Build metadata is ignored.
// Returns undefined when either side is not a plain dotted version, so the caller reports it instead of guessing.
export function compare(left: string, right: string) {
  const a = version.exec(left)
  const b = version.exec(right)
  if (a === null || b === null) return undefined
  return compareCore(a[1]!, b[1]!) || comparePrerelease(a[2], b[2])
}

export function satisfies(installed: string, range: string) {
  return comparators(range).every(({ operator, operand }) => {
    const order = compare(installed, operand)
    return order !== undefined && holds(operator, order)
  })
}

export function match(snapshot: Loaded, packages: readonly Package[]) {
  const unevaluated = packages.flatMap((pkg) => {
    const reason = unevaluable(pkg)
    return reason === undefined ? [] : [{ ecosystem: pkg.ecosystem, package: pkg.name, version: pkg.version, reason }]
  })
  const findings = packages.flatMap((pkg) => {
    if (unevaluable(pkg) !== undefined) return []
    return snapshot.records
      .filter(
        (record) =>
          record.ecosystem === pkg.ecosystem &&
          normalize(pkg.ecosystem, record.package) === normalize(pkg.ecosystem, pkg.name) &&
          satisfies(pkg.version, record.range),
      )
      .map((record) => ({
        id: record.id,
        severity: record.severity,
        summary: record.summary,
        ecosystem: pkg.ecosystem,
        package: pkg.name,
        version: pkg.version,
        range: record.range,
        fixed: record.fixed ?? null,
      }))
  })
  return { evaluated: packages.length - unevaluated.length, findings, unevaluated }
}

// Results show the first page inline; the complete list is stored in the results artifact.
export function page<T>(items: readonly T[], limit = 50) {
  return { items: items.slice(0, limit), next_offset: items.length > limit ? limit : null }
}

export function identity(snapshot: Loaded) {
  return {
    source: snapshot.source,
    snapshot_version: snapshot.snapshot_version,
    sha256: snapshot.sha256,
    records: snapshot.records.length,
  }
}

function unevaluable(pkg: Package) {
  if (!supported(pkg.ecosystem)) return "unsupported_ecosystem"
  if (!version.test(pkg.version)) return "unparsed_version"
  return undefined
}

function supported(ecosystem: string): ecosystem is (typeof ecosystems)[number] {
  return ecosystems.some((known) => known === ecosystem)
}

// PyPI names compare case-insensitively with runs of "-", "_" and "." equal (PEP 503). npm names are exact.
function normalize(ecosystem: string, name: string) {
  return ecosystem === "PyPI" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name
}

function comparators(range: string) {
  return range.split(" ").map((part) => {
    const [, operator = "=", operand = ""] = part.match(comparator) ?? []
    return { operator, operand }
  })
}

function holds(operator: string, order: number) {
  if (operator === "<") return order < 0
  if (operator === "<=") return order <= 0
  if (operator === ">") return order > 0
  if (operator === ">=") return order >= 0
  return order === 0
}

function compareCore(left: string, right: string) {
  const a = left.split(".").map((part) => BigInt(part))
  const b = right.split(".").map((part) => BigInt(part))
  const difference = Array.from(
    { length: Math.max(a.length, b.length) },
    (_, index) => (a[index] ?? 0n) - (b[index] ?? 0n),
  ).find((value) => value !== 0n)
  if (difference === undefined) return 0
  return difference > 0n ? 1 : -1
}

// A release outranks its own prerelease. Numeric identifiers compare numerically and rank below alphanumeric ones.
function comparePrerelease(left: string | undefined, right: string | undefined) {
  if (left === undefined || right === undefined) return left === right ? 0 : left === undefined ? 1 : -1
  const a = left.split(".")
  const b = right.split(".")
  return (
    Array.from({ length: Math.max(a.length, b.length) }, (_, index) => comparePart(a[index], b[index])).find(
      (value) => value !== 0,
    ) ?? 0
  )
}

function comparePart(left: string | undefined, right: string | undefined) {
  if (left === right) return 0
  if (left === undefined) return -1
  if (right === undefined) return 1
  const numeric = [/^\d+$/.test(left), /^\d+$/.test(right)]
  if (numeric[0] && numeric[1]) return order(BigInt(left), BigInt(right))
  if (numeric[0] !== numeric[1]) return numeric[0] ? -1 : 1
  return order(left, right)
}

function order<T extends bigint | string>(left: T, right: T) {
  if (left === right) return 0
  return left < right ? -1 : 1
}

function failure(message: string, recovery?: string) {
  return new ForkCyberDiagnostics.Failure({
    category: "configuration",
    operation: "advisory",
    message,
    target_started: false,
    effects: "not_started",
    recovery,
  })
}
