export * as ForkCyberStoreMigrations from "./store-migrations.js"

import { Effect, Schedule } from "effect"
import { SqlClient } from "effect/sql"
import type { SqlError } from "effect/sql/SqlError"
import { ForkCyberCoordination } from "./coordination.js"

type Coordination = ReturnType<typeof ForkCyberCoordination.make>
type Migration = { version: number; up: Effect.Effect<void, SqlError> }

export const migrate = Effect.fn("ForkCyberStoreMigrations.migrate")(function* (
  sql: SqlClient.SqlClient,
  version: number,
  coordination: Coordination,
) {
  const migrations = steps(sql, coordination)
  const versions = migrations.map((migration) => migration.version)
  if (versions.some((migration, index) => migration !== index + 1))
    return yield* Effect.fail(new Error("OpenCyber evidence migrations are not contiguous"))
  const latest = versions.at(-1) ?? 0
  if (!Number.isInteger(version) || version < 0 || version > latest)
    return yield* Effect.fail(new Error("Unsupported OpenCyber evidence database version"))
  yield* Effect.forEach(
    migrations.filter((step) => version < step.version),
    (step) => retryLockTimeout(step.up),
    { discard: true },
  )
})

// Concurrent first-open migrations can acquire a stale deferred SQLite snapshot, so the whole
// rolled-back migration is retried, never just its last statement.
const retryLockTimeout = <A>(effect: Effect.Effect<A, SqlError>) =>
  effect.pipe(
    Effect.retry({
      while: (error) => error.reason._tag === "LockTimeoutError",
      times: 3,
      schedule: Schedule.spaced(25),
    }),
  )

const steps = (sql: SqlClient.SqlClient, coordination: Coordination): ReadonlyArray<Migration> => [
  {
    version: 1,
    up: sql.withTransaction(
      Effect.gen(function* () {
        yield* sql`CREATE TABLE IF NOT EXISTS engagement (
      owner TEXT PRIMARY KEY, revision INTEGER NOT NULL, manifest TEXT NOT NULL)`
        yield* sql`CREATE TABLE IF NOT EXISTS legacy_tombstone (owner TEXT PRIMARY KEY)`
        yield* sql`CREATE TABLE IF NOT EXISTS note (
      seq INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, origin TEXT NOT NULL,
      content TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(owner, origin))`
        yield* sql`CREATE INDEX IF NOT EXISTS note_owner ON note(owner, seq)`
        yield* sql`CREATE TABLE IF NOT EXISTS execution (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, session TEXT NOT NULL, tool TEXT NOT NULL,
      agent TEXT NOT NULL, started_at INTEGER NOT NULL, finished_at INTEGER, provenance TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('running','completed','error')),
      UNIQUE(owner, id))`
        yield* sql`CREATE INDEX IF NOT EXISTS execution_owner ON execution(owner, started_at, id)`
        yield* sql`CREATE TABLE IF NOT EXISTS artifact (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, execution TEXT NOT NULL, kind TEXT NOT NULL,
      media_type TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, data TEXT NOT NULL,
      UNIQUE(owner, id), FOREIGN KEY(owner, execution) REFERENCES execution(owner, id))`
        yield* sql`CREATE INDEX IF NOT EXISTS artifact_execution ON artifact(owner, execution)`
        yield* sql`CREATE TABLE IF NOT EXISTS finding (
      id TEXT PRIMARY KEY, owner TEXT NOT NULL, revision INTEGER NOT NULL,
      title TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('candidate','confirmed','discarded')),
      rationale TEXT NOT NULL, updated_at INTEGER NOT NULL, UNIQUE(owner, id))`
        yield* sql`CREATE INDEX IF NOT EXISTS finding_owner ON finding(owner, updated_at, id)`
        yield* sql`CREATE TABLE IF NOT EXISTS finding_evidence (
      owner TEXT NOT NULL, finding TEXT NOT NULL, artifact TEXT NOT NULL,
      PRIMARY KEY(owner, finding, artifact),
      FOREIGN KEY(owner, finding) REFERENCES finding(owner, id),
      FOREIGN KEY(owner, artifact) REFERENCES artifact(owner, id))`
        yield* sql`PRAGMA user_version = 1`
      }),
    ),
  },
  {
    version: 2,
    up: sql.withTransaction(
      Effect.gen(function* () {
        yield* sql`CREATE TABLE IF NOT EXISTS http_budget (owner TEXT PRIMARY KEY, next_at REAL NOT NULL)`
        yield* sql`PRAGMA user_version = 2`
      }),
    ),
  },
  {
    version: 3,
    up: coordination.initialize,
  },
  {
    version: 4,
    up: sql.withTransaction(
      Effect.gen(function* () {
        yield* sql`CREATE TABLE IF NOT EXISTS network_budget (owner TEXT PRIMARY KEY, reserved_bytes INTEGER NOT NULL)`
        yield* sql`PRAGMA user_version = 4`
      }),
    ),
  },
  {
    version: 5,
    up: sql.withTransaction(
      Effect.gen(function* () {
        yield* sql`CREATE TABLE IF NOT EXISTS finding_validation (
        owner TEXT NOT NULL, finding TEXT NOT NULL, details TEXT NOT NULL,
        PRIMARY KEY(owner, finding), FOREIGN KEY(owner, finding) REFERENCES finding(owner, id))`
        yield* sql`CREATE TABLE IF NOT EXISTS engagement_approval (
        owner TEXT NOT NULL, revision INTEGER NOT NULL, manifest TEXT NOT NULL, sha256 TEXT NOT NULL,
        approved_at INTEGER NOT NULL, source TEXT NOT NULL, PRIMARY KEY(owner, revision))`
        yield* sql`CREATE TABLE IF NOT EXISTS cyber_task_retry (
        owner TEXT NOT NULL, predecessor TEXT NOT NULL, successor TEXT NOT NULL, reason TEXT NOT NULL,
        effect_state TEXT NOT NULL, authorization TEXT NOT NULL, reconciliation TEXT NOT NULL,
        PRIMARY KEY(owner, predecessor), UNIQUE(owner, successor),
        FOREIGN KEY(owner, predecessor) REFERENCES cyber_task(owner, key),
        FOREIGN KEY(owner, successor) REFERENCES cyber_task(owner, key))`
        // Earlier confirmation recorded traceability only; preserve its evidence as a candidate.
        yield* sql`UPDATE finding SET status = 'candidate', revision = revision + 1
        WHERE status = 'confirmed' AND NOT EXISTS (SELECT 1 FROM finding_validation v WHERE v.owner = finding.owner AND v.finding = finding.id)`
        yield* sql`PRAGMA user_version = 5`
      }),
    ),
  },
  {
    version: 6,
    up: sql.withTransaction(
      Effect.gen(function* () {
        // Charge the whole job allowance before network access. Never refund on crashes or cancellation.
        yield* sql`CREATE TABLE IF NOT EXISTS harness_request (sha256 TEXT PRIMARY KEY, content TEXT NOT NULL)`
        yield* sql`CREATE TABLE IF NOT EXISTS harness_attempt (
        id TEXT PRIMARY KEY, owner TEXT NOT NULL, session TEXT NOT NULL, message TEXT NOT NULL, logical_step INTEGER,
        started_at INTEGER NOT NULL, finished_at INTEGER, status TEXT NOT NULL,
        request_sha256 TEXT NOT NULL REFERENCES harness_request(sha256), result TEXT)`
        yield* sql`CREATE INDEX IF NOT EXISTS harness_attempt_session ON harness_attempt(session, started_at, id)`
        yield* sql`PRAGMA user_version = 6`
      }),
    ),
  },
  {
    version: 7,
    up: sql.withTransaction(
      Effect.gen(function* () {
        // Decisions are append-only. The application has no update or delete path, and the trigger refuses updates.
        yield* sql`CREATE TABLE IF NOT EXISTS cyber_decision (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, session TEXT NOT NULL, agent TEXT NOT NULL,
        tool TEXT NOT NULL, mode TEXT NOT NULL, risk TEXT, decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
        reason TEXT NOT NULL, target TEXT, created_at INTEGER NOT NULL)`
        yield* sql`CREATE INDEX IF NOT EXISTS cyber_decision_owner ON cyber_decision(owner, seq)`
        yield* sql`CREATE TRIGGER IF NOT EXISTS cyber_decision_append_only BEFORE UPDATE ON cyber_decision
        BEGIN SELECT RAISE(ABORT, 'cyber decisions are append-only'); END`
        yield* sql`PRAGMA user_version = 7`
      }),
    ),
  },
  {
    version: 8,
    up: sql.withTransaction(
      Effect.gen(function* () {
        // Each retest execution is linked to the finding it re-checked. Retests never change the finding status.
        yield* sql`CREATE TABLE IF NOT EXISTS finding_retest (
        owner TEXT NOT NULL, finding TEXT NOT NULL, execution TEXT NOT NULL, created_at INTEGER NOT NULL,
        PRIMARY KEY(owner, execution))`
        yield* sql`CREATE INDEX IF NOT EXISTS finding_retest_finding ON finding_retest(owner, finding, created_at)`
        yield* sql`PRAGMA user_version = 8`
      }),
    ),
  },
  {
    version: 9,
    up: sql.withTransaction(
      Effect.gen(function* () {
        // Operator approvals for one R2 action on one target. An approval is honoured only until it expires.
        yield* sql`CREATE TABLE IF NOT EXISTS validation_approval (
        owner TEXT NOT NULL, id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
        approver TEXT NOT NULL, approved_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        PRIMARY KEY(owner, id))`
        yield* sql`CREATE INDEX IF NOT EXISTS validation_approval_subject ON validation_approval(owner, action, target, expires_at)`
        yield* sql`PRAGMA user_version = 9`
      }),
    ),
  },
  {
    version: 10,
    up: sql.withTransaction(
      Effect.gen(function* () {
        // Credentials are sealed before they reach this table, so a database copy holds no plaintext. Leases are
        // append-only, like decisions, and never hold a value.
        yield* sql`CREATE TABLE IF NOT EXISTS engagement_credential (
        owner TEXT NOT NULL, label TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('directory_bind', 'cloud_key')),
        expires_at INTEGER NOT NULL, revoked_at INTEGER, nonce TEXT NOT NULL, ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL, PRIMARY KEY(owner, label))`
        yield* sql`CREATE TABLE IF NOT EXISTS cyber_credential_lease (
        seq INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, label TEXT NOT NULL, action TEXT NOT NULL,
        target TEXT, execution TEXT, outcome TEXT NOT NULL CHECK (outcome IN ('granted', 'refused')),
        reason TEXT NOT NULL, created_at INTEGER NOT NULL)`
        yield* sql`CREATE INDEX IF NOT EXISTS cyber_credential_lease_owner ON cyber_credential_lease(owner, seq)`
        yield* sql`CREATE TRIGGER IF NOT EXISTS cyber_credential_lease_append_only BEFORE UPDATE ON cyber_credential_lease
        BEGIN SELECT RAISE(ABORT, 'credential leases are append-only'); END`
        yield* sql`PRAGMA user_version = 10`
      }),
    ),
  },
  {
    // SQLite cannot widen a CHECK constraint in place, so the table is rebuilt. Rows keep their sealed values.
    version: 11,
    up: sql.withTransaction(
      Effect.gen(function* () {
        yield* sql`CREATE TABLE engagement_credential_v11 (
        owner TEXT NOT NULL, label TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('directory_bind', 'cloud_key', 'database_login')),
        expires_at INTEGER NOT NULL, revoked_at INTEGER, nonce TEXT NOT NULL, ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL, PRIMARY KEY(owner, label))`
        yield* sql`INSERT INTO engagement_credential_v11 SELECT * FROM engagement_credential`
        yield* sql`DROP TABLE engagement_credential`
        yield* sql`ALTER TABLE engagement_credential_v11 RENAME TO engagement_credential`
        yield* sql`PRAGMA user_version = 11`
      }),
    ),
  },
  {
    // host_login (OC-302) joins the kinds the credential table accepts. Same rebuild as version 11.
    version: 12,
    up: sql.withTransaction(
      Effect.gen(function* () {
        yield* sql`CREATE TABLE engagement_credential_v12 (
        owner TEXT NOT NULL, label TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('directory_bind', 'cloud_key', 'database_login', 'host_login')),
        expires_at INTEGER NOT NULL, revoked_at INTEGER, nonce TEXT NOT NULL, ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL, PRIMARY KEY(owner, label))`
        yield* sql`INSERT INTO engagement_credential_v12 SELECT * FROM engagement_credential`
        yield* sql`DROP TABLE engagement_credential`
        yield* sql`ALTER TABLE engagement_credential_v12 RENAME TO engagement_credential`
        yield* sql`PRAGMA user_version = 12`
      }),
    ),
  },
  {
    // ForkCyberCredentials.Kind validates kinds at the Effect Schema boundary, so the table only
    // requires a non-empty kind. Same rebuild as versions 11 and 12, preserving every sealed row.
    version: 13,
    up: sql.withTransaction(
      Effect.gen(function* () {
        yield* sql`CREATE TABLE engagement_credential_v13 (
        owner TEXT NOT NULL, label TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (length(kind) > 0),
        expires_at INTEGER NOT NULL, revoked_at INTEGER, nonce TEXT NOT NULL, ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL, PRIMARY KEY(owner, label))`
        yield* sql`INSERT INTO engagement_credential_v13 SELECT * FROM engagement_credential`
        yield* sql`DROP TABLE engagement_credential`
        yield* sql`ALTER TABLE engagement_credential_v13 RENAME TO engagement_credential`
        yield* sql`PRAGMA user_version = 13`
      }),
    ),
  },
]
