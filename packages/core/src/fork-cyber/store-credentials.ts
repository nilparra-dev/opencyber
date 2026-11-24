export * as ForkCyberStoreCredentials from "./store-credentials.js"

import { SqlClient } from "effect/sql"
import { ForkCyberCredentials } from "./credentials.js"

export function make(sql: SqlClient.SqlClient) {
  const decision = (input: {
    owner: string
    session: string
    agent: string
    tool: string
    mode: string
    risk?: string
    decision: "allow" | "deny"
    reason: string
    target?: string
  }) =>
    sql`INSERT INTO cyber_decision (owner, session, agent, tool, mode, risk, decision, reason, target, created_at)
      VALUES (${input.owner}, ${input.session}, ${input.agent}, ${input.tool}, ${input.mode}, ${input.risk ?? null},
        ${input.decision}, ${input.reason}, ${input.target ?? null}, ${Date.now()})`

  const decisions = (owner: string, offset = 0) =>
    sql<{
      seq: number
      session: string
      agent: string
      tool: string
      mode: string
      risk: string | null
      decision: string
      reason: string
      target: string | null
    }>`SELECT seq, session, agent, tool, mode, risk, decision, reason, target FROM cyber_decision
      WHERE owner = ${owner} ORDER BY seq LIMIT 100 OFFSET ${offset}`

  const grantApproval = (input: {
    owner: string
    id: string
    action: string
    target: string
    approver: string
    approved_at: number
    expires_at: number
  }) =>
    sql`INSERT INTO validation_approval VALUES (${input.owner}, ${input.id}, ${input.action}, ${input.target},
      ${input.approver}, ${input.approved_at}, ${input.expires_at})`

  // Only the exact action and target match. Expired approvals are never returned.
  const activeApproval = (input: { owner: string; action: string; target: string; now: number }) =>
    sql<{ id: string; approver: string; expires_at: number }>`SELECT id, approver, expires_at FROM validation_approval
      WHERE owner = ${input.owner} AND action = ${input.action} AND target = ${input.target} AND expires_at > ${input.now}
      ORDER BY approved_at DESC, id LIMIT 1`

  // The store receives sealed values only. A label cannot be redefined: rotation revokes it and registers a new one.
  const putCredential = (input: {
    owner: string
    label: string
    kind: ForkCyberCredentials.Kind
    expires_at: number
    created_at: number
    nonce: string
    ciphertext: string
  }) =>
    sql`INSERT INTO engagement_credential(owner, label, kind, expires_at, revoked_at, nonce, ciphertext, created_at)
      VALUES (${input.owner}, ${input.label}, ${input.kind}, ${input.expires_at}, NULL, ${input.nonce}, ${input.ciphertext}, ${input.created_at})`

  const credential = (owner: string, label: string) =>
    sql<{
      kind: ForkCyberCredentials.Kind
      expires_at: number
      revoked_at: number | null
      nonce: string
      ciphertext: string
    }>`SELECT kind, expires_at, revoked_at, nonce, ciphertext FROM engagement_credential
      WHERE owner = ${owner} AND label = ${label}`

  // Returns one row when the credential was revoked now, and none when the label is unknown or already revoked.
  const revokeCredential = (owner: string, label: string, now: number) =>
    sql<{ label: string }>`UPDATE engagement_credential SET revoked_at = ${now}
      WHERE owner = ${owner} AND label = ${label} AND revoked_at IS NULL RETURNING label`

  // Metadata only. Sealed values never leave the store through a listing.
  const credentials = (owner: string) =>
    sql<{
      label: string
      kind: string
      expires_at: number
      revoked_at: number | null
    }>`SELECT label, kind, expires_at, revoked_at FROM engagement_credential WHERE owner = ${owner} ORDER BY label`

  // Every lease, granted or refused, is recorded with the label and target. The row never holds a value.
  const recordLease = (input: {
    owner: string
    label: string
    action: string
    target: string
    execution: string
    outcome: "granted" | "refused"
    reason: string
    created_at: number
  }) =>
    sql`INSERT INTO cyber_credential_lease(owner, label, action, target, execution, outcome, reason, created_at)
      VALUES (${input.owner}, ${input.label}, ${input.action}, ${input.target}, ${input.execution}, ${input.outcome},
        ${input.reason}, ${input.created_at})`

  // A granted lease is an attempt. The pacing window reads these rows, so it counts attempts, not outcomes.
  const recentLeases = (input: { owner: string; label: string; target: string; since: number }) =>
    sql<{ seq: number }>`SELECT seq FROM cyber_credential_lease
      WHERE owner = ${input.owner} AND label = ${input.label} AND target = ${input.target}
        AND outcome = 'granted' AND created_at > ${input.since}
      LIMIT 1`

  // Every granted lease counts, whatever its outcome: a rejected attempt still adds a failure at the target.
  const leaseAttempts = (input: { owner: string; label: string; target: string; since: number }) =>
    sql<{ attempts: number }>`SELECT COUNT(*) AS attempts FROM cyber_credential_lease
      WHERE owner = ${input.owner} AND label = ${input.label} AND target = ${input.target}
        AND outcome = 'granted' AND created_at > ${input.since}`

  return {
    decision,
    decisions,
    grantApproval,
    activeApproval,
    putCredential,
    credential,
    revokeCredential,
    credentials,
    recordLease,
    recentLeases,
    leaseAttempts,
  }
}
