export * as ForkCyberOfflineAnalysis from "./offline-analysis.js"

import { Effect } from "effect"
import { ForkCyberStore } from "./store.js"

type Store = Effect.Success<ReturnType<typeof ForkCyberStore.open>>
export type Actor = { owner: string; session: string; agent: string }

// Offline analysis is recorded like cyber_web_plan: one execution with an output artifact, and no network.
// The stored input is the caller's responsibility, so callers redact any credential before passing it.
export const record = Effect.fn(function* (store: Store, actor: Actor, tool: string, input: unknown, output: object) {
  const execution = crypto.randomUUID()
  yield* store.start({
    owner: actor.owner,
    session: actor.session,
    agent: actor.agent,
    id: execution,
    tool,
    input,
    provenance: { operation_class: "analysis", network: "none" },
  })
  const artifacts = yield* store.finish(actor.owner, execution, "completed", { ...output, execution })
  return { content: JSON.stringify({ ...output, execution, completion_evidence: [artifacts[0]!.id] }) }
})
