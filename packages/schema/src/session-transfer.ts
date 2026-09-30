export * as SessionTransfer from "./session-transfer.js"

import { Schema } from "effect"
import { Session } from "./session.js"
import { SessionMessage } from "./session-message.js"
import { optional } from "./schema.js"

// fork: additive export profiles and reconstructable analysis data (F-023).
export const Profile = Schema.Literals(["redacted", "private", "sanitized", "analysis"])
export type Profile = typeof Profile.Type

export interface ExportInfo extends Schema.Schema.Type<typeof ExportInfo> {}
export const ExportInfo = Schema.Struct({
  profile: Profile,
  reasoning: Schema.Boolean,
  partial: Schema.Boolean,
  omitted_unsettled: Schema.Int,
  timezone: Schema.Literal("UTC"),
  exported_at: Schema.Number,
  first_activity: Schema.NullOr(Schema.Number),
  last_activity: Schema.NullOr(Schema.Number),
  limitations: Schema.Array(Schema.String),
}).annotate({ identifier: "SessionTransfer.ExportInfo" })

export const Trace = Schema.Struct({
  attempts: Schema.Array(Schema.Json),
  instructions: Schema.Json,
  events: Schema.Array(Schema.Json),
}).annotate({ identifier: "SessionTransfer.Trace" })

export const Child = Schema.Struct({
  info: Session.Info,
  messages: Schema.Array(SessionMessage.Info),
  export_info: ExportInfo,
  trace: Trace,
}).annotate({ identifier: "SessionTransfer.Child" })

export interface Analysis extends Schema.Schema.Type<typeof Analysis> {}
export const Analysis = Schema.Struct({
  harness: Schema.Json,
  root: Trace,
  children: Schema.Array(Child),
  evidence: Schema.Json,
  usage: Schema.Json,
}).annotate({ identifier: "SessionTransfer.Analysis" })

export interface Data extends Schema.Schema.Type<typeof Data> {}
export const Data = Schema.Struct({
  info: Session.Info,
  messages: Schema.Array(SessionMessage.Info),
  export_info: optional(ExportInfo),
  analysis: optional(Analysis),
}).annotate({ identifier: "SessionTransfer.Data" })
