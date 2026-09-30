export * as ForkCyberFindings from "./findings.js"

import { Schema } from "effect"

const text = Schema.String.check(Schema.isMinLength(1), Schema.isMaxLength(4000), Schema.isPattern(/\S/))

export const Validation = Schema.Struct({
  task: text,
  asset: text,
  method: Schema.Literals(["dynamic", "static", "configuration"]),
  identity: text,
  expected: text,
  observed: text,
  controls: text,
  reproduction: text,
  remediation: text,
})
export type Validation = typeof Validation.Type
