export * as Delegation from "./delegation.js"

import { Schema } from "effect"

export const Mode = Schema.Literals(["manual", "automatic"])
export type Mode = typeof Mode.Type

/** Fork policy stored in the existing host-owned session metadata. */
export const MetadataKey = "opencyber.delegation"
export const ApprovalKey = "opencyber.manualDelegation"
