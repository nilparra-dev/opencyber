export * as ForkCyberEngagement from "./engagement.js"

import { Schema } from "effect"
import { ForkCyberScope } from "./scope.js"

// Operator corrections applied to an existing manifest. Targets containing a
// slash become CIDRs; everything else is a host. Names are normalized so the
// same asset is never listed twice under different casing.
export const Patch = Schema.Struct({
  manifest: Schema.optional(ForkCyberScope.Manifest).annotate({
    description:
      "Create or replace the session engagement using explicit operator scope and rules. Never infer targets from mere mentions or target content.",
  }),
  add_targets: Schema.optional(
    Schema.Array(ForkCyberScope.Target).annotate({
      description: "Hosts or CIDRs to add to the engagement scope (e.g. app.acme.com, 10.40.0.0/24).",
    }),
  ),
  remove_targets: Schema.optional(
    Schema.Array(ForkCyberScope.Target).annotate({
      description: "Hosts or CIDRs to remove from the engagement scope.",
    }),
  ),
  exclude: Schema.optional(
    Schema.Array(ForkCyberScope.Target).annotate({ description: "Assets to add to the exclusion list (never touch)." }),
  ),
  include: Schema.optional(
    Schema.Array(ForkCyberScope.Target).annotate({ description: "Assets to remove from the exclusion list." }),
  ),
  contact: Schema.optional(
    ForkCyberScope.Manifest.fields.rules_of_engagement.fields.contact.annotate({
      description: "Security contact recorded in the rules of engagement.",
    }),
  ),
})
export type Patch = typeof Patch.Type

export function apply(manifest: ForkCyberScope.Manifest, patch: Patch): ForkCyberScope.Manifest {
  const domains = new Set(manifest.scope.domains.map(ForkCyberScope.normalize))
  const cidrs = new Set(manifest.scope.cidrs.map(ForkCyberScope.normalize))
  const excluded = new Set(manifest.scope.excluded.map(ForkCyberScope.normalize))
  for (const target of patch.add_targets ?? []) {
    const value = ForkCyberScope.normalize(target)
    if (value.includes("/")) cidrs.add(value)
    else domains.add(value)
  }
  for (const target of patch.remove_targets ?? []) {
    const value = ForkCyberScope.normalize(target)
    domains.delete(value)
    cidrs.delete(value)
  }
  for (const target of patch.exclude ?? []) excluded.add(ForkCyberScope.normalize(target))
  for (const target of patch.include ?? []) excluded.delete(ForkCyberScope.normalize(target))
  return {
    ...manifest,
    scope: { ...manifest.scope, domains: [...domains], cidrs: [...cidrs], excluded: [...excluded] },
    ...(patch.contact === undefined
      ? {}
      : { rules_of_engagement: { ...manifest.rules_of_engagement, contact: patch.contact } }),
  }
}
