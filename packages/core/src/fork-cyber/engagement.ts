export * as ForkCyberEngagement from "./engagement.js"

import { Schema } from "effect"
import { ForkCyberScope } from "./scope.js"

// Operator corrections applied to an existing manifest. Targets containing a
// slash become CIDRs; everything else is a host. Names are normalized so the
// same asset is never listed twice under different casing.
export const Patch = Schema.Struct({
  add_targets: Schema.optional(
    Schema.Array(Schema.String).annotate({
      description: "Hosts or CIDRs to add to the engagement scope (e.g. app.acme.com, 10.40.0.0/24).",
    }),
  ),
  remove_targets: Schema.optional(
    Schema.Array(Schema.String).annotate({ description: "Hosts or CIDRs to remove from the engagement scope." }),
  ),
  exclude: Schema.optional(
    Schema.Array(Schema.String).annotate({ description: "Assets to add to the exclusion list (never touch)." }),
  ),
  include: Schema.optional(
    Schema.Array(Schema.String).annotate({ description: "Assets to remove from the exclusion list." }),
  ),
  contact: Schema.optional(
    Schema.String.annotate({ description: "Security contact recorded in the rules of engagement." }),
  ),
})
export type Patch = typeof Patch.Type

export function apply(manifest: ForkCyberScope.Manifest, patch: Patch): ForkCyberScope.Manifest {
  const domains = new Set(manifest.scope.domains.map(normalize))
  const cidrs = new Set(manifest.scope.cidrs.map(normalize))
  const excluded = new Set(manifest.scope.excluded.map(normalize))
  for (const target of patch.add_targets ?? []) {
    const value = normalize(target)
    if (value.includes("/")) cidrs.add(value)
    else domains.add(value)
  }
  for (const target of patch.remove_targets ?? []) {
    const value = normalize(target)
    domains.delete(value)
    cidrs.delete(value)
  }
  for (const target of patch.exclude ?? []) excluded.add(normalize(target))
  for (const target of patch.include ?? []) excluded.delete(normalize(target))
  return {
    ...manifest,
    scope: { domains: [...domains], cidrs: [...cidrs], excluded: [...excluded] },
    ...(patch.contact === undefined
      ? {}
      : { rules_of_engagement: { ...manifest.rules_of_engagement, contact: patch.contact } }),
  }
}

function normalize(value: string) {
  return value.trim().toLowerCase()
}
