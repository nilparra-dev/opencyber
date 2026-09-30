export * as ForkToolInputRepair from "./fork-tool-input-repair.js"

import { JsonSchema, Option, Predicate, Schema } from "effect"

const decodeJson = Schema.decodeUnknownOption(Schema.fromJsonString(Schema.Unknown))

export function select(value: unknown, schema: JsonSchema.JsonSchema) {
  if (schema.type !== undefined || Array.isArray(schema.allOf)) return
  if (Array.isArray(schema.anyOf) && Array.isArray(schema.oneOf)) return
  const branches = Array.isArray(schema.anyOf) ? schema.anyOf : schema.oneOf
  if (!Array.isArray(branches) || branches.length === 0) return
  const parsed = typeof value === "string" ? Option.getOrUndefined(decodeJson(value)) : value
  if (!Predicate.isObject(parsed)) return

  // Every alternative must require the same literal field. Matching a single branch's
  // shape is insufficient: another alternative may already accept the original value.
  const selected = Object.keys(parsed).reduce<JsonSchema.JsonSchema | undefined>((selected, key) => {
    if (selected) return selected
    const alternatives = branches.flatMap((branch) => {
      if (
        !Predicate.isObject(branch) ||
        branch.type !== "object" ||
        !Array.isArray(branch.required) ||
        !branch.required.includes(key) ||
        !Predicate.isObject(branch.properties)
      )
        return []
      const property = branch.properties[key]
      if (!Predicate.isObject(property)) return []
      const values = Object.hasOwn(property, "const") ? [property.const] : property.enum
      return Array.isArray(values) && values.length > 0 ? [{ schema: branch, values }] : []
    })
    if (alternatives.length !== branches.length) return
    const matches = alternatives.filter((alternative) => alternative.values.includes(parsed[key]))
    return matches.length === 1 ? matches[0]?.schema : undefined
  }, undefined)
  return selected ? { value: parsed, schema: selected } : undefined
}
