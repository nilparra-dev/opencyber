import { expect, test } from "bun:test"
import { ForkToolInputRepair } from "@opencode/core/plugin/fork-tool-input-repair"

const claim = {
  type: "object",
  properties: { action: { const: "claim" }, revision: { type: "integer" } },
  required: ["action", "revision"],
}
const release = {
  type: "object",
  properties: { action: { enum: ["release", "block"] }, revision: { type: "integer" } },
  required: ["action", "revision"],
}

test.each(["anyOf", "oneOf"])("selects required literal discriminators in %s object unions", (keyword) => {
  const schema = { [keyword]: [claim, release] }
  const input = { action: "claim", revision: "1" }
  expect(ForkToolInputRepair.select(input, schema)).toEqual({ value: input, schema: claim })
  expect(ForkToolInputRepair.select(input, schema)?.value).toBe(input)
  expect(input.revision).toBe("1")
  expect(ForkToolInputRepair.select({ action: "block", revision: "2" }, schema)?.schema).toBe(release)
  expect(ForkToolInputRepair.select(JSON.stringify(input), schema)).toEqual({ value: input, schema: claim })
})

test("preserves missing, unknown, overlapping and optional discriminators", () => {
  const input = { action: "claim", revision: "1" }
  expect(ForkToolInputRepair.select({ revision: "1" }, { anyOf: [claim, release] })).toBeUndefined()
  expect(ForkToolInputRepair.select({ action: "unknown", revision: "1" }, { anyOf: [claim, release] })).toBeUndefined()
  expect(
    ForkToolInputRepair.select(input, {
      anyOf: [claim, { ...release, properties: { ...release.properties, action: { enum: ["claim", "release"] } } }],
    }),
  ).toBeUndefined()
  expect(ForkToolInputRepair.select(input, { anyOf: [claim, { ...release, required: ["revision"] }] })).toBeUndefined()
})

test("preserves unrestricted alternatives, scalar roots and unsupported compositions", () => {
  const input = { action: "claim", revision: "1" }
  for (const branch of [true, {}, { type: "null" }, { ...release, properties: {} }])
    expect(ForkToolInputRepair.select(input, { anyOf: [claim, branch] })).toBeUndefined()
  expect(ForkToolInputRepair.select(input, { anyOf: [claim, release], oneOf: [claim, release] })).toBeUndefined()
  expect(ForkToolInputRepair.select(input, { anyOf: [claim, release], allOf: [{}] })).toBeUndefined()
  expect(ForkToolInputRepair.select(input, { type: "object", anyOf: [claim, release] })).toBeUndefined()
  for (const value of [null, 1, "claim", "{broken", "[]", []])
    expect(ForkToolInputRepair.select(value, { anyOf: [claim, release] })).toBeUndefined()
})
