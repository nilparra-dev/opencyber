import { expect, test } from "bun:test"
import { Schema } from "effect"
import { ForkCyberValidation } from "@opencode/core/fork-cyber/validation"

const step = {
  validator: "cyber_example",
  pre_state: { control: "unchanged" },
  action: { probe: "one request" },
  basis: "The probe is compared with its control.",
} as const

test("a reproduction with completed cleanup and known effects is recorded as reproduced", () => {
  const record = ForkCyberValidation.outcome({ ...step, result: "reproduced", cleanup: "completed" })
  expect(record).toEqual({
    format: "opencyber-validation-v1",
    validator: "cyber_example",
    pre_state: { control: "unchanged" },
    action: { probe: "one request" },
    oracle: { result: "reproduced", basis: "The probe is compared with its control." },
    cleanup: "completed",
    effects: "known",
  })
  expect(Schema.is(ForkCyberValidation.Record)(record)).toBe(true)
})

test.each(["failed", "unknown"] as const)("cleanup %s makes every oracle result inconclusive", (cleanup) => {
  for (const result of ["reproduced", "not_reproduced", "inconclusive"] as const) {
    const record = ForkCyberValidation.outcome({ ...step, result, cleanup })
    expect(record.effects).toBe("unknown")
    expect(record.oracle.result).toBe("inconclusive")
    expect(record.cleanup).toBe(cleanup)
  }
})

test("effects the step cannot report are unknown even when cleanup completed", () => {
  const record = ForkCyberValidation.outcome({ ...step, result: "reproduced", cleanup: "completed", effects: "unknown" })
  expect(record).toMatchObject({ effects: "unknown", oracle: { result: "inconclusive" } })
})

test("the most serious cleanup status across steps decides the record", () => {
  expect(ForkCyberValidation.worstCleanup(["completed", "completed"])).toBe("completed")
  expect(ForkCyberValidation.worstCleanup(["completed", "unknown"])).toBe("unknown")
  expect(ForkCyberValidation.worstCleanup(["unknown", "failed", "completed"])).toBe("failed")
})
