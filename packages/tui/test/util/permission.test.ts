import { expect, test } from "bun:test"
// fork: delegation prompts retain their proposed task without message lookup (F-027).
import { permissionPresentation } from "../../src/util/permission"

test("shows the proposed delegation task from self-contained permission metadata", () => {
  expect(
    permissionPresentation({
      action: "subagent",
      resources: ["cyber-validate"],
      metadata: {
        agent: "cyber-validate",
        description: "Validate the finding",
        prompt: "Review only the assigned fixture",
      },
    }),
  ).toMatchObject({
    title: "Cyber-Validate Subagent",
    lines: ["◉ Validate the finding", "Review only the assigned fixture"],
  })
})

test("preserves permission roots and self-contained metadata", () => {
  expect(permissionPresentation({ action: "external_directory", resources: ["/*"] }).title).toBe(
    "Access external directory /",
  )
  expect(permissionPresentation({ action: "external_directory", resources: ["C:/*"] }).title).toBe(
    "Access external directory C:/",
  )
  expect(
    permissionPresentation({ action: "webfetch", resources: [], metadata: { url: "https://example.com" } }),
  ).toMatchObject({
    title: "WebFetch https://example.com",
    lines: ["URL: https://example.com"],
  })
  expect(permissionPresentation({ action: "websearch", resources: [], metadata: { query: "releases" } })).toMatchObject(
    {
      title: 'Web Search "releases"',
      lines: ["Query: releases"],
    },
  )
})
