import { expect, test } from "bun:test"
import type { SessionTransferData } from "@opencode/client"
import { formatTranscript } from "../src/fork-cyber-export"

const info = {
  id: "root",
  projectID: "fixture",
  cost: 0,
  tokens: { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } },
  time: { created: 0, updated: 100 },
  location: { directory: "/fixture" },
  title: "Controlled export",
} satisfies SessionTransferData["info"]
const metadata = {
  profile: "analysis",
  reasoning: false,
  partial: true,
  omitted_unsettled: 1,
  timezone: "UTC",
  exported_at: 100,
  first_activity: 0,
  last_activity: 100,
  limitations: ["Active work is omitted"],
} satisfies NonNullable<SessionTransferData["export_info"]>
const data = {
  info,
  messages: [
    { type: "system", id: "system", text: "Effective fixture instructions", time: { created: 0 } },
    {
      type: "compaction",
      id: "compaction",
      status: "failed",
      reason: "manual",
      error: { type: "fixture", message: "password=[REDACTED]" },
      time: { created: 1 },
    },
  ],
  export_info: metadata,
  analysis: {
    harness: { version: "fixture" },
    root: { attempts: [], events: [], instructions: { sources: ["fixture"] } },
    children: [
      {
        info: { ...info, id: "child", parentID: "root" },
        messages: [{ type: "user", id: "child-input", text: "Child observation", time: { created: 2 } }],
        export_info: metadata,
        trace: { attempts: [], events: [], instructions: null },
      },
    ],
    evidence: { artifact_bytes: "private" },
    usage: null,
  },
} satisfies SessionTransferData

test("Markdown and JSON retain child identities, partial metadata, errors and available instructions", () => {
  const markdown = formatTranscript(data, { format: "markdown", thinking: false, tools: true })
  const json = formatTranscript(data, { format: "json", thinking: false, tools: true })
  for (const value of [markdown, json]) {
    expect(value).toContain("Effective fixture instructions")
    expect(value).toContain("Child observation")
    expect(value).toContain("password=[REDACTED]")
    expect(value).toContain('"partial": true')
  }
  expect(markdown).toContain("Parent ID: root")
  expect(markdown).toContain("1970-01-01T00:00:00.000Z")
  expect(JSON.parse(json)).toEqual(data)
})

test("Markdown preserves recorded reasoning selection and uses safe fences for captured target content", () => {
  const assistant = {
    ...data,
    analysis: undefined,
    messages: [
      {
        type: "assistant",
        id: "assistant",
        agent: "fixture",
        model: { id: "fixture", providerID: "fixture" },
        content: [
          { type: "reasoning", text: "Recorded fixture thought" },
          {
            type: "tool",
            id: "call",
            name: "fixture",
            state: { status: "error", input: {}, error: { type: "fixture", message: "``` captured target fence" } },
            time: { created: 0 },
          },
        ],
        time: { created: 0, completed: 1 },
      },
    ],
  } satisfies SessionTransferData
  expect(formatTranscript(assistant, { format: "markdown", thinking: false, tools: true })).not.toContain(
    "Recorded fixture thought",
  )
  expect(formatTranscript(assistant, { format: "markdown", thinking: true, tools: true })).toContain(
    "Recorded fixture thought",
  )
  expect(formatTranscript(assistant, { format: "markdown", thinking: false, tools: true })).toContain("````json")
  expect(formatTranscript(assistant, { format: "markdown", thinking: false, tools: false })).not.toContain(
    "captured target fence",
  )
})
