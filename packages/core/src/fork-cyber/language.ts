export * as ForkCyberLanguage from "./language.js"

export const prose =
  "Write generated narrative text in English. Preserve identifiers and verbatim evidence in their original form."

export const delegation =
  "Write every subagent prompt, task description and follow-up instruction in English, regardless of the operator's conversation language. Require subagent replies and handoffs in English. Preserve literal identifiers and evidence."

export const metadata =
  "Write generated session titles and summaries in English, regardless of the source conversation language. This working-language requirement overrides instructions to match the user's language. Preserve names, identifiers and verbatim quotations; keep the requested output structure."

export const policy = [
  "# Assessment working language",
  delegation,
  "Write all generated prose stored in the assessment database in English: session titles and summaries, engagement summaries, notes, task procedures, hypotheses, reasons, rationales, handoffs, finding titles, validation descriptions, impact, reproduction steps and remediation.",
  "Write every assessment report in English, including headings, summaries, findings, coverage, limitations and pending work. The operator's conversation language does not change this requirement.",
  "Translate the meaning of non-English operator requests when preparing operational text. Preserve names, IDs, URLs, paths, commands, payloads and source literals. Keep captured responses, artifacts and quoted evidence unchanged, with English explanations around quotations. Do not translate or rewrite historical records or original evidence.",
  "Conversation with the operator may follow their requested language; generated operational records, subagent communication and reports must remain in English.",
].join("\n")
