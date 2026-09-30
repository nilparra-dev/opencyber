import { parseArgs } from "node:util"
import { Schema } from "effect"
import { ForkCyberScope } from "../src/fork-cyber/scope.js"

// Generate a proposal for review; existing fork-cyber-authorize records approval separately.
const args = parseArgs({
  options: {
    url: { type: "string" },
    engagement: { type: "string" },
    operator: { type: "string" },
    reference: { type: "string" },
    contact: { type: "string" },
    window: { type: "string" },
    "max-rps": { type: "string" },
    output: { type: "string" },
  },
})
if (!args.values.url || !args.values.engagement || !args.values.operator || !args.values.reference)
  throw new Error(
    "Supply --url, --engagement, --operator and --reference. Approve the generated proposal with fork-cyber-authorize.",
  )
const manifest = Schema.decodeUnknownSync(ForkCyberScope.Manifest)({
  engagement: args.values.engagement,
  authorized_by: args.values.operator,
  authorization_ref: args.values.reference,
  scope: ForkCyberScope.webService(args.values.url),
  rules_of_engagement: {
    no_dos: true,
    max_rps: Number(args.values["max-rps"] ?? 1),
    contact: args.values.contact ?? "unspecified",
    window: args.values.window ?? "unspecified",
  },
  provenance: {
    engagement: "operator",
    authorized_by: "operator",
    authorization_ref: "operator",
    scope: "operator",
    "rules_of_engagement.no_dos": "system_default",
    "rules_of_engagement.max_rps": args.values["max-rps"] ? "operator" : "system_default",
    "rules_of_engagement.contact": args.values.contact ? "operator" : "system_default",
    "rules_of_engagement.window": args.values.window ? "operator" : "system_default",
  },
})
const content = JSON.stringify(manifest, null, 2)
if (args.values.output) await Bun.write(args.values.output, content)
if (!args.values.output) console.log(content)
