export * as ForkCyberRefusal from "./refusal.js"

// A refusal is only classified inside a short opening span of assistant text.
// Findings, reports and transcripts quote refusal-like strings mid-document, and
// a model that is working keeps talking past its first paragraph, so anything
// long or late is left alone. The caller additionally requires that the step
// produced no tool call and that the session is idle before correcting.
const patterns = [
  /i can'?t help with (that|this)/i,
  /i'?m (not able|unable) to/i,
  /i cannot (assist|help|provide|do)/i,
  /i (need|have|want) to decline/i,
  /i won'?t (provide|help|assist)/i,
  /i'?m (not comfortable|uncomfortable)/i,
  /as an ai\b/i,
  /as a language model/i,
  /i should note that/i,
  /used responsibly/i,
  /do you have (authorization|permission)/i,
  /(ensure|confirm) (you have|that you have|that this is) (authorization|permission|authorized)/i,
  /in a real(-| )world/i,
  /hypothetically/i,
  /for educational purposes only/i,
  /en lugar de eso puedo ofrecerte/i,
  /alternativa más segura/i,
]

export function isRefusal(text: string) {
  if (text.length > 1200) return false
  const head = text.slice(0, 400)
  return patterns.some((pattern) => pattern.test(head))
}
