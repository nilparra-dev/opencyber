import type { SessionTransferData, SessionMessageInfo } from "@opencode/client"

// Both clipboard and file export format the server-selected privacy profile.
export function formatTranscript(
  data: SessionTransferData,
  options: { format: "markdown" | "json"; thinking: boolean; tools: boolean },
) {
  if (options.format === "json") return JSON.stringify(data, null, 2)
  const transcript = (session: Pick<SessionTransferData, "info" | "messages" | "export_info">) =>
    [
      `# ${session.info.title ?? "Session"}`,
      `Session ID: ${session.info.id}\n\nParent ID: ${session.info.parentID ?? "none"}\n\nCreated: ${new Date(session.info.time.created).toISOString()}\n\nUpdated: ${new Date(session.info.time.updated).toISOString()}`,
      ...session.messages.map((message) => renderMessage(message, options)).filter(Boolean),
      `## Export metadata\n\n${block(session.export_info ?? { profile: "unknown", partial: "unknown" })}`,
    ].join("\n\n")
  return `${transcript(data)}${data.analysis ? `\n\n${data.analysis.children.map(transcript).join("\n\n")}\n\n## Analysis\n\n${block({ ...data.analysis, children: data.analysis.children.map((child) => ({ info: child.info, export_info: child.export_info, trace: child.trace })) })}` : ""}\n`
}

function renderMessage(message: SessionMessageInfo, options: { thinking: boolean; tools: boolean }) {
  const label = `## ${message.type}\n\nMessage ID: ${message.id}\n\n`
  if (message.type === "user" || message.type === "synthetic" || message.type === "system" || message.type === "skill")
    return label + message.text
  if (message.type === "shell") return label + block({ command: message.command, output: message.output })
  if (message.type === "compaction") return label + block(message)
  if (message.type !== "assistant") return label + block(message)
  const content = message.content.flatMap((item) => {
    if (item.type === "text") return [item.text]
    if (item.type === "reasoning") return options.thinking ? [`Recorded reasoning\n\n${item.text}`] : []
    return options.tools ? [`Tool: ${item.name}\n\n${block(item)}`] : []
  })
  return label + content.join("\n\n") + (message.error ? `\n\n${block({ error: message.error })}` : "")
}

function block(value: unknown) {
  const text = JSON.stringify(value, null, 2)
  const fence = "`".repeat(
    Array.from(text.matchAll(/`+/g)).reduce((length, match) => Math.max(length, match[0].length + 1), 3),
  )
  return `${fence}json\n${text}\n${fence}`
}
