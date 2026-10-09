export * as ForkCyberCredentialOutput from "./credential-output.js"

// Bytes that leave a Kali job must not carry a leased value. Each value is replaced in its raw form and in
// standard base64, the two forms a tool prints it in. A tool that transforms the value some other way is outside
// this check (fork-cyber-credentials.md).
const marker = Buffer.from("[CREDENTIAL]")

// `truncated` says that the capture reached its byte limit. The bytes after the cut were never captured, so a value
// straddling the cut would survive as a prefix. Dropping the last bytes that could start a match closes that gap.
export function scrub(bytes: Buffer, values: readonly Buffer[], truncated: boolean): Buffer {
  const needles = values.flatMap((value) => [value, Buffer.from(value.toString("base64"))])
  if (needles.length === 0) return bytes
  const longest = Math.max(...needles.map((needle) => needle.length))
  const kept = truncated ? bytes.subarray(0, Math.max(0, bytes.length - (longest - 1))) : bytes
  return needles.reduce((current, needle) => replaceAll(current, needle), kept)
}

// Error text is built from strings, so the same replacement applies to its UTF-8 bytes.
export function scrubText(text: string, values: readonly Buffer[]) {
  return scrub(Buffer.from(text, "utf8"), values, false).toString("utf8")
}

function replaceAll(bytes: Buffer, needle: Buffer) {
  const parts: Buffer[] = []
  let start = 0
  let at = bytes.indexOf(needle)
  while (at !== -1) {
    parts.push(bytes.subarray(start, at), marker)
    start = at + needle.length
    at = bytes.indexOf(needle, start)
  }
  return Buffer.concat([...parts, bytes.subarray(start)])
}
