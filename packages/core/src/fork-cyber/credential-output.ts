export * as ForkCyberCredentialOutput from "./credential-output.js"

// Bytes that leave a Kali job must not carry a leased value. A tool prints a value raw, or in base64: on one line, or
// wrapped at 64 columns (openssl) or 76 columns (coreutils `base64`), with LF or CRLF line ends. A tool that transforms
// the value some other way is outside this check (fork-cyber-credentials.md).
const marker = Buffer.from("[CREDENTIAL]")

function forms(value: Buffer) {
  const encoded = value.toString("base64")
  const wrapped = [64, 76].flatMap((width) => {
    const lines = encoded.match(new RegExp(`.{1,${width}}`, "g")) ?? []
    return ["\n", "\r\n"].map((eol) => lines.join(eol))
  })
  return [value, ...[encoded, ...wrapped].map((text) => Buffer.from(text))]
}

// `truncated` says that the capture reached its byte limit. The bytes after the cut were never captured, so a value
// straddling the cut would survive as a prefix. Dropping the last bytes that could start a match closes that gap.
// Longest forms go first, so a short form never replaces part of a longer one. An empty form would match everywhere.
export function scrub(bytes: Buffer, values: readonly Buffer[], truncated: boolean): Buffer {
  const needles = values
    .flatMap(forms)
    .filter((needle) => needle.length > 0)
    .sort((left, right) => right.length - left.length)
  if (needles.length === 0) return bytes
  const longest = needles[0]!.length
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
