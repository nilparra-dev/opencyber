export * as ForkCyberKaliAllowlist from "./kali-allowlist.js"

import { Option, Schema } from "effect"

// Versioned with fork-kali/Dockerfile. Its org.opencyber.kali.version label must equal this value; a test
// enforces it, so a recipe change cannot leave the allowlist behind.
export const IMAGE_VERSION = 5

// Offline utilities that read or copy data and never contact a target. Excluded on purpose:
// - interpreters and shells run arbitrary code (python3, sh, node, env, xargs);
// - rg --pre and sort --compress-program execute the command they are given, so an allowed name can run anything;
// - nmap, curl, dig, whois and sqlmap reach targets outside the typed tools that record scope and evidence;
// - readelf runs through cyber_surface (binary.elf); aapt has no tool yet; nft needs NET_ADMIN, which the job container lacks.
export const binaries: readonly string[] = [
  "base64",
  "cat",
  "cp",
  "cut",
  "file",
  "grep",
  "head",
  "jq",
  "md5sum",
  "sha256sum",
  "strings",
  "tail",
  "tr",
  "uniq",
  "wc",
]

const Argv = Schema.Struct({ argv: Schema.Array(Schema.String) })

// Bare names only. The image PATH resolves them under /usr/bin and /work is not on it, so a copy written
// into /work cannot shadow an allowed name. Input that does not decode is refused.
export function allows(input: unknown) {
  const binary = Option.getOrUndefined(Schema.decodeUnknownOption(Argv)(input))?.argv[0]
  return binary !== undefined && binaries.includes(binary)
}
