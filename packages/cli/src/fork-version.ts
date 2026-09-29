import { OPENCODE_VERSION } from "./version"

// Service discovery, release tags and the updater's parseReleaseVersion all require the plain
// SemVer build version, so the human-facing surfaces (TUI footer and splash, `--version`, the
// update notices) show the upstream version with ` (Cyber)` appended instead, dropping the
// `-cyber.N` prerelease: `2.0.18-cyber.1` reads as `2.0.18 (Cyber)` (FORK.md ledger F-005).
export function displayVersion(version: string) {
  return `${version.split("-")[0]} (Cyber)`
}

export const OPENCODE_DISPLAY_VERSION = displayVersion(OPENCODE_VERSION)
