import { OPENCODE_VERSION } from "./version"

// Service discovery, release tags and the updater's parseReleaseVersion all require the plain
// SemVer build version, so the human-facing surfaces (TUI footer and splash, `--version`) show
// this display form instead (FORK.md ledger F-005).
export const OPENCODE_DISPLAY_VERSION = `${OPENCODE_VERSION} (Cyber)`
