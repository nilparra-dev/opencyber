import path from "node:path"

// Called by the launcher before importing application modules that resolve XDG paths.
export function cyberProfile(root: string, inherited: NodeJS.ProcessEnv) {
  if (!path.isAbsolute(root)) throw new Error("The cyber profile directory must be absolute")
  const env = { ...inherited }
  delete env.OPENCODE_CONFIG
  delete env.OPENCODE_CONFIG_CONTENT
  return {
    ...env,
    XDG_DATA_HOME: path.join(root, "data"),
    XDG_CONFIG_HOME: path.join(root, "config"),
    XDG_CACHE_HOME: path.join(root, "cache"),
    XDG_STATE_HOME: path.join(root, "state"),
    TMPDIR: path.join(root, "tmp"),
    TMP: path.join(root, "tmp"),
    TEMP: path.join(root, "tmp"),
    OPENCODE_CONFIG_DIR: path.join(root, "config", "opencode"),
    OPENCODE_DB: path.join(root, "data", "opencode", "opencode.db"),
    OPENCODE_TUI_CHANNEL: "cyber",
    OPENCODE_DISABLE_CHANNEL_DB: "1",
  }
}
