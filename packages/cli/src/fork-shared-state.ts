import { OPENCODE_CHANNEL } from "./version"

// opencyber keeps its own background server (channel "cyber"), so it never replaces the
// official opencode's, but shares that install's state (FORK.md ledger F-004): the database
// (sessions, logins, API keys), the way upstream's latest and beta channels share opencode.db,
// and the TUI's client-local state (recent models, tabs), the way `dev:live` does.
// Source runs (channel "local") keep their separate state. Explicit values in the environment win.
if (OPENCODE_CHANNEL === "cyber") {
  process.env.OPENCODE_DISABLE_CHANNEL_DB ??= "1"
  process.env.OPENCODE_TUI_CHANNEL ??= "latest"
}
