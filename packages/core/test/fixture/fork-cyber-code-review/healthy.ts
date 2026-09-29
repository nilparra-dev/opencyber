export * as ForkCyberHealthy from "./healthy.js"

import { Database } from "bun:sqlite"

export function lookup(db: Database, name: string) {
  return db.query("SELECT id, name FROM account WHERE name = ?").all(name)
}
