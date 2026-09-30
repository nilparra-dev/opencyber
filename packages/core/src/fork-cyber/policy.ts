export * as ForkCyberPolicy from "./policy.js"

import { Context, Layer, Schema } from "effect"
import { makeLocationNode } from "@opencode/util/effect/app-node"
import { ForkCyberRoles } from "./roles.js"

export const Mode = Schema.Literals(["development", "review", "assessment"])
export type Mode = typeof Mode.Type

export function selected() {
  return Schema.decodeUnknownSync(Mode)(process.env.OPENCYBER_MODE ?? "development")
}

export class Service extends Context.Service<Service, Mode>()("@opencyber/Policy") {}

export const configured = (mode: Mode) => Layer.succeed(Service, mode)

export const node = makeLocationNode({
  service: Service,
  layer: Layer.sync(Service, selected),
  deps: [],
})

export function allowed(mode: Mode, agent: string, tool: string) {
  if (!ForkCyberRoles.allowed(agent, tool)) return false
  if (mode === "development") return true
  if (mode === "review") return ForkCyberRoles.tools("cyber-code-review")!.includes(tool)
  return tool === "subagent" || ForkCyberRoles.tools("cyber-validate")!.includes(tool)
}
