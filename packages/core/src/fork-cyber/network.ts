export * as ForkCyberNetwork from "./network.js"

import { isIP } from "node:net"
import { Schema } from "effect"
import { ForkCyberScope } from "./scope.js"

export const Addresses = Schema.Record(
  ForkCyberScope.Host,
  Schema.Array(
    Schema.String.check(Schema.makeFilter<string>((value) => isIP(value) !== 0 || "Expected an IP address")),
  ),
)
export type Addresses = typeof Addresses.Type

// Resolve only the declared names, before untrusted processes exist in this namespace.
export const RESOLVE = `import json,socket,sys
result={}
for host in json.load(sys.stdin):
    result[host]=sorted(set(row[4][0] for row in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)))
json.dump(result,sys.stdout)
`

export function policy(manifest: ForkCyberScope.Manifest, addresses: Addresses) {
  const budget = manifest.rules_of_engagement.network
  if (!budget) throw new Error("Scoped Kali networking requires explicit network budgets in the engagement")
  const resolve = (values: readonly string[]) =>
    values.flatMap((value) => {
      const host = ForkCyberScope.normalize(value)
      if (host.includes("/") || isIP(host)) return [host]
      if (!addresses[host]?.length) throw new Error(`No addresses resolved for ${host}`)
      return addresses[host]
    })
  const allow = resolve([...manifest.scope.domains, ...manifest.scope.cidrs])
  const deny = resolve(manifest.scope.excluded)
  const match = (values: string[], action: string) =>
    [...new Set(values)]
      .map((value) => `${isIP(value.split("/")[0]!) === 4 ? "ip" : "ip6"} daddr ${value} ${action}`)
      .join("\n")
  // After conntrack (-200), before Docker's output DNAT (-100), including embedded DNS.
  return `table inet opencyber {
    quota traffic { over ${budget.bytes_per_job} bytes; }
    chain permitted {
      ct state new limit rate over ${budget.connections_per_second}/second burst 1 packets counter drop
      limit rate over ${budget.packets_per_second}/second burst 1 packets counter drop
      quota name traffic counter drop
      meta l4proto { tcp, udp } counter accept
    }
    chain output {
      type filter hook output priority -150; policy drop;
      ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } limit rate 10/second accept
      ${match(deny, "counter drop")}
      ip daddr 127.0.0.0/8 counter drop
      ip6 daddr ::1 counter drop
      ${match(allow, "jump permitted")}
    }
    chain input {
      type filter hook input priority 0; policy drop;
      ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } limit rate 10/second accept
      quota name traffic counter drop
      ct state established,related counter accept
    }
    chain forward { type filter hook forward priority 0; policy drop; }
  }`
}
