import { describe, expect, test } from "bun:test"
import { Option, Schema } from "effect"
import { ForkCyberHttp } from "@opencode/core/fork-cyber/http"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"

const digest = `registry.example.test/app@sha256:${"a".repeat(64)}`
const rules = { no_dos: true, max_rps: 2, window: "fixture", contact: "operator" }
const manifest = (scope: unknown) => ({
  engagement: "lab",
  authorized_by: "operator",
  authorization_ref: "fixture",
  rules_of_engagement: rules,
  scope,
})
const empty = { domains: [], cidrs: [], excluded: [] }

const valid = [
  ["host", "10.0.0.5"],
  ["host", "app.example.test"],
  ["domain", "app.example.test"],
  ["cidr", "10.0.0.0/24"],
  ["url", "https://app.example.test/api"],
  ["service", { target: "10.0.0.5", protocol: "tcp", ports: [445] }],
  ["cloud_resource", "arn:aws:s3:::example-bucket"],
  ["repo_path", "/work/snapshot"],
  ["container_image", digest],
  ["device", "10.0.0.20"],
  ["directory", "corp.example.test"],
] as const

const invalid = [
  ["host", "https://app.example.test"],
  ["domain", "10.0.0.5"],
  ["cidr", "10.0.0.0/33"],
  ["url", "ftp://app.example.test"],
  ["url", "https://user:secret@app.example.test"],
  ["service", { target: "10.0.0.5", protocol: "tcp", ports: [0] }],
  ["cloud_resource", "arn:aws:iam::123456789012:role/audit"],
  ["repo_path", "/work/\0snapshot"],
  ["container_image", "app:latest"],
  ["device", ""],
  ["directory", ""],
] as const

describe("typed targets", () => {
  test.each(valid)("accepts %s %j", (type, value) => {
    expect(Schema.is(ForkCyberScope.TypedTarget)({ type, value })).toBe(true)
  })

  test.each(invalid)("refuses %s %j", (type, value) => {
    expect(Schema.is(ForkCyberScope.TypedTarget)({ type, value })).toBe(false)
  })

  test.each([
    ["repo_path", "/work/snapshot"],
    ["container_image", digest],
    ["device", "10.0.0.20"],
    ["directory", "corp.example.test"],
  ] as const)("manifest refuses %s until its work item records it", (type, value) => {
    const input = manifest({ ...empty, targets: [{ type, value }] })
    expect(Option.isNone(Schema.decodeUnknownOption(ForkCyberScope.Manifest)(input))).toBe(true)
  })
})

describe("manifest scope", () => {
  test("legacy scope and provenance decode to the same stored text", () => {
    const legacy = {
      ...manifest({
        domains: ["app.example.test"],
        cidrs: ["10.0.0.0/24"],
        excluded: ["admin.example.test"],
        services: [{ target: "10.0.0.5", protocol: "tcp", scheme: "https", ports: [443] }],
      }),
      provenance: { "scope.domains": "operator" },
    }
    const decoded = Schema.decodeUnknownSync(ForkCyberScope.Manifest)(legacy)
    const stored = JSON.stringify(decoded)
    expect(JSON.stringify(decoded.scope)).toBe(
      '{"domains":["app.example.test"],"cidrs":["10.0.0.0/24"],"excluded":["admin.example.test"],"services":[{"target":"10.0.0.5","protocol":"tcp","scheme":"https","ports":[443]}]}',
    )
    expect(decoded.provenance).toEqual({ "scope.domains": "operator" })
    expect(JSON.stringify(Schema.decodeUnknownSync(ForkCyberScope.Manifest)(JSON.parse(stored)))).toBe(stored)
  })

  test("typed targets are recorded into the scope lists", () => {
    const decoded = Schema.decodeUnknownSync(ForkCyberScope.Manifest)(
      manifest({
        ...empty,
        domains: ["lab.example.test"],
        targets: [
          { type: "host", value: "10.0.0.5" },
          { type: "domain", value: "app.example.test" },
          { type: "cidr", value: "10.0.1.0/24" },
          { type: "url", value: "https://app.example.test:8443/api" },
          { type: "service", value: { target: "10.0.0.9", protocol: "udp", ports: [161] } },
          { type: "cloud_resource", value: "arn:aws:s3:::example-bucket" },
        ],
      }),
    )
    expect(decoded.scope.domains).toEqual(["lab.example.test", "10.0.0.5", "app.example.test"])
    expect(decoded.scope.cidrs).toEqual(["10.0.1.0/24"])
    expect(decoded.scope.services).toEqual([
      { target: "app.example.test", protocol: "tcp", scheme: "https", ports: [8443] },
      { target: "10.0.0.9", protocol: "udp", ports: [161] },
    ])
    expect(decoded.scope.resources).toEqual(["arn:aws:s3:::example-bucket"])
    expect("targets" in decoded.scope).toBe(false)
  })

  test("a url target authorizes its own port and nothing else", () => {
    const decoded = Schema.decodeUnknownSync(ForkCyberScope.Manifest)(
      manifest({ ...empty, targets: [{ type: "url", value: "https://app.example.test/api" }] }),
    )
    expect(() => ForkCyberScope.authorize(decoded, "app.example.test", "tcp", 443)).not.toThrow()
    expect(() => ForkCyberScope.authorize(decoded, "app.example.test", "tcp", 80)).toThrow()
  })

  test("a url target scopes HTTP by scheme and port, not by path", () => {
    const decoded = Schema.decodeUnknownSync(ForkCyberScope.Manifest)(
      manifest({ ...empty, targets: [{ type: "url", value: "https://app.example.test/api" }] }),
    )
    expect(() => ForkCyberHttp.authorize(new URL("https://app.example.test/other"), decoded)).not.toThrow()
    expect(() => ForkCyberHttp.authorize(new URL("http://app.example.test/api"), decoded)).toThrow()
    expect(() => ForkCyberHttp.authorize(new URL("https://app.example.test:8443/api"), decoded)).toThrow()
  })

  test("an invalid typed target fails the whole manifest", () => {
    const input = manifest({ ...empty, targets: [{ type: "url", value: "https://user:secret@app.example.test" }] })
    expect(Option.isNone(Schema.decodeUnknownOption(ForkCyberScope.Manifest)(input))).toBe(true)
  })
})
