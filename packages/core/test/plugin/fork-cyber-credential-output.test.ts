import { expect, test } from "bun:test"
import { ForkCyberCredentialOutput } from "@opencode/core/fork-cyber/credential-output"

const secret = Buffer.from("seeded-output-secret-5d1a")
const encoded = secret.toString("base64")

test("replaces a leased value in raw and base64 form, however many times it appears", () => {
  const output = Buffer.from(`raw ${secret.toString()} and again ${secret.toString()}\nencoded ${encoded}\n`)
  const scrubbed = ForkCyberCredentialOutput.scrub(output, [secret], false).toString("utf8")
  expect(scrubbed).toBe("raw [CREDENTIAL] and again [CREDENTIAL]\nencoded [CREDENTIAL]\n")
  expect(scrubbed).not.toContain(secret.toString())
  expect(scrubbed).not.toContain(encoded)
})

test("leaves output alone when no value was leased", () => {
  const output = Buffer.from(`plain ${secret.toString()}`)
  expect(ForkCyberCredentialOutput.scrub(output, [], false)).toBe(output)
  expect(ForkCyberCredentialOutput.scrub(output, [], true)).toBe(output)
})

test("keeps binary bytes that are not part of a value", () => {
  const binary = Buffer.concat([Buffer.from([0, 255, 1]), secret, Buffer.from([254, 0])])
  const scrubbed = ForkCyberCredentialOutput.scrub(binary, [secret], false)
  expect(scrubbed).toEqual(
    Buffer.concat([Buffer.from([0, 255, 1]), Buffer.from("[CREDENTIAL]"), Buffer.from([254, 0])]),
  )
})

test("a capture that reached its limit never keeps the start of a value at the cut", () => {
  const prefix = secret.subarray(0, 10)
  const captured = Buffer.concat([Buffer.alloc(200, "a"), Buffer.from("log line\n"), prefix])
  // Not truncated: the capture is the whole output, and a partial value is not a match, so it stays.
  expect(ForkCyberCredentialOutput.scrub(captured, [secret], false).equals(captured)).toBe(true)
  // Truncated: the bytes that could start a match at the cut are dropped.
  const cut = ForkCyberCredentialOutput.scrub(captured, [secret], true)
  expect(cut.includes(prefix)).toBe(false)
  expect(cut.length).toBeLessThan(captured.length)
})

test("a truncated capture still replaces complete values before the cut", () => {
  const captured = Buffer.concat([secret, Buffer.from(" "), Buffer.alloc(100, "x")])
  const scrubbed = ForkCyberCredentialOutput.scrub(captured, [secret], true).toString("utf8")
  expect(scrubbed.startsWith("[CREDENTIAL] ")).toBe(true)
  expect(scrubbed).not.toContain(secret.toString())
})

test("error text is scrubbed by the same rule", () => {
  const text = `docker exited 1: ${secret.toString()} was printed`
  expect(ForkCyberCredentialOutput.scrubText(text, [secret])).toBe("docker exited 1: [CREDENTIAL] was printed")
})
