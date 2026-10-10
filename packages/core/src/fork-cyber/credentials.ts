export * as ForkCyberCredentials from "./credentials.js"

import { Effect, Schema } from "effect"
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import path from "node:path"

// Identity kinds an engagement can declare. OC-304 adds kinds when live cloud actions need them.
export const Kind = Schema.Literals(["directory_bind", "cloud_key", "database_login"])
export type Kind = typeof Kind.Type

export type Binding = { owner: string; label: string; kind: Kind }
export type Sealed = { nonce: string; ciphertext: string }

const algorithm = "aes-256-gcm"
const keyBytes = 32
const nonceBytes = 12
const tagBytes = 16

// The key lives in the state directory, apart from the evidence database. Its mode is enforced on POSIX only;
// on Windows the profile's ACL is the protection.
export const loadKey = Effect.fn("ForkCyberCredentials.loadKey")(function* (file: string) {
  yield* Effect.tryPromise(() => mkdir(path.dirname(file), { recursive: true, mode: 0o700 }))
  const existing = yield* Effect.tryPromise(() => readFile(file)).pipe(Effect.result)
  const key = existing._tag === "Success" ? existing.success : yield* createKey(file)
  if (key.length !== keyBytes) return yield* Effect.fail(new Error("Credential key must be 32 bytes"))
  return key
})

const createKey = Effect.fn("ForkCyberCredentials.createKey")(function* (file: string) {
  const key = randomBytes(keyBytes)
  const written = yield* Effect.tryPromise(() => writeFile(file, key, { flag: "wx", mode: 0o600 })).pipe(Effect.result)
  if (written._tag === "Success") return key
  // Another process created the key between the read and the write. Use the key it wrote.
  return yield* Effect.tryPromise(() => readFile(file))
})

export function seal(key: Buffer, binding: Binding, value: string): Sealed {
  const nonce = randomBytes(nonceBytes)
  const cipher = createCipheriv(algorithm, key, nonce)
  cipher.setAAD(additional(binding))
  const body = Buffer.concat([cipher.update(value, "utf8"), cipher.final(), cipher.getAuthTag()])
  return { nonce: nonce.toString("base64"), ciphertext: body.toString("base64") }
}

// Returns a Buffer so the caller can zero it. Throws when the key, the binding or the ciphertext does not match.
export function open(key: Buffer, binding: Binding, sealed: Sealed): Buffer {
  const body = Buffer.from(sealed.ciphertext, "base64")
  const decipher = createDecipheriv(algorithm, key, Buffer.from(sealed.nonce, "base64"))
  decipher.setAAD(additional(binding))
  decipher.setAuthTag(body.subarray(-tagBytes))
  return Buffer.concat([decipher.update(body.subarray(0, -tagBytes)), decipher.final()])
}

// A row copied into another engagement, or relabelled, no longer authenticates.
function additional(binding: Binding) {
  return Buffer.from(JSON.stringify([binding.owner, binding.label, binding.kind]))
}
