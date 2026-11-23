export * as ForkCyberCredentials from "./credentials.js"

import { Effect, Schema } from "effect"
import { spawnSync } from "node:child_process"
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import { userInfo } from "node:os"
import path from "node:path"

// Identity kinds an engagement can declare. OC-304 adds kinds when live cloud actions need them.
// host_login is an SSH private key for one account on a host (OC-302).
export const Kind = Schema.Literals(["directory_bind", "cloud_key", "database_login", "host_login"])
export type Kind = typeof Kind.Type

export type Binding = { owner: string; label: string; kind: Kind }
export type Sealed = { nonce: string; ciphertext: string }

const algorithm = "aes-256-gcm"
const keyBytes = 32
const nonceBytes = 12
const tagBytes = 16

// The key lives in the state directory, apart from the evidence database. POSIX enforces its mode; Windows has no
// mode bits, so createKey replaces the inherited ACL with one entry for the current user.
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
  if (written._tag === "Success") {
    if (process.platform === "win32") yield* Effect.try(() => restrict(file))
    return key
  }
  // Another process created the key between the read and the write. Use the key it wrote.
  return yield* Effect.tryPromise(() => readFile(file))
})

// `icacls` is part of Windows, so a failure is a real failure: leave the key untouched but refuse to use it.
function restrict(file: string) {
  const who = spawnSync("whoami", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8", windowsHide: true })
  const sid = who.status === 0 ? /"(S-1-[^"]+)"/.exec(who.stdout)?.[1] : undefined
  const grant = sid === undefined ? userInfo().username : `*${sid}`
  const result = spawnSync("icacls", [file, "/inheritance:r", "/grant:r", `${grant}:(F)`], {
    encoding: "utf8",
    windowsHide: true,
  })
  if (result.status !== 0)
    throw new Error(`icacls could not restrict the credential key: ${(result.stderr || result.stdout).trim()}`)
}

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
