import { expect, test } from "bun:test"
import { Effect, Schema } from "effect"
import { mkdtemp, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { ForkCyberServiceValidation } from "@opencode/core/fork-cyber/service-validation"

const python = Bun.which("python") ?? Bun.which("python3")
const openssl =
  Bun.which("openssl") ??
  ((await Bun.file("C:/Program Files/Git/usr/bin/openssl.exe").exists())
    ? "C:/Program Files/Git/usr/bin/openssl.exe"
    : undefined)
const probeTest = python && openssl ? test : test.skip

probeTest(
  "real TLS probe separates trusted wrong-name, untrusted and expired certificates from identity and protocol observations",
  async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "opencyber-tls-"))
    const certificate = path.resolve(import.meta.dir, "../fixture/fork-cyber-tls-cert.pem")
    const key = path.resolve(import.meta.dir, "../fixture/fork-cyber-tls-key.pem")
    const command = async (args: string[]) => {
      const child = Bun.spawn([openssl!, ...args], { cwd: directory, stdout: "pipe", stderr: "pipe" })
      const [code, error] = await Promise.all([
        child.exited,
        new Response(child.stderr).text(),
        new Response(child.stdout).text(),
      ])
      if (code !== 0) throw new Error(error)
    }
    try {
      const wrong = path.join(directory, "wrong.pem")
      const expired = path.join(directory, "expired.pem")
      await command([
        "req",
        "-new",
        "-x509",
        "-key",
        key,
        "-out",
        wrong,
        "-subj",
        "/CN=wrong.example.test",
        "-days",
        "1",
      ])
      await command(["x509", "-in", certificate, "-signkey", key, "-days", "-1", "-out", expired])
      for (const fixture of [
        { certificate, trust: certificate, chain: "verified", hostname: "verified", valid: true },
        { certificate, trust: wrong, chain: "rejected", hostname: "verified", valid: true },
        { certificate: wrong, trust: wrong, chain: "verified", hostname: "rejected", valid: true },
        { certificate: expired, trust: expired, chain: "rejected", hostname: "verified", valid: false },
      ] as const) {
        const server = Bun.serve({
          hostname: "127.0.0.1",
          port: 0,
          tls: { cert: Bun.file(fixture.certificate), key: Bun.file(key) },
          fetch: () => new Response("TLS fixture"),
        })
        try {
          // Execute only the harness-owned probe against loopback. No target source executes on the host.
          const child = Bun.spawn(
            [
              python!,
              "-I",
              "-c",
              ForkCyberServiceValidation.PROBE,
              JSON.stringify({ module: "tls", host: "127.0.0.1", port: server.port }),
            ],
            {
              cwd: directory,
              env: {
                ...process.env,
                PATH: `${path.dirname(openssl!)}${path.delimiter}${process.env.PATH ?? ""}`,
                SSL_CERT_FILE: fixture.trust,
                SSL_CERT_DIR: directory,
              },
              stdout: "pipe",
              stderr: "pipe",
            },
          )
          const timer = setTimeout(() => child.kill(), 30000)
          const [code, error] = await Promise.all([
            child.exited,
            new Response(child.stderr).text(),
            new Response(child.stdout).text(),
          ]).finally(() => clearTimeout(timer))
          if (code !== 0) throw new Error(error)
          const report = await Effect.runPromise(
            Schema.decodeUnknownEffect(Schema.fromJsonString(ForkCyberServiceValidation.Report))(
              await Bun.file(path.join(directory, "report.json")).text(),
            ),
          )
          expect(report).toMatchObject({
            chain: { status: fixture.chain },
            hostname: { status: fixture.hostname, expected: "127.0.0.1" },
            sni: null,
            certificate_time_valid: fixture.valid,
            cipher_coverage: "negotiated_samples_only",
          })
          if (report.protocol !== "tls") throw new Error("Expected TLS report")
          expect(report.trust_verified).toBe(fixture.chain === "verified")
          expect(report.processes?.every((process) => typeof process.exit_code === "number")).toBe(true)
          expect(
            report.versions.every((version) =>
              version.accepted ? version.state === "negotiated" : version.state !== "negotiated",
            ),
          ).toBe(true)
        } finally {
          await server.stop(true)
        }
      }
    } finally {
      await rm(directory, { recursive: true, force: true })
    }
  },
  60000,
)
