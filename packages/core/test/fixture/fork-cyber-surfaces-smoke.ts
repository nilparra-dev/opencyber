import { Effect } from "effect"
import { ForkCyberServices } from "@opencode/core/fork-cyber/services"
import { ForkCyberServiceValidation } from "@opencode/core/fork-cyber/service-validation"
import { ForkCyberSurfacesLab } from "./fork-cyber-surfaces/lab"

const image = process.env.OPENCYBER_TEST_SURFACES_IMAGE
if (!image) throw new Error("OPENCYBER_TEST_SURFACES_IMAGE must identify image version 4")
await Effect.runPromise(
  Effect.scoped(
    Effect.gen(function* () {
      const env = yield* ForkCyberSurfacesLab.open(image)
      const root = ForkCyberSurfacesLab.assessment
      const recon = { ...root, session: "recon-child", agent: "cyber-enum" }
      yield* env.store.coordination.run(root, {
        action: "create",
        key: "inventory",
        asset: "target:8444",
        procedure: "TCP inventory",
        phase: "cyber-enum",
        hypothesis: "A TLS listener is reachable",
      })
      yield* env.store.coordination.run(recon, { action: "claim", key: "inventory", revision: 1 })
      const inventory = yield* ForkCyberServices.run(env.store, env.profile, env.config, recon, {
        action: "scan",
        host: "target",
        ports: [8444],
      })
      if (!("capture" in inventory) || !inventory.capture?.ports.some((port) => port.state === "open"))
        throw new Error("Inventory failed")
      yield* env.store.finding(root.owner, {
        id: "legacy-tls",
        revision: 0,
        title: "Legacy TLS on the laboratory listener",
        status: "candidate",
        rationale: "Reachable listener requires protocol validation",
        evidence: [inventory.evidence],
      })
      yield* env.store.coordination.run(recon, {
        action: "complete",
        key: "inventory",
        revision: 2,
        outcome: "supported",
        rationale: "TCP listener reachable",
        evidence: [inventory.evidence],
      })
      const validation = { ...root, session: "validation-child", agent: "cyber-validate" }
      yield* env.store.coordination.run(root, {
        action: "create",
        key: "tls-validation",
        asset: "target:8444",
        procedure: "Legacy TLS with healthy control",
        phase: "cyber-validate",
        hypothesis: "TLSv1 is accepted on 8444 and rejected on the healthy 8443 listener",
      })
      yield* env.store.coordination.run(validation, { action: "claim", key: "tls-validation", revision: 1 })
      const positive = yield* ForkCyberServiceValidation.run(env.store, env.profile, env.config, validation, {
        module: "tls",
        action: "probe",
        host: "target",
        port: 8444,
      })
      const control = yield* ForkCyberServiceValidation.run(env.store, env.profile, env.config, validation, {
        module: "tls",
        action: "probe",
        host: "target",
        port: 8443,
      })
      if (
        positive.capture.report.protocol !== "tls" ||
        control.capture.report.protocol !== "tls" ||
        !positive.capture.report.versions.some((row) => row.version === "TLSv1" && row.accepted) ||
        control.capture.report.versions.some((row) => row.version === "TLSv1" && row.accepted)
      )
        throw new Error("TLS controls failed")
      yield* env.store.coordination.run(validation, {
        action: "complete",
        key: "tls-validation",
        revision: 2,
        outcome: "supported",
        rationale: "Legacy TLS reproduced with healthy control",
        evidence: [positive.evidence, control.evidence],
      })
      yield* env.store.finding(root.owner, {
        id: "legacy-tls",
        revision: 1,
        title: "Legacy TLS on the laboratory listener",
        status: "confirmed",
        rationale: "TLSv1 handshake succeeds; healthy control requires modern TLS. Trust and impact remain untested",
        evidence: [positive.evidence, control.evidence],
        validation: {
          task: "tls-validation",
          asset: "target:8444",
          method: "dynamic",
          identity: "unauthenticated laboratory client",
          expected: "Reject TLSv1",
          observed: "TLSv1 handshake succeeded",
          controls: "target:8443 rejects TLSv1",
          reproduction: "Probe both listeners with the same client and compare negotiated protocols",
          remediation: "Disable legacy TLS versions",
        },
      })
      const report = {
        findings: yield* env.store.findings(root.owner),
        coverage: yield* env.store.coordination.coverage(root.owner),
        pending: [
          "TLS certificate trust and cipher coverage",
          "real cloud account",
          "Android emulator",
          "wireless adapter",
          "physical OT equipment",
        ],
      }
      if (report.coverage.some((task) => task.status !== "completed") || report.findings.length !== 1)
        throw new Error("Report is incomplete")
      if (process.env.OPENCYBER_SURFACE_REPORT) {
        const archive = yield* env.store.exportArchive(root.owner)
        yield* Effect.promise(() =>
          Bun.write(process.env.OPENCYBER_SURFACE_REPORT!, JSON.stringify({ report, archive }, null, 2)),
        )
      }
      console.log(JSON.stringify(report))
      console.log("compiled reconnaissance, candidate, validation and report passed")
    }),
  ),
)
