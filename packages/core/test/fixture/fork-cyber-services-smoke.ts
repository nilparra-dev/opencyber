import { Effect } from "effect"
import { ForkCyberServices } from "@opencode/core/fork-cyber/services"
import { ForkCyberServicesLab } from "./fork-cyber-services/lab"

const image = process.env.OPENCYBER_TEST_KALI_IMAGE
if (!image) throw new Error("OPENCYBER_TEST_KALI_IMAGE must identify the built Kali image")
await Effect.runPromise(
  Effect.scoped(
    Effect.gen(function* () {
      const env = yield* ForkCyberServicesLab.open(image)
      const result = yield* ForkCyberServices.run(env.store, env.profile, env.config, ForkCyberServicesLab.assessment, {
        action: "scan",
        host: "target",
        ports: [8000, 8001],
      })
      if (!("capture" in result) || result.capture?.ports.map((port) => port.state).join(",") !== "open,closed")
        throw new Error("Compiled inventory did not distinguish the open and closed controls")
      const raw = yield* env.store.readArtifact(ForkCyberServicesLab.assessment.owner, result.capture.xml_artifact)
      if (!raw.bytes.toString().includes('exit="success"')) throw new Error("Compiled XML evidence is incomplete")
      yield* env.store.coordination.run(ForkCyberServicesLab.assessment, {
        action: "complete",
        key: "management-exposure",
        revision: 2,
        outcome: "supported",
        rationale: "Compiled inventory observed the listening service and rejected the closed control",
        evidence: [result.evidence],
      })
      console.log("compiled TCP service inventory passed")
    }),
  ),
)
