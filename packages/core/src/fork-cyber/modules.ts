export * as ForkCyberModules from "./modules.js"

import { Schema } from "effect"
import { ForkCyberArtifactValidation } from "./artifact-validation.js"
import { ForkCyberIdentityCloud } from "./identity-cloud.js"
import { ForkCyberOt } from "./ot.js"
import { ForkCyberServiceValidation } from "./service-validation.js"
import { ForkCyberSurface } from "./surface.js"

export const Action = Schema.Union([
  Schema.Struct({ action: Schema.Literal("procedures"), module: ForkCyberSurface.Module }),
  Schema.Struct({
    ...ForkCyberSurface.Import.fields,
    module: Schema.Literals(["cloud", "mobile", "binary", "wireless"]),
  }),
  ForkCyberServiceValidation.Action,
  ForkCyberIdentityCloud.Action,
  ForkCyberArtifactValidation.Action,
  ForkCyberOt.Action,
])
export const procedures = {
  tls: ForkCyberServiceValidation.procedures,
  ssh: ForkCyberServiceValidation.procedures,
  ...ForkCyberIdentityCloud.procedures,
  ...ForkCyberArtifactValidation.procedures,
  ot: ForkCyberOt.procedures,
}
