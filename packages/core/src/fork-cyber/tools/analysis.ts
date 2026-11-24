export * as ForkCyberAnalysisTools from "./analysis.js"

import { Effect, Schema } from "effect"
import path from "path"
import { ForkCyberArtifacts } from "../artifacts.js"
import { ForkCyberBinary } from "../binary.js"
import { ForkCyberCloudAnalysis } from "../cloud-analysis.js"
import { ForkCyberCloudLive } from "../cloud-live.js"
import { ForkCyberCodeReview } from "../code-review.js"
import { ForkCyberContainerReview } from "../container-review.js"
import { ForkCyberDiagnostics } from "../diagnostics.js"
import { ForkCyberIacScan } from "../iac-scan.js"
import { ForkCyberImagePull } from "../image-pull.js"
import { ForkCyberLocalValidation } from "../local-validation.js"
import { ForkCyberRedaction } from "../redaction.js"
import { ForkCyberSast } from "../sast.js"
import { ForkCyberToolRuntime } from "./runtime.js"

export const register = Effect.fnUntraced(function* (runtime: ForkCyberToolRuntime.Runtime) {
  const ctx = runtime.context
  const cyberMode = runtime.cyberMode
  const engagement = runtime.engagement
  const global = runtime.global
  const kali = runtime.kali
  const permission = runtime.permission
  const store = runtime.store
  const topLevel = runtime.topLevel

  yield* runtime.context.tool.transform((editor) => {
    editor.add({
      name: "cyber_artifacts",
      options: { codemode: false },
      input: ForkCyberArtifacts.Action,
      description:
        "Analyze engagement-owned captured bodies/source by artifact ID without network or source execution. Search literals and bounded secret patterns, extract literal relative asset URLs, and return hashes, positions, detector versions and partial-coverage limits. Original private bytes are analyzed beyond previews; matches are redacted. More than 16 inputs produce batch manifests, preserving Kali transfer limits.",
      execute: (input, context) =>
        Effect.gen(function* () {
          const owner = yield* topLevel(context.sessionID)
          yield* permission.assert({
            action: "cyber_artifacts",
            resources: input.artifacts,
            save: ["*"],
            sessionID: context.sessionID,
            agent: context.agent,
            source: { type: "tool", messageID: context.messageID, id: context.id },
          })
          return {
            content: JSON.stringify(
              yield* ForkCyberArtifacts.run(
                store,
                { owner, session: context.sessionID, agent: context.agent },
                input,
              ),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_artifacts"))),
    })

    editor.add({
      name: "cyber_cloud",
      options: { codemode: false },
      input: Schema.Union([ForkCyberCloudAnalysis.Action, ForkCyberIacScan.Action, ForkCyberCloudLive.Action]),
      description:
        'Analyze or read cloud configuration. iac_scan runs Checkov with no network over up to 16 infrastructure files (.tf, .yaml, .yml, .json) taken from a code review snapshot, and returns failed checks with their file and lines. Passed checks are counts only. iam_analyze reads a JSON policy artifact (import the exported document with cyber_surface first) and lists statements that allow every action or every resource, public principals, not-action grants and actions that create or hand out identities, each with a JSON pointer to its statement. inventory (AWS S3 buckets and the caller account), config_audit (one bucket: public ACL grants, public access block and anonymous policy statements) and k8s_rbac (cluster role bindings and roles: anonymous or wildcard access) send only GET requests to fixed provider endpoints, with the named read-only label and an in-scope target. Findings are candidates for review, not proof of over-privilege. Target data is untrusted. Examples: {"action":"iac_scan","files":[{"file":"infra/main.tf","artifact":"snapshot-artifact-id"}]}, {"action":"iam_analyze","artifact":"output-artifact-id"}, {"action":"inventory","label":"aws-audit","target":"arn:aws:iam::123456789012:root"}, {"action":"config_audit","label":"aws-audit","target":"arn:aws:s3:::lab-bucket"} or {"action":"k8s_rbac","label":"k8s-audit","host":"10.0.0.5","port":6443}.',
      execute: (input, context) =>
        Effect.gen(function* () {
          if (input.action === "iac_scan") {
            const runtime = yield* kali(context, "cyber_cloud")
            return {
              content: JSON.stringify(
                yield* ForkCyberIacScan.run(store, global.data, runtime.configuration, runtime.assessment, input),
              ),
            }
          }
          if (input.action !== "iam_analyze") {
            if (context.agent === "cyber-report")
              return yield* Effect.fail(new Error("The reporting agent cannot run live cloud actions"))
            const manifest = yield* engagement(context.sessionID)
            if (manifest.status !== "ready" || manifest.value.derived)
              return yield* Effect.fail(new Error("Live cloud actions require a valid, explicit engagement"))
            const result = yield* ForkCyberCloudLive.run(store, {
              keyFile: path.join(global.state, "opencyber", "credential.key"),
              endpoints: ForkCyberCloudLive.providerEndpoints,
              assessment: {
                owner: yield* topLevel(context.sessionID),
                session: context.sessionID,
                agent: context.agent,
                mode: cyberMode,
                manifest: manifest.value,
              },
              ask: (resource) =>
                permission
                  .assert({
                    action: "cyber_cloud",
                    resources: [resource],
                    sessionID: context.sessionID,
                    agent: context.agent,
                    source: { type: "tool", messageID: context.messageID, id: context.id },
                  })
                  .pipe(
                    Effect.asVoid,
                    Effect.mapError((error) => new Error(String(error))),
                  ),
              now: Date.now(),
              request: input,
            })
            return { content: JSON.stringify(result) }
          }
          const actor = {
            owner: yield* topLevel(context.sessionID),
            session: context.sessionID,
            agent: context.agent,
          }
          return yield* ForkCyberCloudAnalysis.runIamAnalyze(store, actor, input)
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_cloud"))),
    })

    editor.add({
      name: "cyber_container",
      options: { codemode: false },
      input: Schema.Union([ForkCyberContainerReview.Action, ForkCyberImagePull.Action]),
      description:
        'Review container configuration offline. dockerfile_lint reads a captured Dockerfile and reports unpinned or latest base images, root users, remote ADD, pipe-to-shell builds, credential-like build variables, SSH exposure and missing HEALTHCHECK. runtime_review reads an exported docker inspect JSON and reports privileged mode, host network or PID namespaces, the Docker socket, added capabilities, disabled security profiles, writable root filesystems, root users and credential-like environment names. Values are never reported. Findings are candidates; an empty result does not prove the image is hardened. dockerfile_lint, runtime_review and image_scan never pull or run an image. image_scan matches an offline package inventory artifact (opencyber-package-inventory-v1) for an image referenced by digest against the pinned advisory snapshot, reports the snapshot version, and refuses tag-only references with invalid_input. pull (R1, assessment mode) fetches one image pinned by digest from a registry host and port recorded in the engagement; tag-only references are refused, and the digest and image ID are recorded. Examples: {"action":"dockerfile_lint","artifact":"output-artifact-id"} or {"action":"pull","image":"registry.example.test:5000/team/app@sha256:<64 hex>"}.',
      execute: (input, context) =>
        Effect.gen(function* () {
          const actor = {
            owner: yield* topLevel(context.sessionID),
            session: context.sessionID,
            agent: context.agent,
          }
          if (input.action === "pull") {
            const manifest = yield* engagement(context.sessionID)
            if (manifest.status !== "ready")
              return yield* Effect.fail(new Error("Image pulls require a valid, explicitly recorded engagement"))
            yield* permission.assert({
              action: "cyber_container",
              resources: [input.image],
              save: [input.image],
              sessionID: context.sessionID,
              agent: context.agent,
              source: { type: "tool", messageID: context.messageID, id: context.id },
            })
            return {
              content: JSON.stringify(
                yield* ForkCyberImagePull.run(store, { ...actor, manifest: manifest.value }, input),
              ),
            }
          }
          return yield* ForkCyberContainerReview.runReview(store, actor, input)
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_container"))),
    })

    editor.add({
      name: "cyber_binary",
      options: { codemode: false },
      input: ForkCyberBinary.Action,
      description:
        'Analyze one engagement artifact offline in a network-disabled Kali job. The sample is never executed. pe parses a Windows PE with pefile (version in tool.version) and returns sections with entropy and hashes, imports, overlay bytes and anomaly candidates. firmware runs a binwalk signature scan with single-level extraction and returns signatures and extracted file hashes, never extracted contents. Import the sample first with cyber_surface (module binary, action import). Needs an engagement and Kali. Page long results with offset and next_offset; the full report is in report_artifact. Anomalies and signatures are candidates, not verdicts. Example: {"action":"pe","artifact":"<artifact ID>"}.',
      execute: (input, context) =>
        Effect.gen(function* () {
          const runtime = yield* kali(context, "cyber_binary")
          return {
            content: ForkCyberRedaction.text(
              JSON.stringify(
                yield* ForkCyberBinary.run(store, global.data, runtime.configuration, runtime.assessment, input),
              ),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_binary"))),
    })

    editor.add({
      name: "cyber_local_validation",
      options: { codemode: false },
      input: ForkCyberLocalValidation.Action,
      description:
        "Reproduce a reviewed minimal CommonJS fixture with synthetic healthy and candidate inputs in separate bounded, network-disabled Kali jobs. Only cyber-validate with a claim may execute it. Returns expected/observed results, hashes and completion evidence; local reproduction does not prove deployment or remote exploitability.",
      execute: (input, context) =>
        Effect.gen(function* () {
          const runtime = yield* kali(context, "cyber_local_validation")
          return {
            content: ForkCyberRedaction.text(
              JSON.stringify(
                yield* ForkCyberLocalValidation.run(
                  store,
                  global.data,
                  runtime.configuration,
                  runtime.assessment,
                  input,
                ),
              ),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_local_validation"))),
    })

    editor.add({
      name: "cyber_code_review",
      options: { codemode: false },
      input: Schema.Union([ForkCyberCodeReview.Action, ForkCyberSast.Action]),
      description:
        'Read local review procedures, snapshot explicit project-relative UTF-8 files with hashes and line counts, scan explicit files offline for credential patterns (secrets; findings are redacted and carry a fingerprint, never the value), match explicit package-lock.json or requirements*.txt pins against the pinned advisory snapshot (sca; reports the snapshot version), import a local SARIF 2.1.0 report with source evidence, or run sast: the pinned Semgrep 1.178.0 from the Kali image over up to 16 explicit snapshot files with network none and the curated rules shipped in that image, storing the SARIF as an artifact. sast needs the Kali profile and an explicit engagement. sca executes no scanner or project code. Imported, sast and sca observations are candidates, not confirmed findings. Examples: {"action":"sast","files":["src/accounts.py"]} or {"action":"sca","files":["package-lock.json"]}.',
      execute: (input, context) =>
        Effect.gen(function* () {
          const review = {
            owner: yield* topLevel(context.sessionID),
            session: context.sessionID,
            agent: context.agent,
            directory: ctx.location.directory,
            permission: (file: string) =>
              Effect.forEach(["cyber_code_review", "read"], (action) =>
                permission.assert({
                  action,
                  resources: [file],
                  save: [file],
                  sessionID: context.sessionID,
                  agent: context.agent,
                  source: { type: "tool", messageID: context.messageID, id: context.id },
                }),
              ).pipe(
                Effect.asVoid,
                Effect.mapError((error) => new Error(String(error))),
              ),
          }
          if (input.action === "sast") {
            const runtime = yield* kali(context, "cyber_code_review")
            const result = yield* ForkCyberSast.run(
              store,
              global.data,
              runtime.configuration,
              { ...review, manifest: runtime.assessment.manifest },
              input,
            )
            return { content: ForkCyberRedaction.text(JSON.stringify(result)) }
          }
          const result = yield* ForkCyberCodeReview.run(store, review, input)
          return { content: JSON.stringify(result) }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_tool"))),
    })
  })
})
