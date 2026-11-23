export * as ForkCyberNetworkTools from "./network.js"

import { Effect, Schema } from "effect"
import path from "path"
import { ForkCyberArtifactValidation } from "../artifact-validation.js"
import { ForkCyberDatabase } from "../database.js"
import { ForkCyberDiagnostics } from "../diagnostics.js"
import { ForkCyberDirectory } from "../directory.js"
import { ForkCyberDirectoryAuth } from "../directory-auth.js"
import { ForkCyberDiscovery } from "../discovery.js"
import { ForkCyberHost } from "../host.js"
import { ForkCyberIdentityCloud } from "../identity-cloud.js"
import { ForkCyberKali } from "../kali.js"
import { ForkCyberKaliAllowlist } from "../kali-allowlist.js"
import { ForkCyberModules } from "../modules.js"
import { ForkCyberOt } from "../ot.js"
import { ForkCyberRoles } from "../roles.js"
import { ForkCyberServiceValidation } from "../service-validation.js"
import { ForkCyberServices } from "../services.js"
import { ForkCyberSurface } from "../surface.js"
import { ForkCyberToolRuntime } from "./runtime.js"

export const register = Effect.fnUntraced(function* (runtime: ForkCyberToolRuntime.Runtime) {
  const ctx = runtime.context
  const cyberMode = runtime.cyberMode
  const engagement = runtime.engagement
  const executionID = runtime.executionID
  const global = runtime.global
  const httpAssessment = runtime.httpAssessment
  const kali = runtime.kali
  const permission = runtime.permission
  const store = runtime.store
  const topLevel = runtime.topLevel

  yield* runtime.context.tool.transform((editor) => {
    editor.add({
      name: "cyber_discover",
      options: { codemode: false },
      input: ForkCyberDiscovery.Action,
      description:
        "Discover within the engagement. passive_dns queries one authorized exact hostname for A, AAAA, CAA, CNAME, TXT, MX, NS or SOA through harness-controlled DNS and records resolver, records, TTL and no-records, NXDOMAIN, timeout and unsupported states. certificates lists in-scope names from public certificate transparency only when the engagement declares passive OSINT. host_sweep checks one declared IPv4 range from /24 to /32 with unprivileged Nmap ping probes in scoped Kali; it needs network budgets and, for workers, an active task claim. fingerprint reads one in-scope HTTP(S) URL and reports technology hints from headers, cookie names and HTML. Results are candidates or observations, not findings. Example: {\"action\":\"passive_dns\",\"host\":\"app.example.test\",\"type\":\"CAA\"}.",
      execute: (input, context) =>
        Effect.gen(function* () {
          const assessment = yield* httpAssessment(context, "cyber_discover")
          yield* permission.assert({
            action: "cyber_discover",
            resources: [ForkCyberDiscovery.target(input)],
            save: [ForkCyberDiscovery.target(input)],
            sessionID: context.sessionID,
            agent: context.agent,
            source: { type: "tool", messageID: context.messageID, id: context.id },
          })
          if (ForkCyberRoles.worker(context.agent)) yield* store.coordination.requireClaim(assessment)
          if (input.action === "host_sweep") {
            const runtime = yield* kali(context, "cyber_discover")
            return {
              content: JSON.stringify(
                yield* ForkCyberDiscovery.sweep(store, global.data, runtime.configuration, runtime.assessment, input),
              ),
            }
          }
          return {
            content: JSON.stringify(
              yield* ForkCyberDiscovery.run(store, () => httpAssessment(context, "cyber_discover"), input),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_discover"))),
    })

    editor.add({
      name: "cyber_surface",
      options: { codemode: false },
      input: ForkCyberModules.Action,
      description:
        "Read module procedures; import explicit local artifacts; validate TLS/SSH, identity controls, AWS S3 listing/policies, Android APK manifests, ELF metadata and isolated reproduction, wireless beacon PCAP, or Modbus simulators. Validation workers require a claim. Network probes enforce service scope; artifact jobs require network-disabled Kali. No automatic finding confirmation. Static mobile and wireless capture do not establish device or radio validation. Example: {\"module\":\"tls\",\"action\":\"procedures\"} then {\"module\":\"tls\",\"action\":\"probe\",\"host\":\"app.example.test\",\"port\":8443}.",
      execute: (input, context) =>
        Effect.gen(function* () {
          if (input.action === "procedures")
            return { content: JSON.stringify(ForkCyberModules.procedures[input.module]) }
          if (input.action === "import") {
            return {
              content: JSON.stringify(
                yield* ForkCyberSurface.importFile(
                  store,
                  {
                    owner: yield* topLevel(context.sessionID),
                    session: context.sessionID,
                    agent: context.agent,
                    directory: ctx.location.directory,
                    permission: (file) =>
                      Effect.forEach(["cyber_surface", "read"], (action) =>
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
                  },
                  input.module,
                  input,
                ),
              ),
            }
          }
          if (input.module === "identity" || input.module === "cloud")
            return {
              content: JSON.stringify(
                yield* ForkCyberIdentityCloud.run(store, () => httpAssessment(context, "cyber_surface"), input),
              ),
            }
          const runtime = yield* kali(context, "cyber_surface")
          if (input.action === "probe")
            return {
              content: JSON.stringify(
                yield* ForkCyberServiceValidation.run(
                  store,
                  global.data,
                  runtime.configuration,
                  runtime.assessment,
                  input,
                ),
              ),
            }
          if (input.module === "ot")
            return {
              content: JSON.stringify(
                yield* ForkCyberOt.run(store, global.data, runtime.configuration, runtime.assessment, input),
              ),
            }
          return {
            content: JSON.stringify(
              yield* ForkCyberArtifactValidation.run(
                store,
                global.data,
                runtime.configuration,
                runtime.assessment,
                input,
              ),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_tool"))),
    })

    editor.add({
      name: "cyber_directory",
      options: { codemode: false },
      input: Schema.Union([ForkCyberDirectory.Action, ForkCyberDirectoryAuth.Action]),
      description: `Assess a directory service: ldap_enum reads the rootDSE, then what an anonymous session and an optional brokered credential can see; password_policy reads pwdPolicy objects and lists review candidates; collect returns a bounded, allowlisted read of one subtree. kerberos_config and adcs_templates review an exported JSON artifact offline (R0). Live actions need a scoped engagement with network budgets and, for workers, an active claim. A credential is a registered label only; its value is never returned. Only bind, search, unbind and StartTLS are sent. Example: {"action":"ldap_enum","host":"dc.lab.example.test","port":389}. auth_test (R2, assessment only) makes one LDAP simple bind as the account declared for a credential label, against a host in scope; the password is leased from the operator's registry and is never returned. Three attempts per label and host are allowed in thirty minutes. crack (R2) tests supplied hashes offline against a supplied wordlist and returns per-hash cracked status only; plaintext is withheld. Each R2 action must be declared in rules_of_engagement.validation and approved by the operator for its target. Example: {"action":"auth_test","label":"lab-alice","host":"ldap.lab.test"}.`,
      execute: (input, context) =>
        Effect.gen(function* () {
          if (input.action === "procedures") return { content: JSON.stringify(ForkCyberDirectory.procedures) }
          if (input.action === "kerberos_config" || input.action === "adcs_templates")
            return {
              content: JSON.stringify(
                yield* ForkCyberDirectory.offline({
                  store,
                  assessment: yield* httpAssessment(context, "cyber_directory"),
                  request: input,
                }),
              ),
            }
          const runtime = yield* kali(context, "cyber_directory")
          if (input.action === "auth_test")
            return {
              content: JSON.stringify(
                yield* ForkCyberDirectoryAuth.authTest({
                  store,
                  profile: global.data,
                  keyFile: path.join(global.state, "opencyber", "credential.key"),
                  config: runtime.configuration,
                  assessment: { ...runtime.assessment, mode: cyberMode },
                  request: input,
                  now: Date.now(),
                }),
              ),
            }
          if (input.action === "crack")
            return {
              content: JSON.stringify(
                yield* ForkCyberDirectoryAuth.crack({
                  store,
                  profile: global.data,
                  config: runtime.configuration,
                  assessment: { ...runtime.assessment, mode: cyberMode },
                  request: input,
                }),
              ),
            }
          return {
            content: JSON.stringify(
              yield* ForkCyberDirectory.live({
                store,
                profile: global.data,
                keyFile: path.join(global.state, "opencyber", "credential.key"),
                mode: cyberMode,
                config: runtime.configuration,
                assessment: runtime.assessment,
                request: input,
                now: Date.now(),
              }),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_directory"))),
    })

    editor.add({
      name: "cyber_services",
      options: { codemode: false },
      input: ForkCyberServices.Action,
      description:
        "Read TCP inventory procedures, scan or version-detect one explicit host and up to 32 TCP ports with unprivileged Nmap connect scans in scoped Kali (version adds light detection without scripts), probe one port with one unauthenticated check (redis_info, elasticsearch_root, ldap_root_dse, smb_signing, nfs_exports or mongodb_build_info), or report udp_top as not_configured because this workload has no raw sockets. Defaults to IPv4; select IPv6 explicitly. Requires an engagement with network budgets and an active worker claim. Returns port states, service names, original XML and output evidence. No scripts, credentials or arbitrary scanner arguments. Open ports are not confirmed vulnerabilities. Example: {\"action\":\"procedures\"} then {\"action\":\"version\",\"host\":\"app.example.test\",\"ports\":[80,443]}.",
      execute: (input, context) =>
        Effect.gen(function* () {
          if (input.action === "procedures") return { content: JSON.stringify(ForkCyberServices.procedures) }
          const runtime = yield* kali(context, "cyber_services")
          if (input.action === "probe")
            return {
              content: JSON.stringify(
                yield* ForkCyberServices.probe(store, global.data, runtime.configuration, runtime.assessment, input),
              ),
            }
          return {
            content: JSON.stringify(
              yield* ForkCyberServices.run(store, global.data, runtime.configuration, runtime.assessment, input),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_tool"))),
    })

    editor.add({
      name: "cyber_host",
      options: { codemode: false },
      input: ForkCyberHost.Action,
      description:
        "Read Linux host audit procedures, or audit one in-scope host or report privilege-escalation conditions over SSH with a declared host_login credential. audit checks SSH daemon settings, login aging and account file modes. privesc_config reports SUID binaries outside the baseline, sudo NOPASSWD rules, file capabilities and group/world-writable cron files. Each remote command is a fixed read-only string; no exploitation or writes. Requires an approved engagement with the host and port in scope, and a credential declared for that action. Findings are observations and candidates. Example: {\"action\":\"audit\",\"host\":\"127.0.0.1\",\"port\":2201,\"label\":\"lab-audit\"}.",
      execute: (input, context) =>
        Effect.gen(function* () {
          if (input.action === "procedures") return { content: JSON.stringify(ForkCyberHost.procedures) }
          const manifest = yield* engagement(context.sessionID)
          if (manifest.status !== "ready" || manifest.value.derived)
            return yield* Effect.fail(new Error("Host audits require a valid, explicit engagement"))
          const owner = yield* topLevel(context.sessionID)
          yield* permission.assert({
            action: "cyber_host",
            resources: [owner],
            save: [owner],
            sessionID: context.sessionID,
            agent: context.agent,
            source: { type: "tool", messageID: context.messageID, id: context.id },
          })
          return {
            content: JSON.stringify(
              yield* ForkCyberHost.run(
                store,
                {
                  owner,
                  session: context.sessionID,
                  agent: context.agent,
                  mode: cyberMode,
                  manifest: manifest.value,
                  keyFile: path.join(global.state, "opencyber", "credential.key"),
                  execution: executionID(context),
                },
                input,
              ),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_host"))),
    })

    editor.add({
      name: "cyber_database",
      options: { codemode: false },
      input: ForkCyberDatabase.Action,
      description:
        'Assess database services. unauth_check sends one unauthenticated request to redis or elasticsearch through the scoped Kali probe (R1). It never attempts a login, and auth_required means the service asked for one and none was sent. config_review reads an exported redis.conf or elasticsearch.yml artifact offline (R0) and reports exposure settings with the line that holds each one. auth_test (R2) makes one login attempt with a declared credential label, only when the engagement declares cyber_database.auth_test and the operator approves this host. It returns the state, never the value. Secret values are never echoed. Requires an explicit engagement; unauth_check and auth_test also need an active worker claim and a scoped Kali network. Example: {"action":"config_review","engine":"redis","artifact":"output-artifact-id"}.',
      execute: (input, context) =>
        Effect.gen(function* () {
          if (input.action === "config_review")
            return yield* ForkCyberDatabase.runConfigReview(
              store,
              {
                owner: yield* topLevel(context.sessionID),
                session: context.sessionID,
                agent: context.agent,
              },
              input,
            )
          const runtime = yield* kali(context, "cyber_database")
          if (input.action === "auth_test")
            return {
              content: JSON.stringify(
                yield* ForkCyberDatabase.runAuthTest({
                  store,
                  profile: global.data,
                  keyFile: path.join(global.state, "opencyber", "credential.key"),
                  config: runtime.configuration,
                  assessment: { ...runtime.assessment, mode: cyberMode },
                  request: input,
                  now: Date.now(),
                }),
              ),
            }
          return {
            content: JSON.stringify(
              yield* ForkCyberDatabase.runUnauthCheck(
                store,
                global.data,
                runtime.configuration,
                runtime.assessment,
                input,
              ),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_database"))),
    })

    editor.add({
      name: "kali_run",
      options: { codemode: false },
      input: ForkCyberKali.Run,
      description:
        `Run argv in an optional Kali Docker job. argv[0] must be a bare name from the allowlist: ${ForkCyberKaliAllowlist.binaries.join(", ")}. Other binaries, paths, shells and interpreters are refused with refused_by_policy before anything starts; typed tools such as cyber_services wrap the rest. Example: argv [\"grep\",\"-c\",\"token\",\"source.txt\"] with inputs [{\"name\":\"source.txt\",\"artifact\":\"<artifact ID>\"}]. Fresh /work, non-root, bounded CPU/memory/files/output/time. Inputs reference this engagement's artifacts; outputs name regular files directly inside /work. Returns stdout/stderr/file artifact IDs and exit code. Default network is none. Scoped networking requires engagement rules_of_engagement.network budgets, pins destinations/exclusions, and reserves the job's full byte allowance against the persistent engagement total. It does not apply HTTP max_rps to arbitrary processes. Cancellation destroys the containers. No host mounts or inherited provider credentials.`,
      execute: (input, context) =>
        Effect.gen(function* () {
          const runtime = yield* kali(context, "kali_run")
          return { content: JSON.stringify(yield* runtime.manager.run(runtime.assessment, input)) }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_tool"))),
    })

    editor.add({
      name: "kali_environment",
      options: { codemode: false },
      input: Schema.Struct({ action: Schema.Literals(["status", "stop"]) }),
      description:
        "Inspect this engagement's Kali containers, or stop them and clear stale admission locks after interruption/restart. Stop cancels active work and deletes its temporary files. Previously archived evidence remains available. Only affects containers labelled for this engagement and data profile. An empty call reports status.",
      execute: (input, context) =>
        Effect.gen(function* () {
          const runtime = yield* kali(context, "kali_environment")
          return {
            content: JSON.stringify(
              yield* input.action === "status"
                ? runtime.manager.status(runtime.assessment.owner)
                : runtime.manager.cleanup(runtime.assessment.owner),
            ),
          }
        }).pipe(Effect.mapError((error) => ForkCyberDiagnostics.toolError(error, "cyber_tool"))),
    })
  })
})
