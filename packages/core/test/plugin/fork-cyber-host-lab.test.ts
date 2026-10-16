import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { randomUUID } from "node:crypto"
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { ForkCyberCredentials } from "@opencode/core/fork-cyber/credentials"
import { ForkCyberHost } from "@opencode/core/fork-cyber/host"
import { ForkCyberScope } from "@opencode/core/fork-cyber/scope"
import { ForkCyberStore } from "@opencode/core/fork-cyber/store"

// Real Docker and OpenSSH. Set OPENCYBER_TEST_HOST_LAB=1 to run; otherwise every case is reported as skipped.
// The lab builds from fork-lab/linux-host with base images pinned by digest. Each run uses its own compose project.
const enabled =
  process.env.OPENCYBER_TEST_HOST_LAB === "1" &&
  Bun.which("docker") !== null &&
  Bun.which("ssh") !== null &&
  Bun.which("ssh-keygen") !== null

const compose = path.resolve(import.meta.dir, "../../../../fork-lab/linux-host/compose.yaml")
const owner = "owner-host-lab"
const session = "session-host-lab"
const agent = "primary"
const label = "lab-audit"
const hardenedPort = Number(process.env.OPENCYBER_LAB_HARDENED_PORT ?? 2201)
const vulnerablePort = Number(process.env.OPENCYBER_LAB_VULNERABLE_PORT ?? 2202)
const project = `ocl-${randomUUID().slice(0, 8)}`
const hardenedContainer = `${project}-hardened-1`
const vulnerableContainer = `${project}-vulnerable-1`
const edgeContainer = `${project}-edge-1`
const checkedFiles = [
  "/etc/ssh/sshd_config",
  "/etc/login.defs",
  "/etc/shadow",
  "/etc/passwd",
  "/etc/sudoers.d/ops",
  "/etc/cron.d/maint",
  "/usr/local/bin/backup-helper",
  "/home/audit/.ssh/authorized_keys",
]

// Paths are set in beforeAll; the lab keeps its private key in `secret` and mounts only the public key.
const paths = { dir: "", secret: "", mount: "", evidence: "", keyFile: "", known: "" }

async function run(command: string[], env: Record<string, string> = {}) {
  const child = Bun.spawn(command, {
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
  })
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ])
  return { code, stdout, stderr }
}

const composeEnv = () => ({ OPENCYBER_LAB_KEY_DIR: paths.mount })
const composeArgs = (args: string[]) => ["docker", "compose", "-p", project, "-f", compose, ...args]
const docker = (args: string[]) => run(["docker", ...args])

function manifest(): ForkCyberScope.Manifest {
  return {
    engagement: "linux-host-lab",
    authorized_by: "operator",
    authorization_ref: "fork-lab/linux-host",
    scope: {
      domains: [],
      cidrs: [],
      excluded: [],
      services: [{ target: "127.0.0.1", protocol: "tcp", ports: [hardenedPort, vulnerablePort] }],
    },
    rules_of_engagement: {
      no_dos: true,
      max_rps: 1,
      window: "lab",
      contact: "operator",
      credentials: [
        {
          label,
          kind: "host_login",
          read_only: true,
          account: "audit",
          targets: [{ type: "host", value: "127.0.0.1" }],
          actions: ["cyber_host.audit", "cyber_host.privesc_config"],
        },
      ],
    },
  }
}

// One call through the production path: approved engagement, lease, SSH, parsing and the transcript artifact.
// Returns the Effect Result so each test can assert the outcome, including refusals.
function act(input: ForkCyberHost.Probe, execution: string) {
  return Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const store = yield* ForkCyberStore.open(paths.evidence)
        yield* store.start({ id: execution, owner, session, tool: "cyber_host", agent, input })
        return yield* ForkCyberHost.run(
          store,
          { owner, session, agent, mode: "assessment", manifest: manifest(), keyFile: paths.keyFile, execution },
          input,
        ).pipe(Effect.result)
      }),
    ),
  )
}

async function waitForSsh(port: number) {
  for (let attempt = 0; attempt < 60; attempt++) {
    const probe = await run([
      "ssh",
      "-F",
      "none",
      "-i",
      path.join(paths.secret, "audit"),
      "-o",
      "BatchMode=yes",
      "-o",
      "IdentitiesOnly=yes",
      "-o",
      "IdentityAgent=none",
      "-o",
      "StrictHostKeyChecking=accept-new",
      "-o",
      `UserKnownHostsFile "${paths.known}"`,
      "-o",
      "ConnectTimeout=3",
      "-o",
      "LogLevel=ERROR",
      "-p",
      String(port),
      "-l",
      "audit",
      "--",
      "127.0.0.1",
      "true",
    ])
    if (probe.code === 0) return
    await Bun.sleep(1000)
  }
  throw new Error(`SSH on port ${port} did not become ready`)
}

const hashes = (container: string) =>
  docker(["exec", container, "sha256sum", ...checkedFiles]).then((result) => result.stdout)

async function teardown() {
  await run(composeArgs(["down", "--volumes", "--remove-orphans", "--rmi", "local"]), composeEnv())
}

async function residue() {
  const filter = `label=com.docker.compose.project=${project}`
  const [containers, networks, volumes, images] = await Promise.all([
    docker(["ps", "-a", "--filter", filter, "-q"]),
    docker(["network", "ls", "--filter", filter, "-q"]),
    docker(["volume", "ls", "--filter", filter, "-q"]),
    docker(["image", "ls", "--filter", "reference=opencyber/lab-linux-host-*", "-q"]),
  ])
  return {
    containers: containers.stdout.trim(),
    networks: networks.stdout.trim(),
    volumes: volumes.stdout.trim(),
    images: images.stdout.trim(),
  }
}

describe.skipIf(!enabled)("Linux host laboratory", () => {
  let before: Awaited<ReturnType<typeof residue>>
  let hardenedBefore = ""

  beforeAll(async () => {
    paths.dir = await mkdtemp(path.join(tmpdir(), "opencyber-host-lab-"))
    paths.secret = path.join(paths.dir, "secret")
    paths.mount = path.join(paths.dir, "mount")
    paths.evidence = path.join(paths.dir, "evidence.sqlite")
    paths.keyFile = path.join(paths.dir, "state", "credential.key")
    paths.known = path.join(paths.dir, "known_hosts")
    await mkdir(paths.secret, { recursive: true })
    await mkdir(paths.mount, { recursive: true })
    const keygen = await run([
      "ssh-keygen",
      "-q",
      "-t",
      "ed25519",
      "-N",
      "",
      "-C",
      "opencyber-lab-audit",
      "-f",
      path.join(paths.secret, "audit"),
    ])
    expect(keygen.code).toBe(0)
    await Bun.write(path.join(paths.mount, "audit.pub"), await readFile(path.join(paths.secret, "audit.pub"), "utf8"))
    before = await residue()

    const privateKey = await readFile(path.join(paths.secret, "audit"), "utf8")
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const store = yield* ForkCyberStore.open(paths.evidence)
          const key = yield* ForkCyberCredentials.loadKey(paths.keyFile)
          const binding = { owner, label, kind: "host_login" as const }
          const now = Date.now()
          yield* store.putCredential({
            ...binding,
            expires_at: now + 86_400_000,
            created_at: now,
            ...ForkCyberCredentials.seal(key, binding, privateKey),
          })
          yield* store.approveManifest(owner, manifest(), 0)
        }),
      ),
    )

    const up = await run(composeArgs(["up", "--build", "-d"]), composeEnv())
    if (up.code !== 0) throw new Error(`compose up failed: ${up.stderr.slice(-2000)}`)
    await waitForSsh(hardenedPort)
    await waitForSsh(vulnerablePort)
    hardenedBefore = await hashes(hardenedContainer)
  }, 900_000)

  afterAll(async () => {
    await teardown()
    await rm(paths.dir, { recursive: true, force: true })
  }, 300_000)

  test("the hardened host passes every audit check", async () => {
    const result = await act({ action: "audit", host: "127.0.0.1", port: hardenedPort, label }, "exec-hardened-audit")
    expect(result._tag).toBe("Success")
    if (result._tag !== "Success") return
    expect(result.success).toMatchObject({
      format: "opencyber-host-audit-v1",
      summary: "6 pass, 0 fail, 0 unknown.",
      checks: [
        { id: "ssh.permit_root_login", status: "pass" },
        { id: "ssh.password_authentication", status: "pass" },
        { id: "ssh.permit_empty_passwords", status: "pass" },
        { id: "account.pass_max_days", status: "pass" },
        { id: "account.shadow_permissions", status: "pass" },
        { id: "account.passwd_permissions", status: "pass" },
      ],
    })
  }, 120_000)

  test("the known-positive host reports each documented misconfiguration", async () => {
    const result = await act(
      { action: "audit", host: "127.0.0.1", port: vulnerablePort, label },
      "exec-vulnerable-audit",
    )
    expect(result._tag).toBe("Success")
    if (result._tag !== "Success") return
    expect(result.success).toMatchObject({
      checks: [
        { id: "ssh.permit_root_login", status: "fail", observed: "PermitRootLogin yes" },
        { id: "ssh.password_authentication", status: "fail" },
        { id: "ssh.permit_empty_passwords", status: "pass" },
        { id: "account.pass_max_days", status: "fail", observed: "PASS_MAX_DAYS 99999" },
        { id: "account.shadow_permissions", status: "fail" },
        { id: "account.passwd_permissions", status: "pass" },
      ],
    })
  }, 120_000)

  test("privesc_config reports the known conditions on the known-positive host and none on the hardened host", async () => {
    const clear = await act(
      { action: "privesc_config", host: "127.0.0.1", port: hardenedPort, label },
      "exec-hardened-privesc",
    )
    expect(clear._tag).toBe("Success")
    if (clear._tag === "Success")
      expect(clear.success).toMatchObject({
        conditions: [
          { id: "suid.unexpected", status: "no_condition" },
          { id: "sudo.nopasswd", status: "no_condition" },
          { id: "file.capabilities", status: "no_condition" },
          { id: "cron.group_or_world_writable", status: "no_condition" },
        ],
      })
    const present = await act(
      { action: "privesc_config", host: "127.0.0.1", port: vulnerablePort, label },
      "exec-vulnerable-privesc",
    )
    expect(present._tag).toBe("Success")
    if (present._tag !== "Success") return
    expect(present.success).toMatchObject({
      conditions: [
        { id: "suid.unexpected", status: "condition_present", items: ["/usr/local/bin/backup-helper (4755 root)"] },
        { id: "sudo.nopasswd", status: "condition_present", items: ["ops ALL=(root) NOPASSWD: /usr/bin/tar"] },
        { id: "file.capabilities", status: "condition_present" },
        { id: "cron.group_or_world_writable", status: "condition_present", items: ["666 root /etc/cron.d/maint"] },
      ],
    })
  }, 120_000)

  test("audits leave every checked file unchanged", async () => {
    expect(await hashes(hardenedContainer)).toBe(hardenedBefore)
    const vulnerableBefore = await hashes(vulnerableContainer)
    await act({ action: "audit", host: "127.0.0.1", port: vulnerablePort, label }, "exec-vulnerable-readonly")
    await act(
      { action: "privesc_config", host: "127.0.0.1", port: vulnerablePort, label },
      "exec-vulnerable-readonly-2",
    )
    expect(await hashes(vulnerableContainer)).toBe(vulnerableBefore)
  }, 120_000)

  test("hosts have no default route, and the relay drops everything except SSH to the hosts", async () => {
    const routes = await docker(["exec", hardenedContainer, "cat", "/proc/net/route"])
    const defaults = routes.stdout.split("\n").filter((line) => line.split(/\s+/)[1] === "00000000")
    expect(defaults).toEqual([])
    const policy = await docker(["exec", edgeContainer, "iptables", "-S", "OUTPUT"])
    expect(policy.stdout).toContain("-P OUTPUT DROP")
    const outside = await docker([
      "exec",
      edgeContainer,
      "timeout",
      "6",
      "socat",
      "-",
      "TCP:1.1.1.1:443,connect-timeout=3",
    ])
    expect(outside.code).not.toBe(0)
  }, 60_000)

  test("teardown returns the laboratory to its initial state", async () => {
    expect(before).toEqual({ containers: "", networks: "", volumes: "", images: expect.any(String) })
    await teardown()
    expect(await residue()).toEqual({ containers: "", networks: "", volumes: "", images: "" })
  }, 300_000)
})
