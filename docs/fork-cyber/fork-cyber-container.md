# Container assessment

`cyber_container` has four actions. `dockerfile_lint`, `runtime_review` and `image_scan` review captured artifacts offline (R0): they never pull, run, mount or inspect an image, and each call is a recorded execution with network `none`. `pull` (R1, assessment mode only) is the only action that contacts a registry; it fetches one image pinned by digest from a registry in the engagement.

Findings from the review actions are candidates. An empty result does not prove that an image is hardened or free of known vulnerabilities.

## dockerfile_lint and runtime_review

- `dockerfile_lint` reads a captured Dockerfile. It reports unpinned or `latest` base images, a root or missing `USER`, remote `ADD`, pipe-to-shell builds, credential-like build variables, SSH exposure and a missing `HEALTHCHECK`. Values are never reported.
- `runtime_review` reads an exported `docker inspect` JSON document. It reports privileged mode, host network or PID namespaces, the Docker socket, added capabilities, disabled security profiles, a writable root filesystem, a root user and credential-like environment names. Values are never reported.

## image_scan

```json
{ "action": "image_scan", "image": "registry.example.test/app@sha256:<64 hex digits>", "artifact": "inventory-artifact-id" }
```

- `image` must be a digest reference (`repository@sha256:` followed by 64 lowercase hex digits). A tag-only reference is refused with `invalid_input` before the artifact is read. The tool never resolves a tag, because that requires a registry request.
- `artifact` is an inventory document captured in the Location. Capture it with `cyber_code_review` `snapshot`, then pass the returned artifact ID. The inventory format is:

```json
{
  "format": "opencyber-package-inventory-v1",
  "image": "registry.example.test/app@sha256:<the same digest>",
  "packages": [{ "ecosystem": "npm", "name": "example-package", "version": "1.4.2" }]
}
```

- The inventory's `image` must equal the requested digest; a different digest is refused with `invalid_input`. The declared digest is trusted, because confirming it requires pulling the image.
- Packages are matched only when the ecosystem is `npm` or `PyPI` and the version is a plain dotted version. Other ecosystems, such as operating-system packages, are counted as `unevaluated`, never as clean.
- The output records the snapshot identity (`advisory`), inventory counts (`inventory`), `finding_count`, at most 50 `findings` inline, `next_offset` when more exist, and `results_artifact` with the complete list. The advisory data is described in [fork-cyber-advisory.md](fork-cyber-advisory.md).

Producing the inventory is outside this tool. An operator exports it with an inventory tool that does not run the image's entrypoint. Converting another tool's output into the format above is a manual step.

Without a configured advisory snapshot, `image_scan` returns `not_configured` and records no execution. Inventories are limited to 1 MiB.

## pull

```json
{ "action": "pull", "image": "registry.example.test:5000/team/app@sha256:<64 hex characters>" }
```

- **Digest only.** The reference needs an explicit registry host (a dot, a port or `localhost`) and a `@sha256:` digest. A tag, a tag with a digest, and an implicit Docker Hub name are refused as `invalid_input` before Docker runs.
- **Scope.** The engagement declares the registry as a `container_image` target. The target is recorded as a service entry for that host and port (443 when no port is written). A pull to another host or port is refused as `outside_scope`. The host-wide rules of domain entries also apply, as they do for every network target.
- **Roles and claims.** The reconnaissance, enumeration and exploitation phases may pull. The code-review phase may not. Workers need their task claim. Review mode does not offer the container tool.
- **Result.** The daemon pulls the reference. The host then inspects the image and requires that its repository digests include the requested digest. The output records the reference, registry, repository, digest, image ID, repository digests and the pull status, with a completion evidence artifact.

Refusals happen before any Docker command, and the test suite checks this with a recording double: a refused pull makes zero Docker calls.

## Limits

- The scope check covers the registry endpoint only. Registries can redirect blob downloads to other hosts, and the daemon performs those requests.
- The daemon uses whatever credentials the host has configured for that registry. Their values are neither read nor recorded.
- The image is not run, extracted or scanned by `pull`.
- Docker performs the pull on the host, not in a Kali workload. The network controls of `fork-cyber-network.md` do not apply to it.

## Laboratory

- `image_scan`: `packages/core/test/fixture/fork-cyber-advisory` contains a vulnerable inventory (`ocfx-parser` 1.4.2 and `ocfx-py` 0.9.0, digest `1111...`) and a fixed inventory (1.4.3 and 0.9.1, digest `2222...`). The vulnerable inventory reports `OCFX-TEST-0001` and `OCFX-TEST-0002`, and the fixed one reports nothing. The tests also check that a tag-only reference, a digest mismatch and a non-inventory artifact are refused, and that the registry named in a reference receives no request. This laboratory needs no Docker.
- `pull`: the Docker test in `packages/core/test/plugin/fork-cyber-image-pull.test.ts` starts a local `registry:2` image, pinned by digest and pulled only when absent. It runs with host networking, because the daemon performs pushes and pulls from its own network namespace, which on Docker Desktop is a VM. It pushes a small image by tag, reads the digest from the push output, removes the local tag and pulls by digest. It then checks that the recorded digest matches and that an out-of-scope port and a tag-only reference are refused without a Docker call. It removes only its own container and references.

Run from `packages/core` with `OPENCYBER_TEST_KALI_IMAGE` set to a local image ID:

```sh
bun test test/plugin/fork-cyber-image-pull.test.ts
```

Without that variable the registry case is skipped, and the decision, reference, scope and role cases still run.

## Pending

- No inventory producer is included. Operators supply `opencyber-package-inventory-v1` documents.
- Operating-system packages and other ecosystems are not matched.
- The `cyber-code-review` worker role does not include `cyber_container` in `packages/core/src/fork-cyber/roles.ts`, so a review-mode worker cannot run any container action. The R-4 phase table lists containers for that phase. Changing the role is a decision for the integrator.
- A decision on which registries an engagement may name in practice, and whether pulls should run through a Kali workload.
