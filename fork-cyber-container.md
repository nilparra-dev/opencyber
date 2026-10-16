# Container assessment: pull (OC-206, partial)

`cyber_container` has three actions. `dockerfile_lint` and `runtime_review` review captured text offline (R0) and are described in the phase 7 plan. `pull` (R1, assessment mode only) fetches one image from a registry in the engagement. Image scanning (`image_scan`) is not implemented yet.

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
- The image is not run, extracted or scanned.
- Docker performs the pull on the host, not in a Kali workload. The network controls of `fork-cyber-network.md` do not apply to it.

## Laboratory

The Docker test in `packages/core/test/plugin/fork-cyber-image-pull.test.ts` starts a local `registry:2` image, pinned by digest and pulled only when absent. It runs with host networking, because the daemon performs pushes and pulls from its own network namespace, which on Docker Desktop is a VM. It pushes a small image by tag, reads the digest from the push output, removes the local tag and pulls by digest. It then checks that the recorded digest matches and that an out-of-scope port and a tag-only reference are refused without a Docker call. It removes only its own container and references.

Run from `packages/core` with `OPENCYBER_TEST_KALI_IMAGE` set to a local image ID:

```sh
bun test test/plugin/fork-cyber-image-pull.test.ts
```

Without that variable the registry case is skipped, and the decision, reference, scope and role cases still run.

## Pending

- `image_scan` (pinned offline advisory database with recorded version).
- A decision on which registries an engagement may name in practice, and whether pulls should run through a Kali workload.
