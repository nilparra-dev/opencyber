# Container review

`cyber_container` reviews container artifacts offline. It never pulls, runs, mounts or inspects an image. Inputs are artifacts already captured in the Location, so the review is repeatable from the recorded evidence. Each call is a recorded execution with network `none`.

## Actions

- `dockerfile_lint` reads a captured Dockerfile. It reports unpinned or `latest` base images, a root or missing `USER`, remote `ADD`, pipe-to-shell builds, credential-like build variables, SSH exposure and a missing `HEALTHCHECK`. Values are never reported.
- `runtime_review` reads an exported `docker inspect` JSON document. It reports privileged mode, host network or PID namespaces, the Docker socket, added capabilities, disabled security profiles, a writable root filesystem, a root user and credential-like environment names. Values are never reported.
- `image_scan` matches an offline package inventory against the pinned advisory snapshot described in [fork-cyber-advisory.md](fork-cyber-advisory.md).

Findings from all three are candidates. An empty result does not prove that an image is hardened or free of known vulnerabilities.

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
- The output records the snapshot identity (`advisory`), inventory counts (`inventory`), `finding_count`, at most 50 `findings` inline, `next_offset` when more exist, and `results_artifact` with the complete list.

Producing the inventory is outside this tool. An operator exports it with an inventory tool that does not run the image's entrypoint. Converting another tool's output into the format above is a manual step.

Without a configured advisory snapshot, `image_scan` returns `not_configured` and records no execution. Inventories are limited to 1 MiB.

## Laboratory

`packages/core/test/fixture/fork-cyber-advisory` contains a vulnerable inventory (`ocfx-parser` 1.4.2 and `ocfx-py` 0.9.0, digest `1111...`) and a fixed inventory (1.4.3 and 0.9.1, digest `2222...`). The vulnerable inventory reports `OCFX-TEST-0001` and `OCFX-TEST-0002`, and the fixed one reports nothing. The tests also check that a tag-only reference, a digest mismatch and a non-inventory artifact are refused, and that the registry named in a reference receives no request. The laboratory needs no Docker.

## Pending

- No inventory producer is included. Operators supply `opencyber-package-inventory-v1` documents.
- The `pull` action (R1, registries in scope, by digest only) is not implemented here.
- The `cyber-code-review` worker role does not include `cyber_container` in `packages/core/src/fork-cyber/roles.ts`, so a review-mode worker cannot run any container action. The R-4 phase table lists containers for that phase. Changing the role is a decision for the integrator.
