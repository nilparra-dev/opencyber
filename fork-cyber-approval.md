# R2 approval

R2 actions are intrusive validation: test payloads, exploitability confirmation and similar checks. [fork-cyber-toolset.md](fork-cyber-toolset.md) (R-2, D-2) sets the rules. This guide describes how the harness applies them (OC-401).

## What must be true before an R2 action runs

1. **Mode.** The session runs in `assessment` mode. `development` and `review` refuse R2 outright (`above_ceiling`).
2. **Phase.** The agent's phase ceiling reaches R2. The phases `cyber-exploit-web`, `cyber-exploit-net` and `cyber-validate` do; `cyber-recon`, `cyber-enum` and `cyber-report` do not. The primary agent has no phase ceiling of its own.
3. **Engagement declaration.** The approved engagement names the action in `rules_of_engagement.validation`. Without it the call is refused with `not_declared`, and no prompt is shown.
4. **Operator approval.** The operator approves the action on its target in the permission prompt. A decline refuses the call (`approval_declined`).

```jsonc
{
  "rules_of_engagement": {
    // ...
    "validation": {
      "environment": "laboratory",
      "actions": ["cyber_local_validation"],
    },
  },
}
```

`environment` accepts only `laboratory` until an approval model exists for other environments. The list of actions is closed: `cyber_local_validation`, `cyber_surface.binary.execute`, `cyber_web_test.validate.open_redirect`, `cyber_web_test.validate.path_traversal`, `cyber_web_test.validate.sql_injection` and `cyber_web_test.validate.command_injection` today. Later validators add their identifiers to the same list.

## Approval scope

- **Action.** The tool, and its variant when the tool has several: `cyber_surface.binary.execute`. Validation classes are separate actions: `cyber_web_test.validate.open_redirect`, `cyber_web_test.validate.path_traversal`, `cyber_web_test.validate.sql_injection` and `cyber_web_test.validate.command_injection`.
- **Target.** For a URL, the origin and path. The query string is excluded because it carries payloads. For a host, the host. For an input that has neither, the SHA-256 digest of the exact input, so an approval covers only that input.
- **Lifetime.** Ten minutes from the operator's reply. Within that window the same action and target run without a new prompt. After it, the next call asks again.
- **Recording.** Each approval is stored with action, target, approver and expiry. Each decision is appended to the decision log: `allow` with `approved:<id>`, or `deny` with `approval_declined`.
- **Not offered.** Saved grants. The prompt carries no `save` resource, so "always" does not persist an approval for later sessions.

The approval prompt is never answered by generic client auto-approval: the request carries the manual-approval marker, the same as manual delegation (F-027).

## Refusals

| Reason              | Category            | Meaning                                                                                |
| ------------------- | ------------------- | -------------------------------------------------------------------------------------- |
| `above_ceiling`     | `refused_by_policy` | The mode or phase does not allow R2.                                                   |
| `not_declared`      | `refused_by_policy` | The engagement does not declare the action.                                            |
| `approval_declined` | `refused_by_policy` | The operator declined, or the prompt was refused. Do not retry without a new approval. |

A denied call sends no traffic and starts no evidence record.

## Limits

- The approval covers one endpoint, not every path on the origin. Payloads for the same endpoint are covered for the window.
- `laboratory` is an attestation in the manifest. The harness cannot prove the target is a laboratory.
- The operator's identity is not known to the permission flow; approvals record `operator`.

## Verification

- `test/plugin/fork-cyber-decision.test.ts`: ceilings, declarations, action identifiers and approval targets.
- `test/plugin/fork-cyber-approval.test.ts`: an approval covers its exact action and target only until it expires.
- `test/plugin/fork-cyber-integration.test.ts`: a declined prompt refuses the call, an approved prompt is reused within its window, a different input asks again, and the primary agent is prompted too.
- `test/plugin/fork-cyber-web-validation.test.ts`: the open redirect and path traversal oracles against a laboratory server, including the cases that must stay unconfirmed.
