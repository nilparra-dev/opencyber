# Web validation with per-class oracles (OC-402)

`cyber_web_test` with `action: "validate"` runs one R2 validation class per call against one URL parameter. It is the web counterpart of the validator contract in [fork-cyber-toolset.md](fork-cyber-toolset.md) (D3, D12): every run records the pre-state, the action, the oracle decision and cleanup in one validation record (`validation.ts`).

## Gates

Every class is R2 and passes these gates in order, before any traffic:

1. The agent runs in the `cyber-validate` phase and holds a claimed task (`cyber_tasks`).
2. The engagement is `laboratory` and declares `cyber_web_test.validate.<class>` in `rules_of_engagement.validation.actions`. An undeclared class is refused with `not_declared`.
3. The operator approves that class on that endpoint (origin and path, not the query string). Approvals last ten minutes ([fork-cyber-approval.md](fork-cyber-approval.md)).
4. Each request passes HTTP scope, including the excluded list and the rate limit. Redirects are never followed.

For SSRF, the callback URL is also checked against scope before the listener starts. A refused callback sends no request to the target.

## Classes and oracles

Each run sends a benign control first. A probe counts only when it differs from the control in the way the oracle requires.

| Class               | Probe                                                           | Reproduced when                                                                         | Inconclusive when                                                       |
| ------------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `open_redirect`     | Canary destination                                              | The probe redirects to the reserved canary host and the control does not                | The control already redirects there                                     |
| `path_traversal`    | Traversal to `file`, expecting `marker`                         | The marker appears only in the probe                                                    | The marker is in the control                                            |
| `sql_injection`     | True and false conditions on `control`                          | The true condition matches the control and the false condition changes the response     | Identical responses, or the true condition does not match the control   |
| `command_injection` | Shell expansion of fresh operands                               | The product of the operands appears only in the probe                                   | The product also appears in the control                                 |
| `xss`               | Breakout plus a script that appends a product the page computes | The product appears in the rendered text of the probe page and not in the control       | The product is already in the control, or the browser reported an issue |
| `ssrf`              | Callback URL with a fresh token, on a listener in scope         | The target requests the listener with that token within 2 seconds of the probe response | Not used; a missing callback is `not_reproduced`                        |

A string appearing in a response is never an oracle by itself. Reflected XSS payloads, echoed callback URLs and echoed canary hosts stay `not_reproduced`, and the laboratory tests check each of those cases.

### XSS

The browser comes from `cyber_browser`, so the operator must configure `opencyber-browser.jsonc`. Without it, the class is refused before any request. Each run opens a fresh identity, navigates to the control page and then to the probe page, and closes the identity. The page text (`innerText`, capped at 16,000 characters) is compared in memory; the record keeps only URL and digest.

The payload is `control"'><svg/onload=document.body.append(A*B)>`, where `A` and `B` are fresh three-digit operands. The product never appears in the payload, so reflected markup cannot produce it.

### SSRF

The harness starts a listener on the host and port of the `callback` URL (default port 80) and stops it when the run ends. The listener accepts only the path `/<token>`, where the token is fresh per run, and records the source address of each matching request. The callback host must be in scope.

The target must be able to reach the callback host. A callback host on a machine the operator does not control is a human decision and is not checked beyond scope.

## Output

The result follows the validation record: `validator`, `pre_state`, `action`, `oracle` with `result` and `basis`, `cleanup`, `effects`, `completion_evidence` and `artifacts`. The model sees digests, URLs, statuses, callback counts and source addresses. It does not see response bodies, page text or secret values.

## Verification

Run from `packages/core`:

```bash
bun test test/plugin/fork-cyber-web-validation.test.ts
OPENCYBER_TEST_BROWSER="C:/Program Files/Google/Chrome/Application/chrome.exe" bun test test/plugin/fork-cyber-web-validation.test.ts
bun test test/plugin/fork-cyber-decision.test.ts test/plugin/fork-cyber-approval.test.ts test/plugin/fork-cyber-web-test.test.ts
```

The first command runs every offline test: the schema, the four HTTP classes, SSRF with a vulnerable, a guarded and an echoing laboratory route, scope refusals with zero target requests, the role refusal, and the XSS refusal without a browser. The XSS laboratory test (a real Chromium run with a vulnerable text context and two inert contexts) is skipped unless `OPENCYBER_TEST_BROWSER` names a Chromium executable. A skip is not a pass.

## Not done

- **XSS in the DOM, stored or blind forms.** Only reflected XSS in a URL parameter is validated. DOM-based sinks need a payload in the fragment or in client state, which the class does not yet send.
- **XSS oracle limits.** The product oracle detects script execution that writes to page text. A server that evaluates the arithmetic itself would produce the same text; such a target is not an XSS mechanism, but the oracle does not separate the two.
- **SSRF through DNS-only or out-of-band channels.** Only an HTTP callback to the listener is recognized. Protocol-specific SSRF (gopher, file, metadata services) and blind callbacks that need a separate collector are not implemented.
- **Callback reachability.** The harness does not check that the target can reach the listener, so a negative result can mean "not reachable" as well as "not vulnerable". The basis states the window; the operator must confirm reachability for a negative SSRF result.
- **Approval prompt detail.** The prompt names the endpoint, not the callback host. The callback host is still scope-checked before any traffic.
- **Shell and database classes beyond the laboratory.** Blind SQL injection, data extraction and command execution on real systems remain out of scope; the classes report whether a probe was observed, not what it could read.
