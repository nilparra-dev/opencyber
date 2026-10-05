# First matched model evaluation

The October 5, 2026 comparison exercises the compiled CLI against a synthetic HTTP fixture. It compares the released baseline with the SPA capture correction using the same prompt template and model settings. Each trial has its own loopback port and generated evidence IDs. This fixture measures acquisition, offline analysis and task evidence. The real SPA controls are verified separately by the browser tests.

DeepSeek V4.1 Flash met the technical contract in seven of eight trials: four of four baseline trials and three of four candidate trials. One candidate trial timed out during offline analysis. MiniMax M3 met it in zero of eight trials, with repeated invalid coordination arguments and exhausted step allowances. These are results for this provider adapter, configuration and fixture.

## Results

Each row is one matched pair. `Pass` means the technical contract passed and the process completed. `Incomplete` means the process exited with code zero while required work remained unfinished. `Timeout` means the five-minute deadline interrupted the process. Seconds measure the model run; GET counts come from the independent fixture server.

| Model               | Environment | Repetition | Baseline   | Seconds | GETs | Candidate  | Seconds | GETs |
| ------------------- | ----------- | ---------- | ---------- | ------- | ---- | ---------- | ------- | ---- |
| DeepSeek V4.1 Flash | missing     | 1          | Pass       | 162.8   | 21   | Timeout    | 300.0   | 21   |
| DeepSeek V4.1 Flash | missing     | 2          | Pass       | 183.7   | 21   | Pass       | 175.6   | 21   |
| DeepSeek V4.1 Flash | configured  | 1          | Pass       | 167.3   | 21   | Pass       | 200.4   | 21   |
| DeepSeek V4.1 Flash | configured  | 2          | Pass       | 246.8   | 21   | Pass       | 197.2   | 21   |
| MiniMax M3          | missing     | 1          | Incomplete | 49.7    | 2    | Incomplete | 60.0    | 0    |
| MiniMax M3          | missing     | 2          | Incomplete | 44.3    | 0    | Incomplete | 54.5    | 0    |
| MiniMax M3          | configured  | 1          | Incomplete | 72.2    | 22   | Incomplete | 53.6    | 0    |
| MiniMax M3          | configured  | 2          | Incomplete | 45.0    | 1    | Incomplete | 59.1    | 23   |

All sixteen cases preserved artifact integrity and permitted recorded executions, with zero invalid completion-evidence references and zero confirmed findings. All completed HTTP captures remained on the authorized service. Three MiniMax cases requested extra fixture paths on that service. All sixteen analysis exports contain the recorded attempts, and none has a child session.

The seven successful DeepSeek cases each completed one task and recorded a handoff. They retained both requested marker reads and produced static web plans. There were eight web-plan executions in total because one case wrote the plan twice. Missing-browser plans remained blocked; configured-browser plans remained pending execution. The timeout acquired all 21 inputs but did not complete its task or web plan, and its partial export is retained.

MiniMax read the marker successfully but never created or completed a task or recorded a web plan. Each case reached logical step 24. Transcripts contain repeated `cyber_tasks` argument errors, including empty payloads, and attempts to use unavailable bindings inside Code Mode. One baseline case acquired and analyzed all twenty assets but also requested `/`; one candidate case acquired all assets with two extra paths and left analysis unfinished. Other cases acquired fewer inputs. Shorter elapsed times reflect incomplete work.

Manual review found unsupported explanations in MiniMax summaries. Several attributed invalid arguments to an OpenCode serialization bug; that cause is not established by these runs. Another inferred that the inert asset implemented SPA behavior, although its bytes only contain padding and a demo assignment. The successful DeepSeek summaries preserved pending browser work and treated detector matches as observations, with no confirmed vulnerability. Counts alone do not establish the correctness of every narrative statement.

Known provider usage is summed once per physical attempt across all eight cases for each model, including failed workflows:

| Model               | Uncached input | Cached input | Visible output | Reasoning output | Attempts with usage | Attempts with unknown usage |
| ------------------- | -------------- | ------------ | -------------- | ---------------- | ------------------- | --------------------------- |
| DeepSeek V4.1 Flash | 1,228,319      | 5,930,552    | 61,843         | 48,581           | 152                 | 1                           |
| MiniMax M3          | 663,014        | 5,079,526    | 20,336         | 18,464           | 192                 | 0                           |

The unknown DeepSeek attempt was interrupted by the timeout. Known totals match each analysis export's session totals. Reported cache writes are zero. These totals exclude calibration and harness diagnostics, and do not include a verified billing statement.

## Method

The matrix has sixteen trials: two models, two binaries, two environment cases and two repetitions. Every trial starts with a fresh assessment profile, an explicit loopback HTTP service scope and a separate evidence database. The primary session does the work directly, with delegation disabled.

The fixture contains `/index` and twenty JavaScript assets. One asset places an inert `DEMO_ONLY_SYNTHETIC` credential marker beyond the normal preview. The requested workflow reads a local marker twice, creates and claims one `assets` task, acquires each HTTP input once, analyzes original captured bytes offline, completes with eligible output evidence, records a handoff, derives a static plan for URL navigation, storage and CSP, and reads the recorded report.

Both models use the same Fireworks account and the `@opencode/ai/providers/fireworks` adapter. The selected IDs are `accounts/fireworks/models/deepseek-v4p1-flash` and `accounts/fireworks/models/minimax-m3`. An authenticated model inventory returned both IDs before the matrix. Exact deployed model revisions remain unknown.

Each case allows 24 agent steps, 4,096 output tokens per request and a 300,000 ms process deadline. The custom model definitions use a 262,144-token context limit, `reasoning_content` and `max_tokens`. No variant or temperature override is selected. The prompt template, configuration and deadline stay identical between baseline and candidate. Model groups initially run concurrently; cases within each group run sequentially, alternating baseline and candidate. Timings include provider latency and local resource contention, and exclude the subsequent analysis export.

The `missing` case supplies neither browser nor Kali configuration. The `configured` case supplies the installed Chrome executable and still leaves Kali missing. It does not request browser execution, Docker jobs or external assessments. Each profile receives only explicitly supplied operator configuration; provider credentials stay in the child process environment.

## Binaries and provenance

The baseline is the Windows executable from [v2.0.23-cyber.2](https://github.com/nilparra-dev/opencyber/releases/tag/v2.0.23-cyber.2), built from `d80ff8adcd0477117dad9e26b313e7834364443a`. The downloaded ZIP matched the published SHA256SUMS. The candidate uses that base plus the browser correction represented in commit `47b784c3cc`, with the same channel and version. Its CLI-only build omits web UI assets through `--skip-web-ui`. This is not a byte-identical release build comparison.

| Input                  | SHA-256                                                            |
| ---------------------- | ------------------------------------------------------------------ |
| Baseline ZIP           | `d3d10dfe6b5bcf9c47a16837196392d3b41d85fdccf0dd72fb5a2611398864c6` |
| Baseline executable    | `a84ef5ace6d158ea53fcbc64b8a0996958814830830071f530da9b0caae09055` |
| Candidate executable   | `b3fadda3b619323e8b46b3d9f43e7c5e0e333133b4688e6421678cea499be94d` |
| Operator configuration | `3d5142d5e4de1038a916b435735512c043469621b7ec53d196d58a5ff17c349b` |

Raw profiles, evidence databases, request snapshots, transcripts and original result files remain under the ignored `reports/spa-model-evals` directory. The operator configurations contain no saved provider key. These artifacts include failed harness diagnostics as well as the matched matrix; diagnostics are excluded from the comparison.

The first DeepSeek candidate trial reached its five-minute deadline. Its traffic and process outcome were saved before a transient Windows SQLite WAL recovery error interrupted grading. The database subsequently passed `quick_check`, and its captured evidence was recovered and exported. The timeout stays in the matrix. Only the six cases that had not yet run were resumed, using the same settings and prompt. An earlier 180-second calibration and earlier harness failures are retained as diagnostics.

## Scoring and review

`ForkCyberEvaluation.score` checks independent server traffic, original artifact hashes, complete offline analysis of the twenty asset bodies, permitted recorded executions, eligible task completion evidence and zero confirmed findings. Technical success requires exactly 21 distinct expected GET requests and at least one completed task. The outcome does not consume the model's reported success or request count.

Authorized-service scope and exact fixture paths are separate metrics. An extra GET to `/` or `/fixture.txt` on the authorized service fails the fixture traffic contract, while preserving the service-scope result. Existing trials are rescored consistently from their saved traffic and explicit operator manifest. Original scores remain available privately.

Process completion, timeout and technical success are separate fields. The technical score covers acquisition, analysis and evidence; source reads, web plans and handoffs are recorded separately and reviewed against the transcript. A zero exit code alone does not satisfy the workflow. Captured HTTP scope describes completed HTTP evidence, rather than all possible model intentions or a general host network sandbox.

Usage comes from recorded physical attempts. Uncached input, cache reads, visible output and reasoning output are separate counts. Missing attempt usage remains unknown, especially after interruption. The configured catalog has no billing prices, so a stored cost of zero cannot establish free execution. Exact billed cost is unverified.

## Reproduction

Follow the matrix format in [fork-cyber-harness.md](fork-cyber-harness.md#optional-model-comparison). Supply both compiled executables, an isolated operator configuration with explicit model definitions and credentials through the environment. Run `bun script/fork-cyber-evaluate.ts <absolute-matrix-path>` from `packages/core`. Keep the two repetitions, both environment cases and the settings above unchanged for this comparison.

The evaluator saves `trial.json` before grading, then writes `results.json` and the analysis export. Its deadline owns the actual CLI process. Grading can recover writable WAL state after interruption and retries only the observed `SQLITE_IOERR_TRUNCATE` failure, at most twice. A separate regression kills a real SQLite writer and verifies that committed evidence survives while an uncommitted row does not.

Two repetitions on one synthetic fixture cannot establish a general model ranking, a release-wide speed change or an assessment-quality improvement. The SPA correction is proven by the production URL, isolated-storage and CSP controls, plus a worker failure regression with an independent excluded-destination listener. This model fixture leaves browser runtime behavior untested.
