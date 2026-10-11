# Database assessment

`cyber_database` assesses database services. `unauth_check` and `config_review` need no credential and never attempt a login. `auth_test` is the only action that uses a credential, and it is disabled unless the engagement declares it and the operator approves it.

| Action          | Risk | Target    | Runs where                                                     |
| --------------- | ---- | --------- | -------------------------------------------------------------- |
| `unauth_check`  | R1   | `service` | One unauthenticated request through the scoped Kali probe      |
| `config_review` | R0   | artifact  | Offline, in the evidence store; nothing is executed            |
| `auth_test`     | R2   | `service` | One login attempt with a declared label, after OC-401 approval |

Example calls:

```json
{"action":"unauth_check","engine":"redis","host":"app.example.test","port":6379}
{"action":"config_review","engine":"elasticsearch","artifact":"output-artifact-id"}
{"action":"auth_test","engine":"redis","host":"app.example.test","port":6379,"label":"db-reader"}
```

## Engines

- `redis`: `unauth_check` runs the `redis_info` probe (`INFO server`, no `AUTH`). `config_review` reads `redis.conf`. `auth_test` sends `AUTH` with the label's value.
- `elasticsearch`: `unauth_check` runs the `elasticsearch_root` probe (`GET /`). `config_review` reads `elasticsearch.yml`. `auth_test` sends `GET /` without credentials first, which is not an attempt, and then the same request with HTTP Basic `user:password` from the label's value.

Other engines are refused by the schema until they have a probe and a configuration rule set.

## unauth_check

The action reuses the `cyber_services` probe, so it inherits its rules: an explicit engagement, a scoped Kali network, network budgets, the scope and exclusion checks, and an active worker claim for worker phases. It sends one request on one connection.

The output reports the probe state and what it observed, and it maps the state to an exposure label:

| State                     | Exposure                   | Meaning                                                                                                             |
| ------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `answered`                | `unauthenticated_response` | The service answered the request without credentials. This is observed reachability, not a vulnerability by itself. |
| `auth_required`           | `authentication_required`  | The service asked for credentials. No login was attempted.                                                          |
| `closed` or `no_response` | `not_observed`             | Nothing was observed on this path. This does not establish security.                                                |
| `unexpected`              | `unexpected_response`      | The reply did not match the expected protocol.                                                                      |
| `error`                   | `check_error`              | The probe failed. The report artifact holds the details.                                                            |

The `probe` field holds the state, the fields the service returned, the checks that ran, the checks that did not run, and the report artifact.

## config_review

The artifact is read from the evidence store and is limited to 256 KiB. Findings are paginated with `offset` and `limit`, and `next_offset` is `null` on the last page.

| Engine        | Flag                      | Condition                                                                                            |
| ------------- | ------------------------- | ---------------------------------------------------------------------------------------------------- |
| redis         | `protected_mode_disabled` | `protected-mode no`                                                                                  |
| redis         | `bind_all_interfaces`     | `bind` includes `0.0.0.0`, `::` or `*`                                                               |
| redis         | `no_password`             | No `requirepass` and no `user` directive. The default user then accepts commands without a password. |
| redis         | `nopass_user`             | A `user` directive includes `nopass`                                                                 |
| elasticsearch | `security_disabled`       | `xpack.security.enabled: false`                                                                      |
| elasticsearch | `bind_all_interfaces`     | `network.host` is `0.0.0.0`, `::`, `*`, `_all_` or `_global_`                                        |

Each finding names its line as `line:N`, so a reviewer can go to it. `no_password` points at `file`. Secret values are never copied into a finding. `requirepass` is only checked for presence, and the tests assert that its value never reaches the output.

## auth_test

`auth_test` is R2 (`fork-cyber-toolset.md`, D10). A call is refused before any Kali job starts unless all of these hold. Each refusal is recorded in the decision log.

1. **Mode and phase.** The session runs in `assessment` mode, and the agent's ceiling reaches R2: `cyber-exploit-net`, `cyber-exploit-web`, `cyber-validate`, or the primary agent.
2. **Engagement flag.** `rules_of_engagement.validation.actions` includes `cyber_database.auth_test`.
3. **Credential declaration.** `rules_of_engagement.credentials` declares the label with `kind: "database_login"`, `read_only: true`, a `host` target that matches the request, and `actions: ["cyber_database.auth_test"]`. The operator registers the value with `script/fork-cyber-credential.ts add … --kind database_login`, reading it from stdin.
4. **Operator approval (OC-401).** The operator approves the action on the host in the permission prompt. The approval lasts ten minutes (`fork-cyber-approval.md`).
5. **Pacing.** A label is tried at most once per target within 60 seconds.

```jsonc
{
  "rules_of_engagement": {
    "validation": { "environment": "laboratory", "actions": ["cyber_database.auth_test"] },
    "credentials": [
      {
        "label": "db-reader",
        "kind": "database_login",
        "read_only": true,
        "targets": [{ "type": "host", "value": "app.example.test" }],
        "actions": ["cyber_database.auth_test"],
      },
    ],
  },
}
```

The value is leased to the Kali job as a file under `/work`. It is never passed in argv, and the job's output is redacted before it is stored. The model sees the label, the state and the report artifact:

| State                   | Meaning                                                                                                                                       |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `accepted`              | The service accepted the value.                                                                                                               |
| `rejected`              | The service refused the value (`WRONGPASS`, or HTTP 401 or 403).                                                                              |
| `not_required`          | The service needed no credential. Redis reports that no password is configured; Elasticsearch answered `GET /` with 200. Not a finding alone. |
| `closed`, `no_response` | Nothing was observed, so no login was possible.                                                                                               |
| `error`                 | The reply was not classified. The report artifact holds the details.                                                                          |

## Limits

- Findings are configuration observations. An exposed setting does not prove that a client can reach the service, and a closed or filtered result does not prove that it is protected.
- Lockout thresholds of the target are not modelled. Pacing allows one attempt per label and target each minute, and one approval lasts ten minutes, so one label can make about ten attempts under a single approval. A cumulative budget per label and target is a policy decision that is not implemented.
- Redis `auth_test` runs against `redis:7.2` pinned by digest. Elasticsearch `auth_test` runs against a protocol stand-in (`test/fixture/fork-cyber-database/lab.ts`), because no Elasticsearch image is pinned. The real Elasticsearch classification is not verified.
- The `unauth_check` and `auth_test` laboratories need the Kali image. They run only when `OPENCYBER_TEST_KALI_IMAGE` is set, and they skip otherwise. The host-Python Redis probe test needs `OPENCYBER_TEST_PYTHON` where `python3` is not a real interpreter. A skipped test is not a passed test.
- `config_review` tests run without Docker.

## Verification

- `test/plugin/fork-cyber-database.test.ts`: schema, decisions for each action, refusals before any Kali job, `config_review` fixtures for both engines, and the `unauth_check` laboratory.
- `test/plugin/fork-cyber-database-labs.test.ts`: the `unauth_check` laboratory records every request and asserts that none carries an authentication command or header, and the `auth_test` laboratory classifies valid and invalid values for Redis and the Elasticsearch stand-in, paces repeats, and keeps values out of outputs, artifacts, decisions, executions and the database file.
- `test/plugin/fork-cyber-database-auth.test.ts`: the Redis probe classes against a real Redis.
