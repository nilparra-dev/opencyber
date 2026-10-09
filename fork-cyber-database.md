# Database assessment without credentials

`cyber_database` assesses database services without credentials. It has two actions, and neither one attempts a login.

| Action          | Risk | Target    | Runs where                                                |
| --------------- | ---- | --------- | --------------------------------------------------------- |
| `unauth_check`  | R1   | `service` | One unauthenticated request through the scoped Kali probe |
| `config_review` | R0   | artifact  | Offline, in the evidence store; nothing is executed       |

Example calls:

```json
{"action":"unauth_check","engine":"redis","host":"app.example.test","port":6379}
{"action":"config_review","engine":"elasticsearch","artifact":"output-artifact-id"}
```

## Engines

- `redis`: `unauth_check` runs the `redis_info` probe (`INFO server`, no `AUTH`). `config_review` reads `redis.conf`.
- `elasticsearch`: `unauth_check` runs the `elasticsearch_root` probe (`GET /`). `config_review` reads `elasticsearch.yml`.

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

## Limits

- Findings are configuration observations. An exposed setting does not prove that a client can reach the service, and a closed or filtered result does not prove that it is protected.
- `auth_test` is the R2 action in the design (`fork-cyber-toolset.md`, D10). It is not implemented, and it stays disabled by default until an operator approval flow exists for it.
- The live `unauth_check` tests need the Kali image. They run only when `OPENCYBER_TEST_KALI_IMAGE` is set, and they use the same fixture as `cyber_services`. The `config_review` tests run without Docker.
