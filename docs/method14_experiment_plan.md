# Method 14 Experiment Plan

## 1. Why Method 14

Current method 10 experiments produced a stable `normal_response` for the LLM candidate payload, but method 9 getter responses did not show an observable state change. Method 14 is the public `changeDoorsState` API and is a better next target because its intended effect can be checked through a matching public getter, method 8 `doorsOpeningStatus`.

This keeps the experiment black-box/feedback-guided: the fuzzer uses public interface IDs, request/response feedback, and getter-observable state only.

## 2. Validation Sequence

Each trial should use the following sequence:

1. Call getter `method_id=8` and save the response payload.
2. Send one `method_id=14` candidate payload.
3. Call getter `method_id=8` again and save the response payload.
4. Mark `state_changed=True` only if the before/after getter SOME/IP payload differs.
5. Mark `state_changed=unknown` if either getter response is missing or malformed.

## 2.1 Pre-Execution Payload Structure Analysis

Do not run Method 14 request probes until the `CarDoorsCommand` wire payload is confirmed from public interface artifacts and observed normal traffic.

Source-code findings:

- Public method declaration: `test-someip-service/franca/org/genivi/vehicle/playground.fidl` defines `changeDoorsState` with one input, `PlaygroundTypes.CarDoorsCommand commands`.
- SOME/IP ID mapping: `test-someip-service/franca/org/genivi/vehicle/playground.fdepl` maps `changeDoorsState` to `SomeIpMethodID = 14`.
- Server implementation: `test-someip-service/src/PlaygroundStubImpl.cpp` reads the current `doorsOpeningStatus`, extracts four commands from `_commands`, computes four next boolean door states, calls `setDoorsOpeningStatusAttribute(doorsStatus)`, then replies with no output payload.
- Generated dispatch path: `PlaygroundSomeIPStubAdapter.hpp` registers method ID `0x000e` with a dispatcher whose input tuple contains `CarDoorsCommandDeployment_t` and whose output tuple is empty.
- Generated proxy path: `PlaygroundSomeIPProxy.cpp` serializes a single deployable `CarDoorsCommand` argument when calling method ID `0x000e`.

Public type shape:

- `changeDoorsState` takes one input named `commands`.
- `commands` is `PlaygroundTypes.CarDoorsCommand`.
- `CarDoorsCommand` contains four fields in order: `frontLeftDoor`, `frontRightDoor`, `rearLeftDoor`, `rearRightDoor`.
- Each field is `DoorCommand`.
- Public `DoorCommand` enum values are `NOTHING=0`, `OPEN_DOOR=1`, and `CLOSE_DOOR=2`.

Generated type/deployment findings:

- `DoorCommand` is generated as `CommonAPI::Enumeration<uint8_t>`.
- `DoorCommandDeployment_t` is `CommonAPI::SomeIP::EnumerationDeployment<uint8_t>`.
- `CarDoorsCommand` is generated as `CommonAPI::Struct<DoorCommand, DoorCommand, DoorCommand, DoorCommand>`.
- `CarDoorsCommandDeployment_t` is a `StructDeployment` of four `DoorCommandDeployment_t` fields.

DoorCommand semantics:

| raw byte | enum | meaning in `getNextStateFromCommand` |
|---:|---|---|
| `00` | `NOTHING` | keep current door state |
| `01` | `OPEN_DOOR` | set door state to open / `true` |
| `02` | `CLOSE_DOOR` | set door state to closed / `false` |

Method 14 request payload encoding estimate:

- The request payload should be exactly four bytes for the normal baseline cases.
- Byte order follows the struct field order: `frontLeftDoor`, `frontRightDoor`, `rearLeftDoor`, `rearRightDoor`.
- Each byte is one `DoorCommand` enum value because the generated enum deployment uses `uint8_t`.
- Method 14 has no output fields, so a normal response is expected to have `retcode=0x00`, `msg_type=0x80`, and an empty response payload.

Getter 8 link:

- Getter 8 is `doorsOpeningStatus` via `SomeIpGetterID = 8`.
- Its return type is `PlaygroundTypes.DoorsStatus`.
- `DoorsStatus` is generated as `CommonAPI::Struct<bool, bool, bool, bool>` with field order `frontLeft`, `frontRight`, `rearLeft`, `rearRight`.
- The completed getter probe observed Getter 8 response payload `00000000`, which matches four false/closed boolean fields in this runtime state.
- Method 14 should therefore be evaluated by `Getter 8 before -> Method 14 -> Getter 8 after`, comparing the four-byte Getter 8 payload rather than trusting Method 14 `normal_response` alone.

Normal baseline payload candidates:

| label | Method 14 payload | command tuple | expected Getter 8 after | purpose |
|---|---|---|---|---|
| `open_all` | `01010101` | open all four doors | `01010101` | primary non-trivial state-change baseline |
| `close_all` | `02020202` | close all four doors | `00000000` | reset / closed-state baseline |
| `nothing` | `00000000` | keep all current states | unchanged from Getter 8 before | no-op control |

Safe analysis steps before any Method 14 execution:

1. Confirm the CommonAPI SOME/IP enum encoding width from generated deployment/proxy code or captured valid Method 14 traffic if available.
2. Derive a minimal candidate set only from the public enum structure, for example all `NOTHING`, all `OPEN_DOOR`, all `CLOSE_DOOR`, and one-door-at-a-time changes.
3. For each candidate, record the expected semantic command tuple separately from the raw `payload_hex`.
4. Use getter 8 before/after as the only state oracle; do not treat Method 14 `normal_response` alone as success.
5. Add a separate `--execute-method14` gate only after this payload mapping is documented and reviewed.

## 3. Normal vs Abnormal Enum Payloads

Normal enum payloads should be generated from the public type shape only:

- `CarDoorsCommand` has four door command fields.
- Each field is a `DoorCommand`.
- Public enum values are `NOTHING=0`, `OPEN_DOOR=1`, and `CLOSE_DOOR=2`.

Abnormal enum payloads should keep the same broad message target but vary values outside the public enum range or use boundary-style byte patterns, for example all-zero, all-one, all-two, mixed valid values, values such as `3`, `255`, truncated payloads, extended payloads, and repeated structured patterns.

Do not use server internal branch logic, state variable names, or implementation-specific parsing assumptions in the prompt.

## 4. Fair Radamsa vs LLM Conditions

Compare Radamsa and LLM under identical external conditions:

- Same target service, endpoint, method IDs, timeout, and retry policy.
- Same number of candidate payloads and same repeat count per candidate.
- Same baseline CSV and same baseline-difference definition.
- Same getter-before/setter/getter-after validation sequence.
- Same CSV schema and same metric script.
- Same payload length limits, unless the experiment explicitly reports a separate length-ablation run.

The LLM may receive public interface information and previous black-box feedback only. Radamsa should receive comparable seed material derived from public interface payload shapes and observed valid traffic, not server source.

## 5. Result Metrics

Report at least:

- `baseline_different_normal_response_count`
- `state_changed_count`
- `timeout_count`
- `error_response_count`
- latency `avg`, `max`, and `p95`
- `unique_payload_count`

For stateful validation, also report:

- getter success count
- setter normal response count
- `state_unchanged_count`
- `unknown_count`
- unique before/after getter payload counts

## 6. Difference from Current Method 10 Result

The method 10 candidate is reproducibly accepted by the server: 30/30 replay trials returned `normal_response`. However, method 9 getter before/after checks showed no observable payload change in 10/10 trials.

Method 14 should be evaluated differently because its public purpose is to change door state, and method 8 is the matching public getter. A successful method 14 result should therefore be judged not only by `normal_response`, but by a reproducible before/after change in method 8 getter payload.

## 7. Short Report Text

The current LLM-generated method 10 candidate was accepted reliably by the target service, but no externally observable state change was confirmed through the corresponding getter. Therefore, we treat it as an interesting accepted input rather than confirmed state-changing behavior. The next planned experiment targets method 14 because its intended effect can be validated with a public getter-before/setter/getter-after sequence, preserving the black-box feedback-guided setting.
