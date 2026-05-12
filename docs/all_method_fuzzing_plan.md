# All Defined Method Fuzzing Plan

## Purpose

This experiment fuzzes only request-capable SOME/IP Method IDs defined by the test service source/FDEP: `1..14`.

It is source-informed smoke/state fuzzing, not a blind method-ID sweep. Event/notifier IDs `0x8001..0x800a` are excluded from request fuzzing.

## Method Roles

| role | method IDs | strategy |
|---|---|---|
| Getter | `1,2,3,4,5,6,7,8,9,11` | payload variation, response classification only |
| Setter | `10,12` | reset-before, paired getter before/after state validation |
| Method | `13` | payload variation, response classification only |
| Method | `14` | reset-before, Getter 8 before/after state validation |
| Event/Notifier | `0x8001..0x800a` | excluded from request fuzzing |

## Method Strategies

Getter methods use empty payload as the normal request and a small fixed sanity set: empty, zero/ff values of several lengths, known four-byte patterns, eight zero bytes, and deterministic random four-byte candidates. No state-change decision is computed for getters.

Method 10 targets `setSeatHeatingStatusAttribute`. It uses Method 9 as the paired getter, reset payload `00000000`, and baseline payload `0000000701000100010001`. Candidates include reset, baseline, all false/true, invalid enum-like values, length-field mutations, short payloads, and padded payloads.

Method 12 targets `setSeatHeatingLevelAttribute`. It uses Method 11 as the paired getter, reset payload `00000000`, and baseline payload `0000000701020300010203`. Candidates include reset, baseline, repeated small values, length-field mutations, short payloads, and padded payloads.

Method 13 targets `initTirePressureCalibration`. It has no paired getter, so it is evaluated by response classification only. Its candidates mirror the compact generic payload set used for getters.

Method 14 targets `changeDoorsState`. It uses Getter 8 as the paired getter, reset payload `02020202`, and reset-expected Getter 8 payload `00000000`. Baseline open payload is `01010101`. Candidates include valid door command tuples, mixed open/close commands, invalid enum values, and length variations.

## State Validation

State validation is only applied where a public paired getter exists:

- Method 10: reset Method 10, call Getter 9 before, send candidate, call Getter 9 after.
- Method 12: reset Method 12, call Getter 11 before, send candidate, call Getter 11 after.
- Method 14: reset Method 14, call Getter 8 before, send candidate, call Getter 8 after.

`state_changed=True` means the paired getter payload changed after the candidate. `reset_equivalent=True` means the after payload equals the reset/before payload. `non_trivial_state_effect=True` means the candidate returned a normal response, changed the getter payload, and did not collapse back to the reset-equivalent state.

Getter methods and Method 13 do not compute state-change fields; they are response-classification targets.

## Metrics

Detail CSV rows are per method, candidate, and trial. They capture request payload, response fields, latency, response payload, optional getter before/after payloads, state flags, and errors.

Summary CSV rows are per method. Important fields:

- `normal_response_count`: trials with protocol-level normal response.
- `error_response_count`: trials with a SOME/IP error response.
- `timeout_count`: trials with no response before timeout.
- `unique_payload_count`: distinct payloads tested for the method.
- `state_changed_count`: stateful trials whose paired getter payload changed.
- `non_trivial_state_effect_count`: stateful trials that changed state beyond reset-equivalent behavior.
- `reproducible_non_trivial_state_effect_count`: candidate count where every trial was non-trivial.
- `classification_counts`: aggregate candidate-level classifications.

## Classification

Candidate-level classification follows:

- `protocol_valid_no_state_effect`: at least one normal response and no non-trivial state effect.
- `reproducible_non_trivial_state_effect`: all trials have non-trivial state effect.
- `unstable_non_trivial_state_effect`: some but not all trials have non-trivial state effect.
- `rejected_or_error`: error responses and no normal responses.
- `timeout_or_no_response`: timeouts and no normal responses.

## Commands

Dry-run all methods:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/fuzz_all_defined_methods.py --method all --dry-run
```

Dry-run Method 14 only:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/fuzz_all_defined_methods.py --method 14 --dry-run
```

Small sanity execution for one method:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/fuzz_all_defined_methods.py \
  --method 14 \
  --trial-count 1 \
  --max-candidates 5 \
  --execute
```

Full configured run:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/fuzz_all_defined_methods.py \
  --method all \
  --trial-count 10 \
  --execute
```

Default output paths:

```text
results/all_method_fuzz_detail_<timestamp>.csv
results/all_method_fuzz_summary_<timestamp>.csv
```

## Result Interpretation

First check the summary CSV for methods with timeouts, error responses, or non-trivial state effects. Then inspect matching detail CSV rows for exact payloads, response payloads, and before/after getter payloads.

For getters and Method 13, useful findings are unexpected normal responses for non-empty payloads, error responses, malformed responses, or timeouts.

For Methods 10, 12, and 14, useful findings are candidates classified as `reproducible_non_trivial_state_effect` or `unstable_non_trivial_state_effect`, because those payloads have externally observable state impact through the public paired getter.
