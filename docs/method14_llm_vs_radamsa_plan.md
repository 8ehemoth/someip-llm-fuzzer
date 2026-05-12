# Method 14 LLM vs Radamsa Plan

## Purpose

Compare LLM-generated and Radamsa-generated Method 14 `changeDoorsState` payloads under identical replay and state-validation conditions.

The comparison target is not raw protocol acceptance alone. The primary outcome is whether a candidate produces a reproducible non-trivial state effect observable through Getter 8 `doorsOpeningStatus`.

## Why Method 14 First

Method 14 has a clear public input type, `CarDoorsCommand`, and a clear public state oracle:

- target method: `14` / `changeDoorsState`
- paired getter: `8` / `getDoorsOpeningStatusAttribute`
- reset payload: `02020202`
- reset-expected Getter 8 payload: `00000000`
- baseline open payload: `01010101`

Baseline validation confirmed:

- `01010101`: Getter 8 changes `00000000 -> 01010101`
- `02020202`: Getter 8 changes open state back to `00000000`
- `00000000`: no state change

This makes Method 14 a better first comparison target than methods where no external paired getter exists.

## Candidate Sources

LLM candidates should be structure-aware and derived from the public `CarDoorsCommand` shape: four `DoorCommand` bytes in field order.

Radamsa candidates should be treated as mutation outputs over a comparable seed corpus, such as `01010101`, `02020202`, `00000000`, and short/long variants. The comparison script does not run the Radamsa binary automatically. It reads a candidate CSV so generated payloads can be audited and replayed under the same conditions.

Future extension only: a `--radamsa-generate` mode could invoke Radamsa over a fixed seed corpus and candidate count, then write a candidate CSV. That mode should remain separate from replay and should record the exact seed file, command, and output count.

## Reset-Before Validation

Each candidate trial uses the same sequence:

1. Send Method 14 reset payload `02020202`.
2. Call Getter 8 and record `reset_after_payload_hex`.
3. Send the candidate Method 14 payload.
4. Call Getter 8 and record `after_payload_hex`.
5. Compute state flags from reset/before/after payloads.

`reset_after_payload_hex` and `before_payload_hex` should both represent the reset-state Getter 8 payload, expected as `00000000`.

## Metrics

Primary comparison order:

1. `reproducible_non_trivial_state_effect_count`
2. `non_trivial_state_effect_count`
3. `normal_response_count`
4. `unique_payload_count`
5. latency metrics

`normal_response` means the SOME/IP request was accepted at protocol level. It does not prove that vehicle state changed. `non_trivial_state_effect` requires a normal response and a Getter 8 after payload that differs from the reset/before state.

## Commands

Create example candidate CSV files:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/compare_method14_llm_radamsa.py --make-example-candidates
```

Dry-run candidate loading:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/compare_method14_llm_radamsa.py \
  --llm-candidates results/method14_llm_candidates_example_<timestamp>.csv \
  --radamsa-candidates results/method14_radamsa_candidates_example_<timestamp>.csv \
  --trial-count 10 \
  --dry-run
```

Execute a small sanity comparison:

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/compare_method14_llm_radamsa.py \
  --llm-candidates results/method14_llm_candidates_example_<timestamp>.csv \
  --radamsa-candidates results/method14_radamsa_candidates_example_<timestamp>.csv \
  --trial-count 1 \
  --execute
```

Default outputs:

```text
results/method14_llm_vs_radamsa_detail_<timestamp>.csv
results/method14_llm_vs_radamsa_summary_<timestamp>.csv
results/method14_llm_vs_radamsa_payload_summary_<timestamp>.csv
```

## Result Interpretation

Start with the source-level summary CSV. Compare LLM and Radamsa using non-trivial state-effect metrics first, not normal response counts.

Then inspect the payload-level summary:

- `reproducible_non_trivial_state_effect`: strongest candidate class; every trial changed Getter 8 away from reset state.
- `unstable_non_trivial_state_effect`: some trials changed state; needs repeat investigation.
- `protocol_valid_no_effect`: request accepted but no non-trivial Getter 8 change.
- `rejected_or_error`: candidate produced protocol errors and no normal response.
- `timeout_or_no_response`: candidate did not receive responses.

Finally use the detail CSV to inspect exact `reset_after_payload_hex`, `after_payload_hex`, retcodes, and latency for each trial.
