# Method 14 LLM Feedback Fuzzer Report

Target: Method 14 `changeDoorsState`, paired Getter 8 `getDoorsOpeningStatusAttribute`.

Reset payload: `02020202`; expected reset Getter 8 payload: `00000000`; baseline open payload: `01010101`.

Primary metric: `non_trivial_state_effect_count`. Final high-value metric: `reproducible_non_trivial_state_effect_count`.

Mode: `dry-run`. OpenAI API requested: `False`.

## Round Summary

| round | candidates | normal_response_count | error_response_count | non_trivial_state_effect_count | reproducible_non_trivial_state_effect_count |
|---:|---:|---:|---:|---:|---:|
| 1 | 5 | 0 | 0 | 0 | 0 |

## Trend

The feedback loop did not improve the state-effect signal across rounds.

## High-Value Final Candidates

Final reproducible high-value candidate count: `0`.

### High-value payload examples

| payload_label | payload_hex | classification | normal | non_trivial |
|---|---|---|---:|---:|
| none |  |  |  |  |

### Protocol-valid no-effect payload examples

| payload_label | payload_hex | classification | normal | non_trivial |
|---|---|---|---:|---:|
| none |  |  |  |  |

### Error payload examples

| payload_label | payload_hex | classification | normal | non_trivial |
|---|---|---|---:|---:|
| none |  |  |  |  |

## Radamsa Baseline

Existing Radamsa comparison source: `results/method14_llm_vs_radamsa_summary_20260506_150411.csv`

| source | unique_payload_count | normal_response_count | error_response_count | non_trivial_state_effect_count | reproducible_non_trivial_state_effect_count |
|---|---:|---:|---:|---:|---:|
| radamsa_real | 100 | 870 | 130 | 210 | 21 |

## Limitation

This is state-aware fuzzing. The goal is to find payloads that produce externally observable Getter 8 state effects after reset. It is not a crash/hang campaign, and `normal_response_count` alone is not treated as success.
