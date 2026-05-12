# SOME/IP State Feedback Fuzzer Report

Target methods: `10,12,14`.

Profiles: Method 10->Getter 9, Method 12->Getter 11, Method 14->Getter 8.

Primary metric: `non_trivial_state_effect_count`. Final high-value metric: `reproducible_non_trivial_state_effect_count`.

Mode: `dry-run`. OpenAI API requested: `False`.

## Round Summary

| round | target_methods | candidates | normal_response_count | error_response_count | non_trivial_state_effect_count | reproducible_non_trivial_state_effect_count |
|---:|---|---:|---:|---:|---:|---:|
| 1 | 10,12,14 | 150 | 0 | 0 | 0 | 0 |
| 2 | 10,12,14 | 150 | 0 | 0 | 0 | 0 |
| 3 | 10,12,14 | 150 | 0 | 0 | 0 | 0 |

## Trend

The feedback loop did not improve the state-effect signal across rounds.

## High-Value Final Candidates

Final reproducible high-value candidate count: `0`.

### High-value payload examples

| method_id | payload_label | payload_hex | classification | normal | non_trivial |
|---:|---|---|---|---:|---:|
|  | none |  |  |  |  |

### Protocol-valid no-effect payload examples

| method_id | payload_label | payload_hex | classification | normal | non_trivial |
|---:|---|---|---|---:|---:|
|  | none |  |  |  |  |

### Error payload examples

| method_id | payload_label | payload_hex | classification | normal | non_trivial |
|---:|---|---|---|---:|---:|
|  | none |  |  |  |  |

## Radamsa Baseline

Existing Radamsa comparison source: `results/method14_llm_vs_radamsa_summary_20260506_144843.csv`

| source | unique_payload_count | normal_response_count | error_response_count | non_trivial_state_effect_count | reproducible_non_trivial_state_effect_count |
|---|---:|---:|---:|---:|---:|
| radamsa_example | 11 | 90 | 20 | 30 | 3 |

## Limitation

This is state-aware fuzzing. The goal is to find payloads that produce externally observable paired-getter state effects after reset. It is not a crash/hang campaign, and `normal_response_count` alone is not treated as success.
