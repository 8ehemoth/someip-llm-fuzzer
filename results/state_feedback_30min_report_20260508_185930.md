# SOME/IP State Feedback Fuzzer Report

Target methods: `10,12,14`.

Profiles: Method 10->Getter 9, Method 12->Getter 11, Method 14->Getter 8.

Primary metric: `non_trivial_state_effect_count`. Final high-value metric: `reproducible_non_trivial_state_effect_count`.

Mode: `execute`. OpenAI API requested: `False`.

## Round Summary

| round | target_methods | candidates | normal_response_count | error_response_count | non_trivial_state_effect_count | reproducible_non_trivial_state_effect_count |
|---:|---|---:|---:|---:|---:|---:|
| 1 | 10,12,14 | 90 | 111 | 159 | 78 | 26 |
| 2 | 10,12,14 | 90 | 114 | 156 | 84 | 28 |
| 3 | 10,12,14 | 90 | 114 | 156 | 84 | 28 |

## Trend

The feedback loop improved the state-effect signal across rounds.

## High-Value Final Candidates

Final reproducible high-value candidate count: `30`.

### High-value payload examples

| method_id | payload_label | payload_hex | classification | normal | non_trivial |
|---:|---|---|---|---:|---:|
| 12 | m12_double_00000001 | `0000000100000001` | reproducible_non_trivial_state_effect | 3 | 3 |
| 12 | m12_suffix_ff_00000001 | `00000001ff` | reproducible_non_trivial_state_effect | 3 | 3 |
| 12 | m12_suffix_zero_00000001 | `0000000100` | reproducible_non_trivial_state_effect | 3 | 3 |
| 14 | m14_baseline_open_all | `01010101` | reproducible_non_trivial_state_effect | 3 | 3 |
| 14 | m14_byte0_0_01010101 | `00010101` | reproducible_non_trivial_state_effect | 3 | 3 |
| 14 | m14_byte0_255_01010101 | `ff010101` | reproducible_non_trivial_state_effect | 3 | 3 |
| 14 | m14_byte0_2_01010101 | `02010101` | reproducible_non_trivial_state_effect | 3 | 3 |
| 14 | m14_byte0_3_01010101 | `03010101` | reproducible_non_trivial_state_effect | 3 | 3 |
| 14 | m14_byte1_0_01010101 | `01000101` | reproducible_non_trivial_state_effect | 3 | 3 |
| 14 | m14_byte1_255_01010101 | `01ff0101` | reproducible_non_trivial_state_effect | 3 | 3 |

### Protocol-valid no-effect payload examples

| method_id | payload_label | payload_hex | classification | normal | non_trivial |
|---:|---|---|---|---:|---:|
| 10 | m10_status_off_zero | `00000000` | protocol_valid_no_effect | 3 | 0 |
| 10 | m10_suffix_ff_00000000 | `00000000ff` | protocol_valid_no_effect | 3 | 0 |
| 10 | m10_suffix_zero_00000000 | `0000000000` | protocol_valid_no_effect | 3 | 0 |
| 12 | m12_level_0_u32 | `00000000` | protocol_valid_no_effect | 3 | 0 |
| 12 | m12_prefix_zero_00000001 | `0000000001` | protocol_valid_no_effect | 3 | 0 |
| 12 | m12_suffix_ff_00000000 | `00000000ff` | protocol_valid_no_effect | 3 | 0 |
| 12 | m12_suffix_zero_00000000 | `0000000000` | protocol_valid_no_effect | 3 | 0 |
| 14 | m14_boundaryff_all | `ffffffff` | protocol_valid_no_effect | 3 | 0 |
| 14 | m14_invalid3_all | `03030303` | protocol_valid_no_effect | 3 | 0 |
| 14 | m14_reset_close_all | `02020202` | protocol_valid_no_effect | 3 | 0 |

### Error payload examples

| method_id | payload_label | payload_hex | classification | normal | non_trivial |
|---:|---|---|---|---:|---:|
| 10 | m10_byte0_255_01000000 | `ff000000` | rejected_or_error | 0 | 0 |
| 10 | m10_byte0_2_01000000 | `02000000` | rejected_or_error | 0 | 0 |
| 10 | m10_byte0_3_01000000 | `03000000` | rejected_or_error | 0 | 0 |
| 10 | m10_byte1_1_01000000 | `01010000` | rejected_or_error | 0 | 0 |
| 10 | m10_byte1_255_01000000 | `01ff0000` | rejected_or_error | 0 | 0 |
| 10 | m10_byte1_2_01000000 | `01020000` | rejected_or_error | 0 | 0 |
| 10 | m10_byte1_3_01000000 | `01030000` | rejected_or_error | 0 | 0 |
| 10 | m10_byte2_1_01000000 | `01000100` | rejected_or_error | 0 | 0 |
| 10 | m10_byte2_255_01000000 | `0100ff00` | rejected_or_error | 0 | 0 |
| 10 | m10_byte2_2_01000000 | `01000200` | rejected_or_error | 0 | 0 |

## Radamsa Baseline

Existing Radamsa comparison source: `results/method14_llm_vs_radamsa_summary_20260506_144843.csv`

| source | unique_payload_count | normal_response_count | error_response_count | non_trivial_state_effect_count | reproducible_non_trivial_state_effect_count |
|---|---:|---:|---:|---:|---:|
| radamsa_example | 11 | 90 | 20 | 30 | 3 |

## Limitation

This is state-aware fuzzing. The goal is to find payloads that produce externally observable paired-getter state effects after reset. It is not a crash/hang campaign, and `normal_response_count` alone is not treated as success.
