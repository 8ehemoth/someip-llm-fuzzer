# All Method Fuzz Result Report

Input summary: `results/all_method_fuzz_summary_20260506_140150.csv`
Input detail: `results/all_method_fuzz_detail_20260506_140150.csv`

## 핵심 해석

- Getter 계열(Method 1~9, 11)은 상태 변경 대상이 아니므로 response classification 중심으로 본다.
- Setter/State-changing Method(Method 10, 12, 14)는 paired Getter before/after payload 비교가 핵심이다.
- `normal_response`는 프로토콜 레벨에서 요청이 수락됐다는 뜻이고, `non_trivial_state_effect`는 reset 이후 공개 Getter payload가 실제로 바뀌었다는 뜻이다. 둘은 같은 지표가 아니다.

## Method Summary

| method_id | method_name | role | total_candidates | total_trials | normal_response_count | error_response_count | timeout_count | state_changed_count | non_trivial_state_effect_count | reproducible_non_trivial_state_effect_count | classification_counts |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | getConsumptionAttribute | getter | 14 | 140 | 140 | 0 | 0 | 0 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 2 | getCapacityAttribute | getter | 14 | 140 | 140 | 0 | 0 | 0 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 3 | getVolumeAttribute | getter | 14 | 140 | 140 | 0 | 0 | 0 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 4 | getEngineSpeedAttribute | getter | 14 | 140 | 140 | 0 | 0 | 0 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 5 | getCurrentGearAttribute | getter | 14 | 140 | 140 | 0 | 0 | 0 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 6 | getIsReverseGearOnAttribute | getter | 14 | 140 | 140 | 0 | 0 | 0 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 7 | getDrivePowerTransmissionAttribute | getter | 14 | 140 | 140 | 0 | 0 | 0 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 8 | getDoorsOpeningStatusAttribute | getter | 14 | 140 | 140 | 0 | 0 | 0 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 9 | getSeatHeatingStatusAttribute | getter | 14 | 140 | 140 | 0 | 0 | 0 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 10 | setSeatHeatingStatusAttribute | setter | 15 | 150 | 110 | 40 | 0 | 90 | 90 | 9 | protocol_valid_no_state_effect=2;rejected_or_error=4;reproducible_non_trivial_state_effect=9 |
| 11 | getSeatHeatingLevelAttribute | getter | 14 | 140 | 140 | 0 | 0 | 0 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 12 | setSeatHeatingLevelAttribute | setter | 15 | 150 | 110 | 40 | 0 | 90 | 90 | 9 | protocol_valid_no_state_effect=2;rejected_or_error=4;reproducible_non_trivial_state_effect=9 |
| 13 | initTirePressureCalibration | method | 14 | 140 | 140 | 0 | 0 | 0 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 14 | changeDoorsState | method | 16 | 160 | 140 | 20 | 0 | 100 | 100 | 10 | protocol_valid_no_state_effect=4;rejected_or_error=2;reproducible_non_trivial_state_effect=10 |

## Getter Methods

| method_id | method_name | total_candidates | total_trials | normal_response_count | error_response_count | timeout_count | classification_counts |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | getConsumptionAttribute | 14 | 140 | 140 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 2 | getCapacityAttribute | 14 | 140 | 140 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 3 | getVolumeAttribute | 14 | 140 | 140 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 4 | getEngineSpeedAttribute | 14 | 140 | 140 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 5 | getCurrentGearAttribute | 14 | 140 | 140 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 6 | getIsReverseGearOnAttribute | 14 | 140 | 140 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 7 | getDrivePowerTransmissionAttribute | 14 | 140 | 140 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 8 | getDoorsOpeningStatusAttribute | 14 | 140 | 140 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 9 | getSeatHeatingStatusAttribute | 14 | 140 | 140 | 0 | 0 | protocol_valid_no_state_effect=14 |
| 11 | getSeatHeatingLevelAttribute | 14 | 140 | 140 | 0 | 0 | protocol_valid_no_state_effect=14 |

## Setter / State-Changing Methods

| method_id | method_name | total_candidates | total_trials | normal_response_count | state_changed_count | non_trivial_state_effect_count | reproducible_non_trivial_state_effect_count | classification_counts |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | setSeatHeatingStatusAttribute | 15 | 150 | 110 | 90 | 90 | 9 | protocol_valid_no_state_effect=2;rejected_or_error=4;reproducible_non_trivial_state_effect=9 |
| 12 | setSeatHeatingLevelAttribute | 15 | 150 | 110 | 90 | 90 | 9 | protocol_valid_no_state_effect=2;rejected_or_error=4;reproducible_non_trivial_state_effect=9 |
| 14 | changeDoorsState | 16 | 160 | 140 | 100 | 100 | 10 | protocol_valid_no_state_effect=4;rejected_or_error=2;reproducible_non_trivial_state_effect=10 |

## Method 13

| method_id | method_name | total_candidates | total_trials | normal_response_count | error_response_count | timeout_count | classification_counts |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 13 | initTirePressureCalibration | 14 | 140 | 140 | 0 | 0 | protocol_valid_no_state_effect=14 |

## High Value Candidates

Method 10/12/14 후보 중 모든 trial에서 `non_trivial_state_effect=True`인 항목이다.

| method_id | payload_label | payload_hex | trials | normal_response_count | state_changed_count | non_trivial_state_effect_count | before_payload_distribution | after_payload_distribution |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | all_false | 0000000700000000000000 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000700000000000000=10 |
| 10 | all_true | 0000000701010101010101 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000701010101010101=10 |
| 10 | alternating | 0000000700ff00ff00ff00 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000700010001000100=10 |
| 10 | baseline_status | 0000000701000100010001 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000701000100010001=10 |
| 10 | invalid_enum_2 | 0000000702020202020202 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000700000000000000=10 |
| 10 | invalid_enum_ff | 00000007ffffffffffffff | 10 | 10 | 10 | 10 | 00000000=10 | 0000000701010101010101=10 |
| 10 | len_field_one | 0000000101000100010001 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000101=10 |
| 10 | long_padding_ff | 0000000701000100010001ffffffff | 10 | 10 | 10 | 10 | 00000000=10 | 0000000701000100010001=10 |
| 10 | long_padding_zero | 00000007010001000100010000000000 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000701000100010001=10 |
| 12 | all_one | 0000000701010101010101 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000701010101010101=10 |
| 12 | all_three | 0000000703030303030303 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000703030303030303=10 |
| 12 | all_two | 0000000702020202020202 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000702020202020202=10 |
| 12 | all_zero | 0000000700000000000000 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000700000000000000=10 |
| 12 | baseline_level | 0000000701020300010203 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000701020300010203=10 |
| 12 | boundary_values | 00000007ff7f8000010203 | 10 | 10 | 10 | 10 | 00000000=10 | 00000007ff7f8000010203=10 |
| 12 | len_field_one | 0000000101020300010203 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000101=10 |
| 12 | long_padding_ff | 0000000701020300010203ffffffff | 10 | 10 | 10 | 10 | 00000000=10 | 0000000701020300010203=10 |
| 12 | long_padding_zero | 000000070102030001020300000000 | 10 | 10 | 10 | 10 | 00000000=10 | 0000000701020300010203=10 |
| 14 | long_one_extra_zero | 0101010100 | 10 | 10 | 10 | 10 | 00000000=10 | 01010101=10 |
| 14 | long_padding_ff | 01010101ffffffff | 10 | 10 | 10 | 10 | 00000000=10 | 01010101=10 |
| 14 | long_prefix_zero | 00000001010101 | 10 | 10 | 10 | 10 | 00000000=10 | 00000001=10 |
| 14 | mixed_open_close_1 | 01020102 | 10 | 10 | 10 | 10 | 00000000=10 | 01000100=10 |
| 14 | mixed_open_close_2 | 02010102 | 10 | 10 | 10 | 10 | 00000000=10 | 00010100=10 |
| 14 | open_all | 01010101 | 10 | 10 | 10 | 10 | 00000000=10 | 01010101=10 |
| 14 | open_front_left | 01000000 | 10 | 10 | 10 | 10 | 00000000=10 | 01000000=10 |
| 14 | open_front_pair | 01010000 | 10 | 10 | 10 | 10 | 00000000=10 | 01010000=10 |
| 14 | open_front_right_and_rear_left | 00010100 | 10 | 10 | 10 | 10 | 00000000=10 | 00010100=10 |
| 14 | open_rear_pair | 00000101 | 10 | 10 | 10 | 10 | 00000000=10 | 00000101=10 |

## Method 14 Protocol-Valid No-Effect Candidates

Method 14에서 `normal_response`는 있었지만 non-trivial state effect가 없었던 후보이다.

| payload_label | payload_hex | trials | normal_response_count | state_changed_count | reset_equivalent_count | after_payload_distribution | classification |
| --- | --- | --- | --- | --- | --- | --- | --- |
| boundary_ff_all | ffffffff | 10 | 10 | 0 | 10 | 00000000=10 | protocol_valid_no_state_effect |
| close_all_reset_equivalent | 02020202 | 10 | 10 | 0 | 10 | 00000000=10 | protocol_valid_no_state_effect |
| invalid_enum_3_all | 03030303 | 10 | 10 | 0 | 10 | 00000000=10 | protocol_valid_no_state_effect |
| nothing | 00000000 | 10 | 10 | 0 | 10 | 00000000=10 | protocol_valid_no_state_effect |
