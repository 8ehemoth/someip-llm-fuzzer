# 1차 검증 실험 결과 보고

## 1. Method ID 정리

본 실험에서 사용한 Seat Heating 관련 SOME/IP Method ID는 다음과 같다.

| Method ID | 의미 |
|---:|---|
| 10 | `setSeatHeatingStatusAttribute` |
| 9 | `getSeatHeatingStatusAttribute` |
| 12 | `setSeatHeatingLevelAttribute` |
| 11 | `getSeatHeatingLevelAttribute` |

즉, Method 10과 Method 12는 각각 상태값을 설정하는 Setter이며, Method 9와 Method 11은 해당 상태를 다시 확인하는 Getter이다.

## 2. 실험 목적

이번 1차 검증의 목적은 후보 payload가 단순히 정상 응답을 받는지와 실제 서버 상태를 변경하는지를 구분하는 것이다.

기존의 단순 판단 기준인 `rsp_retcode=0x00`은 "프로토콜 레벨에서 정상 응답을 받았다"는 의미에 가깝다. 그러나 정상 응답이 곧 서버 내부 상태 변화로 이어졌다는 뜻은 아니다. 따라서 본 실험에서는 Setter 호출 전후에 Getter를 수행하여, 실제 상태값이 변경되었는지를 별도로 검증하였다.

## 3. 정상 Baseline 검증

정상 baseline payload에 대해서는 reset-before 조건에서 검증을 수행하였다. 이 조건에서는 각 trial 전에 서버 상태를 reset payload로 초기화한 뒤, 정상 Setter payload를 전송하고 Getter before/after 결과를 비교하였다.

검증 결과, 정상 Method 10 및 Method 12 payload는 다음 조건을 만족하였다.

| 검증 항목 | 결과 |
|---|---|
| `state_changed` | 성공 |
| `target_state_reached` | 성공 |

따라서 Getter before/after 기반 검증 방식이 실제 서버 상태 변화를 판별하는 데 유효함을 확인하였다.

## 4. LLM/Radamsa 후보 검증 결과

LLM 및 Radamsa로 생성된 후보 payload에 대해 동일한 방식으로 상태 변화 여부를 검증하였다.

사용한 결과 파일은 다음과 같다.

- `results/replay_candidates_state_effect_grouped_nontrivial_20260505_210213.csv`
- `results/replay_candidates_state_effect_summary_nontrivial_20260505_210213.csv`
- `results/replay_candidates_state_effect_trivial_reset_equivalent_20260505_210213.csv`
- `results/replay_candidates_state_effect_high_value_nontrivial_20260505_210213.csv`

전체 결과 요약은 다음과 같다.

| 항목 | 값 |
|---|---:|
| 후보 수 | 29 |
| Trial 수 | 290 |
| `setter_normal_count` | 290 |
| `getter_success_count` | 290 |
| `state_changed_count` | 0 |
| `non_trivial_state_effect_count` | 0 |
| `high_value_nontrivial_count` | 0 |

세부적으로는 LLM 후보가 Method 10에 대해 16개, Method 12에 대해 11개였으며, Radamsa 후보가 Method 10에 대해 2개였다. 각 후보는 10회씩 반복 검증되었다.

| Payload source | Setter Method ID | 후보 수 | Trial 수 | 정상 Setter 응답 | `state_changed_count` | `target_state_reached_count` | `non_trivial_state_effect_count` |
|---|---:|---:|---:|---:|---:|---:|---:|
| LLM | 10 | 16 | 160 | 160 | 0 | 10 | 0 |
| LLM | 12 | 11 | 110 | 110 | 0 | 10 | 0 |
| Radamsa | 10 | 2 | 20 | 20 | 0 | 0 | 0 |
| **합계** | - | **29** | **290** | **290** | **0** | **20** | **0** |

모든 trial에서 Setter는 정상 응답을 반환했고 Getter도 성공하였다. 그러나 Getter before/after 비교 기준으로 확인한 실제 상태 변화는 발생하지 않았다.

## 5. Trivial Reset-equivalent 처리

검증 과정에서 payload `00000000`은 reset payload와 동일한 값으로 확인되었다. 이 payload는 Getter after 값이 기대값과 같아 `target_state_reached`로 집계될 수 있지만, 이는 새로운 상태 변화를 유발한 것이 아니라 이미 reset 상태와 동일한 값을 다시 설정한 경우이다.

따라서 `00000000` payload는 `trivial_reset_equivalent`로 분류하고, high-value 후보 및 non-trivial 상태 변화 후보에서 제외하였다.

확인된 trivial reset-equivalent 후보는 다음과 같다.

| Payload source | Payload label | Setter Method ID | Getter Method ID | Payload | Trial 수 | `target_state_reached_count` | 분류 |
|---|---|---:|---:|---|---:|---:|---|
| LLM | `tail_4` | 10 | 9 | `00000000` | 10 | 10 | `trivial_reset_equivalent` |
| LLM | `tail_4` | 12 | 11 | `00000000` | 10 | 10 | `trivial_reset_equivalent` |

이 두 경우는 `target_state_reached`가 관측되더라도 실제 상태 변화 후보로 보지 않았다.

## 6. 최종 결론

1차 검증 결과, LLM/Radamsa 후보는 일부 protocol-valid payload를 생성하였다. 전체 290회 trial에서 Setter 정상 응답과 Getter 성공은 모두 확인되었다.

그러나 단순 정상 응답과 실제 서버 상태 변화는 구분되어야 한다. Getter before/after 기반 상태 검증 결과, 현재 기준에서 서버 상태를 실제로 변경하는 non-trivial 후보는 확인되지 않았다.

따라서 본 실험 기준에서 LLM/Radamsa 후보의 최종 판정은 다음과 같다.

> LLM/Radamsa 후보는 protocol-valid payload를 일부 생성했지만, 현재 기준에서 서버 상태를 실제로 변경하는 non-trivial 후보는 확인되지 않음.
