# 다음 실험 확장 계획

## 1. 현재 결과의 한계

1차 검증 실험에서는 LLM/Radamsa 후보에 대해 정상 응답 여부와 실제 서버 상태 변화 여부를 분리해서 확인하였다. 그 결과, 단순 `rsp_retcode=0x00` 기준으로는 protocol-valid payload가 일부 확인되었지만, Getter before/after 기준에서 서버 상태를 실제로 변경하는 non-trivial state effect 후보는 확인되지 않았다.

현재 결과의 한계는 다음과 같다.

| 한계 | 내용 |
|---|---|
| 후보 수 제한 | 검증 후보가 29개로 작아 탐색 공간을 충분히 커버하지 못함 |
| Method 범위 제한 | Method 10/12만 검증했으며, 다른 상태 변경 Method는 포함하지 않음 |
| Payload 생성 제한 | LLM/Radamsa 기반 payload 생성 방식이 아직 제한적이며 구조적 다양성이 부족함 |
| 상태 변화 후보 부재 | 현재 기준에서 non-trivial state effect 후보는 확인되지 않음 |

따라서 다음 실험은 후보 수, 대상 Method, payload 생성 전략, 상태 추적 구조를 모두 확장하는 방향으로 진행한다.

## 2. 다음 실험 방향

다음 단계에서는 단순 정상 응답 후보 수를 늘리는 것이 아니라, 실제 서버 상태를 바꾸는 후보를 찾는 방향으로 실험 설계를 확장한다.

| 확장 항목 | 계획 |
|---|---|
| 후보 수 확장 | 후보 payload 수를 수백~수천 개 규모로 확대 |
| 대상 Method 확장 | Method 10/12뿐 아니라 Method 14 `changeDoorsState`도 포함 |
| 초기 조건 유지 | reset-before 조건을 유지하여 trial 간 상태 오염을 방지 |
| Sequence 정보 저장 | 상태 변화가 발생하기 전 previous sequence를 저장하는 구조 추가 |
| 평가 지표 변경 | `normal_response_count` 중심 평가에서 `non_trivial_state_effect_count` 중심 평가로 변경 |

특히 reset-before 조건은 다음 실험에서도 유지한다. 각 trial 전에 서버 상태를 기준 상태로 초기화해야 payload 자체의 효과와 이전 trial의 잔여 상태 효과를 분리할 수 있기 때문이다.

또한 상태 변화가 단일 payload가 아니라 이전 호출 sequence의 영향을 받을 가능성도 고려해야 한다. 따라서 후보 replay 결과에는 해당 후보 실행 직전의 previous sequence를 함께 저장하여, 재현 가능한 상태 변화 조건을 추적할 수 있도록 한다.

## 3. 추가 평가 지표

다음 실험에서는 정상 응답 여부를 계속 기록하되, 최종 ranking 및 high-value 후보 선정 기준은 실제 상태 변화 중심으로 변경한다.

추가 또는 유지할 주요 지표는 다음과 같다.

| 지표 | 의미 |
|---|---|
| `normal_response_count` | Setter 또는 대상 Method 호출이 정상 응답을 반환한 횟수 |
| `target_state_reached_count` | 실행 후 Getter 결과가 기대 상태와 일치한 횟수 |
| `reset_equivalent_count` | 결과가 reset 상태와 동일해 trivial reset-equivalent로 판단된 횟수 |
| `non_trivial_state_effect_count` | reset-equivalent가 아니면서 실제 서버 상태 변화가 확인된 횟수 |
| `reproducible_non_trivial_state_effect_count` | 반복 trial에서 재현 가능하게 non-trivial 상태 변화가 확인된 횟수 |

이 중 `normal_response_count`는 protocol-valid 여부를 판단하는 보조 지표로 사용한다. 핵심 평가지표는 `non_trivial_state_effect_count`와 `reproducible_non_trivial_state_effect_count`로 둔다.

## 4. 최종 목표

다음 실험의 최종 목표는 단순히 정상 응답을 받는 payload를 많이 찾는 것이 아니다.

최종 목표는 다음과 같다.

> 단순 정상 응답 후보가 아니라 서버 상태를 실제로 바꾸는 재현 가능한 후보를 탐색한다.

이를 위해 후보 생성 규모를 확대하고, Method 14 `changeDoorsState`를 포함하며, reset-before 기반 Getter before/after 검증과 previous sequence 저장을 결합한다. 최종적으로는 protocol-valid payload 중에서도 실제 서버 상태에 non-trivial effect를 유발하고 반복 실험에서 재현 가능한 후보를 high-value 후보로 분류한다.
