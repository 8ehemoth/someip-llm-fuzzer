# Method 14 `changeDoorsState` Baseline 검증

## 1. Method 14 입력 타입 및 SOME/IP payload 구조

소스코드 기준 Method 14는 `changeDoorsState`이며 입력 타입은 `PlaygroundTypes.CarDoorsCommand`이다.

정의 위치:

- `test-someip-service/franca/org/genivi/vehicle/playground.fidl`
- `test-someip-service/franca/org/genivi/vehicle/playgroundTypes.fidl`
- `test-someip-service/franca/org/genivi/vehicle/playground.fdepl`
- `test-someip-service/commonapi-wrappers/generated/org.genivi.vehicle.playground/someip/common/org/genivi/vehicle/playgroundtypes/PlaygroundTypesSomeIPDeployment.hpp`

`CarDoorsCommand`는 `DoorCommand` 4개로 구성된다.

| 순서 | 필드 | 타입 |
|---:|---|---|
| 1 | `frontLeftDoor` | `DoorCommand` |
| 2 | `frontRightDoor` | `DoorCommand` |
| 3 | `rearLeftDoor` | `DoorCommand` |
| 4 | `rearRightDoor` | `DoorCommand` |

`DoorCommand` 값은 다음과 같다.

| 값 | 의미 |
|---:|---|
| `0x00` | `NOTHING` |
| `0x01` | `OPEN_DOOR` |
| `0x02` | `CLOSE_DOOR` |

generated SOME/IP deployment에서 `DoorCommandDeployment_t`는 `EnumerationDeployment<uint8_t>`이므로 Method 14 입력 payload는 4바이트로 구성된다.

예:

| 목적 | Method 14 payload |
|---|---|
| 모든 문 열기 | `01010101` |
| 모든 문 닫기 | `02020202` |
| 현재 상태 유지 | `00000000` |

## 2. Getter 8 응답 payload 구조

Getter 8은 `getDoorsOpeningStatusAttribute`이며 `doorsOpeningStatus` attribute를 반환한다.

응답 타입은 `PlaygroundTypes.DoorsStatus`이다.

| 순서 | 필드 | 타입 |
|---:|---|---|
| 1 | `frontLeft` | `Boolean` |
| 2 | `frontRight` | `Boolean` |
| 3 | `rearLeft` | `Boolean` |
| 4 | `rearRight` | `Boolean` |

실제 baseline 결과에서 Getter 8 응답 payload는 4바이트 Boolean 배열처럼 관측되었다.

| 상태 | Getter 8 payload |
|---|---|
| 모든 문 닫힘 | `00000000` |
| 모든 문 열림 | `01010101` |

## 3. Door 상태 reset 방법

Door 상태 reset은 Method 14에 모든 문 닫기 명령을 보내는 방식으로 정의한다.

| 항목 | 값 |
|---|---|
| Reset Method | Method 14 `changeDoorsState` |
| Reset payload | `02020202` |
| Reset 후 Getter 8 기대값 | `00000000` |

이 reset은 각 trial 전에 수행하는 reset-before 조건으로 사용한다.

## 4. Baseline 후보

baseline 검증에는 다음 후보를 사용하였다.

파일:

- `results/method14_baseline_candidates_20260505.csv`

| Payload label | Method 14 payload | Expected Getter 8 after | 기대 분류 |
|---|---|---|---|
| `open_all` | `01010101` | `01010101` | non-trivial state effect |
| `close_all_reset_equivalent` | `02020202` | `00000000` | trivial reset-equivalent |
| `nothing` | `00000000` | `00000000` | trivial reset-equivalent |

## 5. Baseline 실행 결과

실행 파일:

- detail: `results/method14_baseline_state_effect_20260505.csv`
- summary: `results/method14_baseline_state_effect_summary_20260505.csv`

전체 결과:

| 항목 | 값 |
|---|---:|
| 후보 수 | 3 |
| Trial 수 | 9 |
| `setter_normal_count` | 9 |
| `getter_success_count` | 9 |
| `state_changed_count` | 3 |
| `reset_equivalent_count` | 6 |
| `non_trivial_state_effect_count` | 3 |
| `unknown_count` | 0 |

후보별 요약:

| Payload label | Trials | Before Getter 8 | After Getter 8 | `state_changed_count` | `target_state_reached_count` | `reset_equivalent_count` | `non_trivial_state_effect_count` | Classification |
|---|---:|---|---|---:|---:|---:|---:|---|
| `open_all` | 3 | `00000000=3` | `01010101=3` | 3 | 3 | 0 | 3 | `reproducible_non_trivial_state_effect` |
| `close_all_reset_equivalent` | 3 | `00000000=3` | `00000000=3` | 0 | 3 | 3 | 0 | `trivial_reset_equivalent` |
| `nothing` | 3 | `00000000=3` | `00000000=3` | 0 | 3 | 3 | 0 | `trivial_reset_equivalent` |

## 6. Checker 확장 내용

`scripts/check_candidate_state_effect.py`를 Method 14와 Getter 8 조합도 처리할 수 있도록 확장하였다.

주요 변경 사항:

- Method 14 -> Getter 8 매핑 추가
- Method 14 reset payload 기본값 `02020202` 추가
- candidate CSV의 `expected_after_payload_hex` 컬럼 지원
- detail CSV에 다음 지표 추가
  - `reset_equivalent`
  - `non_trivial_state_effect`
  - `classification`
- summary CSV에 다음 집계 추가
  - `reset_equivalent_count`
  - `reset_equivalent_rate`
  - `non_trivial_state_effect_count`
  - `non_trivial_state_effect_rate`
  - `reproducible_non_trivial_state_effect`

기존 지표도 유지하였다.

- `state_changed`
- `target_state_reached`
- `reset_equivalent`
- `non_trivial_state_effect`
- `classification`

## 7. 결론

Method 14 `changeDoorsState`는 baseline payload `01010101`을 통해 `doorsOpeningStatus`를 실제로 변경할 수 있음이 확인되었다.

reset-before 조건에서 Getter 8 before 값은 `00000000`이었고, Method 14 `01010101` 호출 후 Getter 8 after 값은 `01010101`로 변경되었다. 이 결과는 3회 trial에서 모두 재현되었다.

따라서 Method 14는 이후 fuzzing 후보 평가 대상으로 사용할 수 있으며, 후보 평가는 단순 정상 응답이 아니라 Getter 8 before/after 기반 `non_trivial_state_effect_count` 중심으로 수행한다.
