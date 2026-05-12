# SOME/IP LLM Fuzzer

이 저장소는 `test-someip-service`의 SOME/IP `PlaygroundService`를 대상으로, 단순 crash/hang 탐지가 아니라 **외부에서 관찰 가능한 서버 상태 변화**를 찾기 위한 LLM-assisted 상태 인식 퍼징 워크플로우를 정리한 프로젝트입니다.

핵심 목표는 특정 setter/control method에 payload를 입력한 뒤, paired getter를 통해 서버 상태가 실제로 바뀌었는지 확인하는 것입니다. 따라서 현재 실험에서 가장 중요한 성공 지표는 단순 `normal_response_count`가 아니라, **재현 가능한 non-trivial state effect**입니다.

---

## 1. Project Overview

본 프로젝트는 SOME/IP 기반 차량 서비스 예제인 `PlaygroundService`를 대상으로 payload 후보를 생성하고, 실제 서버 응답과 paired getter 결과를 이용해 상태 변화 여부를 검증합니다.

일반적인 퍼징은 crash, hang, timeout, abnormal response 등을 주요 지표로 봅니다. 하지만 본 실험은 SOME/IP 서비스의 상태 변화 가능성을 확인하는 것이 목적이므로, 아래와 같은 흐름으로 판단합니다.

```text
1. Server VM에서 PlaygroundService 실행
2. Client VM에서 특정 method에 payload 전송
3. 서버가 정상 응답하는지 확인
4. paired getter를 호출하여 상태 변화 확인
5. reset-equivalent 상태와 비교
6. non-trivial state effect 여부 판단
7. 같은 payload를 여러 번 반복하여 재현성 확인
```

현재 핵심 지표는 다음과 같습니다.

| 지표 | 의미 |
|---|---|
| `normal_response_count` | target method가 protocol-level 정상 응답을 반환한 횟수입니다. 참고 지표입니다. |
| `non_trivial_state_effect_count` | payload 입력 후 paired getter 결과가 reset-equivalent 상태에서 벗어난 횟수입니다. 핵심 지표입니다. |
| `reproducible_non_trivial_state_effect_count` | 여러 trial에서 반복적으로 non-trivial state effect가 관찰된 payload 수입니다. 최종 high-value 지표입니다. |
| `protocol_valid_no_effect_count` | target method는 payload를 accept했지만 paired getter에서 의미 있는 상태 변화가 보이지 않은 경우입니다. |

---

## 2. Key Idea

기존 mutation 기반 퍼징은 crash/hang처럼 명확한 실패를 찾는 데 강점이 있지만, SOME/IP 서비스처럼 내부 상태가 getter를 통해서만 드러나는 경우에는 단순 응답 코드만으로 유의미한 결과를 판단하기 어렵습니다.

이 프로젝트는 다음 관점을 사용합니다.

```text
payload candidate 생성
        ↓
target method에 SOME/IP request 전송
        ↓
protocol-level 정상 응답 여부 확인
        ↓
paired getter 호출
        ↓
reset-equivalent 상태와 비교
        ↓
non-trivial state effect 여부 판단
        ↓
재현성 검증 후 high-value candidate 선정
```

즉, “서버가 죽었는가?”보다 “서버가 payload를 받아들인 뒤 외부 getter로 관찰 가능한 상태가 바뀌었는가?”를 더 중요하게 봅니다.

---

## 3. Tested Environment

현재 실험은 아래 환경에서 개발하고 확인했습니다.

| Component | Version / Value |
|---|---|
| OS | Ubuntu 20.04.6 LTS `focal` |
| Kernel | Linux `5.15.0-139-generic` x86_64 |
| Python env | `../miniconda3/envs/someipfuzz/bin/python` |
| Python | `3.7.6` |
| TShark / Wireshark | `3.2.3` |
| Radamsa | `0.8a` |
| CMake | `4.3.2` |
| g++ | Ubuntu `9.4.0` |

주요 Python package는 다음과 같습니다.

| Package | Version |
|---|---|
| `openai` | `1.39.0` |
| `scapy` | git `https://github.com/secdev/scapy.git@8b63d73a17266bae2a61513ea97ded5283a7ccd3` |
| `requests` | `2.31.0` |
| `httpx` | `0.24.1` |
| `httpcore` | `0.17.3` |
| `pydantic` | `2.5.3` |
| `pydantic_core` | `2.14.6` |
| `python-dotenv` | `0.21.1` |
| `tqdm` | `4.67.3` |
| `typing_extensions` | `4.7.1` |
| `anyio` | `3.7.1` |
| `sniffio` | `1.3.1` |
| `h11` | `0.14.0` |
| `idna` | `3.10` |
| `urllib3` | `2.0.7` |
| `charset-normalizer` | `3.4.6` |

재현을 위해 pinned package set을 사용합니다.

```bash
python -m pip install -r requirements.txt
```

---

## 4. System Architecture

본 실험은 VMware 기반 Ubuntu 20.04 VM 2대를 사용합니다.

- **Server VM**  
  SOME/IP 서비스 제공자인 `PlaygroundService`를 실행합니다.
- **Client VM**  
  Python 기반 SOME/IP LLM Fuzzer를 실행하고, Server VM으로 SOME/IP payload를 전송합니다.

```text
[Local OS / Host PC]
└─ VMware Virtual Network: 192.168.40.0/24

┌───────────────────────────────┐        ┌───────────────────────────────┐
│ Client VM                     │        │ Server VM                     │
│ - Directory:                  │        │ - Directory:                  │
│   someip-llm-fuzzer/          │        │   test-someip-service/        │
│ - IP: 192.168.40.135          │ <----> │ - IP: 192.168.40.134          │
│ - UDP port: 58423             │        │ - UDP port: 31000             │
│ - SOME/IP LLM Fuzzer          │        │ - PlaygroundService           │
└───────────────────────────────┘        └───────────────────────────────┘
```

| VM | Directory | 역할 |
|---|---|---|
| Server VM | `~/test-someip-service/` | SOME/IP 타깃 서비스인 `PlaygroundService`를 build하고 실행합니다. |
| Client VM | `~/someip-llm-fuzzer/` | SOME/IP LLM Fuzzer를 실행하고 SOME/IP payload를 전송합니다. |

현재 네트워크 설정은 다음을 기준으로 합니다.

| 역할 | IP | UDP port |
|---|---|---:|
| Server VM / PlaygroundService | `192.168.40.134` | `31000` |
| Client VM / fuzzer source | `192.168.40.135` | `58423` |

> 위 IP는 현재 실험에서 사용한 example network configuration입니다. VM 네트워크를 새로 구성하면 `config.ini`와 `scripts/someip_transport.py`의 IP/port를 함께 수정해야 합니다.

---

## 5. Quick Start

실험은 반드시 아래 순서로 진행합니다.

```text
1. Server VM에서 test-someip-service build
2. Server VM에서 PlaygroundService 실행
3. Client VM에서 someip-llm-fuzzer 환경 설정
4. Client VM에서 dry-run 실행
5. 통신이 확인되면 Client VM에서 real replay 실행
```

최소 실행 흐름은 다음과 같습니다.

```bash
# 1) Server VM
cd ~/test-someip-service
export LD_LIBRARY_PATH="$HOME/usr/lib:$PWD/commonapi-wrappers/playground/lib"
VSOMEIP_CONFIGURATION=vsomeip-server-remote.json \
VSOMEIP_APPLICATION_NAME=playground-service \
./build/PlaygroundService
```

```bash
# 2) Client VM
cd ~/someip-llm-fuzzer
conda activate someipfuzz
python -m pip install -r requirements.txt
```

```bash
# 3) Client VM dry-run
../miniconda3/envs/someipfuzz/bin/python scripts/someip_llm_fuzzer.py \
  --target-methods 10,12,14 \
  --rounds 1 \
  --candidates-per-round 5 \
  --trial-count 1 \
  --final-trial-count 1 \
  --dry-run \
  --output-prefix results/someip_llm_fuzzer_smoke
```

---

## 6. Installation

### 6.1 Server VM Setup

이 절은 **Server VM**에서 수행합니다.

시작 위치는 다음 디렉터리입니다.

```bash
cd ~/test-someip-service
```

Server VM은 SOME/IP service provider 역할을 합니다. 즉, Client VM에서 보내는 SOME/IP 요청을 받아 처리하는 `PlaygroundService`를 실행합니다.

#### 6.1.1 Required Packages and Libraries

Server VM에는 다음 항목이 필요합니다.

- CommonAPI Core Runtime `3.2.x`
- CommonAPI-SomeIP Runtime `3.2.x`
- vSomeIP `3.1.x`
- CMake
- Ninja
- C++ compiler

Ubuntu 20.04에서 기본 build 도구가 없다면 다음을 설치합니다.

```bash
sudo apt update
sudo apt install -y cmake ninja-build g++
```

#### 6.1.2 Server Build

Server VM에서 다음 명령을 실행합니다.

```bash
cd ~/test-someip-service
PREFIX_PATH=$HOME/usr
cmake -G Ninja -S . -B build \
  -DCMAKE_PREFIX_PATH="$PREFIX_PATH"
cmake --build build
```

#### 6.1.3 Run PlaygroundService

Server VM에서 다음 명령을 실행합니다.

```bash
cd ~/test-someip-service
export LD_LIBRARY_PATH="$HOME/usr/lib:$PWD/commonapi-wrappers/playground/lib"
VSOMEIP_CONFIGURATION=vsomeip-server-remote.json \
VSOMEIP_APPLICATION_NAME=playground-service \
./build/PlaygroundService
```

정상적으로 실행되면 Server VM은 UDP port `31000`에서 SOME/IP 요청을 받을 준비가 됩니다.

#### 6.1.4 Check Server Port

Server VM에서 다음 명령으로 UDP port `31000` 리스닝 상태를 확인합니다.

```bash
sudo ss -uapn | grep 31000
```

기대되는 형태는 다음과 같습니다.

```text
192.168.40.134:31000
```

### 6.2 Client VM Setup

이 절은 **Client VM**에서 수행합니다.

시작 위치는 다음 디렉터리입니다.

```bash
cd ~/someip-llm-fuzzer
```

Client VM은 SOME/IP LLM Fuzzer를 실행하고, Server VM의 `PlaygroundService`로 SOME/IP payload를 전송합니다.

#### 6.2.1 Create Python Environment

Client VM에서 conda 환경을 생성합니다.

```bash
conda create -n someipfuzz python=3.7.6
conda activate someipfuzz
```

이미 기존 환경을 사용한다면 다음 경로를 기준으로 실행할 수 있습니다.

```bash
../miniconda3/envs/someipfuzz/bin/python
```

#### 6.2.2 Install Python Packages

Client VM의 `~/someip-llm-fuzzer`에서 실행합니다.

```bash
python -m pip install -r requirements.txt
```

Ubuntu 20.04에서 필요한 도구가 없다면 설치합니다.

```bash
sudo apt update
sudo apt install -y tshark g++ cmake
```

Radamsa baseline을 사용할 경우 Radamsa 설치 여부를 확인합니다.

```bash
radamsa --version
```

---

## 7. Configuration

### 7.1 Server Configuration

현재 remote fuzzing에 사용하는 service config는 다음 파일입니다.

```text
test-someip-service/vsomeip-server-remote.json
```

주요 설정은 다음과 같습니다.

| 항목 | 값 |
|---|---|
| `unicast` | `192.168.40.134` |
| application name | `playground-service` |
| service ID | `0xff40` |
| instance ID | `0x0001` |
| unreliable UDP port | `31000` |
| service discovery | disabled |

### 7.2 Client Configuration

Client VM에서 아래 파일을 확인합니다.

```text
config.ini
scripts/someip_transport.py
```

현재 `config.ini`의 주요 값은 다음과 같습니다.

```ini
[Service]
host = 192.168.40.134
port = 31000

[Client]
host = 192.168.40.135
port = 58423

[Fuzzer]
interface = ens33
trace = data/playground_someip_only.pcap
template = data/playground_fields.json
```

주의: Server VM 또는 Client VM의 IP가 바뀌면 real replay를 실행하기 전에 다음 파일들을 함께 수정해야 합니다.

```text
config.ini
scripts/someip_transport.py
```

### 7.3 `.env` Configuration

Client VM의 `~/someip-llm-fuzzer`에서 실행합니다.

```bash
cp .env.example .env
```

OpenAI planner를 사용할 경우 `.env`에 다음 값을 설정합니다.

```dotenv
OPENAI_API_KEY=...
OPENAI_MODEL=gpt-4.1-mini
SOMEIP_LLM_USE_OPENAI=1
SOMEIP_LLM_TARGET_METHODS=10,12,14
SOMEIP_LLM_HYBRID_FEEDBACK=1
SOMEIP_LLM_HYBRID_LLM_INTERVAL_SEC=3m
SOMEIP_LLM_HYBRID_LLM_CALL_CAP=10
SOMEIP_LLM_HYBRID_STAGNATION_PAYLOADS=200
SOMEIP_LLM_EXECUTE=0
```

주의:

- Dry-run에서는 `SOMEIP_LLM_EXECUTE=0`을 유지합니다.
- Server VM이 실행 중이고 네트워크 통신이 확인된 뒤에만 `SOMEIP_LLM_EXECUTE=1` 또는 `--execute`를 사용합니다.
- API key는 코드, README, 결과 파일, 커밋 메시지에 hardcode하지 않습니다.
- 실제 `.env`는 git에 올리지 않습니다.
- 이 저장소의 `.gitignore`는 `.env`, `.env.*`, 하위 디렉터리의 `.env` 파일을 제외하고 `.env.example`만 허용합니다.

---

## 8. How to Run

### 8.1 Syntax Check

Client VM의 `~/someip-llm-fuzzer`에서 활성 스크립트가 문법적으로 정상인지 확인합니다.

```bash
../miniconda3/envs/someipfuzz/bin/python -m py_compile \
  scripts/someip_llm_fuzzer.py \
  scripts/compare_state_fuzzers.py \
  scripts/check_candidate_state_effect.py \
  scripts/someip_transport.py \
  scripts/generate_baseline_candidates.py \
  scripts/balance_candidates.py \
  scripts/check_payload_format.py \
  scripts/probe_state_effect.py
```

### 8.2 Dry-run

Dry-run은 실제 SOME/IP packet을 전송하지 않고 candidate 생성 및 report 생성 흐름만 확인합니다.

먼저 Client VM에서 dry-run을 실행해 전체 파이프라인이 깨지지 않는지 확인합니다.

```bash
cd ~/someip-llm-fuzzer
../miniconda3/envs/someipfuzz/bin/python scripts/someip_llm_fuzzer.py \
  --target-methods 10,12,14 \
  --rounds 1 \
  --candidates-per-round 5 \
  --trial-count 1 \
  --final-trial-count 1 \
  --dry-run \
  --output-prefix results/someip_llm_fuzzer_smoke
```

조금 더 긴 dry-run은 다음과 같이 실행합니다.

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/someip_llm_fuzzer.py \
  --target-methods 10,12,14 \
  --rounds 3 \
  --candidates-per-round 50 \
  --trial-count 3 \
  --final-trial-count 10 \
  --dry-run \
  --output-prefix results/someip_llm_fuzzer
```

### 8.3 Real Replay

Real replay는 실제로 Client VM에서 Server VM으로 SOME/IP payload를 전송합니다. 따라서 실행 전에 반드시 다음 조건을 만족해야 합니다.

```text
1. Server VM에서 PlaygroundService가 실행 중이어야 함
2. Server VM의 UDP port 31000이 열려 있어야 함
3. Client VM에서 Server VM IP로 접근 가능해야 함
4. config.ini와 scripts/someip_transport.py의 IP/port가 현재 VM 설정과 일치해야 함
```

조건이 만족되면 Client VM에서 실행합니다.

```bash
cd ~/someip-llm-fuzzer
../miniconda3/envs/someipfuzz/bin/python scripts/someip_llm_fuzzer.py \
  --target-methods 10,12,14 \
  --rounds 3 \
  --candidates-per-round 50 \
  --trial-count 3 \
  --final-trial-count 10 \
  --execute
```

30분처럼 wall-clock 기준으로 계속 실행하려면 `--duration-sec`를 사용합니다.
이 옵션과 `--execute`를 같이 쓰면 기본적으로 hybrid feedback mode가 켜집니다.
Hybrid mode는 replay 결과를 즉시 local mutation queue에 반영하고, OpenAI를 사용할 경우 3분마다 최대 10회까지만 새 seed를 요청합니다.

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/someip_llm_fuzzer.py \
  --target-methods 10,12,14 \
  --candidates-per-round 50 \
  --trial-count 3 \
  --final-trial-count 10 \
  --duration-sec 30m \
  --execute
```

기존 round 단위 실행으로 되돌리려면 `--no-hybrid-feedback`를 추가합니다.

### 8.4 OpenAI-guided Run

OpenAI-guided planning을 사용할 경우 다음과 같이 실행합니다.

```bash
OPENAI_API_KEY=... \
../miniconda3/envs/someipfuzz/bin/python scripts/someip_llm_fuzzer.py \
  --target-methods 10,12,14 \
  --rounds 3 \
  --candidates-per-round 50 \
  --trial-count 3 \
  --final-trial-count 10 \
  --use-openai-api \
  --model gpt-4.1-mini \
  --execute
```

---

## 9. Target Methods and Default Profile

현재 캠페인의 주요 타깃은 Method 10, Method 12, Method 14입니다. 그중 Method 14 `changeDoorsState`가 가장 정리된 기본 프로파일이며, 현재 feedback loop의 기본 타깃으로 사용됩니다.

| Method ID | Method name / role | Paired getter | Reset payload | Expected reset getter payload | 현재 상태 |
|---:|---|---:|---|---|---|
| 10 | Seat heating status setter | 9 | `00000000` | `00000000` | 이전 state-effect 실험 주요 타깃 |
| 12 | Seat heating level setter | 11 | `00000000` | `00000000` | 이전 state-effect 실험 주요 타깃 |
| 14 | `changeDoorsState` | 8 | `02020202` | `00000000` | 현재 기본 feedback-fuzzer 프로파일 |

### 9.1 Known Playground Method IDs

| Method ID | Name / inferred role | 설명 |
|---:|---|---|
| 1 | Getter: consumption | Empty-payload getter |
| 2 | Getter: capacity | Empty-payload getter |
| 3 | Getter: volume | Empty-payload getter |
| 4 | Getter: engineSpeed | Empty-payload getter |
| 5 | Getter: currentGear | Empty-payload getter |
| 6 | Getter: isReverseGearOn | Empty-payload getter |
| 7 | Getter: drivePowerTransmission | Empty-payload getter |
| 8 | Getter: doorsOpeningStatus | Method 14의 paired getter |
| 9 | Getter: seatHeatingStatus | Method 10의 paired getter |
| 10 | Setter: seatHeatingStatus | 주요 타깃 |
| 11 | Getter: seatHeatingLevel | Method 12의 paired getter |
| 12 | Setter: seatHeatingLevel | 주요 타깃 |
| 13 | Method: initTirePressureCalibration | Non-getter method |
| 14 | Method: changeDoorsState | 주요 타깃, 현재 기본 feedback loop |
| 32778 | Event/currentTankVolume-like ID | capture에서 관찰됨, 주요 타깃은 아님 |

### 9.2 Default Profile

현재 기본 프로파일은 Method 14 `changeDoorsState`입니다.

| 항목 | 값 |
|---|---|
| Target service | `test-someip-service` Playground service |
| SOME/IP UDP port | `31000` |
| Service host | `192.168.40.134` |
| Client host | `192.168.40.135` |
| Default target method | Method 14 `changeDoorsState` |
| Default paired getter | Method 8 `getDoorsOpeningStatusAttribute` |
| Default reset payload | `02020202` |
| Default expected Getter 8 after reset | `00000000` |
| Default baseline open payload | `01010101` |

Method 14 payload는 4바이트 `DoorCommand` 배열로 취급합니다.

| Byte | 의미 |
|---|---|
| `00` | no-op / unchanged |
| `01` | open |
| `02` | close / reset |
| `03` | invalid / boundary |
| `ff` | invalid / boundary |

Candidate payload는 다음 조건을 만족해야 합니다.

- lowercase hex
- even-length hex
- empty payload 금지
- 정규화 후 길이 1~16 bytes 권장

---

## 10. Experiment Logic and Metrics

본 프로젝트의 실험 성공 여부는 crash 발생 여부만으로 판단하지 않습니다.

특히 Method 14 기준에서는 다음 순서로 payload의 가치를 판단합니다.

```text
1. reset payload로 기준 상태 설정
2. target payload 전송
3. target method가 정상 응답했는지 확인
4. paired getter 8 호출
5. getter payload가 reset-equivalent 상태와 다른지 확인
6. 동일 payload를 여러 trial에서 반복 실행
7. 재현 가능한 non-trivial state effect인지 판단
```

해석 시 주의할 점은 다음과 같습니다.

| 결과 | 해석 |
|---|---|
| normal response + no getter change | protocol-level로는 valid하지만 상태 변화는 확인되지 않은 payload입니다. |
| timeout/error response | target method가 처리하지 못했거나 packet/상태/세션 조건이 맞지 않았을 가능성이 있습니다. |
| getter change 1회 | 우연한 상태 변화 또는 초기 상태 영향일 수 있으므로 반복 검증이 필요합니다. |
| reproducible getter change | high-value candidate로 볼 수 있습니다. |

---

## 11. Output Files

Timestamp 기준으로 SOME/IP LLM Fuzzer는 아래 파일을 생성합니다.

```text
results/someip_llm_fuzzer_round_<round>_candidates_<timestamp>.csv
results/someip_llm_fuzzer_round_<round>_detail_<timestamp>.csv
results/someip_llm_fuzzer_round_<round>_payload_summary_<timestamp>.csv
results/someip_llm_fuzzer_round_<round>_summary_<timestamp>.csv
results/someip_llm_fuzzer_hybrid_candidates_<timestamp>.csv
results/someip_llm_fuzzer_hybrid_detail_<timestamp>.csv
results/someip_llm_fuzzer_hybrid_payload_summary_<timestamp>.csv
results/someip_llm_fuzzer_hybrid_summary_<timestamp>.csv
results/someip_llm_fuzzer_final_high_value_<timestamp>.csv
results/someip_llm_fuzzer_report_<timestamp>.md
```

각 파일의 의미는 다음과 같습니다.

| 파일 | 의미 |
|---|---|
| `round_<round>_candidates` | 해당 round에서 생성된 candidate payload 목록 |
| `round_<round>_detail` | 각 payload replay 결과의 상세 로그 |
| `round_<round>_payload_summary` | payload별 trial 결과 요약 |
| `round_<round>_summary` | round별 aggregate summary |
| `hybrid_candidates` | Hybrid feedback mode에서 queue에 들어간 전체 candidate payload 목록 |
| `hybrid_detail` | Hybrid feedback mode의 각 payload replay 상세 로그 |
| `hybrid_payload_summary` | Hybrid feedback mode의 payload별 trial 결과 요약 |
| `hybrid_summary` | Hybrid feedback mode의 aggregate summary |
| `final_high_value` | 최종 high-value candidate 목록 |
| `report.md` | 실험 결과 요약 보고서 |

---

## 12. Candidate Validation

생성된 candidate CSV의 payload 형식을 검증합니다.

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/check_payload_format.py \
  --csv results/someip_llm_fuzzer_round_1_candidates_<timestamp>.csv \
  --method-col method_id
```

확인해야 할 항목은 다음과 같습니다.

| 항목 | 설명 |
|---|---|
| `payload_hex` | lowercase/even-length hex인지 확인 |
| `payload_len` | 실제 payload byte 길이와 일치하는지 확인 |
| `method_id` | target method가 의도한 값인지 확인 |
| empty payload | 현재 candidate에서는 비어 있으면 안 됨 |

---

## 13. Baseline Comparison

### 13.1 LLM-like Baseline

Deterministic current-profile LLM-like 및 Radamsa-like candidate를 생성합니다.

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/generate_baseline_candidates.py \
  --count 100 \
  --balance \
  --seed 42
```

### 13.2 Radamsa Baseline

실제 Radamsa binary를 사용해 candidate를 생성합니다.

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/generate_baseline_candidates.py \
  --count 100 \
  --balance \
  --use-radamsa \
  --radamsa-bin radamsa \
  --radamsa-seed-corpus path/to/seed_corpus \
  --radamsa-count 300
```

별도 LLM CSV와 Radamsa CSV를 balance합니다.

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/balance_candidates.py \
  --llm-candidates results/someip_llm_fuzzer_round_1_candidates_<timestamp>.csv \
  --radamsa-candidates results/method14_radamsa_candidates_real_<timestamp>.csv \
  --count 100
```

같은 state-effect check에서 balanced candidate를 비교합니다.

```bash
../miniconda3/envs/someipfuzz/bin/python scripts/compare_state_fuzzers.py \
  --balanced-candidates results/method14_candidates_balanced_<timestamp>.csv \
  --trial-count 10 \
  --execute
```

Replay 없이 확인만 하려면 `--execute` 대신 `--dry-run`을 사용합니다.

---

## 14. Main Scripts

현재 사용하는 상태 인식 실험 스크립트만 `scripts/` 최상위에 유지합니다.

| Script | 역할 |
|---|---|
| `scripts/someip_llm_fuzzer.py` | 메인 SOME/IP LLM Fuzzer입니다. Round별 candidate 생성, optional OpenAI 호출, optional replay, feedback 분석, 최종 report 생성을 수행합니다. 현재 기본 프로파일은 Method 14입니다. |
| `scripts/compare_state_fuzzers.py` | state-effect 프로파일에 대한 공통 replay/summary 로직과 LLM vs Radamsa 비교를 수행합니다. |
| `scripts/check_candidate_state_effect.py` | Replay path에서 사용하는 low-level SOME/IP call helper입니다. Packet build/send/receive helper와 session ID handling을 제공합니다. |
| `scripts/someip_transport.py` | Playground service용 최소 SOME/IP packet 생성 및 response parsing helper입니다. |
| `scripts/generate_baseline_candidates.py` | LLM-like 및 Radamsa-like baseline candidate를 생성합니다. |
| `scripts/balance_candidates.py` | LLM과 Radamsa candidate CSV의 source count를 동일하게 맞춥니다. |
| `scripts/check_payload_format.py` | Candidate CSV의 `payload_hex`와 `payload_len` 일관성을 검증합니다. |
| `scripts/probe_state_effect.py` | 현재 프로파일용 작은 state sanity probe입니다. |

이전 all-method scan, single-shot planner, generic replay, verbose debug, result reaggregation helper는 `scripts/legacy/`로 이동했습니다.

---

## 15. Reproducibility Notes

실험 결과를 비교할 수 있도록 아래 파일을 보관합니다.

```text
results/*_candidates_*.csv
results/*_payload_summary_*.csv
results/*_summary_*.csv
results/*_report_*.md
```

주의사항:

- 현재 워크플로우는 crash/hang fuzzing이 아니라 state-aware fuzzing입니다.
- Crash가 없어도 재현 가능한 Getter 8 state effect를 찾았다면 캠페인은 성공으로 볼 수 있습니다.
- Real replay를 실행하려면 Server VM의 SOME/IP service가 실행 중이어야 합니다.
- IP, port, interface가 바뀌면 `config.ini`와 `scripts/someip_transport.py`를 먼저 수정해야 합니다.
- 실험 비교 시 candidate 수, trial 수, target method, reset payload, paired getter 조건을 함께 기록해야 합니다.

---

## 16. Security Notes

이 저장소는 네트워크 프로토콜 퍼징 실험을 포함합니다. 따라서 사용 범위를 명확히 제한해야 합니다.

- 본 프로젝트는 사용자가 직접 구성한 로컬 VM 환경과 허가된 테스트 서비스에서만 사용합니다.
- 제3자 시스템, 공개 네트워크, 허가받지 않은 SOME/IP 서비스에 대해 실행하지 않습니다.
- OpenAI API key는 코드에 hardcode하지 말고 환경변수 또는 git에 포함되지 않는 `.env`로 관리합니다.
- 공개 저장소로 push하기 전에는 `git status --short`와 `git diff --cached`에서 `.env`, 실제 API key, 개인 계정명, 불필요한 절대 경로가 포함되지 않았는지 확인합니다.
- 외부 공개용 문서에는 실제 API key나 개인 인증 정보가 포함되면 안 됩니다.

---

## 17. License

현재 README 기준으로 별도 license 정보가 명시되어 있지 않습니다.

공개 저장소로 장기 유지할 계획이라면 `LICENSE` 파일을 추가하고, 이 섹션에 사용 가능한 범위를 명확히 적는 것이 좋습니다.
