#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from statistics import mean

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


def load_dotenv_simple(path=".env"):
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception:
        pass


def latest_file(patterns):
    candidates = []
    for pattern in patterns:
        candidates.extend(glob.glob(pattern))
    if not candidates:
        return None
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]


def safe_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default


def safe_int(x, default=0):
    try:
        s = str(x).strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except Exception:
        return default


def normalize_hex_string(s):
    s = str(s or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


def hex_to_bytes(hx):
    hx = normalize_hex_string(hx)
    if len(hx) % 2 != 0:
        return None
    try:
        return bytes.fromhex(hx)
    except Exception:
        return None


def bytes_to_hex(b):
    try:
        return b.hex()
    except Exception:
        return ""


def summarize_csv(path):
    with open(path, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        raise RuntimeError("CSV is empty: {}".format(path))

    summary = {
        "file": path,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total_cases": len(rows),
        "mode_count": {},
        "verdict_count": {},
        "retcode_count": {},
        "msg_type_count": {},
        "payload_source_count": {},
        "response_received_count": {},
        "latency_ms": {},
        "methods": {},
        "payloads": {},
        "success_cases": [],
        "error_cases": [],
        "observations": [],
    }

    summary["mode_count"] = dict(Counter(r.get("mode", "") for r in rows))
    summary["verdict_count"] = dict(Counter(r.get("verdict", "") for r in rows))
    summary["retcode_count"] = dict(Counter(r.get("rsp_retcode", "") for r in rows))
    summary["msg_type_count"] = dict(Counter(r.get("rsp_msg_type", "") for r in rows))
    summary["payload_source_count"] = dict(Counter(r.get("payload_source", "") for r in rows))
    summary["response_received_count"] = dict(Counter(str(r.get("response_received", "")) for r in rows))

    latencies = [
        safe_float(r.get("response_time_ms", 0))
        for r in rows
        if str(r.get("response_time_ms", "")).strip() != ""
    ]
    if latencies:
        summary["latency_ms"] = {
            "avg": round(mean(latencies), 2),
            "min": round(min(latencies), 2),
            "max": round(max(latencies), 2),
        }
    else:
        summary["latency_ms"] = {"avg": 0.0, "min": 0.0, "max": 0.0}

    by_method = defaultdict(list)
    by_payload = defaultdict(list)

    for r in rows:
        method = str(r.get("target_value", "")).strip()
        payload_label = str(r.get("payload_label", "")).strip()
        if method:
            by_method[method].append(r)
        if payload_label:
            by_payload[payload_label].append(r)

        case = {
            "method": safe_int(r.get("target_value", 0), 0),
            "payload_source": r.get("payload_source", ""),
            "payload_label": r.get("payload_label", ""),
            "payload_hex": normalize_hex_string(r.get("req_payload_hex", "")),
            "payload_len": safe_int(r.get("req_payload_len", 0), 0),
            "retcode": r.get("rsp_retcode", ""),
            "msg_type": r.get("rsp_msg_type", ""),
            "verdict": r.get("verdict", ""),
            "latency_ms": safe_float(r.get("response_time_ms", 0), 0.0),
        }

        if case["verdict"] == "normal_response":
            summary["success_cases"].append(case)
        else:
            summary["error_cases"].append(case)

    for method, grp in sorted(by_method.items(), key=lambda kv: safe_int(kv[0], 99999999)):
        grp_lat = [
            safe_float(r.get("response_time_ms", 0))
            for r in grp
            if str(r.get("response_time_ms", "")).strip() != ""
        ]
        retcodes = Counter(r.get("rsp_retcode", "") for r in grp)
        verdicts = Counter(r.get("verdict", "") for r in grp)
        msg_types = Counter(r.get("rsp_msg_type", "") for r in grp)
        payload_sources = Counter(r.get("payload_source", "") for r in grp)

        payloads = {}
        for r in grp:
            label = str(r.get("payload_label", "")).strip()
            if label:
                payloads[label] = {
                    "payload_len": safe_int(r.get("req_payload_len", 0), 0),
                    "payload_hex": normalize_hex_string(r.get("req_payload_hex", "")),
                    "retcode": r.get("rsp_retcode", ""),
                    "verdict": r.get("verdict", ""),
                    "latency_ms": safe_float(r.get("response_time_ms", 0), 0.0),
                    "payload_source": r.get("payload_source", ""),
                }

        summary["methods"][method] = {
            "count": len(grp),
            "avg_latency_ms": round(mean(grp_lat), 2) if grp_lat else 0.0,
            "min_latency_ms": round(min(grp_lat), 2) if grp_lat else 0.0,
            "max_latency_ms": round(max(grp_lat), 2) if grp_lat else 0.0,
            "retcode_count": dict(retcodes),
            "verdict_count": dict(verdicts),
            "msg_type_count": dict(msg_types),
            "payload_source_count": dict(payload_sources),
            "payloads": payloads,
        }

    for label, grp in sorted(by_payload.items()):
        grp_lat = [
            safe_float(r.get("response_time_ms", 0))
            for r in grp
            if str(r.get("response_time_ms", "")).strip() != ""
        ]
        methods = sorted(
            {str(r.get("target_value", "")).strip() for r in grp},
            key=lambda x: safe_int(x, 99999999)
        )
        retcodes = Counter(r.get("rsp_retcode", "") for r in grp)
        verdicts = Counter(r.get("verdict", "") for r in grp)
        sources = Counter(r.get("payload_source", "") for r in grp)

        summary["payloads"][label] = {
            "count": len(grp),
            "methods": methods,
            "avg_latency_ms": round(mean(grp_lat), 2) if grp_lat else 0.0,
            "retcode_count": dict(retcodes),
            "verdict_count": dict(verdicts),
            "payload_source_count": dict(sources),
        }

    all_methods = sorted(summary["methods"].keys(), key=lambda x: safe_int(x, 99999999))
    if all_methods:
        summary["observations"].append("Observed methods: {}".format(all_methods))

    if summary["success_cases"]:
        summary["observations"].append(
            "Found {} success case(s)".format(len(summary["success_cases"]))
        )

    return summary


def make_payload_case(label, hx):
    hx = normalize_hex_string(hx)
    if len(hx) % 2 != 0:
        return None
    if len(hx) > 128:  # 최대 64 bytes 정도로 제한
        return None
    if not re.fullmatch(r"[0-9a-f]*", hx):
        return None
    return {"label": label, "hex": hx}


def expand_success_payload_family(base_hex):
    """
    Radamsa가 성공한 payload 주변을 heuristic으로 확장.
    너무 무식하게 늘리지 않고, black-box에서 해석 가능한 정도만 만든다.
    """
    base_hex = normalize_hex_string(base_hex)
    base = hex_to_bytes(base_hex)
    if base is None:
        return []

    cases = []
    seen = set()

    def add(label, data_bytes):
        hx = bytes_to_hex(data_bytes)
        if hx in seen:
            return
        seen.add(hx)
        item = make_payload_case(label, hx)
        if item is not None:
            cases.append(item)

    # 1) 원본 그대로
    add("success_exact", base)

    # 2) 앞/뒤 0x00 패딩
    add("pad_left_2", b"\x00\x00" + base)
    add("pad_right_2", base + b"\x00\x00")
    add("pad_left_4", b"\x00\x00\x00\x00" + base)
    add("pad_right_4", base + b"\x00\x00\x00\x00")

    # 3) 끝 2바이트/4바이트만 살린 버전
    if len(base) >= 2:
        add("tail_2", base[-2:])
    if len(base) >= 4:
        add("tail_4", base[-4:])

    # 4) 앞 2바이트/4바이트만 살린 버전
    if len(base) >= 2:
        add("head_2", base[:2])
    if len(base) >= 4:
        add("head_4", base[:4])

    # 5) 16/24/32 바이트 정렬 가설
    if len(base) < 16:
        add("pad_to_16", b"\x00" * (16 - len(base)) + base)
    if len(base) < 24:
        add("pad_to_24", b"\x00" * (24 - len(base)) + base)
    if len(base) < 32:
        add("pad_to_32", b"\x00" * (32 - len(base)) + base)

    # 6) 마지막 2바이트가 의미 있다고 가정
    if len(base) >= 2:
        tail2 = base[-2:]
        add("tail2_pad16", b"\x00" * 14 + tail2)
        add("tail2_pad24", b"\x00" * 22 + tail2)

    return cases[:12]


def build_stronger_structured_cases():
    """
    LLM이 너무 약했던 short family 대신 조금 더 공격적인 structured family.
    """
    raw = [
        ("u16_0001", "0001"),
        ("u16_000a", "000a"),
        ("u16_0100", "0100"),
        ("u32_00000001", "00000001"),
        ("u32_0000000a", "0000000a"),
        ("u32_00000100", "00000100"),
        ("pair_0001_0001", "00010001"),
        ("pair_0001_ffff", "0001ffff"),
        ("pair_0100_0100", "01000100"),
        ("pad16_tail_0001", "00000000000000000000000000000001"),
        ("pad24_tail_0001", "000000000000000000000000000000000000000000000001"),
        ("flag_u16_u16", "000100010001"),
    ]

    cases = []
    for label, hx in raw:
        item = make_payload_case(label, hx)
        if item is not None:
            cases.append(item)
    return cases


def build_cheap_heuristic_plan(summary):
    """
    토큰 절약용 우선순위:
    1) success case 있으면 그 payload 주변 family를 바로 생성
    2) success는 없고 10/12가 계속 stable error면 더 공격적인 structured family 생성
    3) 그 외엔 None 반환 -> LLM 호출
    """
    success_cases = summary.get("success_cases", [])
    methods = summary.get("methods", {})

    # 1) 성공 payload 재활용 우선
    if success_cases:
        # normal_response 중 가장 latency 낮은 것을 하나 고름
        success_cases = sorted(success_cases, key=lambda x: x.get("latency_ms", 999999))
        best = success_cases[0]
        target_method = int(best["method"])
        base_hex = best["payload_hex"]

        payload_cases = expand_success_payload_family(base_hex)
        if payload_cases:
            return {
                "planner_version": "2.0",
                "source_file": summary.get("file", ""),
                "next_action": "structured_payload_focus",
                "reason": "Heuristic shortcut: reuse and expand a previously successful payload neighborhood discovered in prior runs.",
                "target_methods": [target_method],
                "payload_strategy": "success_neighborhood_expansion",
                "payload_cases": payload_cases,
                "run_config": {
                    "mode": "fuzz",
                    "max_cases": len(payload_cases),
                    "fuzz_interval_sec": 1.0,
                    "response_timeout_sec": 0.3,
                    "heartbeat_interval_sec": 3.0,
                    "heartbeat_fail_threshold": 3,
                    "log_csv_base": "results/results_llm_plan.csv"
                },
                "notes": [
                    "Generated locally without LLM API call.",
                    "Focused around previous success payload.",
                    "Black-box only: no server logs or source assumptions."
                ]
            }

    # 2) 여전히 10/12가 stable error면 더 강한 structured family
    stable_error_methods = []
    for method, info in methods.items():
        verdict_count = info.get("verdict_count", {})
        retcode_count = info.get("retcode_count", {})
        count = info.get("count", 0)

        if count >= 2 and len(verdict_count) == 1 and len(retcode_count) == 1:
            only_verdict = next(iter(verdict_count.keys()))
            only_retcode = next(iter(retcode_count.keys()))
            if only_verdict == "error_response":
                stable_error_methods.append({
                    "method": int(method),
                    "retcode": only_retcode,
                    "count": count,
                })

    candidate_methods = [x["method"] for x in stable_error_methods if x["method"] in (10, 12)]
    if candidate_methods:
        payload_cases = build_stronger_structured_cases()
        return {
            "planner_version": "2.0",
            "source_file": summary.get("file", ""),
            "next_action": "structured_payload_focus",
            "reason": "Heuristic shortcut: methods 10/12 still show stable error-only behavior, so escalate to longer and stronger structured payload families.",
            "target_methods": candidate_methods,
            "payload_strategy": "stronger_structured_and_padded",
            "payload_cases": payload_cases,
            "run_config": {
                "mode": "fuzz",
                "max_cases": len(candidate_methods) * len(payload_cases),
                "fuzz_interval_sec": 1.0,
                "response_timeout_sec": 0.3,
                "heartbeat_interval_sec": 3.0,
                "heartbeat_fail_threshold": 3,
                "log_csv_base": "results/results_llm_plan.csv"
            },
            "notes": [
                "Generated locally without LLM API call.",
                "Escalated from short payload family to longer/padded family.",
                "Black-box only: no server logs or source assumptions."
            ]
        }

    return None


def build_system_prompt():
    return (
        "You are an experiment planner for black-box SOME/IP fuzzing. "
        "You only reason from external observations: method id, payload source, payload label, payload hex, payload length, "
        "response_received, response time, response msg_type, retcode, and verdict. "
        "Do not assume server logs, source code, symbols, coverage, or internal state. "
        "Return ONLY valid JSON. "
        "Be conservative but useful: if there was a previous successful payload, propose payloads around it. "
        "If there was no success, propose stronger structured payload families, not just trivial u16 pairs."
    )


def build_user_prompt(summary):
    schema = {
        "planner_version": "2.0",
        "source_file": "string",
        "next_action": "one of: stop | focused_method_recheck | structured_payload_focus | method_scan",
        "reason": "short string",
        "target_methods": [10, 12],
        "payload_strategy": "short string",
        "payload_cases": [
            {"label": "string", "hex": "even-length lowercase hex string without 0x"}
        ],
        "run_config": {
            "mode": "fuzz",
            "max_cases": 12,
            "fuzz_interval_sec": 1.0,
            "response_timeout_sec": 0.3,
            "heartbeat_interval_sec": 3.0,
            "heartbeat_fail_threshold": 3,
            "log_csv_base": "results/results_llm_plan.csv"
        },
        "notes": ["string", "string"]
    }

    return (
        "Current experiment summary JSON:\n\n"
        + json.dumps(summary, ensure_ascii=False, indent=2)
        + "\n\nRules:\n"
        "1) Output ONLY valid JSON.\n"
        "2) target_methods must be a non-empty list of integers unless next_action is stop.\n"
        "3) payload_cases hex must be even-length lowercase hex, <= 64 bytes unless strongly justified.\n"
        "4) If there is a successful payload in history, prioritize payloads around that success.\n"
        "5) If only stable 0x09-like errors are observed, propose longer/padded/structured families.\n"
        "6) Do not propose editing engine files.\n"
        "\nExpected schema example:\n"
        + json.dumps(schema, ensure_ascii=False, indent=2)
    )


def extract_json_object(text):
    text = text.strip()
    text = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    try:
        return json.loads(text)
    except Exception:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("Could not find JSON object in model output")

    return json.loads(text[start:end + 1])


def normalize_payload_cases(cases):
    normalized = []
    seen = set()

    for item in cases:
        if not isinstance(item, dict):
            continue

        label = str(item.get("label", "")).strip()
        hx = normalize_hex_string(item.get("hex", ""))

        if not label:
            continue
        if len(hx) % 2 != 0:
            continue
        if len(hx) > 128:
            continue
        if not re.fullmatch(r"[0-9a-f]*", hx):
            continue
        if hx in seen:
            continue

        seen.add(hx)
        normalized.append({"label": label, "hex": hx})

    return normalized


def sanitize_plan(plan, source_file):
    if not isinstance(plan, dict):
        raise ValueError("Planner output is not a JSON object")

    sanitized = {
        "planner_version": str(plan.get("planner_version", "2.0")),
        "source_file": source_file,
        "next_action": str(plan.get("next_action", "structured_payload_focus")).strip(),
        "reason": str(plan.get("reason", "")).strip(),
        "target_methods": [],
        "payload_strategy": str(plan.get("payload_strategy", "")).strip(),
        "payload_cases": [],
        "run_config": {},
        "notes": [],
    }

    tm = plan.get("target_methods", [])
    if isinstance(tm, list):
        for x in tm:
            try:
                sanitized["target_methods"].append(int(x))
            except Exception:
                continue

    pc = plan.get("payload_cases", [])
    if isinstance(pc, list):
        sanitized["payload_cases"] = normalize_payload_cases(pc)

    rc = plan.get("run_config", {})
    if not isinstance(rc, dict):
        rc = {}

    default_max_cases = max(1, len(sanitized["payload_cases"]) * max(1, len(sanitized["target_methods"])))
    sanitized["run_config"] = {
        "mode": str(rc.get("mode", "fuzz")).strip(),
        "max_cases": int(rc.get("max_cases", default_max_cases)),
        "fuzz_interval_sec": float(rc.get("fuzz_interval_sec", 1.0)),
        "response_timeout_sec": float(rc.get("response_timeout_sec", 0.3)),
        "heartbeat_interval_sec": float(rc.get("heartbeat_interval_sec", 3.0)),
        "heartbeat_fail_threshold": int(rc.get("heartbeat_fail_threshold", 3)),
        "log_csv_base": str(rc.get("log_csv_base", "results/results_llm_plan.csv")).strip(),
    }

    notes = plan.get("notes", [])
    if isinstance(notes, list):
        sanitized["notes"] = [str(x).strip() for x in notes if str(x).strip()]

    if sanitized["next_action"] not in {"stop", "focused_method_recheck", "structured_payload_focus", "method_scan"}:
        sanitized["next_action"] = "structured_payload_focus"

    if sanitized["next_action"] != "stop" and not sanitized["target_methods"]:
        sanitized["target_methods"] = [10, 12]

    if not sanitized["payload_cases"] and sanitized["next_action"] != "stop":
        sanitized["payload_cases"] = build_stronger_structured_cases()[:6]

    return sanitized


def call_llm(summary, model_name):
    if OpenAI is None:
        raise RuntimeError("openai package is not installed. Run: pip install openai")

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")

    client = OpenAI(api_key=api_key)

    response = client.responses.create(
        model=model_name,
        instructions=build_system_prompt(),
        input=build_user_prompt(summary),
        max_output_tokens=900,
    )

    text = getattr(response, "output_text", None)
    if not text or not text.strip():
        raise RuntimeError("Model returned empty text")

    return text


def save_json(path, obj):
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


METHOD14_VALUES = ["00", "01", "02", "03", "ff"]
METHOD14_SEEDS = ["02020202", "00000000", "01010101"]
METHOD14_CSV_HEADER = [
    "payload_source",
    "payload_label",
    "method_id",
    "payload_hex",
    "payload_len",
    "method_name",
    "paired_getter",
    "batch_index",
    "generation_strategy",
    "seed_payload_hex",
    "note",
]


def ensure_parent_dir(path):
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)


def method14_payload_len(payload_hex):
    return len(bytes.fromhex(payload_hex))


def method14_candidate(label, payload_hex, batch_index, strategy, seed_payload_hex="", note=""):
    payload_hex = normalize_hex_string(payload_hex)
    if not payload_hex:
        return None
    if len(payload_hex) % 2 != 0:
        return None
    if not re.fullmatch(r"[0-9a-f]+", payload_hex):
        return None
    payload_bytes = method14_payload_len(payload_hex)
    if payload_bytes < 1 or payload_bytes > 16:
        return None
    return {
        "payload_source": "llm_api",
        "payload_label": str(label or "candidate").strip()[:96],
        "method_id": 14,
        "payload_hex": payload_hex,
        "payload_len": payload_bytes,
        "method_name": "changeDoorsState",
        "paired_getter": 8,
        "batch_index": batch_index,
        "generation_strategy": strategy,
        "seed_payload_hex": normalize_hex_string(seed_payload_hex),
        "note": note,
    }


def method14_label_for_values(values):
    names = {"00": "noop", "01": "open", "02": "close", "03": "invalid3", "ff": "boundaryff"}
    return "_".join(names.get(value, value) for value in values)


def deterministic_method14_candidates(count, batch_size):
    rows = []
    batch_index = 1

    def add(label, payload_hex, strategy, seed_payload_hex="", note=""):
        item = method14_candidate(label, payload_hex, batch_index, strategy, seed_payload_hex, note)
        if item is not None:
            rows.append(item)

    semantic_patterns = [
        ("reset_close_all", "02020202", "semantic_reset"),
        ("reset_expected_getter8", "00000000", "semantic_reset_observation"),
        ("baseline_open_all", "01010101", "semantic_baseline"),
        ("open_front_left", "01000000", "semantic_single_door"),
        ("open_front_right", "00010000", "semantic_single_door"),
        ("open_rear_left", "00000100", "semantic_single_door"),
        ("open_rear_right", "00000001", "semantic_single_door"),
        ("open_front_pair", "01010000", "semantic_pair"),
        ("open_rear_pair", "00000101", "semantic_pair"),
        ("mixed_open_close_1", "01020102", "semantic_mixed"),
        ("mixed_open_close_2", "02010102", "semantic_mixed"),
        ("invalid3_all", "03030303", "invalid_enum"),
        ("boundaryff_all", "ffffffff", "boundary"),
    ]
    for label, payload_hex, strategy in semantic_patterns:
        add(label, payload_hex, strategy, "", "Method 14 dry-run candidate")

    for a in METHOD14_VALUES:
        for b in METHOD14_VALUES:
            for c in METHOD14_VALUES:
                for d in METHOD14_VALUES:
                    values = [a, b, c, d]
                    payload = "".join(values)
                    if all(value in ("00", "01", "02") for value in values):
                        strategy = "semantic_all_door_command_combination"
                    elif any(value == "ff" for value in values):
                        strategy = "boundary_command_included"
                    else:
                        strategy = "invalid_enum_included"
                    add(method14_label_for_values(values), payload, strategy, "", "four DoorCommand bytes")
                    if len(rows) >= max(count * 3, batch_size):
                        break
                if len(rows) >= max(count * 3, batch_size):
                    break
            if len(rows) >= max(count * 3, batch_size):
                break
        if len(rows) >= max(count * 3, batch_size):
            break

    for seed in METHOD14_SEEDS:
        for label, payload, strategy in [
            ("suffix_zero_{}".format(seed), seed + "00", "suffix_padding"),
            ("suffix_ff_{}".format(seed), seed + "ff", "suffix_padding"),
            ("prefix_zero_{}".format(seed), "00" + seed, "prefix_padding"),
            ("prefix_ff_{}".format(seed), "ff" + seed, "prefix_padding"),
            ("double_{}".format(seed), seed + seed, "length_variation_duplication"),
            ("truncated_1_{}".format(seed), seed[:2], "length_variation_truncation"),
            ("truncated_2_{}".format(seed), seed[:4], "length_variation_truncation"),
            ("truncated_3_{}".format(seed), seed[:6], "length_variation_truncation"),
        ]:
            add(label, payload, strategy, seed, "seed-derived Method 14 variation")

    return select_method14_candidates(rows, count, batch_size)


def select_method14_candidates(rows, count, batch_size):
    selected = []
    seen = set()
    for row in rows:
        payload_hex = row["payload_hex"]
        if payload_hex in seen:
            continue
        seen.add(payload_hex)
        row = dict(row)
        row["batch_index"] = (len(selected) // batch_size) + 1
        selected.append(row)
        if len(selected) >= count:
            break
    return selected


def build_method14_candidate_prompt(args, batch_index, batch_count):
    return (
        "Generate Method 14 SOME/IP payload candidates as JSON only.\n"
        "Schema: {\"candidates\":[{\"payload_label\":\"string\",\"payload_hex\":\"lowercase even hex\",\"generation_strategy\":\"semantic|boundary|invalid|padding|prefix|suffix|length_variation\",\"seed_payload_hex\":\"optional\",\"note\":\"optional\"}]}\n"
        "Context:\n"
        "- Method ID: {method_id}\n"
        "- Method name: {method_name}\n"
        "- Paired getter: {getter_id}\n"
        "- Payload is assumed to be a 4-byte DoorCommand array.\n"
        "- 00=no-op/unchanged, 01=open, 02=close/reset, 03 and ff=invalid/boundary.\n"
        "- Reset payload: 02020202; reset Getter 8 expected payload: 00000000.\n"
        "- Baseline open payload: 01010101.\n"
        "Requirements:\n"
        "- Return exactly {batch_count} candidates.\n"
        "- payload_hex must be hex, even length, and 1 to 16 bytes.\n"
        "- Include semantic, boundary, invalid, padding, prefix, suffix, and length variation ideas across batches.\n"
        "- Do not include prose outside JSON.\n"
        "Batch index: {batch_index}\n"
    ).format(
        method_id=args.target_method,
        method_name=args.method_name,
        getter_id=args.paired_getter,
        batch_count=batch_count,
        batch_index=batch_index,
    )


def call_method14_openai_batch(args, batch_index, batch_count):
    if OpenAI is None:
        raise RuntimeError("openai package is not installed. Run: pip install openai")
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    model_name = args.model or os.environ.get("OPENAI_MODEL", "").strip()
    if not model_name:
        raise RuntimeError("--model or OPENAI_MODEL is required with --use-openai-api")

    client = OpenAI(api_key=api_key)
    response = client.responses.create(
        model=model_name,
        instructions="Return only valid JSON for black-box SOME/IP Method 14 candidate generation.",
        input=build_method14_candidate_prompt(args, batch_index, batch_count),
        max_output_tokens=1800,
    )
    text = getattr(response, "output_text", None)
    if not text or not text.strip():
        raise RuntimeError("Model returned empty Method 14 candidate text")
    return extract_json_object(text)


def method14_rows_from_model_object(obj, batch_index):
    candidates = obj.get("candidates", []) if isinstance(obj, dict) else []
    rows = []
    for item_index, item in enumerate(candidates, start=1):
        if not isinstance(item, dict):
            continue
        row = method14_candidate(
            item.get("payload_label") or "llm_candidate_{}".format(item_index),
            item.get("payload_hex", ""),
            batch_index,
            item.get("generation_strategy", "llm_api"),
            item.get("seed_payload_hex", ""),
            item.get("note", ""),
        )
        if row is not None:
            rows.append(row)
    return rows


def generate_method14_openai_candidates(args):
    rows = []
    if args.use_openai_api and not args.dry_run:
        remaining = args.count
        batch_index = 1
        while remaining > 0:
            batch_count = min(args.batch_size, remaining)
            obj = call_method14_openai_batch(args, batch_index, batch_count)
            rows.extend(method14_rows_from_model_object(obj, batch_index))
            remaining -= batch_count
            batch_index += 1
        rows = select_method14_candidates(rows, args.count, args.batch_size)
    else:
        rows = deterministic_method14_candidates(args.count, args.batch_size)

    if len(rows) < args.count:
        fallback = deterministic_method14_candidates(args.count, args.batch_size)
        rows = select_method14_candidates(rows + fallback, args.count, args.batch_size)
    return rows


def write_method14_candidate_csv(path, rows):
    ensure_parent_dir(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=METHOD14_CSV_HEADER)
        writer.writeheader()
        writer.writerows(rows)


def run_method14_candidate_mode(args):
    if args.target_method != 14:
        raise SystemExit("only --target-method 14 is supported by this candidate mode")
    if args.method_name != "changeDoorsState":
        raise SystemExit("--method-name must be changeDoorsState for Method 14")
    if args.paired_getter != 8:
        raise SystemExit("--paired-getter must be 8 for Method 14")
    if args.count <= 0:
        raise SystemExit("--count must be positive")
    if args.batch_size <= 0:
        raise SystemExit("--batch-size must be positive")
    if args.use_openai_api and args.dry_run:
        raise SystemExit("--dry-run and --use-openai-api cannot be used together")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = "{}_{}.csv".format(args.output_prefix, stamp)
    rows = generate_method14_openai_candidates(args)
    write_method14_candidate_csv(output_path, rows)
    print("dry_run={}".format(str(not args.use_openai_api or args.dry_run)))
    print("use_openai_api={}".format(str(args.use_openai_api)))
    print("candidate_count={}".format(len(rows)))
    print("payload_source=llm_api")
    print("wrote {}".format(output_path))
    if not args.use_openai_api:
        print("no OpenAI API call was made; use --use-openai-api to request real LLM candidates")


def main():
    load_dotenv_simple(".env")

    parser = argparse.ArgumentParser()
    parser.add_argument("--input", help="results csv path")
    parser.add_argument("--output", help="output plan json path")
    parser.add_argument("--summary-out", help="summary json output path")
    parser.add_argument("--raw-out", help="raw model text output path")
    parser.add_argument("--model", help="OpenAI model name")
    parser.add_argument("--mode", choices=["auto", "heuristic", "llm"], default="auto")
    parser.add_argument("--target-method", type=int, default=0)
    parser.add_argument("--method-name", default="")
    parser.add_argument("--paired-getter", type=int, default=0)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--use-openai-api", action="store_true")
    parser.add_argument("--output-prefix", default="results/method14_openai_candidates")
    args = parser.parse_args()

    if args.target_method:
        if not args.method_name:
            args.method_name = "changeDoorsState" if args.target_method == 14 else args.method_name
        if not args.paired_getter:
            args.paired_getter = 8 if args.target_method == 14 else args.paired_getter
        run_method14_candidate_mode(args)
        return

    input_path = args.input or latest_file([
        "results/*.csv",
        "results_payload_focus_*.csv",
        "results_focus_*.csv",
        "results_fuzz_*.csv",
        "results_*.csv",
        "results.csv",
    ])

    if not input_path or not os.path.exists(input_path):
        print("No input CSV found.", file=sys.stderr)
        sys.exit(1)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("results", exist_ok=True)

    summary_out = args.summary_out or os.path.join("results", "summary_{}.json".format(ts))
    plan_out = args.output or os.path.join("results", "llm_plan_{}.json".format(ts))
    raw_out = args.raw_out or os.path.join("results", "llm_raw_{}.txt".format(ts))

    summary = summarize_csv(input_path)
    save_json(summary_out, summary)
    print("[+] saved summary: {}".format(summary_out))

    if args.mode in ("auto", "heuristic"):
        cheap_plan = build_cheap_heuristic_plan(summary)
        if cheap_plan is not None:
            plan = sanitize_plan(cheap_plan, source_file=input_path)
            save_json(plan_out, plan)
            print("[+] saved heuristic plan (no LLM call): {}".format(plan_out))
            print(json.dumps(plan, ensure_ascii=False, indent=2))
            return

        if args.mode == "heuristic":
            print("[-] heuristic mode requested but no heuristic plan available", file=sys.stderr)
            sys.exit(2)

    model_name = args.model or os.environ.get("OPENAI_MODEL", "").strip()
    if not model_name:
        raise RuntimeError("OPENAI_MODEL is not set and heuristic plan was not enough")

    raw_text = call_llm(summary, model_name)

    with open(raw_out, "w", encoding="utf-8") as f:
        f.write(raw_text)
    print("[+] saved raw model output: {}".format(raw_out))

    plan = extract_json_object(raw_text)
    plan = sanitize_plan(plan, source_file=input_path)
    save_json(plan_out, plan)
    print("[+] saved plan: {}".format(plan_out))
    print(json.dumps(plan, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
