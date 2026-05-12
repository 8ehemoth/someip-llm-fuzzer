#!/usr/bin/env python3
"""SOME/IP LLM Fuzzer with OpenAI-guided and local hybrid feedback.

The current default profile targets Method 14, but the workflow and report
structure are intended for state-effect fuzzing campaigns more broadly.
"""

import argparse
import csv
import glob
import json
import os
import random
import re
import shutil
import sys
import threading
import textwrap
import time
from collections import Counter, defaultdict, deque
from datetime import datetime

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
SCRIPTS_DIR = os.path.dirname(__file__)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from compare_state_fuzzers import (  # noqa: E402
    DETAIL_HEADER,
    PAYLOAD_SUMMARY_HEADER,
    SUMMARY_HEADER,
    payload_summary,
    run_trial,
    source_summary,
    write_csv,
)


METHOD_PROFILES = {
    10: {
        "method_name": "setSeatHeatingStatus",
        "getter_id": 9,
        "getter_name": "getSeatHeatingStatusAttribute",
        "reset_payload_hex": "00000000",
        "reset_expected_payload_hex": "00000000",
        "baseline_payload_hex": "01000000",
        "payload_assumption": "seat heating status setter payload; start with compact boolean/integer encodings",
        "semantic_payloads": [
            ("status_off_zero", "00000000"),
            ("status_on_u32", "00000001"),
            ("status_on_byte", "01"),
            ("status_off_byte", "00"),
            ("status_true_bool_pad", "01000000"),
            ("status_false_bool_pad", "00000000"),
        ],
    },
    12: {
        "method_name": "setSeatHeatingLevel",
        "getter_id": 11,
        "getter_name": "getSeatHeatingLevelAttribute",
        "reset_payload_hex": "00000000",
        "reset_expected_payload_hex": "00000000",
        "baseline_payload_hex": "00000001",
        "payload_assumption": "seat heating level setter payload; try small enum/integer values and boundary levels",
        "semantic_payloads": [
            ("level_0_u32", "00000000"),
            ("level_1_u32", "00000001"),
            ("level_2_u32", "00000002"),
            ("level_3_u32", "00000003"),
            ("level_1_byte", "01"),
            ("level_2_byte", "02"),
            ("level_3_byte", "03"),
        ],
    },
    14: {
        "method_name": "changeDoorsState",
        "getter_id": 8,
        "getter_name": "getDoorsOpeningStatusAttribute",
        "reset_payload_hex": "02020202",
        "reset_expected_payload_hex": "00000000",
        "baseline_payload_hex": "01010101",
        "payload_assumption": "4-byte DoorCommand array: 00=no-op, 01=open, 02=close/reset, 03/ff=invalid or boundary",
        "semantic_payloads": [
            ("baseline_open_all", "01010101"),
            ("reset_close_all", "02020202"),
            ("reset_expected_noop", "00000000"),
            ("open_front_left", "01000000"),
            ("open_front_right", "00010000"),
            ("open_rear_left", "00000100"),
            ("open_rear_right", "00000001"),
            ("open_front_pair", "01010000"),
            ("open_rear_pair", "00000101"),
            ("mixed_open_close_1", "01020102"),
            ("mixed_open_close_2", "02010102"),
            ("invalid3_all", "03030303"),
            ("boundaryff_all", "ffffffff"),
        ],
    },
}
DEFAULT_TARGET_METHODS = [10, 12, 14]
PAYLOAD_SOURCE = "llm_feedback"
DEFAULT_OUTPUT_PREFIX = "results/someip_llm_fuzzer"
ENV_PATHS = [os.path.join(REPO_ROOT, ".env"), os.path.join(REPO_ROOT, "someip_fuzzer", ".env")]

CANDIDATE_HEADER = [
    "payload_source",
    "payload_label",
    "method_id",
    "method_name",
    "getter_id",
    "payload_hex",
    "payload_len",
    "round_index",
    "generation_strategy",
    "seed_payload_hex",
    "feedback_note",
]
FINAL_HEADER = CANDIDATE_HEADER + [
    "classification",
    "normal_response_count",
    "error_response_count",
    "timeout_count",
    "non_trivial_state_effect_count",
    "non_trivial_state_effect_rate",
]


def load_dotenv_simple(paths=ENV_PATHS):
    for path in paths:
        if not os.path.exists(path):
            continue
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


def env_value(names, default=None):
    if isinstance(names, str):
        names = [names]
    for name in names:
        value = os.environ.get(name)
        if value is not None:
            return value
    return default


def env_bool(names, default=False):
    value = env_value(names)
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def env_int(names, default):
    try:
        return int(env_value(names, default))
    except (TypeError, ValueError):
        return default


def env_float(names, default):
    try:
        return float(env_value(names, default))
    except (TypeError, ValueError):
        return default


def parse_duration_sec(value):
    text = str(value or "").strip().lower()
    if not text:
        return 0
    multipliers = {
        "s": 1,
        "sec": 1,
        "secs": 1,
        "m": 60,
        "min": 60,
        "mins": 60,
        "h": 3600,
        "hr": 3600,
        "hrs": 3600,
    }
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([a-z]*)", text)
    if not match:
        raise argparse.ArgumentTypeError("duration must look like 1800, 30m, or 1h")
    amount = float(match.group(1))
    suffix = match.group(2) or "s"
    if suffix not in multipliers:
        raise argparse.ArgumentTypeError("unsupported duration suffix: {}".format(suffix))
    seconds = int(amount * multipliers[suffix])
    if seconds < 0:
        raise argparse.ArgumentTypeError("duration must be non-negative")
    return seconds


def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def normalize_candidate_hex(value):
    text = str(value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    text = re.sub(r"\s+", "", text)
    if not text:
        return ""
    if len(text) % 2 != 0:
        return ""
    if not re.fullmatch(r"[0-9a-f]+", text):
        return ""
    byte_len = len(text) // 2
    if byte_len < 1 or byte_len > 16:
        return ""
    return text


def payload_len(payload_hex):
    return len(bytes.fromhex(payload_hex))


def profile_for_method(method_id):
    method_id = int(method_id)
    if method_id not in METHOD_PROFILES:
        raise ValueError("unsupported target method: {}".format(method_id))
    return METHOD_PROFILES[method_id]


def make_candidate(method_id, label, payload_hex, round_index, strategy, seed_payload_hex="", feedback_note=""):
    payload_hex = normalize_candidate_hex(payload_hex)
    if not payload_hex:
        return None
    profile = profile_for_method(method_id)
    return {
        "payload_source": PAYLOAD_SOURCE,
        "payload_label": "m{}_{}".format(method_id, str(label or "candidate").strip()[:88]),
        "method_id": method_id,
        "method_name": profile["method_name"],
        "getter_id": profile["getter_id"],
        "payload_hex": payload_hex,
        "payload_len": payload_len(payload_hex),
        "round_index": round_index,
        "generation_strategy": str(strategy or "").strip(),
        "seed_payload_hex": normalize_candidate_hex(seed_payload_hex),
        "feedback_note": str(feedback_note or "").strip()[:160],
    }


def dedupe_candidates(rows, limit):
    selected = []
    seen = set()
    for row in rows:
        if row is None:
            continue
        key = (int(row["method_id"]), row["payload_hex"])
        if key in seen:
            continue
        seen.add(key)
        selected.append(row)
        if len(selected) >= limit:
            break
    return selected


def write_candidate_csv(path, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CANDIDATE_HEADER)
        writer.writeheader()
        writer.writerows(rows)


def read_csv_rows(path):
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def safe_int(value, default=0):
    try:
        return int(str(value).strip() or default)
    except ValueError:
        return default


def length_bucket(payload_hex):
    return str(len(payload_hex) // 2)


def rows_by_classification(payload_rows):
    grouped = defaultdict(list)
    for row in payload_rows:
        grouped[row.get("classification", "")].append(row)
    return grouped


def round_metrics(payload_rows, detail_rows):
    classed = rows_by_classification(payload_rows)
    return {
        "candidate_count": len(payload_rows),
        "normal_response_count": sum(safe_int(row.get("normal_response_count", 0)) for row in payload_rows),
        "error_response_count": sum(safe_int(row.get("error_response_count", 0)) for row in payload_rows),
        "timeout_count": sum(safe_int(row.get("timeout_count", 0)) for row in payload_rows),
        "unique_payload_count": len({row.get("payload_hex", "") for row in payload_rows}),
        "non_trivial_state_effect_count": sum(safe_int(row.get("non_trivial_state_effect_count", 0)) for row in payload_rows),
        "reproducible_non_trivial_state_effect_count": len(classed.get("reproducible_non_trivial_state_effect", [])),
        "protocol_valid_no_effect_count": len(classed.get("protocol_valid_no_effect", [])),
        "detail_trial_count": len(detail_rows),
    }


def live_replay_metrics(rows, candidate_count):
    return {
        "candidate_count": candidate_count,
        "detail_trial_count": len(rows),
        "normal_response_count": sum(1 for row in rows if row.get("verdict") == "normal_response"),
        "error_response_count": sum(1 for row in rows if row.get("verdict") == "error_response"),
        "timeout_count": sum(1 for row in rows if row.get("verdict") == "no_response_timeout"),
        "state_changed_count": sum(1 for row in rows if row.get("state_changed") == "True"),
        "non_trivial_state_effect_count": sum(1 for row in rows if row.get("non_trivial_state_effect") == "True"),
        "unique_payload_count": len({row.get("payload_hex", "") for row in rows}),
    }


def hybrid_paths(output_prefix, stamp):
    return {
        "candidates": "{}_hybrid_candidates_{}.csv".format(output_prefix, stamp),
        "detail": "{}_hybrid_detail_{}.csv".format(output_prefix, stamp),
        "payload_summary": "{}_hybrid_payload_summary_{}.csv".format(output_prefix, stamp),
        "summary": "{}_hybrid_summary_{}.csv".format(output_prefix, stamp),
    }


def local_feedback_mutations(candidate, payload_row, round_index, limit=24):
    payload_hex = normalize_candidate_hex(candidate.get("payload_hex", ""))
    if not payload_hex:
        return []
    try:
        data = bytearray(bytes.fromhex(payload_hex))
    except ValueError:
        return []

    classification = payload_row.get("classification", "")
    normal_count = safe_int(payload_row.get("normal_response_count", 0))
    non_trivial_count = safe_int(payload_row.get("non_trivial_state_effect_count", 0))
    if classification not in (
        "reproducible_non_trivial_state_effect",
        "unstable_non_trivial_state_effect",
        "protocol_valid_no_effect",
    ) and normal_count <= 0 and non_trivial_count <= 0:
        return []

    method_id = int(candidate["method_id"])
    rows = []

    def add(label, mutated_hex, strategy):
        row = make_candidate(
            method_id,
            label,
            mutated_hex,
            round_index,
            strategy,
            payload_hex,
            "live feedback from {}".format(classification or "trial result"),
        )
        if row is not None:
            rows.append(row)

    interesting_values = [0x00, 0x01, 0x02, 0x03, 0xFF]
    for index in range(min(len(data), 8)):
        original = data[index]
        for value in interesting_values:
            if value == original:
                continue
            mutated = bytearray(data)
            mutated[index] = value
            add("live_byte{}_{}_{}".format(index, value, payload_hex), mutated.hex(), "live_byte_mutation")

    if len(data) < 16:
        for suffix in ("00", "01", "02", "03", "ff"):
            add("live_suffix_{}_{}".format(suffix, payload_hex), payload_hex + suffix, "live_suffix_padding")
            add("live_prefix_{}_{}".format(suffix, payload_hex), suffix + payload_hex, "live_prefix_padding")

    if len(data) > 1:
        add("live_trunc_tail_{}".format(payload_hex), payload_hex[:-2], "live_length_truncation")
    if len(data) <= 8:
        add("live_double_{}".format(payload_hex), payload_hex + payload_hex, "live_length_duplication")

    selected = []
    seen = set()
    for row in rows:
        key = (int(row["method_id"]), row["payload_hex"])
        if key in seen:
            continue
        seen.add(key)
        selected.append(row)
        if len(selected) >= limit:
            break
    return selected


def summarize_length_outcomes(payload_rows):
    buckets = defaultdict(Counter)
    for row in payload_rows:
        bucket = length_bucket(row.get("payload_hex", ""))
        classification = row.get("classification", "unknown")
        buckets[bucket][classification] += 1
    return {
        bucket: dict(counter)
        for bucket, counter in sorted(buckets.items(), key=lambda item: int(item[0] or 0))
    }


def examples(rows, limit=8):
    return [
        {
            "payload_label": row.get("payload_label", ""),
            "method_id": row.get("method_id", ""),
            "payload_hex": row.get("payload_hex", ""),
            "classification": row.get("classification", ""),
            "normal_response_count": row.get("normal_response_count", ""),
            "non_trivial_state_effect_count": row.get("non_trivial_state_effect_count", ""),
        }
        for row in rows[:limit]
    ]


def feedback_context(history):
    payload_rows = []
    for item in history:
        payload_rows.extend(item.get("payload_rows", []))
    classed = rows_by_classification(payload_rows)
    high_value = classed.get("reproducible_non_trivial_state_effect", []) + classed.get("unstable_non_trivial_state_effect", [])
    no_effect = classed.get("protocol_valid_no_effect", [])
    errors = classed.get("rejected_or_error", []) + classed.get("timeout_or_no_response", [])
    return {
        "high_value_payloads": examples(high_value, 10),
        "protocol_valid_no_effect_payloads": examples(no_effect, 10),
        "error_response_payloads": examples(errors, 10),
        "payload_length_summary": summarize_length_outcomes(payload_rows),
        "mutation_direction": mutation_direction(high_value, no_effect, errors),
    }


def mutation_direction(high_value, no_effect, errors):
    if high_value:
        return [
            "Mutate around high-value payloads by changing one byte at a time.",
            "Try prefix/suffix padding around successful compact payloads while staying within 1..16 bytes.",
            "Preserve bytes that appear to drive the paired getter away from reset state.",
        ]
    if no_effect:
        return [
            "Avoid pure reset/no-op equivalents such as 02020202 and 00000000.",
            "Bias toward compact semantic setter values before trying random long payloads.",
            "Try 03/ff boundaries in one position only, not all positions at once.",
        ]
    if errors:
        return [
            "Move back toward 4-byte payloads with values limited to 00/01/02.",
            "Use length variations sparingly after protocol-valid candidates appear.",
        ]
    return [
        "Start from semantic payloads for each target method.",
        "Cover valid setter values, boundary values, prefix/suffix padding, and length variations.",
    ]


def deterministic_seed_pool(method_id, round_index, context):
    profile = profile_for_method(method_id)
    rows = []

    def add(label, payload_hex, strategy, seed="", note=""):
        rows.append(make_candidate(method_id, label, payload_hex, round_index, strategy, seed, note))

    high_values = [
        item["payload_hex"]
        for item in context.get("high_value_payloads", [])
        if item.get("payload_hex") and int(item.get("method_id") or method_id) == method_id
    ]
    base_payloads = high_values or [
        profile["baseline_payload_hex"],
        profile["reset_payload_hex"],
        profile["reset_expected_payload_hex"],
    ]

    for label, payload_hex in profile["semantic_payloads"]:
        add(label, payload_hex, "semantic_seed", "", "initial Method {} structure coverage".format(method_id))

    for seed in base_payloads:
        add("suffix_zero_{}".format(seed), seed + "00", "suffix_padding", seed)
        add("suffix_ff_{}".format(seed), seed + "ff", "suffix_padding", seed)
        add("prefix_zero_{}".format(seed), "00" + seed, "prefix_padding", seed)
        add("prefix_ff_{}".format(seed), "ff" + seed, "prefix_padding", seed)
        add("double_{}".format(seed), seed + seed, "length_variation_duplication", seed)
        add("trunc1_{}".format(seed), seed[:2], "length_variation_truncation", seed)
        add("trunc2_{}".format(seed), seed[:4], "length_variation_truncation", seed)
        add("trunc3_{}".format(seed), seed[:6], "length_variation_truncation", seed)

        data = bytearray(bytes.fromhex(seed))
        for index in range(min(len(data), 4)):
            for value in (0x00, 0x01, 0x02, 0x03, 0xFF):
                mutated = bytearray(data)
                mutated[index] = value
                add("byte{}_{}_{}".format(index, value, seed), mutated.hex(), "byte_mutation", seed)

    rng = random.Random((method_id << 16) + round_index)
    for index in range(64):
        length = rng.randint(1, 16)
        payload_hex = bytes(rng.choice([0x00, 0x01, 0x02, 0x03, 0xFF, rng.getrandbits(8)]) for _ in range(length)).hex()
        add("guided_random_{:02d}".format(index), payload_hex, "guided_random", "", "deterministic fallback exploration")

    return rows


def extract_json_object(text):
    text = str(text or "").strip()
    text = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except ValueError:
        pass

    for start in [index for index, ch in enumerate(text) if ch == "{"]:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(text)):
            ch = text[index]
            if escaped:
                escaped = False
                continue
            if ch == "\\" and in_string:
                escaped = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start:index + 1]
                    try:
                        return json.loads(candidate)
                    except ValueError:
                        break
    raise ValueError("could not parse JSON object from model output")


def save_invalid_model_output(method_id, round_index, text):
    path = os.path.join(
        "results",
        "someip_llm_fuzzer_invalid_model_output_m{}_round_{}_{}.txt".format(method_id, round_index, timestamp()),
    )
    ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(text or ""))
    return path


def build_prompt(method_id, round_index, count, context):
    profile = profile_for_method(method_id)
    schema = {
        "candidates": [
            {
                "payload_label": "string",
                "payload_hex": "even-length lowercase hex, 1..16 bytes",
                "generation_strategy": "semantic|boundary|invalid|padding|prefix|suffix|length_variation|feedback_mutation",
                "seed_payload_hex": "optional",
                "feedback_note": "short reason",
            }
        ]
    }
    return (
        "Generate feedback-guided SOME/IP payload candidates. Return JSON only.\n"
        "Target:\n"
        "- Method ID: {method_id}\n"
        "- Method name: {method_name}\n"
        "- Paired getter: Method {getter_id} {getter_name}\n"
        "- Payload assumption: {payload_assumption}\n"
        "- Reset payload is {reset_payload}\n"
        "- Getter after reset is expected to be {reset_expected}\n"
        "- Goal: produce state-changing payloads that are not reset/no-op equivalents.\n"
        "Candidate rules:\n"
        "- Return at least {count} candidates.\n"
        "- payload_hex must be hex only, even length, non-empty, and 1 to 16 bytes.\n"
        "- Remove duplicate ideas before returning.\n"
        "- Include semantic, boundary, invalid, padding, prefix, suffix, and length variation when useful.\n"
        "Previous round feedback:\n"
        "{context}\n"
        "Expected schema:\n"
        "{schema}\n"
        "Round index: {round_index}\n"
    ).format(
        count=count,
        context=json.dumps(context, ensure_ascii=False, indent=2),
        schema=json.dumps(schema, ensure_ascii=False, indent=2),
        round_index=round_index,
        method_id=method_id,
        method_name=profile["method_name"],
        getter_id=profile["getter_id"],
        getter_name=profile["getter_name"],
        payload_assumption=profile["payload_assumption"],
        reset_payload=profile["reset_payload_hex"],
        reset_expected=profile["reset_expected_payload_hex"],
    )


def openai_dashboard_waiter(dashboard, dashboard_state, stop_event, method_id, round_index):
    started = time.time()
    while not stop_event.wait(1.0):
        if dashboard is None or dashboard_state is None:
            continue
        dashboard_state["status"] = "planning"
        dashboard_state["current"] = "OpenAI m{} round {} waiting {}s".format(
            method_id,
            round_index,
            int(time.time() - started),
        )
        dashboard.render(dashboard_state, force=True)


def call_openai_candidates(args, method_id, round_index, context, dashboard=None, dashboard_state=None):
    if OpenAI is None:
        raise RuntimeError("openai package is not installed")
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    model = args.model or os.environ.get("OPENAI_MODEL", "").strip()
    if not model:
        raise RuntimeError("--model or OPENAI_MODEL is required when OpenAI planning is enabled")
    client = OpenAI(api_key=api_key)
    prompt = build_prompt(method_id, round_index, args.candidates_per_round, context)
    stop_event = threading.Event()
    waiter = None
    if dashboard is not None and dashboard_state is not None:
        dashboard_state["status"] = "planning"
        dashboard_state["current"] = "OpenAI m{} round {} waiting 0s".format(method_id, round_index)
        dashboard.render(dashboard_state, force=True)
        waiter = threading.Thread(
            target=openai_dashboard_waiter,
            args=(dashboard, dashboard_state, stop_event, method_id, round_index),
        )
        waiter.daemon = True
        waiter.start()
    try:
        if hasattr(client, "responses"):
            response = client.responses.create(
                model=model,
                instructions="You are a state-aware SOME/IP fuzzing planner. Return only JSON.",
                input=prompt,
                max_output_tokens=2400,
            )
            text = getattr(response, "output_text", None)
        else:
            request = {
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a state-aware SOME/IP fuzzing planner. Return only valid JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 2400,
                "response_format": {"type": "json_object"},
            }
            try:
                response = client.chat.completions.create(**request)
            except TypeError:
                request.pop("response_format", None)
                response = client.chat.completions.create(**request)
            text = response.choices[0].message.content if response.choices else ""
    finally:
        stop_event.set()
        if waiter is not None:
            waiter.join(timeout=1.0)
    if not text:
        raise RuntimeError("model returned empty text")
    try:
        obj = extract_json_object(text)
    except ValueError as exc:
        path = save_invalid_model_output(method_id, round_index, text)
        print(
            "warning: model output was not valid JSON for method {} round {}; saved raw output to {}; using deterministic fallback for this method".format(
                method_id,
                round_index,
                path,
            ),
            file=sys.stderr,
        )
        return []
    rows = []
    for index, item in enumerate(obj.get("candidates", []), start=1):
        if not isinstance(item, dict):
            continue
        rows.append(
            make_candidate(
                method_id,
                item.get("payload_label") or "llm_candidate_{}".format(index),
                item.get("payload_hex", ""),
                round_index,
                item.get("generation_strategy", "llm_feedback_api"),
                item.get("seed_payload_hex", ""),
                item.get("feedback_note", ""),
            )
        )
    return rows


def generate_candidates(args, method_ids, round_index, context, dashboard=None, dashboard_state=None):
    rows = []
    for method_id in method_ids:
        method_rows = []
        if args.use_openai_api:
            method_rows.extend(call_openai_candidates(args, method_id, round_index, context, dashboard, dashboard_state))
        method_rows.extend(deterministic_seed_pool(method_id, round_index, context))
        rows.extend(dedupe_candidates(method_rows, args.candidates_per_round))
    return rows


def run_hybrid_campaign(args, stamp, dashboard, dashboard_state, deadline):
    from check_candidate_state_effect import call_someip, next_session_id  # noqa: WPS433

    paths = hybrid_paths(args.output_prefix, stamp)
    queue = deque()
    queued_or_done = set()
    all_candidates = []
    all_candidates_by_key = {}
    detail_rows = []
    round_index = 1
    session_id = 0x7B00
    llm_calls = 0
    llm_method_index = 0
    next_llm_at = time.time() + args.hybrid_llm_interval_sec
    payloads_since_hit = 0

    def enqueue(rows, front=False):
        added = 0
        for row in rows:
            if row is None:
                continue
            key = (int(row["method_id"]), row["payload_hex"])
            if key in queued_or_done:
                continue
            queued_or_done.add(key)
            all_candidates_by_key.setdefault(key, row)
            all_candidates.append(row)
            if front:
                queue.appendleft(row)
            else:
                queue.append(row)
            added += 1
        return added

    initial_context = feedback_context([])
    for method_id in args.target_method_ids:
        enqueue(dedupe_candidates(deterministic_seed_pool(method_id, round_index, initial_context), args.candidates_per_round))

    dashboard_state["status"] = "hybrid executing"
    dashboard_state["round"] = round_index
    dashboard_state["rounds"] = 0
    dashboard_state["trials_done"] = 0
    dashboard_state["trials_total"] = 0
    dashboard_state["current"] = "hybrid queue initialized"
    dashboard_state["output"] = paths["payload_summary"]
    dashboard_state["metrics"] = {
        "candidate_count": len(all_candidates),
        "unique_payload_count": len(queued_or_done),
        "detail_trial_count": 0,
        "queue_size": len(queue),
        "llm_calls": llm_calls,
    }
    dashboard.render(dashboard_state, force=True)

    while queue and (deadline is None or time.time() < deadline):
        now = time.time()
        should_call_llm = (
            args.use_openai_api
            and llm_calls < args.hybrid_llm_call_cap
            and (now >= next_llm_at or payloads_since_hit >= args.hybrid_stagnation_payloads)
        )
        if should_call_llm:
            payload_rows = payload_summary(detail_rows)
            context = feedback_context([{"payload_rows": payload_rows}])
            method_id = args.target_method_ids[llm_method_index % len(args.target_method_ids)]
            llm_method_index += 1
            dashboard_state["status"] = "planning"
            dashboard_state["current"] = "hybrid OpenAI m{} call {}/{}".format(
                method_id,
                llm_calls + 1,
                args.hybrid_llm_call_cap,
            )
            dashboard.render(dashboard_state, force=True)
            try:
                llm_rows = call_openai_candidates(args, method_id, round_index, context, dashboard, dashboard_state)
                enqueue(dedupe_candidates(llm_rows, args.candidates_per_round))
                llm_calls += 1
            except Exception as exc:
                print("warning: hybrid OpenAI call failed for method {}: {}".format(method_id, exc), file=sys.stderr)
                llm_calls += 1
            next_llm_at = time.time() + args.hybrid_llm_interval_sec
            payloads_since_hit = 0
            round_index += 1

        candidate = queue.popleft()
        replay_item = {
            "payload_source": candidate["payload_source"],
            "payload_label": candidate["payload_label"],
            "method_id": candidate["method_id"],
            "payload_hex": candidate["payload_hex"],
            "payload_len": candidate["payload_len"],
        }
        candidate_rows = []
        for trial_index in range(1, args.trial_count + 1):
            if deadline is not None and time.time() >= deadline:
                break
            dashboard_state["status"] = "hybrid executing"
            dashboard_state["round"] = round_index
            dashboard_state["trials_done"] = len(detail_rows)
            dashboard_state["trials_total"] = 0
            dashboard_state["current"] = "m{} {} trial {}/{} queue {}".format(
                candidate["method_id"],
                candidate["payload_hex"],
                trial_index,
                args.trial_count,
                len(queue),
            )
            dashboard_state["metrics"] = live_replay_metrics(detail_rows, len(all_candidates))
            dashboard_state["metrics"]["queue_size"] = len(queue)
            dashboard_state["metrics"]["llm_calls"] = llm_calls
            dashboard.render(dashboard_state)
            row, session_id = run_trial(call_someip, next_session_id, replay_item, trial_index, session_id, args.timeout)
            detail_rows.append(row)
            candidate_rows.append(row)

        if candidate_rows:
            candidate_payload_rows = payload_summary(candidate_rows)
            payload_row = candidate_payload_rows[0] if candidate_payload_rows else {}
            classification = payload_row.get("classification", "")
            if payload_row.get("non_trivial_state_effect_count") not in ("", "0", 0) or classification in (
                "reproducible_non_trivial_state_effect",
                "unstable_non_trivial_state_effect",
            ):
                payloads_since_hit = 0
                enqueue(local_feedback_mutations(candidate, payload_row, round_index), front=True)
            else:
                payloads_since_hit += 1
                if classification == "protocol_valid_no_effect":
                    enqueue(local_feedback_mutations(candidate, payload_row, round_index), front=False)

        if not queue and (deadline is None or time.time() < deadline):
            payload_rows = payload_summary(detail_rows)
            context = feedback_context([{"payload_rows": payload_rows}])
            for method_id in args.target_method_ids:
                enqueue(dedupe_candidates(deterministic_seed_pool(method_id, round_index + 1, context), args.candidates_per_round))
            round_index += 1

    payload_rows = payload_summary(detail_rows)
    metrics = round_metrics(payload_rows, detail_rows)
    metrics["candidate_count"] = len(all_candidates)
    metrics["queue_size"] = len(queue)
    metrics["llm_calls"] = llm_calls
    write_candidate_csv(paths["candidates"], all_candidates)
    write_csv(paths["detail"], DETAIL_HEADER, detail_rows)
    write_csv(paths["payload_summary"], PAYLOAD_SUMMARY_HEADER, payload_rows)
    write_csv(paths["summary"], SUMMARY_HEADER, source_summary(detail_rows, payload_rows))
    dashboard_state["status"] = "hybrid complete"
    dashboard_state["current"] = "hybrid campaign complete"
    dashboard_state["metrics"] = metrics
    dashboard_state["output"] = paths["payload_summary"]
    dashboard.render(dashboard_state, force=True)
    return {
        "round_records": [{
            "round_index": 1,
            "target_method_ids": list(args.target_method_ids),
            "paths": paths,
            "candidates": all_candidates,
            "payload_rows": payload_rows,
            "detail_rows": detail_rows,
            "metrics": metrics,
        }],
        "all_candidates_by_key": all_candidates_by_key,
        "paths": paths,
    }


def round_paths(output_prefix, round_index, stamp):
    return {
        "candidates": "{}_round_{}_candidates_{}.csv".format(output_prefix, round_index, stamp),
        "detail": "{}_round_{}_detail_{}.csv".format(output_prefix, round_index, stamp),
        "payload_summary": "{}_round_{}_payload_summary_{}.csv".format(output_prefix, round_index, stamp),
        "summary": "{}_round_{}_summary_{}.csv".format(output_prefix, round_index, stamp),
    }


def run_replay(candidates, trial_count, timeout_sec, dashboard=None, dashboard_state=None, deadline=None):
    from check_candidate_state_effect import call_someip, next_session_id  # noqa: WPS433

    rows = []
    session_id = 0x7B00
    total_trials = len(candidates) * trial_count
    done = 0
    for item in candidates:
        if deadline is not None and time.time() >= deadline:
            break
        replay_item = {
            "payload_source": item["payload_source"],
            "payload_label": item["payload_label"],
            "method_id": item["method_id"],
            "payload_hex": item["payload_hex"],
            "payload_len": item["payload_len"],
        }
        for trial_index in range(1, trial_count + 1):
            if deadline is not None and time.time() >= deadline:
                break
            if dashboard is not None and dashboard_state is not None:
                dashboard_state["status"] = "executing"
                dashboard_state["trials_done"] = done
                dashboard_state["trials_total"] = total_trials
                dashboard_state["current"] = "m{} {} trial {}/{}".format(
                    item["method_id"],
                    item["payload_hex"],
                    trial_index,
                    trial_count,
                )
                dashboard.render(dashboard_state)
            row, session_id = run_trial(call_someip, next_session_id, replay_item, trial_index, session_id, timeout_sec)
            rows.append(row)
            done += 1
            if dashboard is not None and dashboard_state is not None:
                dashboard_state["trials_done"] = done
                dashboard_state["metrics"] = live_replay_metrics(rows, len(candidates))
                dashboard.render(dashboard_state)
    if dashboard is not None and dashboard_state is not None:
        dashboard_state["trials_done"] = done
        dashboard_state["trials_total"] = total_trials
        dashboard.render(dashboard_state, force=True)
    return rows


def write_empty_replay_outputs(paths):
    write_csv(paths["detail"], DETAIL_HEADER, [])
    write_csv(paths["payload_summary"], PAYLOAD_SUMMARY_HEADER, [])
    write_csv(paths["summary"], SUMMARY_HEADER, [])


def annotate_final_rows(candidate_by_key, payload_rows):
    rows = []
    for row in payload_rows:
        if row.get("classification") != "reproducible_non_trivial_state_effect":
            continue
        key = (int(row.get("method_id", 0)), row.get("payload_hex", ""))
        candidate = dict(candidate_by_key.get(key, {}))
        if not candidate:
            continue
        for column in [
            "classification",
            "normal_response_count",
            "error_response_count",
            "timeout_count",
            "non_trivial_state_effect_count",
            "non_trivial_state_effect_rate",
        ]:
            candidate[column] = row.get(column, "")
        rows.append(candidate)
    return rows


def write_final_high_value(path, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FINAL_HEADER, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


class TerminalDashboard:
    def __init__(self, enabled, title="SOME/IP LLM Fuzzer"):
        self.enabled = enabled
        self.title = title
        self.is_tty = sys.stdout.isatty()
        self.started_at = time.time()
        self.last_render = 0.0

    def render(self, state, force=False):
        if not self.enabled:
            return
        now = time.time()
        if not force and now - self.last_render < 0.25:
            return
        self.last_render = now
        if self.is_tty:
            self._render_tty(state)
        elif force:
            self._render_line(state)

    def _render_tty(self, state):
        cols = shutil.get_terminal_size((100, 24)).columns
        width = max(40, min(cols, 120))
        line = "+" + "-" * (width - 2) + "+"
        elapsed = int(time.time() - self.started_at)
        metrics = state.get("metrics", {})
        status = state.get("status", "initializing")
        current = state.get("current", "")
        trials_done = int(state.get("trials_done", 0) or 0)
        trials_total = int(state.get("trials_total", 0) or 0)
        progress = self._percent(trials_done, trials_total)
        exec_rate = self._rate(trials_done, elapsed)
        time_limit = int(state.get("duration_sec") or 0)
        remaining = max(0, int(state.get("deadline", 0) - time.time())) if state.get("deadline") else 0
        print("\033[2J\033[H", end="")
        print(self._title(self.title, width))
        print(self._section("process timing", "overall results", width))
        self._pair("run time", self._fmt_duration(elapsed), "rounds done", max(0, state.get("round", 0) - 1), width)
        if time_limit > 0:
            self._pair("time limit", self._fmt_duration(time_limit), "time left", self._fmt_duration(remaining), width)
        else:
            self._pair("time limit", "none", "time left", "n/a", width)
        self._pair("status", status, "exec/sec", exec_rate, width)
        print(self._section("campaign progress", "payload corpus", width))
        self._pair("current round", self._round_label(state), "targets", state.get("targets", ""), width)
        self._pair("trial progress", "{} ({})".format(self._count_label(trials_done, trials_total), progress), "candidates", metrics.get("candidate_count", 0), width)
        self._pair("unique payloads", metrics.get("unique_payload_count", 0), "queue size", metrics.get("queue_size", 0), width)
        self._single("now processing", current, width)
        print(self._section("response summary", "state findings", width))
        self._pair("normal", metrics.get("normal_response_count", 0), "state changed", metrics.get("state_changed_count", 0), width)
        self._pair("errors", metrics.get("error_response_count", 0), "non-trivial", metrics.get("non_trivial_state_effect_count", 0), width)
        self._pair("timeouts", metrics.get("timeout_count", 0), "repro high", metrics.get("reproducible_non_trivial_state_effect_count", 0), width)
        self._pair("valid no effect", metrics.get("protocol_valid_no_effect_count", 0), "trials logged", metrics.get("detail_trial_count", 0), width)
        self._pair("llm calls", metrics.get("llm_calls", 0), "mode", state.get("mode", ""), width)
        self._single("output", state.get("output", ""), width)
        print(line)
        sys.stdout.flush()

    def _render_line(self, state):
        metrics = state.get("metrics", {})
        print(
            "[dashboard] status={status} round={round}/{rounds} trials={done}/{total} "
            "normal={normal} errors={errors} timeouts={timeouts} non_trivial={nontrivial} "
            "repro_high={repro} queue={queue} llm_calls={llm_calls} output={output}".format(
                status=state.get("status", ""),
                round=state.get("round", 0),
                rounds=state.get("rounds", 0),
                done=state.get("trials_done", 0),
                total=state.get("trials_total", 0),
                normal=metrics.get("normal_response_count", 0),
                errors=metrics.get("error_response_count", 0),
                timeouts=metrics.get("timeout_count", 0),
                nontrivial=metrics.get("non_trivial_state_effect_count", 0),
                repro=metrics.get("reproducible_non_trivial_state_effect_count", 0),
                queue=metrics.get("queue_size", 0),
                llm_calls=metrics.get("llm_calls", 0),
                output=state.get("output", ""),
            )
        )

    def _row(self, text, width):
        max_len = width - 4
        return "| " + self._fit(text, max_len).ljust(max_len) + " |"

    def _fit(self, text, width):
        text = str(text)
        if width <= 0:
            return ""
        if len(text) <= width:
            return text
        if width <= 3:
            return text[:width]
        return text[: width - 3] + "..."

    def _title(self, text, width):
        inner = width - 2
        label = " {} ".format(self._fit(text, inner - 2))
        pad = max(0, inner - len(label))
        left = pad // 2
        right = pad - left
        return "+" + "-" * left + label + "-" * right + "+"

    def _section(self, left, right, width):
        inner = width - 2
        left_label = " {} ".format(left)
        right_label = " {} ".format(right)
        left_width = max(1, (inner - 1) // 2)
        right_width = max(1, inner - 1 - left_width)
        return (
            "+"
            + self._fit(left_label, left_width).ljust(left_width, "-")
            + "-"
            + self._fit(right_label, right_width).rjust(right_width, "-")
            + "+"
        )

    def _pair(self, left_key, left_value, right_key, right_value, width):
        inner = width - 4
        gap = 3
        left_width = max(1, (inner - gap) // 2)
        right_width = max(1, inner - gap - left_width)
        left_lines = self._field_lines(left_key, left_value, left_width)
        right_lines = self._field_lines(right_key, right_value, right_width)
        count = max(len(left_lines), len(right_lines))
        for index in range(count):
            left = left_lines[index] if index < len(left_lines) else ""
            right = right_lines[index] if index < len(right_lines) else ""
            print("| " + left.ljust(left_width) + " " * gap + right.ljust(right_width) + " |")

    def _field_lines(self, key, value, width):
        prefix = "{:<14}: ".format(str(key))
        if len(prefix) >= width:
            return [self._fit(prefix.rstrip(), width)]
        value_width = max(1, width - len(prefix))
        chunks = textwrap.wrap(
            str(value),
            width=value_width,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]
        lines = [prefix + chunks[0]]
        continuation = " " * len(prefix)
        for chunk in chunks[1:]:
            lines.append(continuation + chunk)
        return lines

    def _single(self, key, value, width):
        text = "{:<14}: {}".format(str(key), value)
        max_len = width - 4
        lines = textwrap.wrap(
            text,
            width=max_len,
            break_long_words=True,
            break_on_hyphens=False,
        ) or [""]
        for line in lines:
            print("| " + line.ljust(max_len) + " |")

    def _round_label(self, state):
        if state.get("duration_sec"):
            return "{} / time-boxed".format(state.get("round", 0))
        return "{}/{}".format(state.get("round", 0), state.get("rounds", 0))

    def _fmt_duration(self, seconds):
        seconds = max(0, int(seconds))
        minutes, sec = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return "{}h{:02d}m{:02d}s".format(hours, minutes, sec)
        if minutes:
            return "{}m{:02d}s".format(minutes, sec)
        return "{}s".format(sec)

    def _count_label(self, done, total):
        if total > 0:
            return "{}/{}".format(done, total)
        return str(done)

    def _percent(self, done, total):
        if total <= 0:
            return "n/a"
        return "{:.1f}%".format((float(done) / float(total)) * 100.0)

    def _rate(self, count, elapsed):
        if elapsed <= 0:
            return "0.00"
        return "{:.2f}".format(float(count) / float(elapsed))


def latest_radamsa_summary_rows():
    paths = sorted(
        glob.glob("results/method14_llm_vs_radamsa_summary_*.csv"),
        key=lambda path: os.path.getmtime(path),
        reverse=True,
    )
    if not paths:
        return "", []
    return paths[0], read_csv_rows(paths[0])


def radamsa_comparison_table():
    path, rows = latest_radamsa_summary_rows()
    if not rows:
        return "No existing Method 14 Radamsa summary CSV found."
    lines = ["Existing Radamsa comparison source: `{}`".format(path), "", "| source | unique_payload_count | normal_response_count | error_response_count | non_trivial_state_effect_count | reproducible_non_trivial_state_effect_count |", "|---|---:|---:|---:|---:|---:|"]
    for row in rows:
        source = row.get("payload_source", "")
        if not source.startswith("radamsa"):
            continue
        lines.append(
            "| {source} | {unique} | {normal} | {error} | {nontrivial} | {repro} |".format(
                source=source,
                unique=row.get("unique_payload_count", ""),
                normal=row.get("normal_response_count", ""),
                error=row.get("error_response_count", ""),
                nontrivial=row.get("non_trivial_state_effect_count", ""),
                repro=row.get("reproducible_non_trivial_state_effect_count", ""),
            )
        )
    return "\n".join(lines)


def trend_text(round_records):
    values = [record["metrics"]["non_trivial_state_effect_count"] for record in round_records]
    repro = [record["metrics"]["reproducible_non_trivial_state_effect_count"] for record in round_records]
    if not values:
        return "No executed rounds were available for trend analysis."
    if values[-1] > values[0] or repro[-1] > repro[0]:
        return "The feedback loop improved the state-effect signal across rounds."
    if values[-1] == values[0] and repro[-1] == repro[0]:
        return "The feedback loop did not improve the state-effect signal across rounds."
    return "The final round had weaker state-effect counts than the first executed round."


def markdown_examples(title, rows):
    lines = ["### {}".format(title), "", "| method_id | payload_label | payload_hex | classification | normal | non_trivial |", "|---:|---|---|---|---:|---:|"]
    if not rows:
        lines.append("|  | none |  |  |  |  |")
    for row in rows[:10]:
        lines.append(
            "| {method_id} | {label} | `{payload}` | {classification} | {normal} | {nontrivial} |".format(
                method_id=row.get("method_id", ""),
                label=row.get("payload_label", ""),
                payload=row.get("payload_hex", ""),
                classification=row.get("classification", ""),
                normal=row.get("normal_response_count", ""),
                nontrivial=row.get("non_trivial_state_effect_count", ""),
            )
        )
    return "\n".join(lines)


def write_report(path, args, round_records, final_rows):
    all_payload_rows = []
    for record in round_records:
        all_payload_rows.extend(record.get("payload_rows", []))
    classed = rows_by_classification(all_payload_rows)
    high_value = classed.get("reproducible_non_trivial_state_effect", []) + classed.get("unstable_non_trivial_state_effect", [])
    no_effect = classed.get("protocol_valid_no_effect", [])
    errors = classed.get("rejected_or_error", []) + classed.get("timeout_or_no_response", [])

    lines = [
        "# SOME/IP LLM Fuzzer Report",
        "",
        "Target methods: `{}`.".format(",".join(str(x) for x in args.target_method_ids)),
        "",
        "Profiles: Method 10->Getter 9, Method 12->Getter 11, Method 14->Getter 8.",
        "",
        "Primary metric: `non_trivial_state_effect_count`. Final high-value metric: `reproducible_non_trivial_state_effect_count`.",
        "",
        "Mode: `{}`. OpenAI API requested: `{}`.".format("execute" if args.execute else "dry-run", str(args.use_openai_api)),
        "",
        "## Round Summary",
        "",
        "| round | target_methods | candidates | normal_response_count | error_response_count | non_trivial_state_effect_count | reproducible_non_trivial_state_effect_count |",
        "|---:|---|---:|---:|---:|---:|---:|",
    ]
    for record in round_records:
        metrics = record["metrics"]
        lines.append(
            "| {round} | {methods} | {candidates} | {normal} | {error} | {nontrivial} | {repro} |".format(
                round=record["round_index"],
                methods=",".join(str(x) for x in record.get("target_method_ids", [])),
                candidates=metrics["candidate_count"],
                normal=metrics["normal_response_count"],
                error=metrics["error_response_count"],
                nontrivial=metrics["non_trivial_state_effect_count"],
                repro=metrics["reproducible_non_trivial_state_effect_count"],
            )
        )

    lines.extend([
        "",
        "## Trend",
        "",
        trend_text(round_records),
        "",
        "## High-Value Final Candidates",
        "",
        "Final reproducible high-value candidate count: `{}`.".format(len(final_rows)),
        "",
        markdown_examples("High-value payload examples", high_value),
        "",
        markdown_examples("Protocol-valid no-effect payload examples", no_effect),
        "",
        markdown_examples("Error payload examples", errors),
        "",
        "## Radamsa Baseline",
        "",
        radamsa_comparison_table(),
        "",
        "## Limitation",
        "",
        "This is state-aware fuzzing. The goal is to find payloads that produce externally observable paired-getter state effects after reset. It is not a crash/hang campaign, and `normal_response_count` alone is not treated as success.",
    ])

    ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def parse_args():
    load_dotenv_simple()
    default_use_openai = env_bool("SOMEIP_LLM_USE_OPENAI", bool(os.environ.get("OPENAI_API_KEY", "").strip()))
    default_execute = env_bool("SOMEIP_LLM_EXECUTE", False)
    parser = argparse.ArgumentParser(description="SOME/IP LLM Fuzzer with hybrid feedback guidance. Defaults can be set in .env.")
    parser.add_argument("--target-methods", default=env_value("SOMEIP_LLM_TARGET_METHODS", "10,12,14"), help="Comma-separated target methods; supported: 10,12,14")
    parser.add_argument("--rounds", type=int, default=env_int("SOMEIP_LLM_ROUNDS", 3))
    parser.add_argument("--candidates-per-round", type=int, default=env_int("SOMEIP_LLM_CANDIDATES_PER_ROUND", 50))
    parser.add_argument("--trial-count", type=int, default=env_int("SOMEIP_LLM_TRIAL_COUNT", 3))
    parser.add_argument("--final-trial-count", type=int, default=env_int("SOMEIP_LLM_FINAL_TRIAL_COUNT", 10))
    parser.add_argument("--timeout", type=float, default=env_float("SOMEIP_LLM_TIMEOUT", 1.0))
    parser.add_argument(
        "--duration-sec",
        "--max-runtime",
        type=parse_duration_sec,
        default=parse_duration_sec(env_value("SOMEIP_LLM_DURATION_SEC", "0")),
        help="Run for at least this wall-clock budget by continuing rounds until time expires. Accepts seconds, 30m, or 1h.",
    )
    hybrid_group = parser.add_mutually_exclusive_group()
    hybrid_group.add_argument("--hybrid-feedback", dest="hybrid_feedback", action="store_true")
    hybrid_group.add_argument("--no-hybrid-feedback", dest="hybrid_feedback", action="store_false")
    parser.set_defaults(hybrid_feedback=env_bool("SOMEIP_LLM_HYBRID_FEEDBACK", True))
    parser.add_argument(
        "--hybrid-llm-interval-sec",
        type=parse_duration_sec,
        default=parse_duration_sec(env_value("SOMEIP_LLM_HYBRID_LLM_INTERVAL_SEC", "3m")),
        help="Minimum time between hybrid OpenAI seed requests.",
    )
    parser.add_argument("--hybrid-llm-call-cap", type=int, default=env_int("SOMEIP_LLM_HYBRID_LLM_CALL_CAP", 10))
    parser.add_argument("--hybrid-stagnation-payloads", type=int, default=env_int("SOMEIP_LLM_HYBRID_STAGNATION_PAYLOADS", 200))
    openai_group = parser.add_mutually_exclusive_group()
    openai_group.add_argument("--use-openai-api", dest="use_openai_api", action="store_true", help="Enable OpenAI planning. This is the default when SOMEIP_LLM_USE_OPENAI=1 or OPENAI_API_KEY is set.")
    openai_group.add_argument("--no-openai-api", dest="use_openai_api", action="store_false", help="Disable OpenAI planning and use local generation only.")
    parser.set_defaults(use_openai_api=default_use_openai)
    parser.add_argument("--model", default=os.environ.get("OPENAI_MODEL", ""))
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--dry-run", dest="execute", action="store_false")
    mode_group.add_argument("--execute", dest="execute", action="store_true")
    parser.set_defaults(execute=default_execute)
    parser.add_argument("--dashboard", dest="dashboard", action="store_true", default=env_bool("SOMEIP_LLM_DASHBOARD", True))
    parser.add_argument("--no-dashboard", dest="dashboard", action="store_false")
    parser.add_argument("--output-prefix", default=env_value("SOMEIP_LLM_OUTPUT_PREFIX", DEFAULT_OUTPUT_PREFIX))
    return parser.parse_args()


def parse_target_methods(value):
    method_ids = []
    for part in str(value or "").split(","):
        part = part.strip()
        if not part:
            continue
        method_id = int(part, 0)
        profile_for_method(method_id)
        if method_id not in method_ids:
            method_ids.append(method_id)
    if not method_ids:
        method_ids = list(DEFAULT_TARGET_METHODS)
    return method_ids


def validate_args(args):
    if args.rounds <= 0:
        raise SystemExit("--rounds must be positive")
    if args.candidates_per_round <= 0:
        raise SystemExit("--candidates-per-round must be positive")
    if args.trial_count <= 0:
        raise SystemExit("--trial-count must be positive")
    if args.final_trial_count <= 0:
        raise SystemExit("--final-trial-count must be positive")
    if args.duration_sec < 0:
        raise SystemExit("--duration-sec must be non-negative")
    if args.hybrid_llm_interval_sec <= 0:
        raise SystemExit("--hybrid-llm-interval-sec must be positive")
    if args.hybrid_llm_call_cap < 0:
        raise SystemExit("--hybrid-llm-call-cap must be non-negative")
    if args.hybrid_stagnation_payloads <= 0:
        raise SystemExit("--hybrid-stagnation-payloads must be positive")
    args.target_method_ids = parse_target_methods(args.target_methods)
    if args.use_openai_api and not os.environ.get("OPENAI_API_KEY", "").strip():
        raise SystemExit("OPENAI_API_KEY is required when OpenAI planning is enabled")
    if args.use_openai_api and not (args.model or os.environ.get("OPENAI_MODEL", "").strip()):
        raise SystemExit("--model or OPENAI_MODEL is required when OpenAI planning is enabled")


def main():
    args = parse_args()
    validate_args(args)
    stamp = timestamp()
    round_records = []
    all_candidates_by_key = {}
    dashboard = TerminalDashboard(args.dashboard)
    campaign_started = time.time()
    deadline = campaign_started + args.duration_sec if args.duration_sec > 0 else None
    dashboard_state = {
        "status": "starting",
        "mode": "execute" if args.execute else "dry-run",
        "openai": "on" if args.use_openai_api else "off",
        "model": args.model or os.environ.get("OPENAI_MODEL", ""),
        "targets": ",".join(str(x) for x in args.target_method_ids),
        "round": 0,
        "rounds": args.rounds,
        "candidates_per_round": args.candidates_per_round,
        "trials_done": 0,
        "trials_total": 0,
        "current": "",
        "output": args.output_prefix,
        "metrics": {},
        "duration_sec": args.duration_sec,
        "deadline": deadline,
    }
    dashboard.render(dashboard_state, force=True)

    if args.execute and args.duration_sec > 0 and args.hybrid_feedback:
        result = run_hybrid_campaign(args, stamp, dashboard, dashboard_state, deadline)
        round_records = result["round_records"]
        all_candidates_by_key = result["all_candidates_by_key"]
        print("hybrid candidates={} detail={} payload_summary={}".format(
            len(round_records[0]["candidates"]),
            result["paths"]["detail"],
            result["paths"]["payload_summary"],
        ))
        final_path = "{}_final_high_value_{}.csv".format(args.output_prefix, stamp)
        report_path = "{}_report_{}.md".format(args.output_prefix, stamp)
        final_rows = []
        prior_payload_rows = list(round_records[0]["payload_rows"])
        high_value_payloads = [
            (int(row.get("method_id", 0)), row["payload_hex"])
            for row in prior_payload_rows
            if row.get("classification") in ("reproducible_non_trivial_state_effect", "unstable_non_trivial_state_effect")
        ]
        final_candidates = [all_candidates_by_key[key] for key in dict.fromkeys(high_value_payloads) if key in all_candidates_by_key]
        if final_candidates:
            dashboard_state["status"] = "final verification"
            dashboard_state["current"] = "{} high-value candidates".format(len(final_candidates))
            dashboard.render(dashboard_state, force=True)
            detail_rows = run_replay(final_candidates, args.final_trial_count, args.timeout, dashboard, dashboard_state, None)
            payload_rows = payload_summary(detail_rows)
            final_rows = annotate_final_rows(all_candidates_by_key, payload_rows)
        write_final_high_value(final_path, final_rows)
        write_report(report_path, args, round_records, final_rows)
        print("wrote {}".format(final_path))
        print("wrote {}".format(report_path))
        dashboard_state["status"] = "done"
        dashboard_state["output"] = report_path
        dashboard.render(dashboard_state, force=True)
        return

    round_index = 1
    while True:
        if deadline is None and round_index > args.rounds:
            break
        if deadline is not None and time.time() >= deadline:
            break
        context = feedback_context(round_records)
        dashboard_state["status"] = "planning"
        dashboard_state["round"] = round_index
        dashboard_state["current"] = "generating candidates"
        dashboard.render(dashboard_state, force=True)
        candidates = generate_candidates(args, args.target_method_ids, round_index, context, dashboard, dashboard_state)
        dashboard_state["metrics"] = {
            "candidate_count": len(candidates),
            "unique_payload_count": len({(int(candidate["method_id"]), candidate["payload_hex"]) for candidate in candidates}),
            "detail_trial_count": 0,
        }
        dashboard_state["trials_done"] = 0
        dashboard_state["trials_total"] = len(candidates) * args.trial_count if args.execute else 0
        paths = round_paths(args.output_prefix, round_index, stamp)
        write_candidate_csv(paths["candidates"], candidates)
        for candidate in candidates:
            all_candidates_by_key.setdefault((int(candidate["method_id"]), candidate["payload_hex"]), candidate)

        if not args.execute:
            detail_rows = []
            payload_rows = []
            write_empty_replay_outputs(paths)
        else:
            detail_rows = run_replay(candidates, args.trial_count, args.timeout, dashboard, dashboard_state, deadline)
            payload_rows = payload_summary(detail_rows)
            write_csv(paths["detail"], DETAIL_HEADER, detail_rows)
            write_csv(paths["payload_summary"], PAYLOAD_SUMMARY_HEADER, payload_rows)
            write_csv(paths["summary"], SUMMARY_HEADER, source_summary(detail_rows, payload_rows))

        metrics = round_metrics(payload_rows, detail_rows)
        if not args.execute:
            metrics["candidate_count"] = len(candidates)
        dashboard_state["metrics"] = metrics
        dashboard_state["status"] = "round complete"
        dashboard_state["output"] = paths["payload_summary"]
        dashboard.render(dashboard_state, force=True)
        round_records.append({
            "round_index": round_index,
            "target_method_ids": list(args.target_method_ids),
            "paths": paths,
            "candidates": candidates,
            "payload_rows": payload_rows,
            "detail_rows": detail_rows,
            "metrics": metrics,
        })
        print("round={} candidates={} detail={} payload_summary={}".format(
            round_index,
            len(candidates),
            paths["detail"],
            paths["payload_summary"],
        ))
        round_index += 1

    final_path = "{}_final_high_value_{}.csv".format(args.output_prefix, stamp)
    report_path = "{}_report_{}.md".format(args.output_prefix, stamp)
    final_rows = []

    if args.execute:
        prior_payload_rows = []
        for record in round_records:
            prior_payload_rows.extend(record["payload_rows"])
        high_value_payloads = [
            (int(row.get("method_id", 0)), row["payload_hex"])
            for row in prior_payload_rows
            if row.get("classification") in ("reproducible_non_trivial_state_effect", "unstable_non_trivial_state_effect")
        ]
        final_candidates = [all_candidates_by_key[key] for key in dict.fromkeys(high_value_payloads) if key in all_candidates_by_key]
        if final_candidates:
            dashboard_state["status"] = "final verification"
            dashboard_state["current"] = "{} high-value candidates".format(len(final_candidates))
            dashboard.render(dashboard_state, force=True)
            detail_rows = run_replay(final_candidates, args.final_trial_count, args.timeout, dashboard, dashboard_state, deadline)
            payload_rows = payload_summary(detail_rows)
            final_rows = annotate_final_rows(all_candidates_by_key, payload_rows)

    write_final_high_value(final_path, final_rows)
    write_report(report_path, args, round_records, final_rows)
    print("wrote {}".format(final_path))
    print("wrote {}".format(report_path))
    dashboard_state["status"] = "done"
    dashboard_state["output"] = report_path
    dashboard.render(dashboard_state, force=True)
    if not args.execute:
        print("dry-run only: no replay was executed")


if __name__ == "__main__":
    main()
