#!/usr/bin/env python3
"""Source-informed fuzzing harness for request-capable SOME/IP methods 1..14."""

import argparse
import csv
import os
import random
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
SCRIPTS_DIR = os.path.dirname(__file__)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)


METHODS = {
    1: {"name": "getConsumptionAttribute", "role": "getter"},
    2: {"name": "getCapacityAttribute", "role": "getter"},
    3: {"name": "getVolumeAttribute", "role": "getter"},
    4: {"name": "getEngineSpeedAttribute", "role": "getter"},
    5: {"name": "getCurrentGearAttribute", "role": "getter"},
    6: {"name": "getIsReverseGearOnAttribute", "role": "getter"},
    7: {"name": "getDrivePowerTransmissionAttribute", "role": "getter"},
    8: {"name": "getDoorsOpeningStatusAttribute", "role": "getter"},
    9: {"name": "getSeatHeatingStatusAttribute", "role": "getter"},
    10: {
        "name": "setSeatHeatingStatusAttribute",
        "role": "setter",
        "paired_getter": 9,
        "reset_payload_hex": "00000000",
    },
    11: {"name": "getSeatHeatingLevelAttribute", "role": "getter"},
    12: {
        "name": "setSeatHeatingLevelAttribute",
        "role": "setter",
        "paired_getter": 11,
        "reset_payload_hex": "00000000",
    },
    13: {"name": "initTirePressureCalibration", "role": "method"},
    14: {
        "name": "changeDoorsState",
        "role": "method",
        "paired_getter": 8,
        "reset_payload_hex": "02020202",
        "reset_expected_payload_hex": "00000000",
    },
}
GETTER_METHOD_IDS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11]
EXCLUDED_EVENT_IDS = list(range(0x8001, 0x800B))
DEFAULT_OUTPUT_PREFIX = "results/all_method_fuzz"

DETAIL_HEADER = [
    "timestamp",
    "method_id",
    "hex_method_id",
    "method_name",
    "role",
    "payload_source",
    "payload_label",
    "payload_hex",
    "payload_len",
    "trial_index",
    "reset_payload_hex",
    "reset_after_payload_hex",
    "before_payload_hex",
    "response_received",
    "msg_type",
    "retcode",
    "verdict",
    "latency_ms",
    "response_payload_hex",
    "after_payload_hex",
    "state_changed",
    "reset_equivalent",
    "non_trivial_state_effect",
    "error",
]
SUMMARY_HEADER = [
    "method_id",
    "method_name",
    "role",
    "total_candidates",
    "total_trials",
    "normal_response_count",
    "error_response_count",
    "timeout_count",
    "unique_payload_count",
    "state_changed_count",
    "non_trivial_state_effect_count",
    "reproducible_non_trivial_state_effect_count",
    "avg_latency_ms",
    "max_latency_ms",
    "p95_latency_ms",
    "classification_counts",
]


def now_filename():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def now_row():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def hex_method_id(method_id):
    return "0x{:04x}".format(method_id)


def normalize_hex(value):
    text = str(value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    text = "".join(ch for ch in text if ch in "0123456789abcdef")
    if len(text) % 2 == 1:
        text = "0" + text
    return text


def payload_len(payload_hex):
    return len(bytes.fromhex(payload_hex))


def deterministic_random_hex_values(prefix, count=4):
    rng = random.Random(0xA11DEF + sum(ord(ch) for ch in prefix))
    return [bytes(rng.getrandbits(8) for _ in range(4)).hex() for _ in range(count)]


def candidate(source, label, payload_hex):
    payload_hex = normalize_hex(payload_hex)
    return {
        "payload_source": source,
        "payload_label": label,
        "payload_hex": payload_hex,
        "payload_len": payload_len(payload_hex),
    }


def dedupe_candidates(candidates):
    deduped = []
    seen = set()
    for item in candidates:
        key = item["payload_hex"]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def generic_payload_candidates(source_prefix):
    base = [
        ("empty", ""),
        ("zero_1", "00"),
        ("zero_2", "0000"),
        ("zero_4", "00000000"),
        ("ff_1", "ff"),
        ("ff_2", "ffff"),
        ("ff_4", "ffffffff"),
        ("ones_4", "01010101"),
        ("twos_4", "02020202"),
        ("zero_8", "0000000000000000"),
    ]
    items = [candidate(source_prefix, label, payload) for label, payload in base]
    for index, payload in enumerate(deterministic_random_hex_values(source_prefix), start=1):
        items.append(candidate(source_prefix, "random4_{:02d}".format(index), payload))
    return dedupe_candidates(items)


def method10_candidates():
    items = [
        ("reset_empty_vector", "00000000"),
        ("baseline_status", "0000000701000100010001"),
        ("all_false", "0000000700000000000000"),
        ("all_true", "0000000701010101010101"),
        ("invalid_enum_2", "0000000702020202020202"),
        ("len_field_zero", "0000000001000100010001"),
        ("len_field_one", "0000000101000100010001"),
        ("len_field_ff", "000000ff01000100010001"),
        ("short_len_only", "00000007"),
        ("short_len_plus_one", "0000000701"),
        ("truncated_values", "00000007010001"),
        ("long_padding_zero", "00000007010001000100010000000000"),
        ("long_padding_ff", "0000000701000100010001ffffffff"),
        ("invalid_enum_ff", "00000007ffffffffffffff"),
        ("alternating", "0000000700ff00ff00ff00"),
    ]
    return [candidate("method10_sanity", label, payload) for label, payload in items]


def method12_candidates():
    items = [
        ("reset_empty_vector", "00000000"),
        ("baseline_level", "0000000701020300010203"),
        ("all_zero", "0000000700000000000000"),
        ("all_one", "0000000701010101010101"),
        ("all_two", "0000000702020202020202"),
        ("all_three", "0000000703030303030303"),
        ("len_field_zero", "0000000001020300010203"),
        ("len_field_one", "0000000101020300010203"),
        ("len_field_ff", "000000ff01020300010203"),
        ("short_len_only", "00000007"),
        ("short_len_plus_one", "0000000701"),
        ("truncated_values", "00000007010203"),
        ("long_padding_zero", "000000070102030001020300000000"),
        ("long_padding_ff", "0000000701020300010203ffffffff"),
        ("boundary_values", "00000007ff7f8000010203"),
    ]
    return [candidate("method12_sanity", label, payload) for label, payload in items]


def method14_candidates():
    items = [
        ("open_all", "01010101"),
        ("close_all_reset_equivalent", "02020202"),
        ("nothing", "00000000"),
        ("open_front_left", "01000000"),
        ("open_front_right_and_rear_left", "00010100"),
        ("open_front_pair", "01010000"),
        ("open_rear_pair", "00000101"),
        ("mixed_open_close_1", "01020102"),
        ("mixed_open_close_2", "02010102"),
        ("invalid_enum_3_all", "03030303"),
        ("boundary_ff_all", "ffffffff"),
        ("long_one_extra_zero", "0101010100"),
        ("long_prefix_zero", "00000001010101"),
        ("short_one_byte", "01"),
        ("short_two_bytes", "0101"),
        ("long_padding_ff", "01010101ffffffff"),
    ]
    return [candidate("method14_sanity", label, payload) for label, payload in items]


def candidates_for_method(method_id):
    if method_id in GETTER_METHOD_IDS:
        return generic_payload_candidates("getter_sanity")
    if method_id == 10:
        return method10_candidates()
    if method_id == 12:
        return method12_candidates()
    if method_id == 13:
        return generic_payload_candidates("method13_sanity")
    if method_id == 14:
        return method14_candidates()
    raise ValueError("unsupported method_id={}".format(method_id))


def selected_method_ids(method_arg):
    if method_arg == "all":
        return list(range(1, 15))
    method_id = int(method_arg, 0)
    if method_id not in METHODS:
        raise ValueError("method must be all or one of 1..14")
    return [method_id]


def limit_candidates(candidates, max_candidates):
    if max_candidates is None or max_candidates <= 0:
        return candidates
    return candidates[:max_candidates]


def print_dry_run(method_ids, max_candidates):
    total = 0
    for method_id in method_ids:
        method = METHODS[method_id]
        candidates = limit_candidates(candidates_for_method(method_id), max_candidates)
        total += len(candidates)
        print(
            "method_id={} {} role={} candidates={}".format(
                method_id,
                hex_method_id(method_id),
                method["role"],
                len(candidates),
            )
        )
        for index, item in enumerate(candidates, start=1):
            print(
                "  {idx:02d} {source}:{label} len={length} payload={payload}".format(
                    idx=index,
                    source=item["payload_source"],
                    label=item["payload_label"],
                    length=item["payload_len"],
                    payload=item["payload_hex"] or "<empty>",
                )
            )
    print("total_candidates={}".format(total))


def msg_type(result):
    parsed = result.get("parsed")
    if parsed is None:
        return ""
    return "0x{:02x}".format(parsed.msg_type)


def result_ok_for_state(result):
    return result["verdict"] not in ("no_response_timeout", "malformed_response")


def combine_errors(*items):
    errors = []
    for label, result in items:
        error = str(result.get("error", "") or "").strip()
        if error:
            errors.append("{}: {}".format(label, error))
    return "; ".join(errors)


def base_detail_row(method_id, payload_item, trial_index):
    method = METHODS[method_id]
    return {
        "timestamp": now_row(),
        "method_id": method_id,
        "hex_method_id": hex_method_id(method_id),
        "method_name": method["name"],
        "role": method["role"],
        "payload_source": payload_item["payload_source"],
        "payload_label": payload_item["payload_label"],
        "payload_hex": payload_item["payload_hex"],
        "payload_len": payload_item["payload_len"],
        "trial_index": trial_index,
        "reset_payload_hex": "",
        "reset_after_payload_hex": "",
        "before_payload_hex": "",
        "response_received": "",
        "msg_type": "",
        "retcode": "",
        "verdict": "",
        "latency_ms": "",
        "response_payload_hex": "",
        "after_payload_hex": "",
        "state_changed": "",
        "reset_equivalent": "",
        "non_trivial_state_effect": "",
        "error": "",
    }


def run_response_only_trial(call_someip, method_id, payload_item, trial_index, session_id, timeout_sec):
    payload = bytes.fromhex(payload_item["payload_hex"])
    result = call_someip(method_id, payload, session_id, timeout_sec)
    row = base_detail_row(method_id, payload_item, trial_index)
    row.update({
        "response_received": result["response_received"],
        "msg_type": msg_type(result),
        "retcode": result["retcode"],
        "verdict": result["verdict"],
        "latency_ms": result["latency_ms"],
        "response_payload_hex": result["payload_hex"],
        "error": result["error"],
    })
    return row


def run_stateful_trial(call_someip, next_session_id, method_id, payload_item, trial_index, session_id, timeout_sec):
    method = METHODS[method_id]
    getter_id = method["paired_getter"]
    reset_payload_hex = method["reset_payload_hex"]
    reset_expected = method.get("reset_expected_payload_hex", "")
    started = time.time()

    reset = call_someip(method_id, bytes.fromhex(reset_payload_hex), session_id, timeout_sec)
    session_id = next_session_id(session_id)
    before = call_someip(getter_id, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)
    response = call_someip(method_id, bytes.fromhex(payload_item["payload_hex"]), session_id, timeout_sec)
    session_id = next_session_id(session_id)
    after = call_someip(getter_id, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)

    latency_ms = (time.time() - started) * 1000.0
    before_payload = before["payload_hex"]
    after_payload = after["payload_hex"]
    state_known = result_ok_for_state(before) and result_ok_for_state(after)
    reset_confirmed = reset["verdict"] == "normal_response"
    if reset_expected:
        reset_confirmed = reset_confirmed and before_payload == reset_expected

    if state_known and reset_confirmed:
        state_changed = str(before_payload != after_payload)
        reset_equivalent = str(after_payload == before_payload)
    else:
        state_changed = "unknown"
        reset_equivalent = "unknown"

    non_trivial = str(response["verdict"] == "normal_response" and state_changed == "True" and reset_equivalent == "False")
    error_parts = [combine_errors(("reset", reset), ("before_getter", before), ("response", response), ("after_getter", after))]
    if reset["verdict"] != "normal_response":
        error_parts.append("reset_not_normal")
    if reset_expected and result_ok_for_state(before) and before_payload != reset_expected:
        error_parts.append("reset_expected_mismatch")

    row = base_detail_row(method_id, payload_item, trial_index)
    row.update({
        "reset_payload_hex": reset_payload_hex,
        "reset_after_payload_hex": before_payload,
        "before_payload_hex": before_payload,
        "response_received": response["response_received"],
        "msg_type": msg_type(response),
        "retcode": response["retcode"],
        "verdict": response["verdict"],
        "latency_ms": "{:.3f}".format(latency_ms),
        "response_payload_hex": response["payload_hex"],
        "after_payload_hex": after_payload,
        "state_changed": state_changed,
        "reset_equivalent": reset_equivalent,
        "non_trivial_state_effect": non_trivial,
        "error": "; ".join(part for part in error_parts if part),
    })
    return row, session_id


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def classify_candidate(rows):
    total_trials = len(rows)
    normal_response_count = sum(1 for row in rows if row["verdict"] == "normal_response")
    error_response_count = sum(1 for row in rows if row["verdict"] == "error_response")
    timeout_count = sum(1 for row in rows if row["verdict"] == "no_response_timeout")
    non_trivial_count = sum(1 for row in rows if row["non_trivial_state_effect"] == "True")
    if normal_response_count > 0 and non_trivial_count == 0:
        return "protocol_valid_no_state_effect"
    if non_trivial_count == total_trials and total_trials > 0:
        return "reproducible_non_trivial_state_effect"
    if 0 < non_trivial_count < total_trials:
        return "unstable_non_trivial_state_effect"
    if error_response_count > 0 and normal_response_count == 0:
        return "rejected_or_error"
    if timeout_count > 0 and normal_response_count == 0:
        return "timeout_or_no_response"
    return "rejected_or_error"


def summarize(rows, method_candidate_counts):
    grouped = defaultdict(list)
    for row in rows:
        grouped[int(row["method_id"])].append(row)

    summary_rows = []
    for method_id in sorted(grouped):
        method = METHODS[method_id]
        group = grouped[method_id]
        latencies = []
        for row in group:
            try:
                if row["latency_ms"] != "":
                    latencies.append(float(row["latency_ms"]))
            except ValueError:
                pass
        candidate_groups = defaultdict(list)
        for row in group:
            candidate_groups[(row["payload_source"], row["payload_label"], row["payload_hex"])].append(row)
        classification_counts = Counter(classify_candidate(candidate_rows) for candidate_rows in candidate_groups.values())
        p95 = percentile(latencies, 95)
        summary_rows.append({
            "method_id": method_id,
            "method_name": method["name"],
            "role": method["role"],
            "total_candidates": method_candidate_counts.get(method_id, len(candidate_groups)),
            "total_trials": len(group),
            "normal_response_count": sum(1 for row in group if row["verdict"] == "normal_response"),
            "error_response_count": sum(1 for row in group if row["verdict"] == "error_response"),
            "timeout_count": sum(1 for row in group if row["verdict"] == "no_response_timeout"),
            "unique_payload_count": len({row["payload_hex"] for row in group}),
            "state_changed_count": sum(1 for row in group if row["state_changed"] == "True"),
            "non_trivial_state_effect_count": sum(1 for row in group if row["non_trivial_state_effect"] == "True"),
            "reproducible_non_trivial_state_effect_count": classification_counts.get("reproducible_non_trivial_state_effect", 0),
            "avg_latency_ms": "" if not latencies else "{:.3f}".format(sum(latencies) / len(latencies)),
            "max_latency_ms": "" if not latencies else "{:.3f}".format(max(latencies)),
            "p95_latency_ms": "" if p95 is None else "{:.3f}".format(p95),
            "classification_counts": ";".join("{}={}".format(key, classification_counts[key]) for key in sorted(classification_counts)),
        })
    return summary_rows


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def write_csv(path, header, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)


def output_paths(prefix):
    stamp = now_filename()
    return "{}_detail_{}.csv".format(prefix, stamp), "{}_summary_{}.csv".format(prefix, stamp)


def execute(method_ids, max_candidates, trial_count, output_prefix, timeout_sec, start_session_id):
    from check_candidate_state_effect import call_someip, next_session_id  # noqa: WPS433

    rows = []
    method_candidate_counts = {}
    session_id = start_session_id
    for method_id in method_ids:
        candidates = limit_candidates(candidates_for_method(method_id), max_candidates)
        method_candidate_counts[method_id] = len(candidates)
        for payload_item in candidates:
            for trial_index in range(1, trial_count + 1):
                if "paired_getter" in METHODS[method_id]:
                    row, session_id = run_stateful_trial(
                        call_someip,
                        next_session_id,
                        method_id,
                        payload_item,
                        trial_index,
                        session_id,
                        timeout_sec,
                    )
                else:
                    row = run_response_only_trial(
                        call_someip,
                        method_id,
                        payload_item,
                        trial_index,
                        session_id,
                        timeout_sec,
                    )
                    session_id = next_session_id(session_id)
                rows.append(row)

    detail_path, summary_path = output_paths(output_prefix)
    write_csv(detail_path, DETAIL_HEADER, rows)
    write_csv(summary_path, SUMMARY_HEADER, summarize(rows, method_candidate_counts))
    print("wrote {}".format(detail_path))
    print("wrote {}".format(summary_path))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Fuzz only source/FDEP-defined request method IDs 1..14 with method-aware payloads."
    )
    parser.add_argument("--method", default="all", help="'all' or a method ID from 1..14.")
    parser.add_argument("--trial-count", type=int, default=1)
    parser.add_argument("--max-candidates", type=int, default=0, help="Limit candidates per method; 0 means no limit.")
    parser.add_argument("--dry-run", action="store_true", help="Print candidate plan without sending traffic.")
    parser.add_argument("--execute", action="store_true", help="Actually send probes. Required for network traffic.")
    parser.add_argument("--output-prefix", default=DEFAULT_OUTPUT_PREFIX)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--start-session-id", type=lambda value: int(value, 0), default=0x7800)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.trial_count <= 0:
        raise SystemExit("--trial-count must be positive")
    method_ids = selected_method_ids(args.method)
    if any(method_id in EXCLUDED_EVENT_IDS for method_id in method_ids):
        raise SystemExit("event/notifier IDs 0x8001..0x800a are excluded")

    if not args.execute:
        print_dry_run(method_ids, args.max_candidates)
        return
    execute(method_ids, args.max_candidates, args.trial_count, args.output_prefix, args.timeout, args.start_session_id)


if __name__ == "__main__":
    main()
