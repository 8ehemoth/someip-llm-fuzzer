#!/usr/bin/env python3
"""Compare state-aware SOME/IP candidates under the same reset/getter check."""

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


METHOD_PROFILES = {
    10: {
        "method_name": "setSeatHeatingStatus",
        "getter_id": 9,
        "getter_name": "getSeatHeatingStatusAttribute",
        "reset_payload_hex": "00000000",
        "reset_expected_payload_hex": "00000000",
    },
    12: {
        "method_name": "setSeatHeatingLevel",
        "getter_id": 11,
        "getter_name": "getSeatHeatingLevelAttribute",
        "reset_payload_hex": "00000000",
        "reset_expected_payload_hex": "00000000",
    },
    14: {
        "method_name": "changeDoorsState",
        "getter_id": 8,
        "getter_name": "getDoorsOpeningStatusAttribute",
        "reset_payload_hex": "02020202",
        "reset_expected_payload_hex": "00000000",
    },
}
DEFAULT_METHOD_IDS = sorted(METHOD_PROFILES)
DEFAULT_OUTPUT_PREFIX = "results/method14_llm_vs_radamsa"

DETAIL_HEADER = [
    "timestamp",
    "payload_source",
    "payload_label",
    "method_id",
    "hex_method_id",
    "method_name",
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
    "payload_source",
    "total_candidates",
    "total_trials",
    "normal_response_count",
    "error_response_count",
    "timeout_count",
    "unique_payload_count",
    "state_changed_count",
    "non_trivial_state_effect_count",
    "reproducible_non_trivial_state_effect_count",
    "protocol_valid_no_effect_count",
    "avg_latency_ms",
    "max_latency_ms",
    "p95_latency_ms",
    "classification_counts",
]
PAYLOAD_SUMMARY_HEADER = [
    "method_id",
    "payload_source",
    "payload_label",
    "payload_hex",
    "trials",
    "normal_response_count",
    "error_response_count",
    "timeout_count",
    "state_changed_count",
    "non_trivial_state_effect_count",
    "non_trivial_state_effect_rate",
    "classification",
]
CANDIDATE_HEADER = ["payload_source", "payload_label", "method_id", "payload_hex", "payload_len"]


def timestamp_filename():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def timestamp_row():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


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


def profile_for_method(method_id):
    method_id = int(method_id)
    if method_id not in METHOD_PROFILES:
        raise ValueError("unsupported state-aware method_id: {}".format(method_id))
    return METHOD_PROFILES[method_id]


def candidate(source, label, payload_hex, method_id=14):
    payload_hex = normalize_hex(payload_hex)
    return {
        "payload_source": source,
        "payload_label": label,
        "method_id": method_id,
        "payload_hex": payload_hex,
        "payload_len": payload_len(payload_hex),
    }


def deterministic_random_hex_values(count=4):
    rng = random.Random(0x14ADA)
    return [bytes(rng.getrandbits(8) for _ in range(4)).hex() for _ in range(count)]


def example_llm_candidates():
    values = [
        ("open_all", "01010101"),
        ("close_all_reset_equivalent", "02020202"),
        ("nothing", "00000000"),
        ("open_front_left", "01000000"),
        ("open_front_right_and_rear_left", "00010100"),
        ("open_front_pair", "01010000"),
        ("open_rear_pair", "00000101"),
        ("mixed_open_close_1", "01020102"),
        ("mixed_open_close_2", "02010102"),
        ("long_one_extra_zero", "0101010100"),
        ("long_prefix_zero", "00000001010101"),
        ("long_padding_ff", "01010101ffffffff"),
    ]
    return [candidate("llm_example", label, payload_hex, 14) for label, payload_hex in values]


def example_radamsa_candidates():
    values = [
        ("truncated_one", "01"),
        ("truncated_two", "0101"),
        ("boundary_ff_all", "ffffffff"),
        ("invalid_enum_3_all", "03030303"),
        ("long_one_extra_zero", "0101010100"),
        ("long_padding_ff", "01010101ffffffff"),
        ("long_prefix_zero", "00000001010101"),
    ]
    items = [candidate("radamsa_example", label, payload_hex, 14) for label, payload_hex in values]
    for index, payload_hex in enumerate(deterministic_random_hex_values(), start=1):
        items.append(candidate("radamsa_example", "deterministic_random4_{:02d}".format(index), payload_hex, 14))
    return items


def write_csv(path, header, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)


def make_example_candidates(output_prefix):
    stamp = timestamp_filename()
    llm_path = "results/method14_llm_candidates_example_{}.csv".format(stamp)
    radamsa_path = "results/method14_radamsa_candidates_example_{}.csv".format(stamp)
    write_csv(llm_path, CANDIDATE_HEADER, example_llm_candidates())
    write_csv(radamsa_path, CANDIDATE_HEADER, example_radamsa_candidates())
    print("wrote {}".format(llm_path))
    print("wrote {}".format(radamsa_path))
    return llm_path, radamsa_path


def load_candidates(path, expected_source, method_ids=None):
    allowed_methods = set(method_ids or DEFAULT_METHOD_IDS)
    rows = []
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required = set(CANDIDATE_HEADER)
        missing = sorted(required - set(reader.fieldnames or []))
        if missing:
            raise ValueError("missing candidate CSV columns in {}: {}".format(path, ",".join(missing)))
        for row_index, row in enumerate(reader, start=1):
            method_id = int(str(row["method_id"]).strip(), 0)
            if method_id not in allowed_methods:
                continue
            payload_hex = normalize_hex(row["payload_hex"])
            length = int(str(row["payload_len"]).strip(), 0)
            if length != payload_len(payload_hex):
                raise ValueError("payload_len mismatch in {} row {}".format(path, row_index))
            rows.append({
                "payload_source": row["payload_source"] or expected_source,
                "payload_label": row["payload_label"],
                "method_id": method_id,
                "payload_hex": payload_hex,
                "payload_len": length,
            })
    return rows


def print_dry_run(llm_candidates, radamsa_candidates, trial_count):
    for source_name, rows in (("LLM", llm_candidates), ("Radamsa", radamsa_candidates)):
        print("{} candidates={} trial_count={}".format(source_name, len(rows), trial_count))
        for index, row in enumerate(rows, start=1):
            print(
                "  {idx:02d} {source}:{label} len={length} payload={payload}".format(
                    idx=index,
                    source=row["payload_source"],
                    label=row["payload_label"],
                    length=row["payload_len"],
                    payload=row["payload_hex"] or "<empty>",
                )
            )


def split_balanced_candidates(path):
    rows = load_candidates(path, "")
    llm_rows = [row for row in rows if str(row["payload_source"]).startswith("llm")]
    radamsa_rows = [row for row in rows if str(row["payload_source"]).startswith("radamsa")]
    if not llm_rows or not radamsa_rows:
        raise ValueError("balanced candidate CSV must contain llm* and radamsa* payload_source rows, such as llm_api and radamsa_bin")
    return llm_rows, radamsa_rows


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


def run_trial(call_someip, next_session_id, item, trial_index, session_id, timeout_sec):
    method_id = int(item["method_id"])
    profile = profile_for_method(method_id)
    getter_id = profile["getter_id"]
    reset_payload_hex = profile["reset_payload_hex"]
    reset_expected_payload_hex = profile["reset_expected_payload_hex"]
    started = time.time()
    reset = call_someip(method_id, bytes.fromhex(reset_payload_hex), session_id, timeout_sec)
    session_id = next_session_id(session_id)
    before = call_someip(getter_id, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)
    response = call_someip(method_id, bytes.fromhex(item["payload_hex"]), session_id, timeout_sec)
    session_id = next_session_id(session_id)
    after = call_someip(getter_id, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)

    latency_ms = (time.time() - started) * 1000.0
    reset_after_payload = before["payload_hex"]
    state_known = result_ok_for_state(before) and result_ok_for_state(after)
    reset_confirmed = reset["verdict"] == "normal_response" and reset_after_payload == reset_expected_payload_hex
    if state_known and reset_confirmed:
        state_changed = str(reset_after_payload != after["payload_hex"])
        reset_equivalent = str(reset_after_payload == after["payload_hex"])
    else:
        state_changed = "unknown"
        reset_equivalent = "unknown"

    non_trivial = str(response["verdict"] == "normal_response" and state_changed == "True" and reset_equivalent == "False")
    error_parts = [combine_errors(("reset", reset), ("getter_before", before), ("candidate", response), ("getter_after", after))]
    if reset["verdict"] != "normal_response":
        error_parts.append("reset_not_normal")
    if result_ok_for_state(before) and reset_after_payload != reset_expected_payload_hex:
        error_parts.append("reset_expected_mismatch")

    row = {
        "timestamp": timestamp_row(),
        "payload_source": item["payload_source"],
        "payload_label": item["payload_label"],
        "method_id": method_id,
        "hex_method_id": "0x{:04x}".format(method_id),
        "method_name": profile["method_name"],
        "payload_hex": item["payload_hex"],
        "payload_len": item["payload_len"],
        "trial_index": trial_index,
        "reset_payload_hex": reset_payload_hex,
        "reset_after_payload_hex": reset_after_payload,
        "before_payload_hex": reset_after_payload,
        "response_received": response["response_received"],
        "msg_type": msg_type(response),
        "retcode": response["retcode"],
        "verdict": response["verdict"],
        "latency_ms": "{:.3f}".format(latency_ms),
        "response_payload_hex": response["payload_hex"],
        "after_payload_hex": after["payload_hex"],
        "state_changed": state_changed,
        "reset_equivalent": reset_equivalent,
        "non_trivial_state_effect": non_trivial,
        "error": "; ".join(part for part in error_parts if part),
    }
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


def classify_payload(rows):
    trials = len(rows)
    normal = sum(1 for row in rows if row["verdict"] == "normal_response")
    error = sum(1 for row in rows if row["verdict"] == "error_response")
    timeout = sum(1 for row in rows if row["verdict"] == "no_response_timeout")
    non_trivial = sum(1 for row in rows if row["non_trivial_state_effect"] == "True")
    if non_trivial == trials and trials > 0:
        return "reproducible_non_trivial_state_effect"
    if 0 < non_trivial < trials:
        return "unstable_non_trivial_state_effect"
    if normal > 0 and non_trivial == 0:
        return "protocol_valid_no_effect"
    if error > 0 and normal == 0:
        return "rejected_or_error"
    if timeout > 0 and normal == 0:
        return "timeout_or_no_response"
    return "rejected_or_error"


def payload_summary(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["method_id"], row["payload_source"], row["payload_label"], row["payload_hex"])].append(row)
    summary_rows = []
    for (method_id, source, label, payload_hex), group in sorted(grouped.items()):
        trials = len(group)
        non_trivial = sum(1 for row in group if row["non_trivial_state_effect"] == "True")
        summary_rows.append({
            "method_id": method_id,
            "payload_source": source,
            "payload_label": label,
            "payload_hex": payload_hex,
            "trials": trials,
            "normal_response_count": sum(1 for row in group if row["verdict"] == "normal_response"),
            "error_response_count": sum(1 for row in group if row["verdict"] == "error_response"),
            "timeout_count": sum(1 for row in group if row["verdict"] == "no_response_timeout"),
            "state_changed_count": sum(1 for row in group if row["state_changed"] == "True"),
            "non_trivial_state_effect_count": non_trivial,
            "non_trivial_state_effect_rate": "{:.6f}".format(0.0 if trials == 0 else non_trivial / trials),
            "classification": classify_payload(group),
        })
    return summary_rows


def source_summary(rows, payload_rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["payload_source"]].append(row)
    payload_grouped = defaultdict(list)
    for row in payload_rows:
        payload_grouped[row["payload_source"]].append(row)

    summary_rows = []
    for source, group in sorted(grouped.items()):
        latencies = []
        for row in group:
            try:
                if row["latency_ms"]:
                    latencies.append(float(row["latency_ms"]))
            except ValueError:
                pass
        p95 = percentile(latencies, 95)
        class_counts = Counter(row["classification"] for row in payload_grouped[source])
        summary_rows.append({
            "payload_source": source,
            "total_candidates": len({(row["payload_label"], row["payload_hex"]) for row in group}),
            "total_trials": len(group),
            "normal_response_count": sum(1 for row in group if row["verdict"] == "normal_response"),
            "error_response_count": sum(1 for row in group if row["verdict"] == "error_response"),
            "timeout_count": sum(1 for row in group if row["verdict"] == "no_response_timeout"),
            "unique_payload_count": len({row["payload_hex"] for row in group}),
            "state_changed_count": sum(1 for row in group if row["state_changed"] == "True"),
            "non_trivial_state_effect_count": sum(1 for row in group if row["non_trivial_state_effect"] == "True"),
            "reproducible_non_trivial_state_effect_count": class_counts.get("reproducible_non_trivial_state_effect", 0),
            "protocol_valid_no_effect_count": class_counts.get("protocol_valid_no_effect", 0),
            "avg_latency_ms": "" if not latencies else "{:.3f}".format(sum(latencies) / len(latencies)),
            "max_latency_ms": "" if not latencies else "{:.3f}".format(max(latencies)),
            "p95_latency_ms": "" if p95 is None else "{:.3f}".format(p95),
            "classification_counts": ";".join("{}={}".format(key, class_counts[key]) for key in sorted(class_counts)),
        })
    return summary_rows


def output_paths(prefix):
    stamp = timestamp_filename()
    return (
        "{}_detail_{}.csv".format(prefix, stamp),
        "{}_summary_{}.csv".format(prefix, stamp),
        "{}_payload_summary_{}.csv".format(prefix, stamp),
    )


def execute(all_candidates, trial_count, timeout_sec, output_prefix):
    from check_candidate_state_effect import call_someip, next_session_id  # noqa: WPS433

    rows = []
    session_id = 0x7A00
    for item in all_candidates:
        for trial_index in range(1, trial_count + 1):
            row, session_id = run_trial(call_someip, next_session_id, item, trial_index, session_id, timeout_sec)
            rows.append(row)

    payload_rows = payload_summary(rows)
    detail_path, summary_path, payload_summary_path = output_paths(output_prefix)
    write_csv(detail_path, DETAIL_HEADER, rows)
    write_csv(payload_summary_path, PAYLOAD_SUMMARY_HEADER, payload_rows)
    write_csv(summary_path, SUMMARY_HEADER, source_summary(rows, payload_rows))
    print("wrote {}".format(detail_path))
    print("wrote {}".format(summary_path))
    print("wrote {}".format(payload_summary_path))


def parse_args():
    parser = argparse.ArgumentParser(description="Compare Method 14 LLM vs Radamsa candidate payloads.")
    parser.add_argument("--llm-candidates", default="")
    parser.add_argument("--radamsa-candidates", default="")
    parser.add_argument("--balanced-candidates", default="")
    parser.add_argument("--trial-count", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output-prefix", default=DEFAULT_OUTPUT_PREFIX)
    parser.add_argument("--make-example-candidates", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.trial_count <= 0:
        raise SystemExit("--trial-count must be positive")

    if args.make_example_candidates:
        make_example_candidates(args.output_prefix)
        return

    if args.balanced_candidates:
        llm_candidates, radamsa_candidates = split_balanced_candidates(args.balanced_candidates)
    elif not args.llm_candidates or not args.radamsa_candidates:
        raise SystemExit("--llm-candidates and --radamsa-candidates are required unless --make-example-candidates is used")
    else:
        llm_candidates = load_candidates(args.llm_candidates, "llm")
        radamsa_candidates = load_candidates(args.radamsa_candidates, "radamsa")
    all_candidates = llm_candidates + radamsa_candidates

    if not args.execute:
        print_dry_run(llm_candidates, radamsa_candidates, args.trial_count)
        return

    execute(all_candidates, args.trial_count, args.timeout, args.output_prefix)


if __name__ == "__main__":
    main()
