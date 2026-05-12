#!/usr/bin/env python3
"""Check Method 14 payload candidates with Getter 8 state feedback."""

import argparse
import csv
import os
import sys
import time
from collections import defaultdict
from datetime import datetime


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
SCRIPTS_DIR = os.path.dirname(__file__)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from check_candidate_state_effect import call_someip, next_session_id  # noqa: E402


METHOD14_ID = 14
GETTER8_ID = 8
DEFAULT_RESET_PAYLOAD_HEX = "02020202"
DEFAULT_RESET_EXPECTED_PAYLOAD_HEX = "00000000"
DEFAULT_CANDIDATES = "results/method14_state_sanity_candidates.csv"

DETAIL_HEADER = [
    "timestamp",
    "candidate_index",
    "trial_index",
    "payload_source",
    "payload_label",
    "method_id",
    "payload_hex",
    "payload_len",
    "reset_payload_hex",
    "reset_after_payload_hex",
    "before_payload_hex",
    "setter_response_received",
    "setter_msg_type",
    "setter_retcode",
    "setter_verdict",
    "after_payload_hex",
    "state_changed",
    "reset_equivalent",
    "non_trivial_state_effect",
    "latency_ms",
    "error",
]
SUMMARY_HEADER = [
    "payload_source",
    "payload_label",
    "payload_hex",
    "trials",
    "normal_response_count",
    "state_changed_count",
    "non_trivial_state_effect_count",
    "reproducible_non_trivial_state_effect",
    "classification",
]


def timestamp_for_filename():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def timestamp_for_row():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def default_detail_out():
    return os.path.join("results", "method14_state_effect_{}.csv".format(timestamp_for_filename()))


def default_summary_out(detail_out):
    base, ext = os.path.splitext(detail_out)
    return "{}_summary{}".format(base, ext or ".csv")


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


def parse_method_id(value):
    return int(str(value).strip(), 0)


def msg_type(result):
    parsed = result.get("parsed")
    if parsed is None:
        return ""
    return "0x{:02x}".format(parsed.msg_type)


def result_ok_for_state(result):
    return result["verdict"] not in ("no_response_timeout", "malformed_response")


def combined_error(*items):
    errors = []
    for label, result in items:
        error = str(result.get("error", "") or "").strip()
        if error:
            errors.append("{}: {}".format(label, error))
    return "; ".join(errors)


def load_candidates(path):
    candidates = []
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required = {"payload_source", "payload_label", "method_id", "payload_hex", "payload_len"}
        missing = sorted(required - set(reader.fieldnames or []))
        if missing:
            raise ValueError("missing candidate CSV columns: {}".format(",".join(missing)))

        for row_index, row in enumerate(reader, start=1):
            method_id = parse_method_id(row["method_id"])
            if method_id != METHOD14_ID:
                continue
            payload_hex = normalize_hex(row["payload_hex"])
            payload = bytes.fromhex(payload_hex)
            payload_len = int(str(row["payload_len"]).strip(), 0)
            if payload_len != len(payload):
                raise ValueError(
                    "payload_len mismatch at row {}: got {}, expected {}".format(
                        row_index,
                        payload_len,
                        len(payload),
                    )
                )
            candidates.append({
                "payload_source": row["payload_source"],
                "payload_label": row["payload_label"],
                "method_id": method_id,
                "payload_hex": payload_hex,
                "payload": payload,
                "payload_len": payload_len,
            })
    return candidates


def classify_summary(trials, normal_response_count, non_trivial_state_effect_count):
    if non_trivial_state_effect_count == trials:
        return "reproducible_non_trivial_state_effect"
    if 0 < non_trivial_state_effect_count < trials:
        return "unstable_non_trivial_state_effect"
    if normal_response_count > 0 and non_trivial_state_effect_count == 0:
        return "protocol_valid_no_state_effect"
    return "rejected_or_error"


def run_trial(candidate, candidate_index, trial_index, session_id, timeout_sec, reset_payload_hex, reset_expected_hex):
    started = time.time()

    reset = call_someip(METHOD14_ID, bytes.fromhex(reset_payload_hex), session_id, timeout_sec)
    session_id = next_session_id(session_id)

    reset_after = call_someip(GETTER8_ID, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)

    setter = call_someip(METHOD14_ID, candidate["payload"], session_id, timeout_sec)
    session_id = next_session_id(session_id)

    after = call_someip(GETTER8_ID, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)

    latency_ms = (time.time() - started) * 1000.0
    before_payload_hex = reset_after["payload_hex"]
    reset_after_payload_hex = reset_after["payload_hex"]

    getter_state_known = result_ok_for_state(reset_after) and result_ok_for_state(after)
    reset_confirmed = reset["verdict"] == "normal_response" and reset_after_payload_hex == reset_expected_hex
    if getter_state_known and reset_confirmed:
        state_changed = str(before_payload_hex != after["payload_hex"])
        reset_equivalent = str(after["payload_hex"] == reset_after_payload_hex)
    else:
        state_changed = "unknown"
        reset_equivalent = "unknown"

    non_trivial_state_effect = str(
        setter["verdict"] == "normal_response"
        and state_changed == "True"
        and reset_equivalent == "False"
    )

    error_parts = [combined_error(("reset", reset), ("reset_after_getter", reset_after), ("setter", setter), ("after_getter", after))]
    if reset["verdict"] != "normal_response":
        error_parts.append("reset_not_normal")
    if result_ok_for_state(reset_after) and reset_after_payload_hex != reset_expected_hex:
        error_parts.append("reset_expected_mismatch")

    row = {
        "timestamp": timestamp_for_row(),
        "candidate_index": candidate_index,
        "trial_index": trial_index,
        "payload_source": candidate["payload_source"],
        "payload_label": candidate["payload_label"],
        "method_id": candidate["method_id"],
        "payload_hex": candidate["payload_hex"],
        "payload_len": candidate["payload_len"],
        "reset_payload_hex": reset_payload_hex,
        "reset_after_payload_hex": reset_after_payload_hex,
        "before_payload_hex": before_payload_hex,
        "setter_response_received": setter["response_received"],
        "setter_msg_type": msg_type(setter),
        "setter_retcode": setter["retcode"],
        "setter_verdict": setter["verdict"],
        "after_payload_hex": after["payload_hex"],
        "state_changed": state_changed,
        "reset_equivalent": reset_equivalent,
        "non_trivial_state_effect": non_trivial_state_effect,
        "latency_ms": "{:.3f}".format(latency_ms),
        "error": "; ".join(part for part in error_parts if part),
    }
    return row, session_id


def write_csv(path, header, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["payload_source"], row["payload_label"], row["payload_hex"])].append(row)

    summary_rows = []
    for (payload_source, payload_label, payload_hex), group in sorted(grouped.items()):
        trials = len(group)
        normal_response_count = sum(1 for row in group if row["setter_verdict"] == "normal_response")
        state_changed_count = sum(1 for row in group if row["state_changed"] == "True")
        non_trivial_state_effect_count = sum(1 for row in group if row["non_trivial_state_effect"] == "True")
        classification = classify_summary(trials, normal_response_count, non_trivial_state_effect_count)
        summary_rows.append({
            "payload_source": payload_source,
            "payload_label": payload_label,
            "payload_hex": payload_hex,
            "trials": trials,
            "normal_response_count": normal_response_count,
            "state_changed_count": state_changed_count,
            "non_trivial_state_effect_count": non_trivial_state_effect_count,
            "reproducible_non_trivial_state_effect": str(classification == "reproducible_non_trivial_state_effect"),
            "classification": classification,
        })
    return summary_rows


def parse_args():
    parser = argparse.ArgumentParser(
        description="Validate Method 14 payload candidates with reset + Getter 8 state feedback."
    )
    parser.add_argument("--candidates", default=DEFAULT_CANDIDATES, help="Input Method 14 candidate CSV.")
    parser.add_argument("--out", default="", help="Detail result CSV path.")
    parser.add_argument("--summary-out", default="", help="Summary CSV path.")
    parser.add_argument("--trial-count", type=int, default=10, help="Trials per candidate.")
    parser.add_argument("--timeout", type=float, default=1.0, help="Response timeout in seconds.")
    parser.add_argument("--start-session-id", type=lambda value: int(value, 0), default=0x7600)
    parser.add_argument("--reset-payload", default=DEFAULT_RESET_PAYLOAD_HEX)
    parser.add_argument("--reset-expected", default=DEFAULT_RESET_EXPECTED_PAYLOAD_HEX)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.trial_count <= 0:
        raise SystemExit("--trial-count must be positive")

    candidates = load_candidates(args.candidates)
    if not candidates:
        raise SystemExit("no Method 14 candidates loaded")

    reset_payload_hex = normalize_hex(args.reset_payload)
    reset_expected_hex = normalize_hex(args.reset_expected)
    detail_out = args.out or default_detail_out()
    summary_out = args.summary_out or default_summary_out(detail_out)

    rows = []
    session_id = args.start_session_id
    for candidate_index, candidate in enumerate(candidates, start=1):
        for trial_index in range(1, args.trial_count + 1):
            row, session_id = run_trial(
                candidate,
                candidate_index,
                trial_index,
                session_id,
                args.timeout,
                reset_payload_hex,
                reset_expected_hex,
            )
            rows.append(row)

    summary_rows = summarize(rows)
    write_csv(detail_out, DETAIL_HEADER, rows)
    write_csv(summary_out, SUMMARY_HEADER, summary_rows)
    print("wrote {}".format(detail_out))
    print("wrote {}".format(summary_out))


if __name__ == "__main__":
    main()
