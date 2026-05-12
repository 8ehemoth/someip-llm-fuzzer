#!/usr/bin/env python3
"""Probe whether Method 14 changes the Getter 8 observable door state."""

import argparse
import csv
import os
import sys
from datetime import datetime


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from check_candidate_state_effect import call_someip, next_session_id  # noqa: E402


GETTER8_METHOD_ID = 8
METHOD14_METHOD_ID = 14
CANDIDATES = [
    ("open_all", "01010101"),
    ("close_all", "02020202"),
    ("nothing", "00000000"),
]
CSV_HEADER = [
    "timestamp",
    "candidate_label",
    "method14_payload_hex",
    "getter_before_payload_hex",
    "method14_response_received",
    "method14_msg_type",
    "method14_retcode",
    "method14_verdict",
    "getter_after_payload_hex",
    "state_changed",
    "error",
]


def timestamp_for_filename():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def timestamp_for_row():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def default_out_path():
    return os.path.join("results", "method14_state_probe_{}.csv".format(timestamp_for_filename()))


def msg_type(result):
    parsed = result.get("parsed")
    if parsed is None:
        return ""
    return "0x{:02x}".format(parsed.msg_type)


def combined_error(*results):
    errors = []
    for label, result in results:
        error = str(result.get("error", "") or "").strip()
        if error:
            errors.append("{}: {}".format(label, error))
    return "; ".join(errors)


def state_changed(before, after):
    if before["verdict"] in ("no_response_timeout", "malformed_response"):
        return "unknown"
    if after["verdict"] in ("no_response_timeout", "malformed_response"):
        return "unknown"
    return str(before["payload_hex"] != after["payload_hex"])


def run_trial(candidate_label, payload_hex, session_id, timeout_sec):
    before = call_someip(GETTER8_METHOD_ID, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)

    method14 = call_someip(METHOD14_METHOD_ID, bytes.fromhex(payload_hex), session_id, timeout_sec)
    session_id = next_session_id(session_id)

    after = call_someip(GETTER8_METHOD_ID, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)

    row = {
        "timestamp": timestamp_for_row(),
        "candidate_label": candidate_label,
        "method14_payload_hex": payload_hex,
        "getter_before_payload_hex": before["payload_hex"],
        "method14_response_received": method14["response_received"],
        "method14_msg_type": msg_type(method14),
        "method14_retcode": method14["retcode"],
        "method14_verdict": method14["verdict"],
        "getter_after_payload_hex": after["payload_hex"],
        "state_changed": state_changed(before, after),
        "error": combined_error(("getter_before", before), ("method14", method14), ("getter_after", after)),
    }
    return row, session_id


def write_rows(path, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        writer.writerows(rows)


def print_selected_baselines(rows):
    selected = []
    for row in rows:
        if row["method14_verdict"] == "normal_response" and row["state_changed"] == "True":
            selected.append((row["candidate_label"], row["method14_payload_hex"]))
    if not selected:
        print("selected_baseline_payload_hex=")
        return
    deduped = []
    seen = set()
    for item in selected:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    print("selected_baseline_payload_hex={}".format(deduped[0][1]))
    print("selected_baseline_label={}".format(deduped[0][0]))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run Method 14 candidates and compare Getter 8 before/after payloads."
    )
    parser.add_argument("--out", default="", help="Output CSV path.")
    parser.add_argument("--repeat", type=int, default=1, help="Repeat count per candidate, limited to 1..3.")
    parser.add_argument("--timeout", type=float, default=1.0, help="Response timeout in seconds.")
    parser.add_argument("--start-session-id", type=lambda value: int(value, 0), default=0x7400)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.repeat < 1 or args.repeat > 3:
        raise SystemExit("--repeat must be between 1 and 3")

    rows = []
    session_id = args.start_session_id
    for _ in range(args.repeat):
        for candidate_label, payload_hex in CANDIDATES:
            row, session_id = run_trial(candidate_label, payload_hex, session_id, args.timeout)
            rows.append(row)

    out_path = args.out or default_out_path()
    write_rows(out_path, rows)
    print("wrote {}".format(out_path))
    print_selected_baselines(rows)


if __name__ == "__main__":
    main()
