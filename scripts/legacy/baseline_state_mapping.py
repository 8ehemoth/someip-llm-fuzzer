#!/usr/bin/env python3
"""Replay baseline setter payloads and map getter before/after state changes."""

import argparse
import csv
import glob
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


GETTER_BY_SETTER = {
    10: 9,
    12: 11,
}
DETAIL_HEADER = [
    "source_file",
    "setter_method_id",
    "getter_method_id",
    "setter_payload_hex",
    "expected_after_payload_hex",
    "before_payload_hex",
    "after_payload_hex",
    "state_changed",
    "target_state_reached",
    "setter_retcode",
    "after_retcode",
    "latency_ms",
]
SUMMARY_HEADER = [
    "setter_method_id",
    "getter_method_id",
    "payload_hex",
    "expected_after_payload_hex",
    "trials",
    "state_changed_count",
    "target_state_reached_count",
    "target_state_reached_rate",
    "before_payload_distribution",
    "after_payload_distribution",
    "classification",
]
CANDIDATE_HEADER = [
    "source_file",
    "setter_method_id",
    "getter_method_id",
    "payload_hex",
    "expected_after_payload_hex",
]


def first_present(row, names, default=""):
    for name in names:
        if name in row:
            value = row.get(name)
            if value is not None and str(value).strip() != "":
                return str(value).strip()
    return default


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


def next_session_id(session_id):
    session_id = (session_id + 1) & 0xFFFF
    return 1 if session_id == 0 else session_id


def parse_globs(patterns):
    paths = []
    seen = set()
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if path in seen:
                continue
            seen.add(path)
            paths.append(path)
    return paths


def extract_candidates(patterns):
    candidates = []
    seen = set()
    for path in parse_globs(patterns):
        with open(path, "r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                continue
            for row in reader:
                method_text = first_present(row, ["req_method_id", "method_id", "setter_method_id"])
                try:
                    setter_method_id = parse_method_id(method_text)
                except ValueError:
                    continue
                if setter_method_id not in GETTER_BY_SETTER:
                    continue

                payload_hex = normalize_hex(
                    first_present(row, ["req_payload_hex", "payload_hex", "setter_payload_hex"])
                )
                key = (setter_method_id, payload_hex)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append({
                    "source_file": os.path.basename(path),
                    "setter_method_id": setter_method_id,
                    "getter_method_id": GETTER_BY_SETTER[setter_method_id],
                    "payload_hex": payload_hex,
                    "expected_after_payload_hex": payload_hex,
                    "payload": bytes.fromhex(payload_hex),
                })
    return candidates


def parse_expected_overrides(values):
    overrides = {}
    for value in values:
        for part in str(value or "").split(","):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                raise ValueError("expected override must be payload_hex=expected_hex")
            payload_hex, expected_hex = part.split("=", 1)
            overrides[normalize_hex(payload_hex)] = normalize_hex(expected_hex)
    return overrides


def apply_expected_after_payloads(candidates, default_expected_after_payload_hex, expected_overrides):
    default_expected = normalize_hex(default_expected_after_payload_hex)
    for candidate in candidates:
        candidate["expected_after_payload_hex"] = (
            expected_overrides.get(candidate["payload_hex"])
            or default_expected
            or candidate["payload_hex"]
        )
    return candidates


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


def timestamp_paths(results_dir):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return {
        "candidates": os.path.join(results_dir, "baseline_state_mapping_candidates_{}.csv".format(stamp)),
        "detail": os.path.join(results_dir, "baseline_state_mapping_{}.csv".format(stamp)),
        "summary": os.path.join(results_dir, "baseline_state_mapping_summary_{}.csv".format(stamp)),
    }


def run_trial(candidate, session_id, timeout_sec):
    from check_candidate_state_effect import call_someip  # noqa: WPS433

    started = time.time()
    before = call_someip(candidate["getter_method_id"], b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)
    setter = call_someip(candidate["setter_method_id"], candidate["payload"], session_id, timeout_sec)
    session_id = next_session_id(session_id)
    after = call_someip(candidate["getter_method_id"], b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)
    latency_ms = (time.time() - started) * 1000.0

    getter_ok = before["retcode"] == "0x00" and after["retcode"] == "0x00"
    state_changed = "unknown"
    if getter_ok:
        state_changed = str(before["payload_hex"] != after["payload_hex"])
    target_state_reached = str(after["payload_hex"] == candidate["expected_after_payload_hex"])

    return {
        "row": {
            "source_file": candidate["source_file"],
            "setter_method_id": candidate["setter_method_id"],
            "getter_method_id": candidate["getter_method_id"],
            "setter_payload_hex": candidate["payload_hex"],
            "expected_after_payload_hex": candidate["expected_after_payload_hex"],
            "before_payload_hex": before["payload_hex"],
            "after_payload_hex": after["payload_hex"],
            "state_changed": state_changed,
            "target_state_reached": target_state_reached,
            "setter_retcode": setter["retcode"],
            "after_retcode": after["retcode"],
            "latency_ms": "{:.3f}".format(latency_ms),
        },
        "next_session_id": session_id,
    }


def format_distribution(values):
    counter = Counter(values)
    return ";".join("{}={}".format(value, count) for value, count in sorted(counter.items()))


def classify(state_changed_count, target_state_reached_count, trials):
    if state_changed_count >= 1 and target_state_reached_count == trials:
        return "normal_idempotent_state_setter"
    if target_state_reached_count == trials:
        return "reproducible_target_state"
    if target_state_reached_count == 0:
        return "no_state_effect"
    return "partial_or_unstable_state_effect"


def summarize(rows):
    grouped = defaultdict(list)
    for row in rows:
        key = (
            row["setter_method_id"],
            row["getter_method_id"],
            row["setter_payload_hex"],
            row["expected_after_payload_hex"],
        )
        grouped[key].append(row)

    summary_rows = []
    for (setter_method_id, getter_method_id, payload_hex, expected_after_payload_hex), group in sorted(grouped.items()):
        trials = len(group)
        state_changed_count = sum(1 for row in group if row["state_changed"] == "True")
        target_state_reached_count = sum(1 for row in group if row["target_state_reached"] == "True")
        target_state_reached_rate = 0.0 if trials == 0 else target_state_reached_count / trials
        summary_rows.append({
            "setter_method_id": setter_method_id,
            "getter_method_id": getter_method_id,
            "payload_hex": payload_hex,
            "expected_after_payload_hex": expected_after_payload_hex,
            "trials": trials,
            "state_changed_count": state_changed_count,
            "target_state_reached_count": target_state_reached_count,
            "target_state_reached_rate": "{:.6f}".format(target_state_reached_rate),
            "before_payload_distribution": format_distribution(row["before_payload_hex"] for row in group),
            "after_payload_distribution": format_distribution(row["after_payload_hex"] for row in group),
            "classification": classify(state_changed_count, target_state_reached_count, trials),
        })
    return summary_rows


def candidate_rows(candidates):
    rows = []
    for candidate in candidates:
        rows.append({
            "source_file": candidate["source_file"],
            "setter_method_id": candidate["setter_method_id"],
            "getter_method_id": candidate["getter_method_id"],
            "payload_hex": candidate["payload_hex"],
            "expected_after_payload_hex": candidate["expected_after_payload_hex"],
        })
    return rows


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract Method 10/12 baseline payloads and replay them with Getter 9/11 before/after mapping."
    )
    parser.add_argument(
        "--input-glob",
        action="append",
        default=[],
        help="Input CSV glob. Can be repeated. Default: results/results_baseline_*.csv",
    )
    parser.add_argument("--trial-count", type=int, default=10, help="Trials per payload; minimum is 10")
    parser.add_argument("--timeout", type=float, default=1.0, help="Response timeout in seconds")
    parser.add_argument("--results-dir", default="results", help="Directory for timestamped outputs")
    parser.add_argument("--out", default="", help="Detail output CSV path")
    parser.add_argument("--summary-out", default="", help="Summary output CSV path")
    parser.add_argument("--candidates-out", default="", help="Extracted baseline candidate CSV path")
    parser.add_argument(
        "--expected-after-payload-hex",
        default="",
        help="Default expected after getter payload; default is each setter payload",
    )
    parser.add_argument(
        "--expected-after",
        action="append",
        default=[],
        help="Override expected after payload as payload_hex=expected_hex. Can be repeated or comma-separated.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.trial_count < 10:
        raise ValueError("--trial-count must be at least 10")

    patterns = args.input_glob or [os.path.join(args.results_dir, "results_baseline_*.csv")]
    paths = timestamp_paths(args.results_dir)
    candidates_out = args.candidates_out or paths["candidates"]
    detail_out = args.out or paths["detail"]
    summary_out = args.summary_out or paths["summary"]

    candidates = apply_expected_after_payloads(
        extract_candidates(patterns),
        args.expected_after_payload_hex,
        parse_expected_overrides(args.expected_after),
    )
    write_csv(candidates_out, CANDIDATE_HEADER, candidate_rows(candidates))
    print("input_globs={}".format(",".join(patterns)))
    print("baseline_candidates={}".format(len(candidates)))
    print("wrote_candidates: {}".format(candidates_out))

    if not candidates:
        print("no Method 10/12 baseline setter payloads found; replay skipped")
        return

    rows = []
    session_id = 0x7000
    for candidate in candidates:
        for _ in range(args.trial_count):
            trial = run_trial(candidate, session_id, args.timeout)
            rows.append(trial["row"])
            session_id = trial["next_session_id"]

    summary_rows = summarize(rows)
    write_csv(detail_out, DETAIL_HEADER, rows)
    write_csv(summary_out, SUMMARY_HEADER, summary_rows)
    print("wrote: {}".format(detail_out))
    print("wrote_summary: {}".format(summary_out))
    print("total_trials={}".format(len(rows)))
    print("state_changed_count={}".format(sum(1 for row in rows if row["state_changed"] == "True")))


if __name__ == "__main__":
    main()
