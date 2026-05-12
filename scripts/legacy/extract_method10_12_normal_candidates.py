#!/usr/bin/env python3
"""
Extract normal-response candidates for setter methods 10 and 12 from results CSVs.

The script intentionally uses the stdlib csv module so payload hex values remain
strings; leading zeroes are never coerced through numeric parsing.
"""

import argparse
import csv
import glob
import os
from collections import Counter
from datetime import datetime


TARGET_METHOD_IDS = {10, 12}
OUTPUT_COLUMNS = [
    "source_file",
    "payload_source",
    "payload_label",
    "req_method_id",
    "req_payload_len",
    "req_payload_hex",
    "rsp_msg_type",
    "rsp_retcode",
    "verdict",
    "response_time_ms",
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


def normalize_method_id(value):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def normalize_retcode(value):
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return "0x{:02x}".format(int(text, 0))
    except ValueError:
        return text.lower()


def normalize_msg_type(value):
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return "0x{:02x}".format(int(text, 0))
    except ValueError:
        return text.lower()


def payload_len(row, payload_hex):
    text = first_present(row, ["req_payload_len", "payload_len"], "")
    if text:
        return text
    return str(len(payload_hex) // 2)


def iter_csv_rows(results_dir):
    pattern = os.path.join(results_dir, "*.csv")
    for path in sorted(glob.glob(pattern)):
        name = os.path.basename(path)
        if name.startswith("normal_response_candidates_") or name.startswith("replay_candidates_"):
            continue
        with open(path, "r", newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                continue
            for row in reader:
                yield path, row


def extract_candidates(results_dir):
    rows = []
    seen = set()
    raw_normal_counts = Counter()

    for path, row in iter_csv_rows(results_dir):
        method_id = normalize_method_id(first_present(row, ["req_method_id"]))
        if method_id not in TARGET_METHOD_IDS:
            continue

        verdict = first_present(row, ["verdict", "status", "result", "outcome"]).lower()
        retcode = normalize_retcode(
            first_present(row, ["rsp_retcode", "retcode", "return_code", "response_retcode"])
        )
        if verdict != "normal_response" or retcode != "0x00":
            continue

        payload_hex = normalize_hex(first_present(row, ["req_payload_hex"]))
        if payload_hex == "":
            continue

        raw_normal_counts[method_id] += 1
        key = (method_id, payload_hex)
        if key in seen:
            continue
        seen.add(key)

        rows.append({
            "source_file": os.path.basename(path),
            "payload_source": first_present(row, ["payload_source"], ""),
            "payload_label": first_present(row, ["payload_label"], ""),
            "req_method_id": str(method_id),
            "req_payload_len": payload_len(row, payload_hex),
            "req_payload_hex": payload_hex,
            "rsp_msg_type": normalize_msg_type(first_present(row, ["rsp_msg_type", "msg_type"], "")),
            "rsp_retcode": retcode,
            "verdict": verdict,
            "response_time_ms": first_present(row, ["response_time_ms", "latency_ms"], ""),
        })

    return rows, raw_normal_counts


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def timestamp_path(results_dir):
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(results_dir, "normal_response_candidates_method10_12_{}.csv".format(stamp))


def write_csv(path, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract deduplicated Method 10/12 normal-response candidates from results/*.csv."
    )
    parser.add_argument("--results-dir", default="results", help="Directory containing result CSV files")
    parser.add_argument("--out", default="", help="Output CSV path; default uses timestamp in results dir")
    return parser.parse_args()


def main():
    args = parse_args()
    out = args.out or timestamp_path(args.results_dir)
    rows, raw_normal_counts = extract_candidates(args.results_dir)
    write_csv(out, rows)

    dedup_counts = Counter(int(row["req_method_id"]) for row in rows)
    print("wrote: {}".format(out))
    for method_id in sorted(TARGET_METHOD_IDS):
        print(
            "method_id={} raw_normal_rows={} dedup_candidates={}".format(
                method_id,
                raw_normal_counts.get(method_id, 0),
                dedup_counts.get(method_id, 0),
            )
        )
    print("total_dedup_candidates={}".format(len(rows)))


if __name__ == "__main__":
    main()
