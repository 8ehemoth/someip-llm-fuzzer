#!/usr/bin/env python3
"""Balance Method 14 candidate CSVs by payload_source."""

import argparse
import csv
import os
from datetime import datetime


REQUIRED_COLUMNS = ["payload_source", "payload_label", "method_id", "payload_hex", "payload_len"]
DEFAULT_OUTPUT_PREFIX = "results/method14_candidates_balanced"


def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


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


def read_rows(path):
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = sorted(set(REQUIRED_COLUMNS) - set(reader.fieldnames or []))
        if missing:
            raise ValueError("missing candidate CSV columns in {}: {}".format(path, ",".join(missing)))
        rows = []
        for row_index, row in enumerate(reader, start=1):
            if int(str(row["method_id"]).strip(), 0) != 14:
                continue
            payload_hex = normalize_hex(row["payload_hex"])
            if not payload_hex:
                continue
            row = dict(row)
            row["payload_hex"] = payload_hex
            row["payload_len"] = str(payload_len(payload_hex))
            rows.append(row)
        return rows


def dedupe(rows):
    selected = []
    seen = set()
    for row in rows:
        key = (row.get("payload_source", ""), row["payload_hex"])
        if key in seen:
            continue
        seen.add(key)
        selected.append(row)
    return selected


def source_kind(row):
    source = str(row.get("payload_source", "")).strip().lower()
    if source.startswith("llm"):
        return "llm"
    if source.startswith("radamsa"):
        return "radamsa"
    return ""


def balanced_rows(rows, count):
    llm_rows = [row for row in rows if source_kind(row) == "llm"]
    radamsa_rows = [row for row in rows if source_kind(row) == "radamsa"]
    if not llm_rows:
        raise ValueError("no llm* payload_source rows found")
    if not radamsa_rows:
        raise ValueError("no radamsa* payload_source rows found")
    common_count = min(len(llm_rows), len(radamsa_rows))
    if count > 0:
        common_count = min(common_count, count)
    return llm_rows[:common_count] + radamsa_rows[:common_count], common_count, len(llm_rows), len(radamsa_rows)


def output_header(rows):
    header = []
    for column in REQUIRED_COLUMNS:
        if column not in header:
            header.append(column)
    for row in rows:
        for column in row.keys():
            if column not in header:
                header.append(column)
    return header


def write_rows(path, rows):
    ensure_parent(path)
    header = output_header(rows)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def parse_args():
    parser = argparse.ArgumentParser(description="Balance Method 14 LLM and Radamsa candidate CSVs.")
    parser.add_argument("--llm-candidates", default="")
    parser.add_argument("--radamsa-candidates", default="")
    parser.add_argument("--combined-candidates", default="")
    parser.add_argument("--count", type=int, default=0, help="Maximum rows per source; default is min source count")
    parser.add_argument("--output-prefix", default=DEFAULT_OUTPUT_PREFIX)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.combined_candidates:
        rows = read_rows(args.combined_candidates)
    elif args.llm_candidates and args.radamsa_candidates:
        rows = read_rows(args.llm_candidates) + read_rows(args.radamsa_candidates)
    else:
        raise SystemExit("--combined-candidates or both --llm-candidates and --radamsa-candidates are required")

    rows = dedupe(rows)
    balanced, common_count, llm_count, radamsa_count = balanced_rows(rows, args.count)
    output_path = "{}_{}.csv".format(args.output_prefix, timestamp())
    write_rows(output_path, balanced)
    print("llm_input_count={}".format(llm_count))
    print("radamsa_input_count={}".format(radamsa_count))
    print("balanced_count_per_source={}".format(common_count))
    print("wrote {}".format(output_path))


if __name__ == "__main__":
    main()
