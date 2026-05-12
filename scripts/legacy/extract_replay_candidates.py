#!/usr/bin/env python3
"""
Extract replay candidates from an LLM fuzzing CSV.

The extractor stays within black-box feedback data: it only compares observed
payloads and verdict fields from CSV outputs. It does not send packets.
"""

import argparse
import csv
import json
import os


PAYLOAD_COLUMNS = [
    "payload_hex",
    "req_payload_hex",
    "load_hex",
    "payload",
    "load",
    "req_payload",
]
VERDICT_COLUMNS = ["verdict", "status", "result", "outcome"]
RETCODE_COLUMNS = ["retcode", "rsp_retcode", "return_code", "response_retcode", "someip_retcode"]
METHOD_COLUMNS = ["method_id", "req_method_id", "target_value", "method", "req_method"]
LATENCY_COLUMNS = ["latency_ms", "response_time_ms", "response_ms", "rtt_ms", "duration_ms"]


def read_csv(path):
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def first_present(row, candidates, default=""):
    for name in candidates:
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


def normalize_int_string(value):
    text = str(value or "").strip()
    if text == "":
        return ""
    try:
        return str(int(text, 0))
    except ValueError:
        return text.lower()


def normalize_retcode(value):
    text = str(value or "").strip()
    if text == "":
        return ""
    try:
        return "0x{:02x}".format(int(text, 0))
    except ValueError:
        return text.lower()


def parse_float_string(value):
    text = str(value or "").strip()
    if text == "":
        return ""
    try:
        return "{:.3f}".format(float(text))
    except ValueError:
        return text


def row_payload(row):
    return normalize_hex(first_present(row, PAYLOAD_COLUMNS))


def row_verdict(row):
    return first_present(row, VERDICT_COLUMNS).strip().lower()


def build_baseline_payload_set(rows):
    return {row_payload(row) for row in rows}


def extract_candidates(llm_rows, baseline_payloads):
    candidates = []
    seen_payloads = set()

    for index, row in enumerate(llm_rows, start=1):
        payload_hex = row_payload(row)
        verdict = row_verdict(row)

        if verdict != "normal_response":
            continue
        if payload_hex in baseline_payloads:
            continue
        if payload_hex in seen_payloads:
            continue

        seen_payloads.add(payload_hex)
        candidates.append({
            "method_id": normalize_int_string(first_present(row, METHOD_COLUMNS)),
            "payload_hex": payload_hex,
            "verdict": verdict,
            "retcode": normalize_retcode(first_present(row, RETCODE_COLUMNS)),
            "latency_ms": parse_float_string(first_present(row, LATENCY_COLUMNS)),
            "original_row_index": index,
        })

    return candidates


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def write_jsonl(path, rows):
    ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def print_summary(candidates):
    print("candidate_count={}".format(len(candidates)))
    if not candidates:
        print("no replay candidates found")
        return

    print("")
    print("| index | method_id | payload_len | payload_hex | retcode | latency_ms |")
    print("|---:|---:|---:|---|---|---:|")
    for candidate in candidates:
        payload_hex = candidate["payload_hex"]
        payload_len = len(payload_hex) // 2
        short_payload = payload_hex
        if len(short_payload) > 96:
            short_payload = short_payload[:96] + "..."
        print(
            "| {idx} | {method} | {plen} | `{payload}` | {retcode} | {latency} |".format(
                idx=candidate["original_row_index"],
                method=candidate["method_id"],
                plen=payload_len,
                payload=short_payload,
                retcode=candidate["retcode"],
                latency=candidate["latency_ms"],
            )
        )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract LLM normal-response payloads absent from baseline CSV payloads."
    )
    parser.add_argument("--llm", required=True, help="LLM result CSV")
    parser.add_argument("--baseline", required=True, help="Baseline CSV")
    parser.add_argument("--out", required=True, help="Output JSONL path")
    return parser.parse_args()


def main():
    args = parse_args()
    baseline_rows = read_csv(args.baseline)
    llm_rows = read_csv(args.llm)
    baseline_payloads = build_baseline_payload_set(baseline_rows)
    candidates = extract_candidates(llm_rows, baseline_payloads)
    write_jsonl(args.out, candidates)
    print_summary(candidates)
    print("")
    print("wrote: {}".format(args.out))


if __name__ == "__main__":
    main()
