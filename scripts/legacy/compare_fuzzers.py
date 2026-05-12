#!/usr/bin/env python3
"""
Compare LLM-guided and Radamsa fuzzing CSV outputs against a baseline.

This script intentionally uses only black-box feedback fields from CSV files:
request method/payload, response verdict, response retcode, and latency.
It does not inspect server source code or implementation details.
"""

import argparse
import csv
import json
import math
import os
from collections import Counter, defaultdict


PAYLOAD_COLUMNS = [
    "payload_hex",
    "req_payload_hex",
    "load_hex",
    "payload",
    "load",
    "req_payload",
]
VERDICT_COLUMNS = ["verdict", "result", "outcome", "status"]
RETCODE_COLUMNS = ["retcode", "rsp_retcode", "return_code", "response_retcode", "someip_retcode"]
METHOD_COLUMNS = ["method_id", "req_method_id", "target_value", "method", "req_method"]
LATENCY_COLUMNS = ["latency_ms", "response_time_ms", "response_ms", "rtt_ms", "duration_ms"]
MSG_TYPE_COLUMNS = ["rsp_msg_type", "msg_type", "response_msg_type"]
RESPONSE_RECEIVED_COLUMNS = ["response_received", "received", "has_response"]


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


def parse_float(value):
    text = str(value or "").strip()
    if text == "":
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    if math.isnan(value) or math.isinf(value):
        return None
    return value


def parse_bool(value):
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "y"}:
        return True
    if text in {"false", "0", "no", "n"}:
        return False
    return None


def percentile(values, pct):
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (pct / 100.0)
    low = int(math.floor(rank))
    high = int(math.ceil(rank))
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] * (1.0 - weight) + ordered[high] * weight


def classify_row(row):
    payload_raw = first_present(row, PAYLOAD_COLUMNS)
    payload = normalize_hex(payload_raw)
    verdict = first_present(row, VERDICT_COLUMNS).lower()
    retcode = normalize_retcode(first_present(row, RETCODE_COLUMNS))
    method_id = normalize_int_string(first_present(row, METHOD_COLUMNS))
    msg_type = normalize_retcode(first_present(row, MSG_TYPE_COLUMNS))
    latency_ms = parse_float(first_present(row, LATENCY_COLUMNS))
    response_received = parse_bool(first_present(row, RESPONSE_RECEIVED_COLUMNS))

    if verdict == "":
        if response_received is False:
            verdict = "no_response_timeout"
        elif retcode == "0x00":
            verdict = "normal_response"
        elif retcode != "":
            verdict = "error_response"
        else:
            verdict = "unknown"

    return {
        "payload": payload,
        "verdict": verdict,
        "retcode": retcode,
        "method_id": method_id,
        "msg_type": msg_type,
        "latency_ms": latency_ms,
    }


def response_signature(row):
    return (
        row["method_id"],
        row["retcode"],
        row["msg_type"],
        row["verdict"],
    )


def baseline_profile(rows):
    normalized = [classify_row(row) for row in rows]
    latencies = [row["latency_ms"] for row in normalized if row["latency_ms"] is not None]
    normal_signatures = {
        response_signature(row)
        for row in normalized
        if row["verdict"] == "normal_response"
    }
    retcodes = {row["retcode"] for row in normalized if row["retcode"] != ""}
    return {
        "avg_latency_ms": sum(latencies) / len(latencies) if latencies else None,
        "normal_signatures": normal_signatures,
        "retcodes": retcodes,
    }


def summarize(rows, baseline):
    normalized = [classify_row(row) for row in rows]
    latencies = [row["latency_ms"] for row in normalized if row["latency_ms"] is not None]

    verdict_count = Counter(row["verdict"] for row in normalized)
    retcode_count = Counter(row["retcode"] for row in normalized if row["retcode"] != "")

    method_verdicts = defaultdict(Counter)
    for row in normalized:
        method = row["method_id"] if row["method_id"] != "" else "unknown"
        method_verdicts[method][row["verdict"]] += 1

    baseline_avg = baseline["avg_latency_ms"]
    interesting_score = 0
    baseline_different_normal = 0
    new_retcode_rows = 0
    slow_rows = 0

    for row in normalized:
        if (
            row["verdict"] == "normal_response"
            and response_signature(row) not in baseline["normal_signatures"]
        ):
            baseline_different_normal += 1
            interesting_score += 3

        if row["verdict"] == "no_response_timeout":
            interesting_score += 2

        if row["verdict"] == "malformed_response":
            interesting_score += 2

        if row["retcode"] != "" and row["retcode"] not in baseline["retcodes"]:
            new_retcode_rows += 1
            interesting_score += 2

        if (
            baseline_avg is not None
            and baseline_avg > 0
            and row["latency_ms"] is not None
            and row["latency_ms"] >= baseline_avg * 2.0
        ):
            slow_rows += 1
            interesting_score += 1

    return {
        "total_cases": len(normalized),
        "unique_payload_count": len({row["payload"] for row in normalized}),
        "verdict_count": dict(sorted(verdict_count.items())),
        "retcode_count": dict(sorted(retcode_count.items())),
        "method_id_verdict_distribution": {
            method: dict(sorted(counts.items()))
            for method, counts in sorted(method_verdicts.items(), key=lambda item: sort_key(item[0]))
        },
        "normal_response_count": verdict_count.get("normal_response", 0),
        "baseline_different_normal_response_count": baseline_different_normal,
        "timeout_count": verdict_count.get("no_response_timeout", 0),
        "malformed_response_count": verdict_count.get("malformed_response", 0),
        "error_response_count": verdict_count.get("error_response", 0),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else None,
        "max_latency_ms": round(max(latencies), 3) if latencies else None,
        "p95_latency_ms": round(percentile(latencies, 95), 3) if latencies else None,
        "interesting_score": interesting_score,
        "interesting_breakdown": {
            "baseline_different_normal_response_rows": baseline_different_normal,
            "timeout_rows": verdict_count.get("no_response_timeout", 0),
            "malformed_response_rows": verdict_count.get("malformed_response", 0),
            "new_retcode_rows": new_retcode_rows,
            "latency_ge_2x_baseline_avg_rows": slow_rows,
        },
    }


def sort_key(value):
    try:
        return (0, int(str(value), 0))
    except ValueError:
        return (1, str(value))


def baseline_summary(rows):
    normalized = [classify_row(row) for row in rows]
    latencies = [row["latency_ms"] for row in normalized if row["latency_ms"] is not None]
    return {
        "total_cases": len(normalized),
        "retcodes": sorted({row["retcode"] for row in normalized if row["retcode"] != ""}),
        "normal_response_signatures": [
            list(sig)
            for sig in sorted(
                {
                    response_signature(row)
                    for row in normalized
                    if row["verdict"] == "normal_response"
                }
            )
        ],
        "avg_latency_ms": round(sum(latencies) / len(latencies), 3) if latencies else None,
    }


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def write_json(path, obj):
    ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")


def md_value(value):
    if value is None:
        return ""
    if isinstance(value, dict):
        return "`" + json.dumps(value, sort_keys=True) + "`"
    return str(value)


def write_markdown(path, result):
    ensure_parent(path)
    metrics = [
        "total_cases",
        "unique_payload_count",
        "normal_response_count",
        "baseline_different_normal_response_count",
        "timeout_count",
        "malformed_response_count",
        "error_response_count",
        "avg_latency_ms",
        "max_latency_ms",
        "p95_latency_ms",
        "interesting_score",
    ]

    lines = [
        "# Fuzzer Comparison",
        "",
        "## Inputs",
        "",
        "| input | path |",
        "|---|---|",
        "| llm | `{}` |".format(result["inputs"]["llm"]),
        "| radamsa | `{}` |".format(result["inputs"]["radamsa"]),
        "| baseline | `{}` |".format(result["inputs"]["baseline"]),
        "",
        "## Summary",
        "",
        "| metric | llm | radamsa |",
        "|---|---:|---:|",
    ]

    for metric in metrics:
        lines.append(
            "| {} | {} | {} |".format(
                metric,
                md_value(result["llm"].get(metric)),
                md_value(result["radamsa"].get(metric)),
            )
        )

    lines.extend([
        "",
        "## Verdict Counts",
        "",
        "| fuzzer | counts |",
        "|---|---|",
        "| llm | {} |".format(md_value(result["llm"]["verdict_count"])),
        "| radamsa | {} |".format(md_value(result["radamsa"]["verdict_count"])),
        "",
        "## Retcode Counts",
        "",
        "| fuzzer | counts |",
        "|---|---|",
        "| llm | {} |".format(md_value(result["llm"]["retcode_count"])),
        "| radamsa | {} |".format(md_value(result["radamsa"]["retcode_count"])),
        "",
        "## Method Verdict Distribution",
        "",
        "| fuzzer | distribution |",
        "|---|---|",
        "| llm | {} |".format(md_value(result["llm"]["method_id_verdict_distribution"])),
        "| radamsa | {} |".format(md_value(result["radamsa"]["method_id_verdict_distribution"])),
        "",
        "## Interesting Score",
        "",
        "Scoring: baseline-different normal response = 3, timeout = 2, malformed response = 2, new retcode = 2, latency >= 2x baseline average = 1.",
        "",
        "| fuzzer | breakdown |",
        "|---|---|",
        "| llm | {} |".format(md_value(result["llm"]["interesting_breakdown"])),
        "| radamsa | {} |".format(md_value(result["radamsa"]["interesting_breakdown"])),
        "",
    ])

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def build_result(args):
    baseline_rows = read_csv(args.baseline)
    baseline = baseline_profile(baseline_rows)

    result = {
        "inputs": {
            "llm": args.llm,
            "radamsa": args.radamsa,
            "baseline": args.baseline,
        },
        "metric_policy": {
            "mode": "black_box_feedback_guided",
            "used_fields": [
                "payload",
                "method_id",
                "verdict",
                "retcode",
                "latency_ms",
                "response msg_type when present",
            ],
            "interesting_score": {
                "baseline_different_normal_response": 3,
                "timeout": 2,
                "malformed_response": 2,
                "new_retcode": 2,
                "latency_ge_2x_baseline_avg": 1,
            },
        },
        "baseline": baseline_summary(baseline_rows),
        "llm": summarize(read_csv(args.llm), baseline),
        "radamsa": summarize(read_csv(args.radamsa), baseline),
    }
    return result


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compare LLM and Radamsa fuzzing CSVs using black-box feedback metrics."
    )
    parser.add_argument("--llm", required=True, help="LLM result CSV")
    parser.add_argument("--radamsa", required=True, help="Radamsa result CSV")
    parser.add_argument("--baseline", required=True, help="Normal baseline CSV")
    parser.add_argument("--out-json", required=True, help="Output JSON path")
    parser.add_argument("--out-md", required=True, help="Output Markdown path")
    return parser.parse_args()


def main():
    args = parse_args()
    result = build_result(args)
    write_json(args.out_json, result)
    write_markdown(args.out_md, result)
    print("wrote JSON: {}".format(args.out_json))
    print("wrote Markdown: {}".format(args.out_md))


if __name__ == "__main__":
    main()
