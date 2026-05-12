#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
from collections import Counter, defaultdict
from statistics import mean


def safe_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default


def load_csv(path):
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def summarize(rows):
    total = len(rows)
    verdicts = Counter(r.get("verdict", "") for r in rows)
    retcodes = Counter(r.get("rsp_retcode", "") for r in rows)
    msg_types = Counter(r.get("rsp_msg_type", "") for r in rows)
    methods = Counter(r.get("target_value", "") for r in rows)
    payload_sources = Counter(r.get("payload_source", "") for r in rows)

    latencies = [
        safe_float(r.get("response_time_ms", 0))
        for r in rows
        if str(r.get("response_time_ms", "")).strip() != ""
    ]
    avg_lat = round(mean(latencies), 2) if latencies else 0.0
    min_lat = round(min(latencies), 2) if latencies else 0.0
    max_lat = round(max(latencies), 2) if latencies else 0.0

    unique_retcodes = len([k for k in retcodes.keys() if str(k).strip() != ""])
    unique_msg_types = len([k for k in msg_types.keys() if str(k).strip() != ""])

    triplets = set()
    for r in rows:
        triplets.add((
            r.get("target_value", ""),
            r.get("rsp_retcode", ""),
            r.get("verdict", ""),
        ))

    by_method = defaultdict(list)
    for r in rows:
        by_method[r.get("target_value", "")].append(r)

    method_summary = {}
    for method, grp in sorted(
        by_method.items(),
        key=lambda kv: int(kv[0]) if str(kv[0]).isdigit() else 999999
    ):
        m_lat = [
            safe_float(r.get("response_time_ms", 0))
            for r in grp
            if str(r.get("response_time_ms", "")).strip() != ""
        ]
        method_summary[method] = {
            "count": len(grp),
            "retcodes": dict(Counter(r.get("rsp_retcode", "") for r in grp)),
            "verdicts": dict(Counter(r.get("verdict", "") for r in grp)),
            "payload_sources": dict(Counter(r.get("payload_source", "") for r in grp)),
            "avg_latency_ms": round(mean(m_lat), 2) if m_lat else 0.0,
            "min_latency_ms": round(min(m_lat), 2) if m_lat else 0.0,
            "max_latency_ms": round(max(m_lat), 2) if m_lat else 0.0,
        }

    return {
        "total_cases": total,
        "verdict_count": dict(verdicts),
        "retcode_count": dict(retcodes),
        "msg_type_count": dict(msg_types),
        "method_count": dict(methods),
        "payload_source_count": dict(payload_sources),
        "unique_retcode_count": unique_retcodes,
        "unique_msg_type_count": unique_msg_types,
        "unique_method_retcode_verdict_count": len(triplets),
        "avg_latency_ms": avg_lat,
        "min_latency_ms": min_lat,
        "max_latency_ms": max_lat,
        "methods": method_summary,
    }


def print_markdown_table(llm_summary, rad_summary, llm_name, rad_name):
    headers = ["metric", llm_name, rad_name]
    rows = [
        ("total_cases", llm_summary["total_cases"], rad_summary["total_cases"]),
        ("unique_retcode_count", llm_summary["unique_retcode_count"], rad_summary["unique_retcode_count"]),
        ("unique_msg_type_count", llm_summary["unique_msg_type_count"], rad_summary["unique_msg_type_count"]),
        ("unique_method_retcode_verdict_count", llm_summary["unique_method_retcode_verdict_count"], rad_summary["unique_method_retcode_verdict_count"]),
        ("avg_latency_ms", llm_summary["avg_latency_ms"], rad_summary["avg_latency_ms"]),
        ("min_latency_ms", llm_summary["min_latency_ms"], rad_summary["min_latency_ms"]),
        ("max_latency_ms", llm_summary["max_latency_ms"], rad_summary["max_latency_ms"]),
        ("normal_response", llm_summary["verdict_count"].get("normal_response", 0), rad_summary["verdict_count"].get("normal_response", 0)),
        ("error_response", llm_summary["verdict_count"].get("error_response", 0), rad_summary["verdict_count"].get("error_response", 0)),
        ("no_response_timeout", llm_summary["verdict_count"].get("no_response_timeout", 0), rad_summary["verdict_count"].get("no_response_timeout", 0)),
        ("malformed_response", llm_summary["verdict_count"].get("malformed_response", 0), rad_summary["verdict_count"].get("malformed_response", 0)),
    ]

    print("| " + " | ".join(headers) + " |")
    print("|" + "|".join(["---"] * len(headers)) + "|")
    for r in rows:
        print("| " + " | ".join(str(x) for x in r) + " |")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm", required=True, help="LLM campaign csv")
    parser.add_argument("--radamsa", required=True, help="Radamsa campaign csv")
    parser.add_argument("--output", help="Optional JSON output")
    args = parser.parse_args()

    llm_rows = load_csv(args.llm)
    rad_rows = load_csv(args.radamsa)

    llm_summary = summarize(llm_rows)
    rad_summary = summarize(rad_rows)

    result = {
        "llm_file": args.llm,
        "radamsa_file": args.radamsa,
        "llm_summary": llm_summary,
        "radamsa_summary": rad_summary,
    }

    print("\n[overall comparison]")
    print_markdown_table(llm_summary, rad_summary, "llm", "radamsa")

    print("\n[llm method summary]")
    print(json.dumps(llm_summary["methods"], indent=2, ensure_ascii=False))

    print("\n[radamsa method summary]")
    print(json.dumps(rad_summary["methods"], indent=2, ensure_ascii=False))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n[+] saved comparison json: {args.output}")


if __name__ == "__main__":
    main()
