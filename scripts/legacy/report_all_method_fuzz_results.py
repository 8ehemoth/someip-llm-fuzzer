#!/usr/bin/env python3
"""Generate reports from the latest all_method_fuzz result CSVs."""

import argparse
import csv
import glob
import os
from collections import Counter, defaultdict
from datetime import datetime


STATEFUL_METHOD_IDS = {10, 12, 14}
GETTER_METHOD_IDS = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11}

METHOD_SUMMARY_HEADER = [
    "method_id",
    "method_name",
    "role",
    "total_candidates",
    "total_trials",
    "normal_response_count",
    "error_response_count",
    "timeout_count",
    "normal_response_rate",
    "state_changed_count",
    "non_trivial_state_effect_count",
    "reproducible_non_trivial_state_effect_count",
    "classification_counts",
    "avg_latency_ms",
    "max_latency_ms",
    "p95_latency_ms",
]
HIGH_VALUE_HEADER = [
    "method_id",
    "method_name",
    "role",
    "payload_source",
    "payload_label",
    "payload_hex",
    "payload_len",
    "trials",
    "normal_response_count",
    "state_changed_count",
    "non_trivial_state_effect_count",
    "before_payload_distribution",
    "after_payload_distribution",
    "classification",
]
PROTOCOL_VALID_NO_EFFECT_HEADER = [
    "method_id",
    "method_name",
    "role",
    "payload_source",
    "payload_label",
    "payload_hex",
    "payload_len",
    "trials",
    "normal_response_count",
    "state_changed_count",
    "non_trivial_state_effect_count",
    "reset_equivalent_count",
    "after_payload_distribution",
    "classification",
]


def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def latest_path(pattern):
    paths = sorted(glob.glob(pattern))
    if not paths:
        raise FileNotFoundError("no files matched {}".format(pattern))
    return paths[-1]


def read_csv(path):
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def write_csv(path, header, rows):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)


def int_value(row, key):
    value = str(row.get(key, "") or "").strip()
    return int(value) if value else 0


def float_value(row, key):
    value = str(row.get(key, "") or "").strip()
    return float(value) if value else 0.0


def method_summary_rows(summary_rows):
    rows = []
    for row in sorted(summary_rows, key=lambda item: int_value(item, "method_id")):
        total_trials = int_value(row, "total_trials")
        normal = int_value(row, "normal_response_count")
        normal_rate = 0.0 if total_trials == 0 else normal / total_trials
        rows.append({
            "method_id": row["method_id"],
            "method_name": row["method_name"],
            "role": row["role"],
            "total_candidates": row["total_candidates"],
            "total_trials": row["total_trials"],
            "normal_response_count": row["normal_response_count"],
            "error_response_count": row["error_response_count"],
            "timeout_count": row["timeout_count"],
            "normal_response_rate": "{:.6f}".format(normal_rate),
            "state_changed_count": row["state_changed_count"],
            "non_trivial_state_effect_count": row["non_trivial_state_effect_count"],
            "reproducible_non_trivial_state_effect_count": row["reproducible_non_trivial_state_effect_count"],
            "classification_counts": row["classification_counts"],
            "avg_latency_ms": row["avg_latency_ms"],
            "max_latency_ms": row["max_latency_ms"],
            "p95_latency_ms": row["p95_latency_ms"],
        })
    return rows


def distribution(values):
    counter = Counter(value for value in values if value != "")
    return ";".join("{}={}".format(key, counter[key]) for key in sorted(counter))


def classify_candidate(rows):
    trials = len(rows)
    normal = sum(1 for row in rows if row["verdict"] == "normal_response")
    error = sum(1 for row in rows if row["verdict"] == "error_response")
    timeout = sum(1 for row in rows if row["verdict"] == "no_response_timeout")
    non_trivial = sum(1 for row in rows if row["non_trivial_state_effect"] == "True")
    if normal > 0 and non_trivial == 0:
        return "protocol_valid_no_state_effect"
    if non_trivial == trials and trials > 0:
        return "reproducible_non_trivial_state_effect"
    if 0 < non_trivial < trials:
        return "unstable_non_trivial_state_effect"
    if error > 0 and normal == 0:
        return "rejected_or_error"
    if timeout > 0 and normal == 0:
        return "timeout_or_no_response"
    return "rejected_or_error"


def candidate_groups(detail_rows):
    grouped = defaultdict(list)
    for row in detail_rows:
        key = (
            int_value(row, "method_id"),
            row["method_name"],
            row["role"],
            row["payload_source"],
            row["payload_label"],
            row["payload_hex"],
            row["payload_len"],
        )
        grouped[key].append(row)
    return grouped


def high_value_rows(detail_rows):
    rows = []
    for key, group in sorted(candidate_groups(detail_rows).items()):
        method_id, method_name, role, payload_source, payload_label, payload_hex, payload_len = key
        if method_id not in STATEFUL_METHOD_IDS:
            continue
        trials = len(group)
        normal = sum(1 for row in group if row["verdict"] == "normal_response")
        state_changed = sum(1 for row in group if row["state_changed"] == "True")
        non_trivial = sum(1 for row in group if row["non_trivial_state_effect"] == "True")
        if trials == 0 or non_trivial != trials:
            continue
        rows.append({
            "method_id": method_id,
            "method_name": method_name,
            "role": role,
            "payload_source": payload_source,
            "payload_label": payload_label,
            "payload_hex": payload_hex,
            "payload_len": payload_len,
            "trials": trials,
            "normal_response_count": normal,
            "state_changed_count": state_changed,
            "non_trivial_state_effect_count": non_trivial,
            "before_payload_distribution": distribution(row["before_payload_hex"] for row in group),
            "after_payload_distribution": distribution(row["after_payload_hex"] for row in group),
            "classification": "reproducible_non_trivial_state_effect",
        })
    return rows


def method14_protocol_valid_no_effect_rows(detail_rows):
    rows = []
    for key, group in sorted(candidate_groups(detail_rows).items()):
        method_id, method_name, role, payload_source, payload_label, payload_hex, payload_len = key
        if method_id != 14:
            continue
        normal = sum(1 for row in group if row["verdict"] == "normal_response")
        non_trivial = sum(1 for row in group if row["non_trivial_state_effect"] == "True")
        if normal <= 0 or non_trivial != 0:
            continue
        rows.append({
            "method_id": method_id,
            "method_name": method_name,
            "role": role,
            "payload_source": payload_source,
            "payload_label": payload_label,
            "payload_hex": payload_hex,
            "payload_len": payload_len,
            "trials": len(group),
            "normal_response_count": normal,
            "state_changed_count": sum(1 for row in group if row["state_changed"] == "True"),
            "non_trivial_state_effect_count": non_trivial,
            "reset_equivalent_count": sum(1 for row in group if row["reset_equivalent"] == "True"),
            "after_payload_distribution": distribution(row["after_payload_hex"] for row in group),
            "classification": classify_candidate(group),
        })
    return rows


def markdown_table(header, rows):
    lines = []
    lines.append("| " + " | ".join(header) + " |")
    lines.append("| " + " | ".join("---" for _ in header) + " |")
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(key, "")) for key in header) + " |")
    return "\n".join(lines)


def build_markdown(summary_path, detail_path, method_rows, high_rows, no_effect_rows):
    getter_rows = [row for row in method_rows if int(row["method_id"]) in GETTER_METHOD_IDS]
    stateful_rows = [row for row in method_rows if int(row["method_id"]) in STATEFUL_METHOD_IDS]
    method13_rows = [row for row in method_rows if int(row["method_id"]) == 13]
    lines = [
        "# All Method Fuzz Result Report",
        "",
        "Input summary: `{}`".format(summary_path),
        "Input detail: `{}`".format(detail_path),
        "",
        "## 핵심 해석",
        "",
        "- Getter 계열(Method 1~9, 11)은 상태 변경 대상이 아니므로 response classification 중심으로 본다.",
        "- Setter/State-changing Method(Method 10, 12, 14)는 paired Getter before/after payload 비교가 핵심이다.",
        "- `normal_response`는 프로토콜 레벨에서 요청이 수락됐다는 뜻이고, `non_trivial_state_effect`는 reset 이후 공개 Getter payload가 실제로 바뀌었다는 뜻이다. 둘은 같은 지표가 아니다.",
        "",
        "## Method Summary",
        "",
        markdown_table(
            [
                "method_id",
                "method_name",
                "role",
                "total_candidates",
                "total_trials",
                "normal_response_count",
                "error_response_count",
                "timeout_count",
                "state_changed_count",
                "non_trivial_state_effect_count",
                "reproducible_non_trivial_state_effect_count",
                "classification_counts",
            ],
            method_rows,
        ),
        "",
        "## Getter Methods",
        "",
        markdown_table(
            ["method_id", "method_name", "total_candidates", "total_trials", "normal_response_count", "error_response_count", "timeout_count", "classification_counts"],
            getter_rows,
        ),
        "",
        "## Setter / State-Changing Methods",
        "",
        markdown_table(
            ["method_id", "method_name", "total_candidates", "total_trials", "normal_response_count", "state_changed_count", "non_trivial_state_effect_count", "reproducible_non_trivial_state_effect_count", "classification_counts"],
            stateful_rows,
        ),
        "",
        "## Method 13",
        "",
        markdown_table(
            ["method_id", "method_name", "total_candidates", "total_trials", "normal_response_count", "error_response_count", "timeout_count", "classification_counts"],
            method13_rows,
        ),
        "",
        "## High Value Candidates",
        "",
        "Method 10/12/14 후보 중 모든 trial에서 `non_trivial_state_effect=True`인 항목이다.",
        "",
        markdown_table(
            ["method_id", "payload_label", "payload_hex", "trials", "normal_response_count", "state_changed_count", "non_trivial_state_effect_count", "before_payload_distribution", "after_payload_distribution"],
            high_rows,
        ),
        "",
        "## Method 14 Protocol-Valid No-Effect Candidates",
        "",
        "Method 14에서 `normal_response`는 있었지만 non-trivial state effect가 없었던 후보이다.",
        "",
        markdown_table(
            ["payload_label", "payload_hex", "trials", "normal_response_count", "state_changed_count", "reset_equivalent_count", "after_payload_distribution", "classification"],
            no_effect_rows,
        ),
        "",
    ]
    return "\n".join(lines)


def parse_args():
    parser = argparse.ArgumentParser(description="Report all_method_fuzz CSV results.")
    parser.add_argument("--summary", default="", help="Input summary CSV. Defaults to latest.")
    parser.add_argument("--detail", default="", help="Input detail CSV. Defaults to latest.")
    parser.add_argument("--out-prefix", default="results/all_method_fuzz")
    return parser.parse_args()


def main():
    args = parse_args()
    summary_path = args.summary or latest_path("results/all_method_fuzz_summary_*.csv")
    detail_path = args.detail or latest_path("results/all_method_fuzz_detail_*.csv")
    stamp = timestamp()
    report_path = "{}_report_{}.md".format(args.out_prefix, stamp)
    method_summary_path = "{}_method_summary_{}.csv".format(args.out_prefix, stamp)
    high_value_path = "{}_high_value_candidates_{}.csv".format(args.out_prefix, stamp)
    no_effect_path = "{}_protocol_valid_no_effect_{}.csv".format(args.out_prefix, stamp)

    summary_rows = read_csv(summary_path)
    detail_rows = read_csv(detail_path)
    method_rows = method_summary_rows(summary_rows)
    high_rows = high_value_rows(detail_rows)
    no_effect_rows = method14_protocol_valid_no_effect_rows(detail_rows)

    write_csv(method_summary_path, METHOD_SUMMARY_HEADER, method_rows)
    write_csv(high_value_path, HIGH_VALUE_HEADER, high_rows)
    write_csv(no_effect_path, PROTOCOL_VALID_NO_EFFECT_HEADER, no_effect_rows)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(build_markdown(summary_path, detail_path, method_rows, high_rows, no_effect_rows))

    print("wrote {}".format(report_path))
    print("wrote {}".format(method_summary_path))
    print("wrote {}".format(high_value_path))
    print("wrote {}".format(no_effect_path))


if __name__ == "__main__":
    main()
