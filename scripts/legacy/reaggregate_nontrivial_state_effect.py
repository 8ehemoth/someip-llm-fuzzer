#!/usr/bin/env python3
"""Re-aggregate state-effect detail CSV without replaying candidates."""

import argparse
import csv
import os
from collections import Counter, defaultdict


RESET_PAYLOAD_HEX = "00000000"

SUMMARY_HEADER = [
    "source_file",
    "payload_source",
    "payload_label",
    "setter_method_id",
    "getter_method_id",
    "payload_hex",
    "expected_after_payload_hex",
    "reset_equivalent",
    "trials",
    "normal_response_count",
    "state_changed_count",
    "state_changed_rate",
    "target_state_reached_count",
    "target_state_reached_rate",
    "non_trivial_state_effect_count",
    "non_trivial_state_effect_rate",
    "reproducible_state_changed",
    "classification",
    "before_payload_distribution",
    "after_payload_distribution",
    "avg_latency_ms",
]

GROUPED_HEADER = [
    "payload_source",
    "setter_method_id",
    "total_candidates",
    "total_trials",
    "setter_normal_count",
    "state_changed_count",
    "target_state_reached_count",
    "non_trivial_state_effect_count",
    "target_state_reached_rate",
    "non_trivial_state_effect_rate",
    "classification_counts",
]

HIGH_VALUE_HEADER = [
    "source_file",
    "payload_source",
    "payload_label",
    "setter_method_id",
    "getter_method_id",
    "payload_hex",
    "expected_after_payload_hex",
    "trials",
    "target_state_reached_count",
    "target_state_reached_rate",
    "non_trivial_state_effect_count",
    "non_trivial_state_effect_rate",
    "classification",
]


def normalize_hex(value):
    return (value or "").strip().lower()


def bool_string(value):
    return str(bool(value))


def read_rows(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def write_csv(path, header, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def format_distribution(values):
    counter = Counter(values)
    return ";".join("{}={}".format(value, count) for value, count in sorted(counter.items()))


def output_paths(detail_path):
    stem = os.path.splitext(os.path.basename(detail_path))[0]
    prefix = "replay_candidates_state_effect"
    stamp = stem.removeprefix(prefix).lstrip("_")
    directory = os.path.dirname(detail_path) or "."
    return {
        "summary": os.path.join(directory, "{}_summary_nontrivial_{}.csv".format(prefix, stamp)),
        "grouped": os.path.join(directory, "{}_grouped_nontrivial_{}.csv".format(prefix, stamp)),
        "high_value": os.path.join(directory, "{}_high_value_nontrivial_{}.csv".format(prefix, stamp)),
        "trivial": os.path.join(directory, "{}_trivial_reset_equivalent_{}.csv".format(prefix, stamp)),
    }


def candidate_key(row):
    return (
        row["source_file"],
        row["payload_source"],
        row["payload_label"],
        row["setter_method_id"],
        row["getter_method_id"],
        row["setter_payload_hex"],
        row["expected_after_payload_hex"],
    )


def is_reset_equivalent(payload_hex):
    return normalize_hex(payload_hex) == RESET_PAYLOAD_HEX


def row_has_non_trivial_state_effect(row, reset_equivalent):
    if reset_equivalent:
        return False
    return normalize_hex(row.get("after_payload_hex")) != RESET_PAYLOAD_HEX


def classify_candidate(reset_equivalent, target_state_reached_count, non_trivial_count, trials):
    if reset_equivalent and target_state_reached_count > 0:
        return "trivial_reset_equivalent"
    if non_trivial_count == trials and trials > 0:
        return "reproducible_non_trivial_state_effect"
    if non_trivial_count > 0:
        return "partial_or_unstable_non_trivial_state_effect"
    if target_state_reached_count == 0:
        return "no_state_effect"
    return "target_state_reached_without_non_trivial_effect"


def summarize_by_candidate(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[candidate_key(row)].append(row)

    summary_rows = []
    for (
        source_file,
        payload_source,
        payload_label,
        setter_method_id,
        getter_method_id,
        payload_hex,
        expected_after_payload_hex,
    ), group in sorted(grouped.items()):
        trials = len(group)
        latencies = []
        for row in group:
            try:
                latencies.append(float(row["latency_ms"]))
            except (TypeError, ValueError):
                pass

        reset_equivalent = is_reset_equivalent(payload_hex)
        state_changed_count = sum(1 for row in group if row["state_changed"] == "True")
        target_state_reached_count = sum(1 for row in group if row["target_state_reached"] == "True")
        non_trivial_count = sum(1 for row in group if row_has_non_trivial_state_effect(row, reset_equivalent))
        state_changed_rate = 0.0 if trials == 0 else state_changed_count / trials
        target_state_reached_rate = 0.0 if trials == 0 else target_state_reached_count / trials
        non_trivial_rate = 0.0 if trials == 0 else non_trivial_count / trials

        summary_rows.append({
            "source_file": source_file,
            "payload_source": payload_source,
            "payload_label": payload_label,
            "setter_method_id": setter_method_id,
            "getter_method_id": getter_method_id,
            "payload_hex": payload_hex,
            "expected_after_payload_hex": expected_after_payload_hex,
            "reset_equivalent": bool_string(reset_equivalent),
            "trials": trials,
            "normal_response_count": sum(1 for row in group if row["setter_verdict"] == "normal_response"),
            "state_changed_count": state_changed_count,
            "state_changed_rate": "{:.6f}".format(state_changed_rate),
            "target_state_reached_count": target_state_reached_count,
            "target_state_reached_rate": "{:.6f}".format(target_state_reached_rate),
            "non_trivial_state_effect_count": non_trivial_count,
            "non_trivial_state_effect_rate": "{:.6f}".format(non_trivial_rate),
            "reproducible_state_changed": bool_string(state_changed_count == trials and trials > 0),
            "classification": classify_candidate(reset_equivalent, target_state_reached_count, non_trivial_count, trials),
            "before_payload_distribution": format_distribution(row["before_payload_hex"] for row in group),
            "after_payload_distribution": format_distribution(row["after_payload_hex"] for row in group),
            "avg_latency_ms": "" if not latencies else "{:.3f}".format(sum(latencies) / len(latencies)),
        })
    return summary_rows


def summarize_grouped(summary_rows):
    grouped = defaultdict(list)
    for row in summary_rows:
        grouped[(row["payload_source"], row["setter_method_id"])].append(row)

    grouped_rows = []
    for (payload_source, setter_method_id), group in sorted(grouped.items()):
        total_trials = sum(int(row["trials"]) for row in group)
        target_count = sum(int(row["target_state_reached_count"]) for row in group)
        non_trivial_count = sum(int(row["non_trivial_state_effect_count"]) for row in group)
        grouped_rows.append({
            "payload_source": payload_source,
            "setter_method_id": setter_method_id,
            "total_candidates": len(group),
            "total_trials": total_trials,
            "setter_normal_count": sum(int(row["normal_response_count"]) for row in group),
            "state_changed_count": sum(int(row["state_changed_count"]) for row in group),
            "target_state_reached_count": target_count,
            "non_trivial_state_effect_count": non_trivial_count,
            "target_state_reached_rate": "{:.6f}".format(0.0 if total_trials == 0 else target_count / total_trials),
            "non_trivial_state_effect_rate": "{:.6f}".format(0.0 if total_trials == 0 else non_trivial_count / total_trials),
            "classification_counts": format_distribution(row["classification"] for row in group),
        })
    return grouped_rows


def high_value_rows(summary_rows):
    rows = []
    for row in summary_rows:
        if row["reset_equivalent"] == "True":
            continue
        if int(row["non_trivial_state_effect_count"]) <= 0:
            continue
        rows.append({key: row[key] for key in HIGH_VALUE_HEADER})
    return rows


def print_grouped_summary(grouped_rows):
    print(",".join(GROUPED_HEADER))
    for row in grouped_rows:
        print(",".join(str(row[key]) for key in GROUPED_HEADER))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("detail_csv", help="Existing replay_candidates_state_effect detail CSV")
    parser.add_argument("--summary-out", default="")
    parser.add_argument("--grouped-out", default="")
    parser.add_argument("--high-value-out", default="")
    parser.add_argument("--trivial-out", default="")
    args = parser.parse_args()

    paths = output_paths(args.detail_csv)
    summary_out = args.summary_out or paths["summary"]
    grouped_out = args.grouped_out or paths["grouped"]
    high_value_out = args.high_value_out or paths["high_value"]
    trivial_out = args.trivial_out or paths["trivial"]

    rows = read_rows(args.detail_csv)
    summary_rows = summarize_by_candidate(rows)
    grouped_rows = summarize_grouped(summary_rows)
    high_rows = high_value_rows(summary_rows)
    trivial_rows = [row for row in summary_rows if row["classification"] == "trivial_reset_equivalent"]

    write_csv(summary_out, SUMMARY_HEADER, summary_rows)
    write_csv(grouped_out, GROUPED_HEADER, grouped_rows)
    write_csv(high_value_out, HIGH_VALUE_HEADER, high_rows)
    write_csv(trivial_out, SUMMARY_HEADER, trivial_rows)

    print_grouped_summary(grouped_rows)
    print("high_value_nontrivial_count={}".format(len(high_rows)))


if __name__ == "__main__":
    main()
