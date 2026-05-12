#!/usr/bin/env python3
"""Check whether replay candidate setter payloads change observable server state."""

import argparse
import csv
import json
import os
import socket
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scapy.all import IP, UDP, Raw  # noqa: E402
from someip_transport import (  # noqa: E402
    CLIENT_IP,
    CLIENT_PORT,
    SERVER_IP,
    SERVER_PORT,
    build_packet,
    parse_response,
)


METHOD_CONFIG = {
    10: {
        "getter_method_id": 9,
        "reset_payload_arg": "reset_payload_method10",
    },
    12: {
        "getter_method_id": 11,
        "reset_payload_arg": "reset_payload_method12",
    },
    14: {
        "getter_method_id": 8,
        "reset_payload_arg": "reset_payload_method14",
    },
}
CSV_HEADER = [
    "candidate_index",
    "trial_index",
    "source_file",
    "payload_source",
    "payload_label",
    "setter_method_id",
    "getter_method_id",
    "setter_payload_hex",
    "expected_after_payload_hex",
    "reset_payload_hex",
    "reset_retcode",
    "reset_verdict",
    "reset_after_retcode",
    "reset_after_payload_hex",
    "before_retcode",
    "before_payload_hex",
    "setter_retcode",
    "setter_verdict",
    "after_retcode",
    "after_payload_hex",
    "state_changed",
    "target_state_reached",
    "reset_equivalent",
    "non_trivial_state_effect",
    "classification",
    "latency_ms",
    "error",
]
SUMMARY_HEADER = [
    "source_file",
    "payload_source",
    "payload_label",
    "setter_method_id",
    "getter_method_id",
    "payload_hex",
    "expected_after_payload_hex",
    "trials",
    "normal_response_count",
    "state_changed_count",
    "state_changed_rate",
    "target_state_reached_count",
    "target_state_reached_rate",
    "reset_equivalent_count",
    "reset_equivalent_rate",
    "non_trivial_state_effect_count",
    "non_trivial_state_effect_rate",
    "reproducible_state_changed",
    "reproducible_non_trivial_state_effect",
    "classification",
    "before_payload_distribution",
    "after_payload_distribution",
    "avg_latency_ms",
]
SELECTED_CANDIDATE_HEADER = [
    "candidate_index",
    "setter_method_id",
    "getter_method_id",
    "payload_hex",
]


def now_str():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


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


def first_present(row, names, default=""):
    for name in names:
        if name in row:
            value = row.get(name)
            if value is not None and str(value).strip() != "":
                return str(value).strip()
    return default


def candidate_from_obj(obj, source_index):
    method_text = first_present(obj, ["req_method_id", "method_id", "setter_method_id"])
    payload_hex = normalize_hex(first_present(obj, ["req_payload_hex", "payload_hex", "setter_payload_hex"]))
    try:
        method_id = parse_method_id(method_text)
    except ValueError:
        return None
    if method_id not in METHOD_CONFIG:
        return None
    if payload_hex == "":
        return None
    expected_after_payload_hex = normalize_hex(
        first_present(obj, ["expected_after_payload_hex", "expected_after_hex"], "")
    )
    return {
        "source_line": source_index,
        "source_file": first_present(obj, ["source_file", "file"], ""),
        "payload_source": first_present(obj, ["payload_source"], ""),
        "payload_label": first_present(obj, ["payload_label"], ""),
        "method_id": method_id,
        "getter_method_id": METHOD_CONFIG[method_id]["getter_method_id"],
        "payload_hex": payload_hex,
        "payload": bytes.fromhex(payload_hex),
        "expected_after_payload_hex": expected_after_payload_hex,
    }


def load_jsonl_candidates(path):
    candidates = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            candidate = candidate_from_obj(obj, line_no)
            if candidate is not None:
                candidates.append(candidate)
    return dedupe_candidates(candidates)


def load_csv_candidates(path):
    candidates = []
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row_index, row in enumerate(reader, start=1):
            candidate = candidate_from_obj(row, row_index)
            if candidate is not None:
                candidates.append(candidate)
    return dedupe_candidates(candidates)


def dedupe_candidates(candidates):
    deduped = []
    seen = set()
    for candidate in candidates:
        key = (candidate["method_id"], candidate["payload_hex"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def load_candidates(path):
    if path.lower().endswith(".csv"):
        return load_csv_candidates(path)
    return load_jsonl_candidates(path)


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
            or candidate.get("expected_after_payload_hex", "")
            or default_expected
            or candidate["payload_hex"]
        )
    return candidates


def assign_candidate_indexes(candidates):
    for index, candidate in enumerate(candidates, start=1):
        candidate["candidate_index"] = index
    return candidates


def parse_csv_int_set(value):
    result = set()
    for part in str(value or "").split(","):
        part = part.strip()
        if not part:
            continue
        result.add(int(part, 0))
    return result


def parse_csv_hex_set(value):
    result = set()
    for part in str(value or "").split(","):
        part = normalize_hex(part)
        if part:
            result.add(part)
    return result


def reset_payload_options(args):
    if not args.reset_before:
        return {}
    return {
        method_id: normalize_hex(getattr(args, config["reset_payload_arg"]))
        for method_id, config in METHOD_CONFIG.items()
    }


def load_state_changed_keys(path):
    keys = set()
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if str(row.get("state_changed", "")).strip() != "True":
                continue
            try:
                setter_method_id = parse_method_id(row.get("setter_method_id", ""))
            except ValueError:
                continue
            payload_hex = normalize_hex(row.get("setter_payload_hex", ""))
            if payload_hex:
                keys.add((setter_method_id, payload_hex))
    return keys


def filter_candidates(candidates, candidate_indexes, payload_hexes, state_changed_keys):
    filtered = []
    for candidate in candidates:
        include = True
        if candidate_indexes:
            include = include and candidate["candidate_index"] in candidate_indexes
        if payload_hexes:
            include = include and candidate["payload_hex"] in payload_hexes
        if state_changed_keys:
            include = include and (candidate["method_id"], candidate["payload_hex"]) in state_changed_keys
        if include:
            filtered.append(candidate)
    return filtered


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def response_payload_hex(parsed):
    if parsed is None:
        return ""
    try:
        payload = bytes(parsed.payload)
    except Exception:
        payload = b""
    return payload.hex()


def judge(parsed, response_received):
    if not response_received:
        return "no_response_timeout"
    if parsed is None:
        return "malformed_response"
    if getattr(parsed, "retcode", None) != 0:
        return "error_response"
    return "normal_response"


def udp_socket_roundtrip(packet, timeout_sec):
    udp_payload = bytes(packet[UDP].payload)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout_sec)
        sock.bind((CLIENT_IP, CLIENT_PORT))
        sock.sendto(udp_payload, (SERVER_IP, SERVER_PORT))
        try:
            response_data, _ = sock.recvfrom(65535)
        except socket.timeout:
            return None

    return IP(src=SERVER_IP, dst=CLIENT_IP) / UDP(sport=SERVER_PORT, dport=CLIENT_PORT) / Raw(response_data)


def call_someip(method_id, payload, session_id, timeout_sec):
    packet = build_packet(method_id, session_id, payload)
    started = time.time()
    response_received = False
    parsed = None
    error = ""

    try:
        response = udp_socket_roundtrip(packet, timeout_sec)
        latency_ms = (time.time() - started) * 1000.0
        if response is not None:
            response_received = True
            parsed = parse_response(response)
    except Exception as exc:
        latency_ms = (time.time() - started) * 1000.0
        error = str(exc)

    return {
        "response_received": response_received,
        "parsed": parsed,
        "retcode": "" if parsed is None else "0x{:02x}".format(parsed.retcode),
        "verdict": judge(parsed, response_received),
        "payload_hex": response_payload_hex(parsed),
        "latency_ms": "{:.3f}".format(latency_ms),
        "error": error,
    }


def next_session_id(session_id):
    session_id = (session_id + 1) & 0xFFFF
    return 1 if session_id == 0 else session_id


def run_trial(candidate, candidate_index, trial_index, session_id, timeout_sec, reset_payloads):
    getter_method_id = candidate["getter_method_id"]
    started = time.time()
    reset_payload_hex = reset_payloads.get(candidate["method_id"], "")
    reset = {
        "retcode": "",
        "verdict": "",
        "payload_hex": "",
        "error": "",
    }
    reset_after = {
        "retcode": "",
        "verdict": "",
        "payload_hex": "",
        "error": "",
    }
    reset_failed = False

    if reset_payload_hex:
        reset = call_someip(candidate["method_id"], bytes.fromhex(reset_payload_hex), session_id, timeout_sec)
        session_id = next_session_id(session_id)
        reset_after = call_someip(getter_method_id, b"", session_id, timeout_sec)
        session_id = next_session_id(session_id)
        reset_failed = reset["verdict"] != "normal_response" or reset_after["verdict"] != "normal_response"

    before = call_someip(getter_method_id, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)

    setter = call_someip(candidate["method_id"], candidate["payload"], session_id, timeout_sec)
    session_id = next_session_id(session_id)

    after = call_someip(getter_method_id, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)
    latency_ms = (time.time() - started) * 1000.0

    error_parts = [x["error"] for x in (reset, reset_after, before, setter, after) if x["error"]]
    if reset_failed:
        error_parts.append("reset_failed")
    getter_ok = before["verdict"] != "no_response_timeout" and after["verdict"] != "no_response_timeout"
    getter_ok = getter_ok and before["verdict"] != "malformed_response" and after["verdict"] != "malformed_response"

    if getter_ok:
        state_changed = str(before["payload_hex"] != after["payload_hex"])
    else:
        state_changed = "unknown"
    target_state_reached = str(after["payload_hex"] == candidate["expected_after_payload_hex"])
    reset_equivalent = str(
        bool(reset_payload_hex)
        and reset_after["verdict"] == "normal_response"
        and after["verdict"] == "normal_response"
        and after["payload_hex"] == reset_after["payload_hex"]
    )
    non_trivial_state_effect = str(state_changed == "True" and reset_equivalent != "True")
    if reset_failed:
        state_changed = "unknown"
        target_state_reached = "False"
        reset_equivalent = "unknown"
        non_trivial_state_effect = "unknown"

    row = {
        "candidate_index": candidate_index,
        "trial_index": trial_index,
        "source_file": candidate["source_file"],
        "payload_source": candidate["payload_source"],
        "payload_label": candidate["payload_label"],
        "setter_method_id": candidate["method_id"],
        "getter_method_id": getter_method_id,
        "setter_payload_hex": candidate["payload_hex"],
        "expected_after_payload_hex": candidate["expected_after_payload_hex"],
        "reset_payload_hex": reset_payload_hex,
        "reset_retcode": reset["retcode"],
        "reset_verdict": reset["verdict"],
        "reset_after_retcode": reset_after["retcode"],
        "reset_after_payload_hex": reset_after["payload_hex"],
        "before_retcode": before["retcode"],
        "before_payload_hex": before["payload_hex"],
        "setter_retcode": setter["retcode"],
        "setter_verdict": setter["verdict"],
        "after_retcode": after["retcode"],
        "after_payload_hex": after["payload_hex"],
        "state_changed": state_changed,
        "target_state_reached": target_state_reached,
        "reset_equivalent": reset_equivalent,
        "non_trivial_state_effect": non_trivial_state_effect,
        "latency_ms": "{:.3f}".format(latency_ms),
        "error": "; ".join(error_parts),
    }
    row["classification"] = classify_trial(row)

    return {
        "row": row,
        "next_session_id": session_id,
    }


def write_rows(path, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_summary_rows(path, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SUMMARY_HEADER)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_selected_candidates(path, candidates):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SELECTED_CANDIDATE_HEADER)
        writer.writeheader()
        for candidate in candidates:
            writer.writerow({
                "candidate_index": candidate["candidate_index"],
                "setter_method_id": candidate["method_id"],
                "getter_method_id": candidate["getter_method_id"],
                "payload_hex": candidate["payload_hex"],
            })


def summarize(rows):
    state_counts = Counter(row["state_changed"] for row in rows)
    setter_normal = sum(1 for row in rows if row["setter_verdict"] == "normal_response")
    getter_success = sum(1 for row in rows if row["before_retcode"] == "0x00" and row["after_retcode"] == "0x00")
    return {
        "total_trials": len(rows),
        "setter_normal_count": setter_normal,
        "getter_success_count": getter_success,
        "state_changed_count": state_counts.get("True", 0),
        "state_unchanged_count": state_counts.get("False", 0),
        "reset_equivalent_count": sum(1 for row in rows if row["reset_equivalent"] == "True"),
        "non_trivial_state_effect_count": sum(1 for row in rows if row["non_trivial_state_effect"] == "True"),
        "unknown_count": state_counts.get("unknown", 0),
    }


def summarize_by_candidate(rows):
    grouped = defaultdict(list)
    for row in rows:
        key = (
            row["source_file"],
            row["payload_source"],
            row["payload_label"],
            row["setter_method_id"],
            row["getter_method_id"],
            row["setter_payload_hex"],
            row["expected_after_payload_hex"],
        )
        grouped[key].append(row)

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
        latencies = []
        for row in group:
            try:
                latencies.append(float(row["latency_ms"]))
            except ValueError:
                pass
        state_changed_count = sum(1 for row in group if row["state_changed"] == "True")
        trials = len(group)
        state_changed_rate = 0.0 if trials == 0 else state_changed_count / trials
        target_state_reached_count = sum(1 for row in group if row["target_state_reached"] == "True")
        target_state_reached_rate = 0.0 if trials == 0 else target_state_reached_count / trials
        reset_equivalent_count = sum(1 for row in group if row["reset_equivalent"] == "True")
        reset_equivalent_rate = 0.0 if trials == 0 else reset_equivalent_count / trials
        non_trivial_state_effect_count = sum(1 for row in group if row["non_trivial_state_effect"] == "True")
        non_trivial_state_effect_rate = 0.0 if trials == 0 else non_trivial_state_effect_count / trials
        summary_rows.append({
            "source_file": source_file,
            "payload_source": payload_source,
            "payload_label": payload_label,
            "setter_method_id": setter_method_id,
            "getter_method_id": getter_method_id,
            "payload_hex": payload_hex,
            "expected_after_payload_hex": expected_after_payload_hex,
            "trials": trials,
            "normal_response_count": sum(1 for row in group if row["setter_verdict"] == "normal_response"),
            "state_changed_count": state_changed_count,
            "state_changed_rate": "{:.6f}".format(state_changed_rate),
            "target_state_reached_count": target_state_reached_count,
            "target_state_reached_rate": "{:.6f}".format(target_state_reached_rate),
            "reset_equivalent_count": reset_equivalent_count,
            "reset_equivalent_rate": "{:.6f}".format(reset_equivalent_rate),
            "non_trivial_state_effect_count": non_trivial_state_effect_count,
            "non_trivial_state_effect_rate": "{:.6f}".format(non_trivial_state_effect_rate),
            "reproducible_state_changed": str(state_changed_count == trials and trials > 0),
            "reproducible_non_trivial_state_effect": str(non_trivial_state_effect_count == trials and trials > 0),
            "classification": classify_non_trivial_effect(
                non_trivial_state_effect_count,
                reset_equivalent_count,
                target_state_reached_count,
                trials,
            ),
            "before_payload_distribution": format_distribution(row["before_payload_hex"] for row in group),
            "after_payload_distribution": format_distribution(row["after_payload_hex"] for row in group),
            "avg_latency_ms": "" if not latencies else "{:.3f}".format(sum(latencies) / len(latencies)),
        })
    return summary_rows


def format_distribution(values):
    counter = Counter(values)
    return ";".join("{}={}".format(payload_hex, count) for payload_hex, count in sorted(counter.items()))


def classify_state_changer(state_changed_count, trials):
    if trials > 0 and state_changed_count == trials:
        return "reproducible_state_changer"
    if state_changed_count >= 15:
        return "unstable_state_changer"
    if 1 <= state_changed_count <= 2:
        return "flaky_candidate"
    if state_changed_count == 0:
        return "protocol_valid_no_state_change"
    return "intermittent_state_changer"


def classify_target_state_effect(state_changed_count, target_state_reached_count, trials):
    if state_changed_count >= 1 and target_state_reached_count == trials:
        return "normal_idempotent_state_setter"
    if target_state_reached_count == trials:
        return "reproducible_target_state"
    if target_state_reached_count == 0:
        return "no_state_effect"
    return "partial_or_unstable_state_effect"


def classify_trial(row):
    if row["setter_verdict"] != "normal_response":
        return "setter_not_normal"
    if row["state_changed"] == "unknown":
        return "unknown_state_effect"
    if row["reset_equivalent"] == "True":
        return "trivial_reset_equivalent"
    if row["non_trivial_state_effect"] == "True":
        if row["target_state_reached"] == "True":
            return "non_trivial_target_state_effect"
        return "non_trivial_unexpected_state_effect"
    return "no_state_effect"


def classify_non_trivial_effect(non_trivial_count, reset_equivalent_count, target_state_reached_count, trials):
    if trials > 0 and non_trivial_count == trials:
        return "reproducible_non_trivial_state_effect"
    if non_trivial_count > 0:
        return "partial_non_trivial_state_effect"
    if reset_equivalent_count > 0 and target_state_reached_count > 0:
        return "trivial_reset_equivalent"
    if target_state_reached_count > 0:
        return "target_reached_without_non_trivial_change"
    return "no_state_effect"


def print_summary(summary):
    print("summary")
    for key in [
        "total_trials",
        "setter_normal_count",
        "getter_success_count",
        "state_changed_count",
        "state_unchanged_count",
        "reset_equivalent_count",
        "non_trivial_state_effect_count",
        "unknown_count",
    ]:
        print("{}={}".format(key, summary[key]))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Check whether Method 10/12/14 replay candidates affect Getter 9/11/8 observable state."
    )
    parser.add_argument("--candidates", required=True, help="Candidate CSV or JSONL path")
    parser.add_argument("--out", default="", help="Output detail CSV path; default uses timestamp in results dir")
    parser.add_argument("--summary-out", default="", help="Output summary CSV path; default uses timestamp in results dir")
    parser.add_argument("--selected-candidates-out", default="", help="Output CSV for candidates selected by filters")
    parser.add_argument("--repeat", type=int, default=3, help="Repeat count per candidate; minimum is 3")
    parser.add_argument("--trial-count", type=int, default=None, help="Alias for --repeat")
    parser.add_argument("--timeout", type=float, default=1.0, help="Response timeout in seconds")
    parser.add_argument("--reset-before", action="store_true", help="Send a reset setter and verify getter state before each trial")
    parser.add_argument("--reset-payload-method10", default="00000000", help="Reset payload hex for Method 10")
    parser.add_argument("--reset-payload-method12", default="00000000", help="Reset payload hex for Method 12")
    parser.add_argument("--reset-payload-method14", default="02020202", help="Reset payload hex for Method 14")
    parser.add_argument("--candidate-indexes", default="", help="Comma-separated original candidate indexes to replay")
    parser.add_argument("--payload-hex", default="", help="Comma-separated setter payload hex values to replay")
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
    parser.add_argument(
        "--state-changed-from",
        default="",
        help="Detail replay CSV; replay candidates whose prior rows had state_changed=True",
    )
    return parser.parse_args()


def default_output_paths():
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    detail = os.path.join("results", "replay_candidates_state_effect_{}.csv".format(stamp))
    summary = os.path.join("results", "replay_candidates_state_effect_summary_{}.csv".format(stamp))
    selected = os.path.join("results", "state_changed_candidates_{}.csv".format(stamp))
    return detail, summary, selected


def main():
    args = parse_args()
    repeat = args.trial_count if args.trial_count is not None else args.repeat
    if repeat < 3:
        raise ValueError("--repeat must be at least 3")

    candidates = assign_candidate_indexes(load_candidates(args.candidates))
    candidates = apply_expected_after_payloads(
        candidates,
        args.expected_after_payload_hex,
        parse_expected_overrides(args.expected_after),
    )
    candidate_indexes = parse_csv_int_set(args.candidate_indexes)
    payload_hexes = parse_csv_hex_set(args.payload_hex)
    state_changed_keys = load_state_changed_keys(args.state_changed_from) if args.state_changed_from else set()
    candidates = filter_candidates(candidates, candidate_indexes, payload_hexes, state_changed_keys)

    detail_out, summary_out, selected_out = default_output_paths()
    detail_out = args.out or detail_out
    summary_out = args.summary_out or summary_out
    selected_out = args.selected_candidates_out or (selected_out if state_changed_keys else "")

    rows = []
    session_id = 0x5000
    reset_payloads = reset_payload_options(args)

    for candidate in candidates:
        for trial_index in range(1, repeat + 1):
            trial = run_trial(
                candidate,
                candidate["candidate_index"],
                trial_index,
                session_id,
                args.timeout,
                reset_payloads,
            )
            rows.append(trial["row"])
            session_id = trial["next_session_id"]

    write_rows(detail_out, rows)
    write_summary_rows(summary_out, summarize_by_candidate(rows))
    if selected_out:
        write_selected_candidates(selected_out, candidates)
    print("candidates={}".format(len(candidates)))
    print("wrote: {}".format(detail_out))
    print("wrote_summary: {}".format(summary_out))
    if selected_out:
        print("wrote_selected_candidates: {}".format(selected_out))
    print_summary(summarize(rows))


if __name__ == "__main__":
    main()
