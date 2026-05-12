#!/usr/bin/env python3
"""
Verbose state-effect check for SOME/IP replay candidates.

For each candidate, this script calls getter method 9, sends the candidate
setter payload, then calls getter method 9 again. It records both the raw UDP
payload bytes and parsed SOME/IP fields for the getter/setter responses.
"""

import argparse
import csv
import json
import os
import socket
import sys
import time
from collections import Counter
from datetime import datetime


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scapy.all import IP, UDP, Raw  # noqa: E402
from replay_method_10_12_with_payload import (  # noqa: E402
    CLIENT_IP,
    CLIENT_PORT,
    SERVER_IP,
    SERVER_PORT,
    build_packet,
    parse_response,
)


GETTER_METHOD_ID = 9
CSV_HEADER = [
    "timestamp",
    "candidate_index",
    "trial_index",
    "setter_method_id",
    "getter_method_id",
    "setter_payload_hex",
    "before_response_received",
    "before_raw_udp_payload_hex",
    "before_someip_payload_hex",
    "before_srv_id",
    "before_method_id",
    "before_client_id",
    "before_session_id",
    "before_msg_type",
    "before_retcode",
    "before_verdict",
    "before_payload_hex",
    "setter_response_received",
    "setter_raw_udp_payload_hex",
    "setter_someip_payload_hex",
    "setter_srv_id",
    "setter_method_id_rsp",
    "setter_client_id",
    "setter_session_id",
    "setter_msg_type",
    "setter_retcode",
    "setter_verdict",
    "setter_latency_ms",
    "after_response_received",
    "after_raw_udp_payload_hex",
    "after_someip_payload_hex",
    "after_srv_id",
    "after_method_id",
    "after_client_id",
    "after_session_id",
    "after_msg_type",
    "after_retcode",
    "after_verdict",
    "after_payload_hex",
    "state_changed",
    "error",
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


def load_candidates(path):
    candidates = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            payload_hex = normalize_hex(obj["payload_hex"])
            candidates.append({
                "source_line": line_no,
                "method_id": parse_method_id(obj["method_id"]),
                "payload_hex": payload_hex,
                "payload": bytes.fromhex(payload_hex),
            })
    return candidates


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def hex_field(value, width):
    if value is None or value == "":
        return ""
    return "0x{:0{}x}".format(int(value), width)


def someip_payload_hex(parsed):
    if parsed is None:
        return ""
    try:
        return bytes(parsed.payload).hex()
    except Exception:
        return ""


def parsed_fields(parsed):
    if parsed is None:
        return {
            "srv_id": "",
            "method_id": "",
            "client_id": "",
            "session_id": "",
            "msg_type": "",
            "retcode": "",
            "someip_payload_hex": "",
        }
    return {
        "srv_id": hex_field(parsed.srv_id, 4),
        "method_id": hex_field(parsed.method_id, 4),
        "client_id": hex_field(parsed.client_id, 4),
        "session_id": hex_field(parsed.session_id, 4),
        "msg_type": hex_field(parsed.msg_type, 2),
        "retcode": hex_field(parsed.retcode, 2),
        "someip_payload_hex": someip_payload_hex(parsed),
    }


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
            return None, b""

    response_packet = IP(src=SERVER_IP, dst=CLIENT_IP) / UDP(sport=SERVER_PORT, dport=CLIENT_PORT) / Raw(response_data)
    return response_packet, response_data


def call_someip(method_id, payload, session_id, timeout_sec):
    packet = build_packet(method_id, session_id, payload)
    started = time.time()
    response_received = False
    parsed = None
    raw_response = b""
    error = ""

    try:
        response, raw_response = udp_socket_roundtrip(packet, timeout_sec)
        latency_ms = (time.time() - started) * 1000.0
        if response is not None:
            response_received = True
            parsed = parse_response(response)
    except Exception as exc:
        latency_ms = (time.time() - started) * 1000.0
        error = str(exc)

    fields = parsed_fields(parsed)
    return {
        "response_received": response_received,
        "raw_udp_payload_hex": raw_response.hex(),
        "someip_payload_hex": fields["someip_payload_hex"],
        "srv_id": fields["srv_id"],
        "method_id": fields["method_id"],
        "client_id": fields["client_id"],
        "session_id": fields["session_id"],
        "msg_type": fields["msg_type"],
        "retcode": fields["retcode"],
        "verdict": judge(parsed, response_received),
        "latency_ms": "{:.3f}".format(latency_ms),
        "error": error,
    }


def next_session_id(session_id):
    session_id = (session_id + 1) & 0xFFFF
    return 1 if session_id == 0 else session_id


def getter_observable(call_result):
    return call_result["verdict"] not in {"no_response_timeout", "malformed_response"}


def run_trial(candidate, candidate_index, trial_index, session_id, timeout_sec):
    timestamp = now_str()

    before = call_someip(GETTER_METHOD_ID, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)

    setter = call_someip(candidate["method_id"], candidate["payload"], session_id, timeout_sec)
    session_id = next_session_id(session_id)

    after = call_someip(GETTER_METHOD_ID, b"", session_id, timeout_sec)
    session_id = next_session_id(session_id)

    error_parts = [x["error"] for x in (before, setter, after) if x["error"]]
    if getter_observable(before) and getter_observable(after):
        state_changed = str(before["someip_payload_hex"] != after["someip_payload_hex"])
    else:
        state_changed = "unknown"

    return {
        "row": {
            "timestamp": timestamp,
            "candidate_index": candidate_index,
            "trial_index": trial_index,
            "setter_method_id": candidate["method_id"],
            "getter_method_id": GETTER_METHOD_ID,
            "setter_payload_hex": candidate["payload_hex"],
            "before_response_received": before["response_received"],
            "before_raw_udp_payload_hex": before["raw_udp_payload_hex"],
            "before_someip_payload_hex": before["someip_payload_hex"],
            "before_srv_id": before["srv_id"],
            "before_method_id": before["method_id"],
            "before_client_id": before["client_id"],
            "before_session_id": before["session_id"],
            "before_msg_type": before["msg_type"],
            "before_retcode": before["retcode"],
            "before_verdict": before["verdict"],
            "before_payload_hex": before["someip_payload_hex"],
            "setter_response_received": setter["response_received"],
            "setter_raw_udp_payload_hex": setter["raw_udp_payload_hex"],
            "setter_someip_payload_hex": setter["someip_payload_hex"],
            "setter_srv_id": setter["srv_id"],
            "setter_method_id_rsp": setter["method_id"],
            "setter_client_id": setter["client_id"],
            "setter_session_id": setter["session_id"],
            "setter_msg_type": setter["msg_type"],
            "setter_retcode": setter["retcode"],
            "setter_verdict": setter["verdict"],
            "setter_latency_ms": setter["latency_ms"],
            "after_response_received": after["response_received"],
            "after_raw_udp_payload_hex": after["raw_udp_payload_hex"],
            "after_someip_payload_hex": after["someip_payload_hex"],
            "after_srv_id": after["srv_id"],
            "after_method_id": after["method_id"],
            "after_client_id": after["client_id"],
            "after_session_id": after["session_id"],
            "after_msg_type": after["msg_type"],
            "after_retcode": after["retcode"],
            "after_verdict": after["verdict"],
            "after_payload_hex": after["someip_payload_hex"],
            "state_changed": state_changed,
            "error": "; ".join(error_parts),
        },
        "next_session_id": session_id,
    }


def write_rows(path, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def summarize(rows):
    state_counts = Counter(row["state_changed"] for row in rows)
    setter_normal = sum(1 for row in rows if row["setter_verdict"] == "normal_response")
    getter_success = sum(
        1
        for row in rows
        if row["before_verdict"] == "normal_response" and row["after_verdict"] == "normal_response"
    )
    return {
        "total_trials": len(rows),
        "setter_normal_count": setter_normal,
        "getter_success_count": getter_success,
        "state_changed_count": state_counts.get("True", 0),
        "state_unchanged_count": state_counts.get("False", 0),
        "unknown_count": state_counts.get("unknown", 0),
        "unique_before_payloads": len({row["before_someip_payload_hex"] for row in rows}),
        "unique_after_payloads": len({row["after_someip_payload_hex"] for row in rows}),
        "unique_setter_response_payloads": len({row["setter_someip_payload_hex"] for row in rows}),
    }


def print_summary(summary):
    print("summary")
    for key in [
        "total_trials",
        "setter_normal_count",
        "getter_success_count",
        "state_changed_count",
        "state_unchanged_count",
        "unknown_count",
        "unique_before_payloads",
        "unique_after_payloads",
        "unique_setter_response_payloads",
    ]:
        print("{}={}".format(key, summary[key]))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Verbose check for whether method 10 replay candidates affect getter method 9 state."
    )
    parser.add_argument("--candidates", required=True, help="Candidate JSONL path")
    parser.add_argument("--out", required=True, help="Output CSV path")
    parser.add_argument("--repeat", type=int, required=True, help="Repeat count per candidate")
    parser.add_argument("--timeout", type=float, default=1.0, help="Response timeout in seconds")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.repeat <= 0:
        raise ValueError("--repeat must be positive")

    candidates = load_candidates(args.candidates)
    rows = []
    session_id = 0x6000

    for candidate_index, candidate in enumerate(candidates, start=1):
        for trial_index in range(1, args.repeat + 1):
            trial = run_trial(candidate, candidate_index, trial_index, session_id, args.timeout)
            rows.append(trial["row"])
            session_id = trial["next_session_id"]

    write_rows(args.out, rows)
    print("wrote: {}".format(args.out))
    print_summary(summarize(rows))


if __name__ == "__main__":
    main()
