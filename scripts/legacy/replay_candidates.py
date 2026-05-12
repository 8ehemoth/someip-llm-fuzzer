#!/usr/bin/env python3
"""
Replay extracted SOME/IP payload candidates and record black-box outcomes.

Packet construction and response parsing are reused from
replay_method_10_12_with_payload.py. This script only handles candidate loading,
repeat scheduling, CSV logging, and summary statistics.
"""

import argparse
import csv
import json
import math
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


CSV_HEADER = [
    "timestamp",
    "candidate_index",
    "trial_index",
    "method_id",
    "payload_hex",
    "payload_len",
    "response_received",
    "msg_type",
    "retcode",
    "verdict",
    "latency_ms",
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
            method_id = parse_method_id(obj["method_id"])
            payload_hex = normalize_hex(obj["payload_hex"])
            payload = bytes.fromhex(payload_hex)
            candidates.append({
                "source_line": line_no,
                "method_id": method_id,
                "payload_hex": payload_hex,
                "payload": payload,
            })
    return candidates


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def judge(parsed, response_received):
    if not response_received:
        return "no_response_timeout"
    if parsed is None:
        return "malformed_response"
    if getattr(parsed, "retcode", None) != 0:
        return "error_response"
    return "normal_response"


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


def udp_socket_roundtrip(packet, timeout_sec):
    udp_payload = bytes(packet[UDP].payload)
    response_data = None

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout_sec)
        sock.bind((CLIENT_IP, CLIENT_PORT))
        sock.sendto(udp_payload, (SERVER_IP, SERVER_PORT))
        try:
            response_data, _ = sock.recvfrom(65535)
        except socket.timeout:
            return None

    if response_data is None:
        return None
    return IP(src=SERVER_IP, dst=CLIENT_IP) / UDP(sport=SERVER_PORT, dport=CLIENT_PORT) / Raw(response_data)


def replay_once(candidate, candidate_index, trial_index, session_id, timeout_sec):
    packet = build_packet(candidate["method_id"], session_id, candidate["payload"])
    started = time.time()
    timestamp = now_str()
    error = ""
    response_received = False
    parsed = None
    latency_ms = None

    try:
        response = udp_socket_roundtrip(packet, timeout_sec)
        latency_ms = (time.time() - started) * 1000.0
        if response is not None:
            response_received = True
            parsed = parse_response(response)
    except Exception as exc:
        latency_ms = (time.time() - started) * 1000.0
        error = str(exc)

    verdict = judge(parsed, response_received)
    msg_type = ""
    retcode = ""
    if parsed is not None:
        msg_type = "0x{:02x}".format(parsed.msg_type)
        retcode = "0x{:02x}".format(parsed.retcode)

    return {
        "timestamp": timestamp,
        "candidate_index": candidate_index,
        "trial_index": trial_index,
        "method_id": candidate["method_id"],
        "payload_hex": candidate["payload_hex"],
        "payload_len": len(candidate["payload"]),
        "response_received": response_received,
        "msg_type": msg_type,
        "retcode": retcode,
        "verdict": verdict,
        "latency_ms": "" if latency_ms is None else "{:.3f}".format(latency_ms),
        "error": error,
    }


def write_rows(path, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def summarize(rows):
    verdicts = Counter(row["verdict"] for row in rows)
    latencies = []
    for row in rows:
        value = str(row.get("latency_ms", "")).strip()
        if value:
            latencies.append(float(value))

    avg_latency = sum(latencies) / len(latencies) if latencies else None
    max_latency = max(latencies) if latencies else None
    p95_latency = percentile(latencies, 95) if latencies else None

    return {
        "total_trials": len(rows),
        "normal_response_count": verdicts.get("normal_response", 0),
        "error_response_count": verdicts.get("error_response", 0),
        "timeout_count": verdicts.get("no_response_timeout", 0),
        "malformed_response_count": verdicts.get("malformed_response", 0),
        "avg_latency_ms": None if avg_latency is None else round(avg_latency, 3),
        "max_latency_ms": None if max_latency is None else round(max_latency, 3),
        "p95_latency_ms": None if p95_latency is None else round(p95_latency, 3),
    }


def print_summary(summary):
    print("summary")
    for key in [
        "total_trials",
        "normal_response_count",
        "error_response_count",
        "timeout_count",
        "malformed_response_count",
        "avg_latency_ms",
        "max_latency_ms",
        "p95_latency_ms",
    ]:
        print("{}={}".format(key, summary[key]))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Replay SOME/IP payload candidates and write per-trial CSV results."
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
    session_id = 0x4000

    for candidate_index, candidate in enumerate(candidates, start=1):
        for trial_index in range(1, args.repeat + 1):
            row = replay_once(
                candidate,
                candidate_index,
                trial_index,
                session_id,
                args.timeout,
            )
            rows.append(row)
            session_id = (session_id + 1) & 0xFFFF
            if session_id == 0:
                session_id = 1

    write_rows(args.out, rows)
    print("wrote: {}".format(args.out))
    print_summary(summarize(rows))


if __name__ == "__main__":
    main()
