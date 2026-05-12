#!/usr/bin/env python3
"""Design scaffold for probing only SOME/IP IDs defined by test-someip-service.

This script intentionally does not send network traffic yet. It documents the
allowed probe set and prints the planned request probes. Actual execution should
be added/enabled only after explicit user confirmation.
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


DEFINED_METHODS = [
    {
        "method_id": 1,
        "name": "getConsumptionAttribute",
        "role": "getter",
        "payload_hex": "",
        "paired_getter": None,
        "state_probe": False,
        "notes": "Empty-payload getter probe.",
    },
    {
        "method_id": 2,
        "name": "getCapacityAttribute",
        "role": "getter",
        "payload_hex": "",
        "paired_getter": None,
        "state_probe": False,
        "notes": "Empty-payload getter probe.",
    },
    {
        "method_id": 3,
        "name": "getVolumeAttribute",
        "role": "getter",
        "payload_hex": "",
        "paired_getter": None,
        "state_probe": False,
        "notes": "Empty-payload getter probe.",
    },
    {
        "method_id": 4,
        "name": "getEngineSpeedAttribute",
        "role": "getter",
        "payload_hex": "",
        "paired_getter": None,
        "state_probe": False,
        "notes": "Empty-payload getter probe.",
    },
    {
        "method_id": 5,
        "name": "getCurrentGearAttribute",
        "role": "getter",
        "payload_hex": "",
        "paired_getter": None,
        "state_probe": False,
        "notes": "Empty-payload getter probe.",
    },
    {
        "method_id": 6,
        "name": "getIsReverseGearOnAttribute",
        "role": "getter",
        "payload_hex": "",
        "paired_getter": None,
        "state_probe": False,
        "notes": "Empty-payload getter probe.",
    },
    {
        "method_id": 7,
        "name": "getDrivePowerTransmissionAttribute",
        "role": "getter",
        "payload_hex": "",
        "paired_getter": None,
        "state_probe": False,
        "notes": "Empty-payload getter probe.",
    },
    {
        "method_id": 8,
        "name": "getDoorsOpeningStatusAttribute",
        "role": "getter",
        "payload_hex": "",
        "paired_getter": None,
        "state_probe": False,
        "notes": "Empty-payload getter probe; paired observable getter for Method 14.",
    },
    {
        "method_id": 9,
        "name": "getSeatHeatingStatusAttribute",
        "role": "getter",
        "payload_hex": "",
        "paired_getter": None,
        "state_probe": False,
        "notes": "Empty-payload getter probe; paired observable getter for Method 10.",
    },
    {
        "method_id": 10,
        "name": "setSeatHeatingStatusAttribute",
        "role": "setter",
        "payload_hex": "0000000701000100010001",
        "reset_payload_hex": "00000000",
        "paired_getter": 9,
        "state_probe": True,
        "notes": "Use Getter 9 before/after. Baseline validation already completed.",
    },
    {
        "method_id": 11,
        "name": "getSeatHeatingLevelAttribute",
        "role": "getter",
        "payload_hex": "",
        "paired_getter": None,
        "state_probe": False,
        "notes": "Empty-payload getter probe; paired observable getter for Method 12.",
    },
    {
        "method_id": 12,
        "name": "setSeatHeatingLevelAttribute",
        "role": "setter",
        "payload_hex": "00000007b40000640000000000000000",
        "reset_payload_hex": "00000000",
        "paired_getter": 11,
        "state_probe": True,
        "notes": "Use Getter 11 before/after. Baseline validation already completed.",
    },
    {
        "method_id": 13,
        "name": "initTirePressureCalibration",
        "role": "method",
        "payload_hex": "",
        "paired_getter": None,
        "state_probe": False,
        "notes": "Response-only probe first; no clear paired getter identified.",
    },
    {
        "method_id": 14,
        "name": "changeDoorsState",
        "role": "method",
        "payload_hex": "01010101",
        "reset_payload_hex": "02020202",
        "paired_getter": 8,
        "state_probe": True,
        "notes": "Use Getter 8 before/after; reset with all-doors-close payload.",
    },
]

EXCLUDED_EVENTS = [
    (32769, "0x8001", "consumption notifier"),
    (32770, "0x8002", "engineSpeed notifier"),
    (32771, "0x8003", "currentGear notifier"),
    (32772, "0x8004", "isReverseGearOn notifier"),
    (32773, "0x8005", "drivePowerTransmission notifier"),
    (32774, "0x8006", "doorsOpeningStatus notifier"),
    (32775, "0x8007", "seatHeatingStatus notifier"),
    (32776, "0x8008", "seatHeatingLevel notifier"),
    (32777, "0x8009", "vehiclePosition event"),
    (32778, "0x800a", "currentTankVolume event"),
]

GETTER_PROBE_METHOD_IDS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 11]
METHOD13_PROBE_METHOD_ID = 13
ALL_DEFINED_ONCE_PROBES = [
    (1, ""),
    (2, ""),
    (3, ""),
    (4, ""),
    (5, ""),
    (6, ""),
    (7, ""),
    (8, ""),
    (9, ""),
    (10, "0000000701000100010001"),
    (11, ""),
    (12, "0000000701020300010203"),
    (13, ""),
    (14, "01010101"),
]
EXECUTION_CSV_HEADER = [
    "timestamp",
    "probe_name",
    "method_id",
    "hex_method_id",
    "method_name",
    "payload_hex",
    "payload_len",
    "response_received",
    "msg_type",
    "retcode",
    "verdict",
    "latency_ms",
    "response_payload_hex",
    "error",
]
ALL_DEFINED_ONCE_CSV_HEADER = [
    "timestamp",
    "sequence_index",
    "method_id",
    "hex_method_id",
    "method_name",
    "role",
    "payload_hex",
    "payload_len",
    "response_received",
    "msg_type",
    "retcode",
    "verdict",
    "latency_ms",
    "response_payload_hex",
    "error",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Print the planned probe set for SOME/IP IDs defined by test-someip-service."
    )
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table")
    parser.add_argument("--out", default="", help="Optional output path for csv/json plan.")
    parser.add_argument("--timeout", type=float, default=1.0, help="Response timeout in seconds for execute modes.")
    parser.add_argument("--start-session-id", type=lambda value: int(value, 0), default=0x7000)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Reserved for future use. Currently refuses to send traffic.",
    )
    parser.add_argument(
        "--execute-getters",
        action="store_true",
        help="Probe only getter methods 1,2,3,4,5,6,7,8,9,11 with empty payloads.",
    )
    parser.add_argument(
        "--execute-method13",
        action="store_true",
        help="Probe only method 13 with an empty payload.",
    )
    parser.add_argument(
        "--execute-all-defined-once",
        action="store_true",
        help="Probe source-defined request method IDs 1..14 once with fixed baseline payloads.",
    )
    return parser.parse_args()


def hex_method_id(method_id):
    return "0x{:04x}".format(method_id)


def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def now_str():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def method_by_id(method_id):
    for item in DEFINED_METHODS:
        if item["method_id"] == method_id:
            return item
    raise ValueError("undefined method_id={}".format(method_id))


def plan_rows():
    rows = []
    for item in DEFINED_METHODS:
        rows.append({
            "method_id": item["method_id"],
            "hex_method_id": hex_method_id(item["method_id"]),
            "method_name": item["name"],
            "role": item["role"],
            "payload_hex": item.get("payload_hex", ""),
            "reset_payload_hex": item.get("reset_payload_hex", ""),
            "paired_getter": "" if item.get("paired_getter") is None else item["paired_getter"],
            "state_probe": str(item["state_probe"]),
            "notes": item["notes"],
        })
    return rows


def write_plan(rows, fmt, out_path):
    if fmt == "json":
        data = {
            "probe_targets": rows,
            "excluded_events": [
                {"method_id": method_id, "hex_method_id": hex_id, "name": name}
                for method_id, hex_id, name in EXCLUDED_EVENTS
            ],
        }
        text = json.dumps(data, indent=2)
        if out_path:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        else:
            print(text)
        return

    fieldnames = [
        "method_id",
        "hex_method_id",
        "method_name",
        "role",
        "payload_hex",
        "reset_payload_hex",
        "paired_getter",
        "state_probe",
        "notes",
    ]
    if fmt == "csv":
        if out_path:
            parent = os.path.dirname(out_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
        else:
            writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        return

    print("Defined request probe targets:")
    for row in rows:
        print(
            "{hex_method_id} {role:<6} {method_name:<38} payload={payload_hex} "
            "paired_getter={paired_getter} state_probe={state_probe}".format(**row)
        )
    print()
    print("Excluded event/notifier IDs:")
    for _, hex_id, name in EXCLUDED_EVENTS:
        print("{} {}".format(hex_id, name))


def response_msg_type(result):
    parsed = result.get("parsed")
    if parsed is None:
        return ""
    return "0x{:02x}".format(parsed.msg_type)


def execution_row(probe_name, method, result):
    return {
        "timestamp": now_str(),
        "probe_name": probe_name,
        "method_id": method["method_id"],
        "hex_method_id": hex_method_id(method["method_id"]),
        "method_name": method["name"],
        "payload_hex": "",
        "payload_len": 0,
        "response_received": result["response_received"],
        "msg_type": response_msg_type(result),
        "retcode": result["retcode"],
        "verdict": result["verdict"],
        "latency_ms": result["latency_ms"],
        "response_payload_hex": result["payload_hex"],
        "error": result["error"],
    }


def default_execution_out_path(kind):
    return os.path.join("results", "{}_{}.csv".format(kind, timestamp()))


def write_execution_rows(path, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EXECUTION_CSV_HEADER)
        writer.writeheader()
        writer.writerows(rows)


def write_all_defined_once_rows(path, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ALL_DEFINED_ONCE_CSV_HEADER)
        writer.writeheader()
        writer.writerows(rows)


def run_empty_payload_probes(method_ids, probe_name, out_path, timeout_sec, start_session_id):
    from check_candidate_state_effect import call_someip, next_session_id  # noqa: WPS433

    if any(method_id >= 0x8000 for method_id in method_ids):
        raise ValueError("event/notifier IDs must not be request-probed")
    rows = []
    session_id = start_session_id
    for method_id in method_ids:
        method = method_by_id(method_id)
        if method.get("payload_hex", "") != "":
            raise ValueError("refusing non-empty planned payload for method_id={}".format(method_id))
        result = call_someip(method_id, b"", session_id, timeout_sec)
        rows.append(execution_row(probe_name, method, result))
        session_id = next_session_id(session_id)
    write_execution_rows(out_path, rows)
    print("wrote {}".format(out_path))
    return rows


def execute_getters(args):
    out_path = args.out or default_execution_out_path("all_method_getter_probe")
    return run_empty_payload_probes(
        GETTER_PROBE_METHOD_IDS,
        "execute_getters",
        out_path,
        args.timeout,
        args.start_session_id,
    )


def execute_method13(args):
    out_path = args.out or default_execution_out_path("method13_probe")
    return run_empty_payload_probes(
        [METHOD13_PROBE_METHOD_ID],
        "execute_method13",
        out_path,
        args.timeout,
        args.start_session_id,
    )


def all_defined_once_row(sequence_index, method, payload_hex, result):
    return {
        "timestamp": now_str(),
        "sequence_index": sequence_index,
        "method_id": method["method_id"],
        "hex_method_id": hex_method_id(method["method_id"]),
        "method_name": method["name"],
        "role": method["role"],
        "payload_hex": payload_hex,
        "payload_len": len(bytes.fromhex(payload_hex)),
        "response_received": result["response_received"],
        "msg_type": response_msg_type(result),
        "retcode": result["retcode"],
        "verdict": result["verdict"],
        "latency_ms": result["latency_ms"],
        "response_payload_hex": result["payload_hex"],
        "error": result["error"],
    }


def execute_all_defined_once(args):
    from check_candidate_state_effect import call_someip, next_session_id  # noqa: WPS433

    method_ids = [method_id for method_id, _ in ALL_DEFINED_ONCE_PROBES]
    if method_ids != list(range(1, 15)):
        raise ValueError("all-defined once probe must cover method IDs 1..14 in order")
    if any(method_id >= 0x8000 for method_id in method_ids):
        raise ValueError("event/notifier IDs must not be request-probed")

    rows = []
    session_id = args.start_session_id
    for sequence_index, (method_id, payload_hex) in enumerate(ALL_DEFINED_ONCE_PROBES, start=1):
        method = method_by_id(method_id)
        payload = bytes.fromhex(payload_hex)
        result = call_someip(method_id, payload, session_id, args.timeout)
        rows.append(all_defined_once_row(sequence_index, method, payload_hex, result))
        session_id = next_session_id(session_id)

    out_path = args.out or default_execution_out_path("all_defined_methods_once")
    write_all_defined_once_rows(out_path, rows)
    print("wrote {}".format(out_path))
    return rows


def main():
    args = parse_args()
    execute_mode_count = int(args.execute_getters) + int(args.execute_method13) + int(args.execute_all_defined_once)
    if execute_mode_count > 1:
        raise SystemExit("Choose only one execute mode at a time.")
    if args.execute:
        raise SystemExit(
            "--execute is intentionally disabled. This design scaffold must not send probes "
            "directly. Use --execute-getters or --execute-method13 for the approved safe probes."
        )
    if args.execute_getters:
        execute_getters(args)
        return
    if args.execute_method13:
        execute_method13(args)
        return
    if args.execute_all_defined_once:
        execute_all_defined_once(args)
        return
    write_plan(plan_rows(), args.format, args.out)


if __name__ == "__main__":
    main()
