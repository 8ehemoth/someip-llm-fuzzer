from scapy.all import *
from scapy.contrib.automotive.someip import SOMEIP
import time
import json
from datetime import datetime

load_contrib("automotive.someip")


SERVER_IP = "192.168.40.134"
CLIENT_IP = "192.168.40.135"
SERVER_PORT = 31000
CLIENT_PORT = 58423

SERVICE_ID = 0xFF40
CLIENT_ID = 0x1343
PROTO_VER = 1
IFACE_VER = 1

TARGET_METHODS = [10, 12]
DELAY_SEC = 0.5
REPEAT_PER_CASE = 3

LOG_FILE = "replay_method_10_12_focus.jsonl"


def now_str():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def build_packet(method_id: int, session_id: int, payload: bytes):
    ip = IP(src=CLIENT_IP, dst=SERVER_IP)
    udp = UDP(sport=CLIENT_PORT, dport=SERVER_PORT)

    sip = SOMEIP()
    sip.srv_id = SERVICE_ID
    sip.sub_id = 0
    sip.method_id = method_id
    sip.len = 8 + len(payload)
    sip.client_id = CLIENT_ID
    sip.session_id = session_id
    sip.proto_ver = PROTO_VER
    sip.iface_ver = IFACE_VER
    sip.msg_type = 0   # REQUEST
    sip.retcode = 0    # E_OK

    if payload:
        sip.add_payload(Raw(payload))

    return ip / udp / sip


def parse_response(pkt):
    if pkt is None or UDP not in pkt:
        return None

    try:
        udp_payload = bytes(pkt[UDP].payload)
        if len(udp_payload) == 0:
            return None
        return SOMEIP(udp_payload)
    except Exception:
        return None


def to_hex(payload: bytes):
    return payload.hex() if payload is not None else ""


def log_jsonl(obj):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def build_focus_cases():
    return [
        ("empty", b""),
        ("len4_zero", b"\x00\x00\x00\x00"),
        ("idx0_val0_u16", b"\x00\x00\x00\x00"),
        ("idx1_val50_u16", b"\x00\x01\x00\x32"),
        ("len8_zero", b"\x00" * 8),
        ("len8_inc", bytes(range(8))),
    ]


def replay_one(method_id: int, session_id: int, case_name: str, payload: bytes, repeat_idx: int):
    pkt = build_packet(method_id, session_id, payload)

    send_wall = now_str()
    send_ts = time.time()

    print(
        "[{}] SEND case='{}' repeat={} method=0x{:04x} session=0x{:04x} payload_len={} payload_hex={}".format(
            send_wall,
            case_name,
            repeat_idx,
            method_id,
            session_id,
            len(payload),
            to_hex(payload),
        )
    )

    res = sr1(pkt, retry=0, timeout=1, verbose=False)
    latency_ms = (time.time() - send_ts) * 1000.0

    result = {
        "ts": send_wall,
        "case": case_name,
        "repeat_idx": repeat_idx,
        "method_id": method_id,
        "session_id": session_id,
        "payload_len": len(payload),
        "payload_hex": to_hex(payload),
        "latency_ms": round(latency_ms, 3),
    }

    if res is None:
        result["response"] = None
        log_jsonl(result)

        print(
            "[{}] NORESP case='{}' repeat={} method=0x{:04x} session=0x{:04x} latency_ms={:.2f}".format(
                now_str(),
                case_name,
                repeat_idx,
                method_id,
                session_id,
                latency_ms,
            )
        )
        return

    parsed = parse_response(res)
    if parsed is None:
        result["response"] = "parse_fail"
        log_jsonl(result)

        print(
            "[{}] RECV_PARSE_FAIL case='{}' repeat={} method=0x{:04x} session=0x{:04x} latency_ms={:.2f}".format(
                now_str(),
                case_name,
                repeat_idx,
                method_id,
                session_id,
                latency_ms,
            )
        )
        return

    result["response"] = {
        "rsp_method_id": parsed.method_id,
        "rsp_session_id": parsed.session_id,
        "rsp_client_id": parsed.client_id,
        "msg_type": parsed.msg_type,
        "retcode": parsed.retcode,
    }
    log_jsonl(result)

    print(
        "[{}] RECV case='{}' repeat={} req_method=0x{:04x} req_session=0x{:04x} -> rsp_method=0x{:04x} rsp_session=0x{:04x} msg_type=0x{:02x} retcode=0x{:02x} latency_ms={:.2f}".format(
            now_str(),
            case_name,
            repeat_idx,
            method_id,
            session_id,
            parsed.method_id,
            parsed.session_id,
            parsed.msg_type,
            parsed.retcode,
            latency_ms,
        )
    )


def main():
    cases = build_focus_cases()

    print("=== replay_method_10_12_focus start ===")
    print("methods         :", TARGET_METHODS)
    print("repeat_per_case :", REPEAT_PER_CASE)
    print("delay(sec)      :", DELAY_SEC)
    print("server          : {}:{}".format(SERVER_IP, SERVER_PORT))
    print("client          : {}:{} client_id=0x{:04x}".format(CLIENT_IP, CLIENT_PORT, CLIENT_ID))
    print("log_file        :", LOG_FILE)
    print()

    session_id = 0x3000

    for method_id in TARGET_METHODS:
        print("=== method_id={} (0x{:04x}) ===".format(method_id, method_id))
        for case_name, payload in cases:
            print("--- case='{}' payload_len={} ---".format(case_name, len(payload)))
            for repeat_idx in range(1, REPEAT_PER_CASE + 1):
                replay_one(method_id, session_id, case_name, payload, repeat_idx)
                session_id = (session_id + 1) & 0xFFFF
                if session_id == 0:
                    session_id = 1
                time.sleep(DELAY_SEC)
            print()
        print()

    print("=== replay_method_10_12_focus end ===")


if __name__ == "__main__":
    main()
