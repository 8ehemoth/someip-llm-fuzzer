from scapy.all import IP, UDP, load_contrib, sr1
import threading
import time

from someip_fuzzer.config import config
from someip_fuzzer.log import log_info
from someip_fuzzer.types import NoHeartbeatError, NoSudoError

load_contrib("automotive.someip")
from scapy.contrib.automotive.someip import SOMEIP


class Heartbeat(threading.Thread):
    def __init__(self, excq):
        super().__init__()
        self.excq = excq
        self.shutdown = threading.Event()

        self.service_id = 0xFF40
        self.method_id = config["Heartbeat"].getint("MethodId", fallback=1)
        self.client_id = config["Heartbeat"].getint("ClientId", fallback=0x1343)
        self.session_id = 0x0001
        self.proto_ver = 1
        self.iface_ver = 1

        self.interval = config["Run"].getfloat("HeartbeatIntervalSec", fallback=3.0)
        self.fail_threshold = config["Run"].getint("HeartbeatFailThreshold", fallback=3)
        self.timeout_sec = config["Run"].getfloat("HeartbeatTimeoutSec", fallback=3.0)

        self.consecutive_fail = 0

    def run(self):
        log_info("Heartbeat is started")

        while not self.shutdown.is_set():
            try:
                time.sleep(self.interval)
                ok = self.check()

                if ok:
                    if self.consecutive_fail > 0:
                        log_info("Heartbeat recovered")
                    self.consecutive_fail = 0
                else:
                    self.consecutive_fail += 1
                    log_info("Heartbeat fail count={}".format(self.consecutive_fail))

                    if self.consecutive_fail >= self.fail_threshold:
                        self.excq.put(
                            NoHeartbeatError(
                                "Heartbeat lost consecutively ({} fails)".format(
                                    self.consecutive_fail
                                )
                            )
                        )
                        break

            except PermissionError:
                self.excq.put(
                    NoSudoError("Permission as sudo required to send SOME/IP packets")
                )
                break

        log_info("Heartbeat is stopped")

    def _build_packet(self):
        ip = IP(
            src=config["Heartbeat"]["Host"],
            dst=config["Service"]["Host"]
        )

        udp = UDP(
            sport=config["Heartbeat"].getint("Port"),
            dport=config["Service"].getint("Port")
        )

        sip = SOMEIP()
        sip.srv_id = self.service_id
        sip.sub_id = 0
        sip.method_id = self.method_id
        sip.len = 8
        sip.client_id = self.client_id
        sip.session_id = self.session_id
        sip.proto_ver = self.proto_ver
        sip.iface_ver = self.iface_ver
        sip.msg_type = 0
        sip.retcode = 0

        return ip / udp / sip

    def _parse_someip_from_response(self, res):
        if res is None or UDP not in res:
            return None

        try:
            udp_payload = bytes(res[UDP].payload)
            if len(udp_payload) == 0:
                return None
            return SOMEIP(udp_payload)
        except Exception:
            return None

    def check(self):
        packet = self._build_packet()
        expected_session = self.session_id

        log_info(
            "Heartbeat sending ff40 request: method=0x{:04x}, session=0x{:04x}".format(
                self.method_id, expected_session
            )
        )

        res = sr1(packet, retry=0, timeout=self.timeout_sec, verbose=False)

        if res is None:
            log_info("Heartbeat no response")
            return False

        parsed = self._parse_someip_from_response(res)
        if parsed is None:
            log_info("Heartbeat response parse failed")
            return False

        if parsed.srv_id != self.service_id:
            log_info(
                "Heartbeat unexpected service id: got=0x{:04x}, expected=0x{:04x}".format(
                    parsed.srv_id, self.service_id
                )
            )
            return False

        if parsed.method_id != self.method_id:
            log_info(
                "Heartbeat unexpected method id: got=0x{:04x}, expected=0x{:04x}".format(
                    parsed.method_id, self.method_id
                )
            )
            return False

        if parsed.session_id != expected_session:
            log_info(
                "Heartbeat unexpected session id: got=0x{:04x}, expected=0x{:04x}".format(
                    parsed.session_id, expected_session
                )
            )
            return False

        if parsed.client_id != self.client_id:
            log_info(
                "Heartbeat unexpected client id: got=0x{:04x}, expected=0x{:04x}".format(
                    parsed.client_id, self.client_id
                )
            )
            return False

        if parsed.retcode != 0:
            log_info("Heartbeat retcode is not E_OK: {}".format(parsed.retcode))
            return False

        log_info(
            "Heartbeat OK: service=0x{:04x}, method=0x{:04x}, session=0x{:04x}, client=0x{:04x}, msg_type=0x{:02x}".format(
                parsed.srv_id,
                parsed.method_id,
                parsed.session_id,
                parsed.client_id,
                parsed.msg_type
            )
        )

        self.session_id = (self.session_id + 1) & 0xFFFF
        if self.session_id == 0:
            self.session_id = 1

        return True
