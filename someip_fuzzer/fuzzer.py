from datetime import datetime
import binascii
import json
import os
import random
import subprocess
import threading
import time

from scapy.all import IP, UDP, Raw, load_contrib, sr1

from someip_fuzzer.config import config
from someip_fuzzer.log import log_csv_row, log_info
from someip_fuzzer.types import NoSudoError

load_contrib("automotive.someip")
from scapy.contrib.automotive.someip import SOMEIP


class Fuzzer(threading.Thread):
    def __init__(self, index, excq, template, target_info):
        super().__init__()
        self.index = index
        self.excq = excq
        self.template = template
        self.target_field, self.target_fuzzer = target_info
        self.shutdown = threading.Event()

        self.mode = config["Run"].get("Mode", fallback="baseline").strip().lower()
        self.max_cases = config["Run"].getint("MaxCases", fallback=0)
        self.duration_sec = config["Run"].getint("DurationSec", fallback=0)
        self.fuzz_interval = config["Run"].getfloat("FuzzIntervalSec", fallback=1.0)
        self.timeout_sec = config["Run"].getfloat("ResponseTimeoutSec", fallback=1.0)
        self.log_csv = config["Run"].get("LogCsv", fallback="results/results.csv")
        self.baseline_method_id = config["Run"].getint("BaselineMethodId", fallback=1)

        self.payload_generator = config["Run"].get("PayloadGenerator", fallback="none").strip().lower()
        self.payload_cases_file = config["Run"].get("PayloadCasesFile", fallback="results/payload_cases.json")
        self.payload_repeat_count = config["Run"].getint("PayloadRepeatCount", fallback=1)
        self.radamsa_repeat_count = config["Run"].getint("RadamsaRepeatCount", fallback=1)
        self.max_payload_len = config["Run"].getint("MaxPayloadLen", fallback=32)

        self.case_count = 0
        self.start_time = time.time()

        self.default_srv_id = 0xFF40
        self.default_method_id = 0x0001
        self.default_client_id = 0x1343
        self.default_proto_ver = 1
        self.default_iface_ver = 1
        self.default_msg_type = 0x00
        self.default_retcode = 0x00
        self.session_counter = 0x0010

        self.method_campaign = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 11,
            0, 10, 12, 13, 255, 256, 1024, 0x7FFF, 0xFFFF
        ]

        self.focused_method_ids = self._parse_int_list(
            config["Run"].get("FocusedMethodIds", fallback="")
        )
        self.focused_repeat_count = config["Run"].getint("FocusedRepeatCount", fallback=0)
        self.radamsa_seed_hex_list = self._parse_seed_hex_list(
            config["Run"].get("RadamsaSeedHexList", fallback="EMPTY,00,0000,0001,00010001")
        )

        self.method_index = 0

        self.csv_header = [
            "timestamp",
            "thread_index",
            "test_id",
            "mode",
            "target_field",
            "target_value",
            "payload_source",
            "payload_label",
            "req_payload_len",
            "req_payload_hex",
            "req_service_id",
            "req_method_id",
            "req_session_id",
            "response_received",
            "response_time_ms",
            "rsp_method_id",
            "rsp_session_id",
            "rsp_client_id",
            "rsp_msg_type",
            "rsp_retcode",
            "verdict",
        ]

        self._build_campaign()

    def _build_campaign(self):
        if self.mode == "baseline":
            return

        if self.payload_generator == "payload_json" and self.focused_method_ids:
            self.method_campaign = self._build_payload_json_campaign()
            self.method_campaign = self._normalize_campaign_to_max_cases(self.method_campaign)
            return

        if self.payload_generator == "radamsa" and self.focused_method_ids:
            self.method_campaign = self._build_radamsa_campaign()
            self.method_campaign = self._normalize_campaign_to_max_cases(self.method_campaign)
            return

        if self.focused_method_ids and self.focused_repeat_count > 0:
            focused_campaign = []
            for _ in range(self.focused_repeat_count):
                for mid in self.focused_method_ids:
                    focused_campaign.append(mid)

            self.method_campaign = self._normalize_campaign_to_max_cases(focused_campaign)
            return

        # 일반 method campaign도 max_cases가 있으면 정확히 맞춤
        self.method_campaign = self._normalize_campaign_to_max_cases(self.method_campaign)

    def _normalize_campaign_to_max_cases(self, campaign):
        """
        max_cases가 0보다 크면 정확히 그 길이만큼 campaign를 맞춘다.
        - campaign가 짧으면 round-robin으로 반복
        - campaign가 길면 앞에서부터 자름
        """
        if not isinstance(campaign, list):
            return campaign

        if self.max_cases <= 0:
            return campaign

        if len(campaign) == 0:
            return campaign

        if len(campaign) == self.max_cases:
            return campaign

        normalized = []
        idx = 0
        while len(normalized) < self.max_cases:
            normalized.append(campaign[idx % len(campaign)])
            idx += 1

        return normalized[:self.max_cases]

    def _parse_int_list(self, text):
        text = str(text).strip()
        if text == "":
            return []

        result = []
        for token in text.split(","):
            token = token.strip()
            if token == "":
                continue
            try:
                result.append(int(token, 0))
            except Exception:
                pass
        return result

    def _parse_seed_hex_list(self, text):
        out = []
        if not text:
            return out

        for token in text.split(","):
            token = token.strip()
            if token == "":
                continue

            if token.upper() == "EMPTY":
                out.append(("empty_seed", b""))
                continue

            hx = token.lower()
            if hx.startswith("0x"):
                hx = hx[2:]

            try:
                out.append((f"seed_{hx}", bytes.fromhex(hx)))
            except Exception:
                continue

        return out

    def _load_payload_cases_from_json(self):
        if not os.path.exists(self.payload_cases_file):
            return []

        try:
            with open(self.payload_cases_file, "r", encoding="utf-8") as f:
                obj = json.load(f)

            payload_cases = obj.get("payload_cases", [])
            out = []

            for item in payload_cases:
                label = str(item.get("label", "")).strip()
                hx = str(item.get("hex", "")).strip().lower()

                if hx.startswith("0x"):
                    hx = hx[2:]

                if not label:
                    continue
                if len(hx) % 2 != 0:
                    continue

                try:
                    payload = bytes.fromhex(hx)
                except Exception:
                    continue

                out.append((label, payload))

            return out
        except Exception:
            return []

    def _build_payload_json_campaign(self):
        cases = self._load_payload_cases_from_json()
        campaign = []

        for method_id in self.focused_method_ids:
            for label, payload in cases:
                for _ in range(self.payload_repeat_count):
                    campaign.append({
                        "generator": "payload_json",
                        "method_id": method_id,
                        "payload_label": label,
                        "payload": payload,
                    })

        return campaign

    def _build_radamsa_campaign(self):
        campaign = []

        for method_id in self.focused_method_ids:
            for seed_label, seed_bytes in self.radamsa_seed_hex_list:
                for _ in range(self.radamsa_repeat_count):
                    campaign.append({
                        "generator": "radamsa",
                        "method_id": method_id,
                        "seed_label": seed_label,
                        "seed_bytes": seed_bytes,
                    })

        return campaign

    def _request_fields(self):
        layer = config["Fuzzer"]["Layer"]

        # 현재 playground_fields.json 구조: list[dict]
        if isinstance(self.template, list):
            for item in self.template:
                if not isinstance(item, dict):
                    continue
                if item.get("outgoing") is True and item.get("layer") == layer:
                    return item["fields"]

        # 예전 dict 구조도 지원
        if isinstance(self.template, dict):
            tuple_key = (True, layer)
            if tuple_key in self.template:
                return self.template[tuple_key]["fields"]

            str_key = str(tuple_key)
            if str_key in self.template:
                return self.template[str_key]["fields"]

            alt_key = f"{True},{layer}"
            if alt_key in self.template:
                return self.template[alt_key]["fields"]

            if layer in self.template and isinstance(self.template[layer], dict) and "fields" in self.template[layer]:
                return self.template[layer]["fields"]

        raise KeyError(f"Could not find fields for layer={layer}")

    def _normalize_seed_values(self, values):
        if not isinstance(values, list):
            values = [values]

        normalized = []
        for v in values:
            if isinstance(v, (int, bytes, bytearray)):
                normalized.append(v)
            elif isinstance(v, str):
                try:
                    normalized.append(int(v, 0))
                    continue
                except Exception:
                    pass

                try:
                    normalized.append(binascii.unhexlify(v))
                    continue
                except Exception:
                    normalized.append(v)
            else:
                normalized.append(v)

        return normalized

    def _pick_seed(self, fieldname):
        fields = self._request_fields()
        seeds = self._normalize_seed_values(fields[fieldname]["values"])
        return random.choice(seeds)

    def _mutate_numeric(self, fieldname, seed):
        if fieldname == "method_id":
            if not self.method_campaign:
                return 1
            value = self.method_campaign[self.method_index % len(self.method_campaign)]
            self.method_index += 1
            return value

        if fieldname == "session_id":
            choices = [0, 1, 2, 10, 0x7FFF, 0xFFFE, 0xFFFF, random.randint(0, 0xFFFF)]
            return random.choice(choices)

        if fieldname == "msg_type":
            return random.choice([0, 1, 2, 0x80, 0x81, 0xFF])

        if fieldname == "client_id":
            return random.choice([0x0000, 0x0001, 0x1343, 0x1344, 0xFFFF, random.randint(0, 0xFFFF)])

        if fieldname == "proto_ver":
            return random.choice([0, 1, 2, 0xFF])

        if fieldname == "iface_ver":
            return random.choice([0, 1, 2, 0xFF])

        if fieldname == "retcode":
            return random.choice([0, 1, 2, 3, 4, 5, 0xFF])

        if fieldname == "srv_id":
            return random.choice([0xFF40, 0x0000, 0x0001, 0x1234, 0xFFFF])

        if fieldname == "sub_id":
            return random.choice([0, 1])

        if isinstance(seed, int):
            delta = random.choice([-2, -1, 1, 2, 16, 255])
            return max(0, min(0xFFFF, seed + delta))

        return seed

    def _mutate_load_with_radamsa(self, seed_bytes):
        p = subprocess.Popen(
            ["radamsa"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        fuzzed = p.communicate(input=seed_bytes)[0]

        if fuzzed is None:
            fuzzed = b""

        if len(fuzzed) > self.max_payload_len:
            fuzzed = fuzzed[:self.max_payload_len]

        return fuzzed

    def _now_str(self):
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def _stop_due_to_budget(self):
        if self.max_cases > 0 and self.case_count >= self.max_cases:
            return True

        if self.duration_sec > 0 and (time.time() - self.start_time) >= self.duration_sec:
            return True

        return False

    def run(self):
        campaign_len = len(self.method_campaign) if isinstance(self.method_campaign, list) else 0

        log_info(
            "Thread #{} started field='{}' mode='{}' max_cases={} payload_generator={} campaign_len={}".format(
                self.index,
                self.target_field,
                self.mode,
                self.max_cases,
                self.payload_generator,
                campaign_len
            )
        )

        while not self.shutdown.is_set():
            if self._stop_due_to_budget():
                break

            time.sleep(self.fuzz_interval)

            prepared = self.prepare()
            if prepared is None:
                continue

            self.send(prepared)
            self.case_count += 1

        log_info("Thread #{} stopped after {} cases".format(self.index, self.case_count))

    def prepare(self):
        if self.shutdown.is_set():
            return None

        target = self.target_field
        fuzzer_name = self.target_fuzzer
        seed = self._pick_seed(target)

        if self.mode == "baseline":
            if target == "method_id":
                value = {
                    "method_id": self.baseline_method_id,
                    "payload": b"",
                    "payload_label": "",
                    "payload_source": "none",
                }
            else:
                value = seed

        else:
            if target != "method_id":
                if target == "load" and fuzzer_name == "radamsa":
                    raw_seed = seed if isinstance(seed, bytes) else bytes(seed)
                    value = self._mutate_load_with_radamsa(raw_seed)
                else:
                    value = self._mutate_numeric(target, seed)
            else:
                if not self.method_campaign:
                    return None

                entry = self.method_campaign[self.method_index % len(self.method_campaign)]
                self.method_index += 1

                if isinstance(entry, dict):
                    gen = entry.get("generator", "none")

                    if gen == "payload_json":
                        value = {
                            "method_id": int(entry["method_id"]),
                            "payload": bytes(entry["payload"]),
                            "payload_label": entry.get("payload_label", ""),
                            "payload_source": "llm",
                        }

                    elif gen == "radamsa":
                        seed_bytes = bytes(entry["seed_bytes"])
                        fuzzed = self._mutate_load_with_radamsa(seed_bytes)
                        value = {
                            "method_id": int(entry["method_id"]),
                            "payload": fuzzed,
                            "payload_label": entry.get("seed_label", ""),
                            "payload_source": "radamsa",
                        }

                    else:
                        value = {
                            "method_id": int(entry.get("method_id", self.default_method_id)),
                            "payload": b"",
                            "payload_label": "",
                            "payload_source": "none",
                        }
                else:
                    value = {
                        "method_id": int(entry),
                        "payload": b"",
                        "payload_label": "",
                        "payload_source": "none",
                    }

        log_info("[{}] PREP field='{}' value={}".format(self._now_str(), target, value))
        return (target, value)

    def _build_base_packet(self):
        i = IP(
            src=config["Client"]["Host"],
            dst=config["Service"]["Host"],
        )
        u = UDP(
            sport=config["Client"].getint("Port"),
            dport=config["Service"].getint("Port"),
        )

        sip = SOMEIP()
        sip.srv_id = self.default_srv_id
        sip.sub_id = 0
        sip.method_id = self.default_method_id
        sip.len = 8
        sip.client_id = self.default_client_id
        sip.session_id = self.session_counter
        sip.proto_ver = self.default_proto_ver
        sip.iface_ver = self.default_iface_ver
        sip.msg_type = self.default_msg_type
        sip.retcode = self.default_retcode

        return i, u, sip

    def _parse_response(self, res):
        if res is None or UDP not in res:
            return None

        try:
            udp_payload = bytes(res[UDP].payload)
            if len(udp_payload) == 0:
                return None
            return SOMEIP(udp_payload)
        except Exception:
            return None

    def _judge_verdict(self, response_received, parsed):
        if not response_received:
            return "no_response_timeout"
        if parsed is None:
            return "malformed_response"
        if getattr(parsed, "retcode", None) != 0:
            return "error_response"
        return "normal_response"

    def send(self, prepared):
        target, value = prepared

        i, u, sip = self._build_base_packet()

        payload_bytes = b""
        payload_label = ""
        payload_source = "none"

        if target == "srv_id":
            sip.srv_id = int(value)

        elif target == "sub_id":
            sip.sub_id = int(value)

        elif target == "method_id":
            if isinstance(value, dict):
                sip.method_id = int(value.get("method_id", self.default_method_id))
                payload_bytes = value.get("payload", b"")
                payload_label = value.get("payload_label", "")
                payload_source = value.get("payload_source", "none")
            else:
                sip.method_id = int(value)

        elif target == "client_id":
            sip.client_id = int(value)

        elif target == "session_id":
            sip.session_id = int(value)

        elif target == "proto_ver":
            sip.proto_ver = int(value)

        elif target == "iface_ver":
            sip.iface_ver = int(value)

        elif target == "msg_type":
            sip.msg_type = int(value)

        elif target == "retcode":
            sip.retcode = int(value)

        elif target == "load":
            if isinstance(value, str):
                try:
                    payload_bytes = binascii.unhexlify(value)
                except Exception:
                    payload_bytes = value.encode(errors="ignore")
            elif isinstance(value, int):
                payload_bytes = value.to_bytes(2, byteorder="big", signed=False)
            else:
                payload_bytes = bytes(value)

        if payload_bytes:
            sip.add_payload(Raw(payload_bytes))

        sip.len = 8 + len(payload_bytes)

        packet = i / u / sip

        send_ts = self._now_str()
        send_ts_epoch = time.time()
        test_id = self.case_count + 1

        payload_hex = payload_bytes.hex()
        payload_len = len(payload_bytes)

        log_info(
            "[{}] SEND field='{}' method=0x{:04x} payload_source='{}' payload_label='{}' payload_len={} payload_hex={} srv=0x{:04x} session=0x{:04x} client=0x{:04x} msg_type=0x{:02x} retcode=0x{:02x} sport={} dport={}".format(
                send_ts,
                target,
                sip.method_id,
                payload_source,
                payload_label,
                payload_len,
                payload_hex,
                sip.srv_id,
                sip.session_id,
                sip.client_id,
                sip.msg_type,
                sip.retcode,
                u.sport,
                u.dport,
            )
        )

        response_received = False
        parsed = None
        latency_ms = None
        recv_ts = self._now_str()

        try:
            res = sr1(packet, retry=0, timeout=self.timeout_sec, verbose=False)
            recv_ts = self._now_str()
            latency_ms = (time.time() - send_ts_epoch) * 1000.0

            if res is None:
                log_info(
                    "[{}] NORESP method=0x{:04x} payload_source='{}' payload_label='{}' payload_len={} payload_hex={} req_session=0x{:04x} latency_ms={:.2f}".format(
                        recv_ts,
                        sip.method_id,
                        payload_source,
                        payload_label,
                        payload_len,
                        payload_hex,
                        sip.session_id,
                        latency_ms,
                    )
                )
            else:
                response_received = True
                parsed = self._parse_response(res)

                if parsed is None:
                    log_info(
                        "[{}] RECV_PARSE_FAIL method=0x{:04x} payload_source='{}' payload_label='{}' payload_len={} payload_hex={} req_session=0x{:04x} latency_ms={:.2f}".format(
                            recv_ts,
                            sip.method_id,
                            payload_source,
                            payload_label,
                            payload_len,
                            payload_hex,
                            sip.session_id,
                            latency_ms,
                        )
                    )
                else:
                    log_info(
                        "[{}] RECV method=0x{:04x} payload_source='{}' payload_label='{}' payload_len={} payload_hex={} req_session=0x{:04x} -> rsp_method=0x{:04x} rsp_session=0x{:04x} rsp_client=0x{:04x} msg_type=0x{:02x} retcode=0x{:02x} latency_ms={:.2f}".format(
                            recv_ts,
                            sip.method_id,
                            payload_source,
                            payload_label,
                            payload_len,
                            payload_hex,
                            sip.session_id,
                            parsed.method_id,
                            parsed.session_id,
                            parsed.client_id,
                            parsed.msg_type,
                            parsed.retcode,
                            latency_ms,
                        )
                    )

        except PermissionError:
            self.excq.put(NoSudoError("Permission as sudo required to send SOME/IP packets"))
            return
        except Exception as exc:
            log_info(
                "[{}] SEND_EXCEPTION method=0x{:04x} payload_source='{}' payload_label='{}' payload_len={} payload_hex={} req_session=0x{:04x} err={}".format(
                    self._now_str(),
                    sip.method_id,
                    payload_source,
                    payload_label,
                    payload_len,
                    payload_hex,
                    sip.session_id,
                    exc,
                )
            )

        verdict = self._judge_verdict(response_received, parsed)

        rsp_method_id = ""
        rsp_session_id = ""
        rsp_client_id = ""
        rsp_msg_type = ""
        rsp_retcode = ""

        if parsed is not None:
            rsp_method_id = "0x{:04x}".format(parsed.method_id)
            rsp_session_id = "0x{:04x}".format(parsed.session_id)
            rsp_client_id = "0x{:04x}".format(parsed.client_id)
            rsp_msg_type = "0x{:02x}".format(parsed.msg_type)
            rsp_retcode = "0x{:02x}".format(parsed.retcode)

        log_csv_row(
            self.log_csv,
            [
                recv_ts,
                self.index,
                test_id,
                self.mode,
                target,
                str(sip.method_id),
                payload_source,
                payload_label,
                payload_len,
                payload_hex,
                "0x{:04x}".format(sip.srv_id),
                "0x{:04x}".format(sip.method_id),
                "0x{:04x}".format(sip.session_id),
                response_received,
                "" if latency_ms is None else "{:.2f}".format(latency_ms),
                rsp_method_id,
                rsp_session_id,
                rsp_client_id,
                rsp_msg_type,
                rsp_retcode,
                verdict,
            ],
            header=self.csv_header,
        )

        self.session_counter = (self.session_counter + 1) & 0xFFFF
        if self.session_counter == 0:
            self.session_counter = 1
