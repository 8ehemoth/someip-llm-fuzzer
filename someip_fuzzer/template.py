from scapy.all import *
from scapy.utils import rdpcap
from someip_fuzzer.config import config
from someip_fuzzer.log import log_info
import binascii
import json

load_contrib("automotive.someip")
from scapy.contrib.automotive.someip import SOMEIP


class Template:

    def read_capture(self):
        # offline pcap은 sniff(filter=...) 대신 rdpcap으로 읽는 편이 안정적
        packets = rdpcap(config["Fuzzer"]["Trace"])
        return list(packets)

    @staticmethod
    def log_packet(packet):
        log_info(packet.summary())

    def create_template(self, packets):
        template = {}
        service_port = int(config["Service"]["Port"])
        wanted_layer = config["Fuzzer"]["Layer"].upper()

        while packets:
            packet = packets.pop(0)

            if UDP not in packet:
                continue

            # 서비스 포트와 무관한 패킷은 제외
            if packet[UDP].sport != service_port and packet[UDP].dport != service_port:
                continue

            self.log_packet(packet)
            layer_names = [layer.name for layer in self.__count_layers(packet)]
            log_info(layer_names)

            payload = packet[UDP].payload
            if payload is None or isinstance(payload, NoPayload):
                continue

            # Scapy가 SOME/IP로 자동 해석 못한 경우 Raw -> SOMEIP 수동 파싱 시도
            if type(payload).__name__ == "Raw":
                raw_bytes = bytes(payload)
                try:
                    payload = SOMEIP(raw_bytes)
                except Exception:
                    # SOME/IP로 못 읽으면 이번 패킷은 건너뜀
                    continue

            actual_layer = type(payload).__name__.upper()
            if actual_layer != wanted_layer:
                continue

            outgoing = packet[UDP].dport == service_port
            self.__add_to_template(template, outgoing, payload)

        return template

    def save_template(self, template):
        template_json = []
        for key, value in template.items():
            item = {
                "outgoing": key[0],
                "layer": key[1],
                "fields": value["fields"]
            }
            template_json.append(item)

        with open(config["Fuzzer"]["Template"], "w") as outfile:
            json.dump(template_json, outfile, indent=4, cls=TemplateEncoder)

    def print_template(self, template):
        template_json = []
        for key, value in template.items():
            item = {
                "outgoing": key[0],
                "layer": key[1],
                "fields": value["fields"]
            }
            template_json.append(item)

        print(json.dumps(template_json, default=str, indent=4, sort_keys=False))

    def read_template(self):
        with open(config["Fuzzer"]["Template"], "r") as infile:
            template_json = json.load(infile)

        template = {}
        for item in template_json:
            template[(item["outgoing"], item["layer"])] = {"fields": item["fields"]}
        return template

    def __add_to_template(self, template, outgoing, payload):
        key = (outgoing, type(payload).__name__.upper())  # (True, "SOMEIP")

        if key not in template:
            template[key] = {"fields": {}}

        template_layer = template[key]["fields"]

        for layer_obj in self.__count_layers(payload):
            if layer_obj is None or isinstance(layer_obj, NoPayload):
                continue

            for name, value in layer_obj.fields.items():
                field_type = type(layer_obj.get_field(name)).__name__

                if name not in template_layer:
                    template_layer[name] = {
                        "values": set(),
                        "type": field_type,
                        "fuzzing": {"fuzzer": None},
                    }

                try:
                    template_layer[name]["values"].add(value)
                except TypeError:
                    # list/dict/option 구조는 문자열로 저장
                    template_layer[name]["values"].add(str(value))

    def __count_layers(self, packet):
        cur = packet
        while cur is not None and not isinstance(cur, NoPayload):
            yield cur
            cur = cur.payload


class TemplateEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, bytes):
            return binascii.hexlify(obj).decode("utf-8")
        return json.JSONEncoder.default(self, obj)
