#!/usr/bin/env python3
"""SOME/IP packet helpers for the Playground state-aware experiments."""

from scapy.all import IP, UDP, Raw, load_contrib
from scapy.contrib.automotive.someip import SOMEIP


load_contrib("automotive.someip")


SERVER_IP = "192.168.40.134"
CLIENT_IP = "192.168.40.135"
SERVER_PORT = 31000
CLIENT_PORT = 58423

SERVICE_ID = 0xFF40
CLIENT_ID = 0x1343
PROTO_VER = 1
IFACE_VER = 1


def build_packet(method_id, session_id, payload):
    ip = IP(src=CLIENT_IP, dst=SERVER_IP)
    udp = UDP(sport=CLIENT_PORT, dport=SERVER_PORT)

    someip = SOMEIP()
    someip.srv_id = SERVICE_ID
    someip.sub_id = 0
    someip.method_id = method_id
    someip.len = 8 + len(payload)
    someip.client_id = CLIENT_ID
    someip.session_id = session_id
    someip.proto_ver = PROTO_VER
    someip.iface_ver = IFACE_VER
    someip.msg_type = 0
    someip.retcode = 0

    if payload:
        someip.add_payload(Raw(payload))

    return ip / udp / someip


def parse_response(packet):
    if packet is None or UDP not in packet:
        return None
    try:
        udp_payload = bytes(packet[UDP].payload)
        if not udp_payload:
            return None
        return SOMEIP(udp_payload)
    except Exception:
        return None
