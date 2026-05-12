#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import configparser
from datetime import datetime


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def ensure_run_section(cfg):
    if not cfg.has_section("Run"):
        cfg.add_section("Run")


def normalize_int_list(values):
    out = []
    for x in values:
        try:
            out.append(int(x))
        except Exception:
            continue
    return out


def build_payload_cases(plan):
    payload_cases = []
    for item in plan.get("payload_cases", []):
        if not isinstance(item, dict):
            continue

        label = str(item.get("label", "")).strip()
        hx = str(item.get("hex", "")).strip().lower()
        if hx.startswith("0x"):
            hx = hx[2:]

        if not label:
            continue
        if len(hx) % 2 != 0:
            continue

        payload_cases.append({
            "label": label,
            "hex": hx,
            "length": len(hx) // 2
        })

    return payload_cases


def apply_plan_to_config(plan, config_path, payload_path):
    cfg = configparser.ConfigParser()
    cfg.read(config_path, encoding="utf-8")

    ensure_run_section(cfg)

    run_cfg = plan.get("run_config", {})
    target_methods = normalize_int_list(plan.get("target_methods", []))
    payload_cases = build_payload_cases(plan)

    cfg["Run"]["Mode"] = str(run_cfg.get("mode", "fuzz"))
    cfg["Run"]["MaxCases"] = str(run_cfg.get("max_cases", max(1, len(target_methods) * max(1, len(payload_cases)))))
    cfg["Run"]["DurationSec"] = "0"
    cfg["Run"]["FuzzIntervalSec"] = str(run_cfg.get("fuzz_interval_sec", 1.0))
    cfg["Run"]["HeartbeatIntervalSec"] = str(run_cfg.get("heartbeat_interval_sec", 3.0))
    cfg["Run"]["HeartbeatFailThreshold"] = str(run_cfg.get("heartbeat_fail_threshold", 3))
    cfg["Run"]["ResponseTimeoutSec"] = str(run_cfg.get("response_timeout_sec", 0.3))
    cfg["Run"]["HeartbeatTimeoutSec"] = str(run_cfg.get("heartbeat_interval_sec", 3.0))
    cfg["Run"]["BaselineMethodId"] = cfg["Run"].get("BaselineMethodId", "1")
    cfg["Run"]["LogCsv"] = str(run_cfg.get("log_csv_base", "results_llm_plan.csv"))

    cfg["Run"]["FocusedMethodIds"] = ",".join(str(x) for x in target_methods) if target_methods else ""
    cfg["Run"]["FocusedRepeatCount"] = "1"

    if payload_cases:
        cfg["Run"]["PayloadGenerator"] = "payload_json"
        cfg["Run"]["PayloadCasesFile"] = payload_path
        cfg["Run"]["PayloadRepeatCount"] = "1"
    else:
        cfg["Run"]["PayloadGenerator"] = "none"
        cfg["Run"]["PayloadCasesFile"] = payload_path
        cfg["Run"]["PayloadRepeatCount"] = "1"

    # radamsa 비교 모드에서 사용할 기본값도 유지
    cfg["Run"]["RadamsaRepeatCount"] = cfg["Run"].get("RadamsaRepeatCount", "1")
    cfg["Run"]["RadamsaSeedHexList"] = cfg["Run"].get("RadamsaSeedHexList", "EMPTY,00,0000,0001,00010001")
    cfg["Run"]["MaxPayloadLen"] = cfg["Run"].get("MaxPayloadLen", "32")

    with open(config_path, "w", encoding="utf-8") as f:
        cfg.write(f)


def apply_plan_to_payload_file(plan, payload_path):
    payload_cases = build_payload_cases(plan)

    payload_obj = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source_plan_reason": plan.get("reason", ""),
        "payload_strategy": plan.get("payload_strategy", ""),
        "payload_cases": payload_cases
    }

    save_json(payload_path, payload_obj)
    return payload_obj


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, help="planner json path")
    parser.add_argument("--config", default="config.ini", help="config.ini path")
    parser.add_argument("--payload", default="payload_cases.json", help="payload cases json path")
    args = parser.parse_args()

    plan = load_json(args.plan)

    if not os.path.exists(args.config):
        raise FileNotFoundError(f"config not found: {args.config}")

    apply_plan_to_config(plan, args.config, args.payload)
    payload_obj = apply_plan_to_payload_file(plan, args.payload)

    print("[+] Applied plan successfully")
    print(json.dumps({
        "plan": args.plan,
        "config": args.config,
        "payload": args.payload,
        "payload_case_count": len(payload_obj.get("payload_cases", [])),
        "next_action": plan.get("next_action", ""),
        "reason": plan.get("reason", ""),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
