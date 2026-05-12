#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import glob
import json
import os
import pwd
from datetime import datetime

import main as engine
import llm_planner
import apply_plan
import compare_campaigns


RESULTS_DIR = "results"
CONFIG_PATH = "config.ini"
PAYLOAD_PATH = os.path.join(RESULTS_DIR, "payload_cases.json")


def ensure_results_dir():
    os.makedirs(RESULTS_DIR, exist_ok=True)


def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def latest_file(pattern):
    candidates = glob.glob(pattern)
    if not candidates:
        return None
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]


def csv_methods(path):
    try:
        rows = compare_campaigns.load_csv(path)
        methods = sorted(set(r.get("target_value", "") for r in rows))
        return methods
    except Exception:
        return []


def latest_csv_for_method(pattern, method):
    candidates = glob.glob(pattern)
    if not candidates:
        return None

    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)

    for path in candidates:
        methods = csv_methods(path)
        if methods == [str(method)] or str(method) in methods:
            return path

    return None


def chown_back(paths):
    """
    runner.py를 sudo로 실행했을 때 results/와 config.ini가 root 소유로 남지 않게 복구.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() != 0 or not sudo_user:
        return

    try:
        pw = pwd.getpwnam(sudo_user)
        uid = pw.pw_uid
        gid = pw.pw_gid

        for path in paths:
            if not path or not os.path.exists(path):
                continue

            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    os.chown(root, uid, gid)
                    for name in dirs:
                        os.chown(os.path.join(root, name), uid, gid)
                    for name in files:
                        os.chown(os.path.join(root, name), uid, gid)
            else:
                os.chown(path, uid, gid)
    except Exception as exc:
        print("[WARN] chown_back failed:", exc)


def make_overrides(mode, method=None, cases=None, timeout=None, interval=None):
    run = {}

    if mode == "baseline":
        run["Mode"] = "baseline"
        run["PayloadGenerator"] = "none"
        run["LogCsv"] = "results/results_baseline.csv"
        run["BaselineMethodId"] = "1"

    elif mode == "llm":
        run["Mode"] = "fuzz"
        run["PayloadGenerator"] = "payload_json"
        run["PayloadCasesFile"] = PAYLOAD_PATH
        run["LogCsv"] = "results/results_llm_plan.csv"

    elif mode == "radamsa":
        run["Mode"] = "fuzz"
        run["PayloadGenerator"] = "radamsa"
        run["LogCsv"] = "results/results_radamsa.csv"

    if method is not None:
        run["FocusedMethodIds"] = str(method)

    if cases is not None:
        run["MaxCases"] = str(cases)

    if timeout is not None:
        run["ResponseTimeoutSec"] = str(timeout)

    if interval is not None:
        run["FuzzIntervalSec"] = str(interval)

    return {"Run": run}


def save_json(path, obj):
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def build_and_apply_plan(input_csv=None, planner_mode="auto"):
    ensure_results_dir()
    llm_planner.load_dotenv_simple(".env")

    if input_csv is None:
        input_csv = latest_file(os.path.join(RESULTS_DIR, "*.csv"))

    if not input_csv or not os.path.exists(input_csv):
        raise FileNotFoundError("planner input csv not found")

    ts = timestamp()
    summary_out = os.path.join(RESULTS_DIR, f"summary_{ts}.json")
    plan_out = os.path.join(RESULTS_DIR, f"llm_plan_{ts}.json")
    raw_out = os.path.join(RESULTS_DIR, f"llm_raw_{ts}.txt")

    summary = llm_planner.summarize_csv(input_csv)
    llm_planner.save_json(summary_out, summary)

    plan = None

    if planner_mode in ("auto", "heuristic"):
        cheap_plan = llm_planner.build_cheap_heuristic_plan(summary)
        if cheap_plan is not None:
            plan = llm_planner.sanitize_plan(cheap_plan, source_file=input_csv)

    if plan is None and planner_mode in ("auto", "llm"):
        model_name = os.environ.get("OPENAI_MODEL", "").strip()
        if not model_name:
            raise RuntimeError("OPENAI_MODEL is not set")

        raw_text = llm_planner.call_llm(summary, model_name)
        with open(raw_out, "w", encoding="utf-8") as f:
            f.write(raw_text)

        plan = llm_planner.extract_json_object(raw_text)
        plan = llm_planner.sanitize_plan(plan, source_file=input_csv)

    if plan is None:
        raise RuntimeError("planner could not produce a plan")

    # results 경로 강제
    run_cfg = plan.setdefault("run_config", {})
    run_cfg["log_csv_base"] = "results/results_llm_plan.csv"

    llm_planner.save_json(plan_out, plan)

    apply_plan.apply_plan_to_config(plan, CONFIG_PATH, PAYLOAD_PATH)
    apply_plan.apply_plan_to_payload_file(plan, PAYLOAD_PATH)

    chown_back([RESULTS_DIR, CONFIG_PATH])

    return {
        "input_csv": input_csv,
        "summary_out": summary_out,
        "plan_out": plan_out,
        "payload_path": PAYLOAD_PATH,
        "plan": plan,
    }


def run_baseline(cases, timeout, interval):
    overrides = make_overrides(
        mode="baseline",
        cases=cases,
        timeout=timeout,
        interval=interval,
    )
    out_csv = engine.run_campaign(CONFIG_PATH, overrides)
    chown_back([RESULTS_DIR, CONFIG_PATH])
    return out_csv


def run_llm(method, cases, timeout, interval, input_csv=None, planner_mode="auto"):
    plan_info = build_and_apply_plan(input_csv=input_csv, planner_mode=planner_mode)

    overrides = make_overrides(
        mode="llm",
        method=method,
        cases=cases,
        timeout=timeout,
        interval=interval,
    )
    out_csv = engine.run_campaign(CONFIG_PATH, overrides)
    chown_back([RESULTS_DIR, CONFIG_PATH])
    return out_csv, plan_info


def run_radamsa(method, cases, timeout, interval):
    overrides = make_overrides(
        mode="radamsa",
        method=method,
        cases=cases,
        timeout=timeout,
        interval=interval,
    )
    out_csv = engine.run_campaign(CONFIG_PATH, overrides)
    chown_back([RESULTS_DIR, CONFIG_PATH])
    return out_csv


def compare_files(llm_file, radamsa_file, output_path=None):
    llm_rows = compare_campaigns.load_csv(llm_file)
    rad_rows = compare_campaigns.load_csv(radamsa_file)

    llm_summary = compare_campaigns.summarize(llm_rows)
    rad_summary = compare_campaigns.summarize(rad_rows)

    result = {
        "llm_file": llm_file,
        "radamsa_file": radamsa_file,
        "llm_summary": llm_summary,
        "radamsa_summary": rad_summary,
    }

    print("\n[overall comparison]")
    compare_campaigns.print_markdown_table(llm_summary, rad_summary, "llm", "radamsa")

    print("\n[llm method summary]")
    print(json.dumps(llm_summary["methods"], indent=2, ensure_ascii=False))

    print("\n[radamsa method summary]")
    print(json.dumps(rad_summary["methods"], indent=2, ensure_ascii=False))

    if output_path:
        save_json(output_path, result)
        print("\n[+] saved comparison json:", output_path)
        chown_back([output_path])

    return result


def parse_args():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_base = sub.add_parser("baseline")
    p_base.add_argument("--cases", type=int, default=30)
    p_base.add_argument("--timeout", type=float, default=None)
    p_base.add_argument("--interval", type=float, default=None)

    p_llm = sub.add_parser("llm")
    p_llm.add_argument("--method", type=int, required=True)
    p_llm.add_argument("--cases", type=int, default=10)
    p_llm.add_argument("--timeout", type=float, default=0.3)
    p_llm.add_argument("--interval", type=float, default=1.0)
    p_llm.add_argument("--input", type=str, default=None, help="planner input csv")
    p_llm.add_argument("--planner-mode", choices=["auto", "heuristic", "llm"], default="auto")

    p_rad = sub.add_parser("radamsa")
    p_rad.add_argument("--method", type=int, required=True)
    p_rad.add_argument("--cases", type=int, default=10)
    p_rad.add_argument("--timeout", type=float, default=0.3)
    p_rad.add_argument("--interval", type=float, default=1.0)

    p_cmp = sub.add_parser("compare")
    p_cmp.add_argument("--method", type=int, required=False)
    p_cmp.add_argument("--llm-file", type=str, default=None)
    p_cmp.add_argument("--radamsa-file", type=str, default=None)
    p_cmp.add_argument("--output", type=str, default=None)

    p_battle = sub.add_parser("battle")
    p_battle.add_argument("--method", type=int, required=True)
    p_battle.add_argument("--cases", type=int, default=10)
    p_battle.add_argument("--timeout", type=float, default=0.3)
    p_battle.add_argument("--interval", type=float, default=1.0)
    p_battle.add_argument("--input", type=str, default=None, help="planner input csv")
    p_battle.add_argument("--planner-mode", choices=["auto", "heuristic", "llm"], default="auto")

    return parser.parse_args()


def main():
    ensure_results_dir()
    args = parse_args()

    if args.cmd == "baseline":
        out_csv = run_baseline(
            cases=args.cases,
            timeout=args.timeout,
            interval=args.interval,
        )
        print("[+] baseline csv:", out_csv)
        return

    if args.cmd == "llm":
        input_csv = args.input
        if input_csv is None:
            input_csv = latest_csv_for_method(os.path.join(RESULTS_DIR, "*.csv"), args.method)
        out_csv, plan_info = run_llm(
            method=args.method,
            cases=args.cases,
            timeout=args.timeout,
            interval=args.interval,
            input_csv=input_csv,
            planner_mode=args.planner_mode,
        )
        print("[+] planner input:", plan_info["input_csv"])
        print("[+] llm csv:", out_csv)
        return

    if args.cmd == "radamsa":
        out_csv = run_radamsa(
            method=args.method,
            cases=args.cases,
            timeout=args.timeout,
            interval=args.interval,
        )
        print("[+] radamsa csv:", out_csv)
        return

    if args.cmd == "compare":
        llm_file = args.llm_file
        rad_file = args.radamsa_file

        if llm_file is None:
            if args.method is None:
                llm_file = latest_file(os.path.join(RESULTS_DIR, "results_llm_plan_*.csv"))
            else:
                llm_file = latest_csv_for_method(os.path.join(RESULTS_DIR, "results_llm_plan_*.csv"), args.method)

        if rad_file is None:
            if args.method is None:
                rad_file = latest_file(os.path.join(RESULTS_DIR, "results_radamsa_*.csv"))
            else:
                rad_file = latest_csv_for_method(os.path.join(RESULTS_DIR, "results_radamsa_*.csv"), args.method)

        if not llm_file or not rad_file:
            raise FileNotFoundError("llm/radamsa csv not found for compare")

        output = args.output
        if output is None:
            tag = f"method{args.method}" if args.method is not None else "latest"
            output = os.path.join(RESULTS_DIR, f"compare_{tag}_{timestamp()}.json")

        compare_files(llm_file, rad_file, output_path=output)
        return

    if args.cmd == "battle":
        input_csv = args.input
        if input_csv is None:
            input_csv = latest_csv_for_method(os.path.join(RESULTS_DIR, "*.csv"), args.method)

        llm_csv, plan_info = run_llm(
            method=args.method,
            cases=args.cases,
            timeout=args.timeout,
            interval=args.interval,
            input_csv=input_csv,
            planner_mode=args.planner_mode,
        )
        print("[+] planner input:", plan_info["input_csv"])
        print("[+] llm csv:", llm_csv)

        rad_csv = run_radamsa(
            method=args.method,
            cases=args.cases,
            timeout=args.timeout,
            interval=args.interval,
        )
        print("[+] radamsa csv:", rad_csv)

        output = os.path.join(
            RESULTS_DIR,
            f"compare_method{args.method}_llm_vs_radamsa_{timestamp()}.json"
        )
        compare_files(llm_csv, rad_csv, output_path=output)
        return


if __name__ == "__main__":
    main()
