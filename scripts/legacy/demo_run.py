#!/usr/bin/env python3
"""
One-command demo runner for replay/state-effect experiments with resource logs.

This wrapper starts a ps-based CPU/memory sampler for a local or remote server
PID, runs one of the existing replay validation scripts, and writes a
human-readable log plus CSV outputs for demonstration.
"""

import argparse
import csv
import os
import subprocess
import sys
import threading
import time
from datetime import datetime


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_SCAPY_PYTHON = os.path.abspath(
    os.path.join(REPO_ROOT, "..", "miniconda3", "envs", "someipfuzz", "bin", "python")
)

RESOURCE_HEADER = ["timestamp", "pid", "pcpu", "pmem", "rss", "vsz", "command"]


def now_stamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def now_log():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_dir(path):
    if path:
        os.makedirs(path, exist_ok=True)


def ps_command(pid):
    return ["ps", "-p", str(pid), "-o", "pid=,pcpu=,pmem=,rss=,vsz=,args="]


def ps_line_from_command(command):
    output = subprocess.check_output(
        command,
        text=True,
    ).strip()
    if not output:
        return None
    parts = output.split(None, 5)
    if len(parts) < 6:
        return None
    return {
        "pid": parts[0],
        "pcpu": parts[1],
        "pmem": parts[2],
        "rss": parts[3],
        "vsz": parts[4],
        "command": parts[5],
    }


def local_ps_line(pid):
    return ps_line_from_command(ps_command(pid))


def remote_ps_line(remote, pid):
    return ps_line_from_command(["ssh", remote] + ps_command(pid))


def pid_exists(pid, remote=None):
    try:
        if remote:
            return remote_ps_line(remote, pid) is not None
        return local_ps_line(pid) is not None
    except subprocess.CalledProcessError:
        return False


def resource_watch(pid, out_csv, interval, stop_event, log, remote=None):
    samples = 0
    target = "{}:{}".format(remote, pid) if remote else str(pid)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=RESOURCE_HEADER)
        writer.writeheader()

        while not stop_event.is_set():
            try:
                if remote:
                    row = remote_ps_line(remote, pid)
                else:
                    row = local_ps_line(pid)
            except subprocess.CalledProcessError:
                log("server PID {} disappeared; stopping resource watch".format(target))
                break

            if row is None:
                log("server PID {} disappeared; stopping resource watch".format(target))
                break

            row["timestamp"] = now_log()
            writer.writerow(row)
            f.flush()
            samples += 1
            stop_event.wait(interval)

    log("resource samples written: {}".format(samples))


def tee_process(command, log):
    log("running command: {}".format(" ".join(command)))
    proc = subprocess.Popen(
        command,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        print(line)
        log(line, echo=False)

    return proc.wait()


def build_experiment_command(args, experiment_csv):
    python_bin = args.python
    if python_bin == "auto":
        python_bin = DEFAULT_SCAPY_PYTHON if os.path.exists(DEFAULT_SCAPY_PYTHON) else sys.executable

    if args.mode == "replay":
        script = "scripts/replay_candidates.py"
        return [
            python_bin,
            script,
            "--candidates",
            args.candidates,
            "--out",
            experiment_csv,
            "--repeat",
            str(args.repeat),
        ]

    if args.mode == "state":
        script = "scripts/check_candidate_state_effect_verbose.py"
        return [
            python_bin,
            script,
            "--candidates",
            args.candidates,
            "--out",
            experiment_csv,
            "--repeat",
            str(args.repeat),
        ]

    raise ValueError("unsupported mode: {}".format(args.mode))


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run a replay/state demo while recording server CPU/memory usage."
    )
    parser.add_argument("--pid", type=int, help="Local server process PID")
    parser.add_argument("--remote", help="Remote SSH target, for example server@192.168.40.134")
    parser.add_argument("--remote-pid", type=int, help="Remote server process PID")
    parser.add_argument(
        "--mode",
        choices=["replay", "state"],
        default="replay",
        help="Demo experiment to run: replay or state",
    )
    parser.add_argument(
        "--candidates",
        default="results/replay_candidates_llm.jsonl",
        help="Candidate JSONL path",
    )
    parser.add_argument("--repeat", type=int, default=30, help="Repeat count")
    parser.add_argument("--interval", type=float, default=1.0, help="Resource sampling interval")
    parser.add_argument("--out-dir", default="results/demo", help="Output directory")
    parser.add_argument(
        "--python",
        default="auto",
        help="Python used for Scapy experiment scripts. Default: auto-detect someipfuzz env.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.repeat <= 0:
        raise ValueError("--repeat must be positive")
    if args.interval <= 0:
        raise ValueError("--interval must be positive")
    if args.remote or args.remote_pid is not None:
        if not args.remote or args.remote_pid is None:
            print("error: use --remote and --remote-pid together", file=sys.stderr)
            sys.exit(1)
        watch_pid = args.remote_pid
        watch_remote = args.remote
    else:
        if args.pid is None:
            print("error: provide --pid for local watch or --remote and --remote-pid for remote watch", file=sys.stderr)
            sys.exit(1)
        watch_pid = args.pid
        watch_remote = None

    if not pid_exists(watch_pid, remote=watch_remote):
        target = "{}:{}".format(watch_remote, watch_pid) if watch_remote else str(watch_pid)
        print("error: PID {} does not exist".format(target), file=sys.stderr)
        sys.exit(1)

    ensure_dir(args.out_dir)
    stamp = now_stamp()
    resource_csv = os.path.join(args.out_dir, "server_resource_{}_{}.csv".format(args.mode, stamp))
    experiment_csv = os.path.join(args.out_dir, "experiment_{}_{}.csv".format(args.mode, stamp))
    log_path = os.path.join(args.out_dir, "demo_{}_{}.log".format(args.mode, stamp))

    with open(log_path, "w", encoding="utf-8") as log_file:
        def log(message, echo=True):
            text = "[{}] {}".format(now_log(), message)
            if echo:
                print(text)
            log_file.write(text + "\n")
            log_file.flush()

        log("demo mode: {}".format(args.mode))
        if watch_remote:
            log("server target: {} pid {}".format(watch_remote, watch_pid))
        else:
            log("server pid: {}".format(watch_pid))
        log("resource csv: {}".format(resource_csv))
        log("experiment csv: {}".format(experiment_csv))
        log("log file: {}".format(log_path))

        stop_event = threading.Event()
        watcher = threading.Thread(
            target=resource_watch,
            args=(watch_pid, resource_csv, args.interval, stop_event, log, watch_remote),
        )
        watcher.start()

        command = build_experiment_command(args, experiment_csv)
        try:
            exit_code = tee_process(command, log)
        finally:
            stop_event.set()
            watcher.join()

        log("experiment exit code: {}".format(exit_code))
        log("done")

    if exit_code != 0:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
