#!/usr/bin/env python3
"""
Record server process CPU/memory usage with ps at a fixed interval.
"""

import argparse
import csv
import os
import subprocess
import sys
import time
from datetime import datetime


CSV_HEADER = ["timestamp", "pid", "pcpu", "pmem", "rss", "vsz", "command"]


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def ps_line(pid):
    cmd = ["ps", "-p", str(pid), "-o", "pid=,pcpu=,pmem=,rss=,vsz=,args="]
    output = subprocess.check_output(cmd, text=True).strip()
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


def pid_exists(pid):
    try:
        return ps_line(pid) is not None
    except subprocess.CalledProcessError:
        return False


def watch(pid, out_path, interval, duration):
    ensure_parent(out_path)
    deadline = time.time() + duration

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()

        while time.time() <= deadline:
            try:
                row = ps_line(pid)
            except subprocess.CalledProcessError:
                print("server PID {} disappeared; stopping".format(pid), file=sys.stderr)
                break

            if row is None:
                print("server PID {} disappeared; stopping".format(pid), file=sys.stderr)
                break

            row["timestamp"] = now_str()
            writer.writerow(row)
            f.flush()
            time.sleep(interval)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Watch a server process with ps and write CPU/memory samples to CSV."
    )
    parser.add_argument("--pid", required=True, type=int, help="Server process PID")
    parser.add_argument("--out", required=True, help="Output CSV path")
    parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval in seconds")
    parser.add_argument("--duration", type=float, default=60.0, help="Total watch duration in seconds")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.interval <= 0:
        raise ValueError("--interval must be positive")
    if args.duration <= 0:
        raise ValueError("--duration must be positive")

    if not pid_exists(args.pid):
        print("error: PID {} does not exist".format(args.pid), file=sys.stderr)
        sys.exit(1)

    watch(args.pid, args.out, args.interval, args.duration)
    print("wrote: {}".format(args.out))


if __name__ == "__main__":
    main()
