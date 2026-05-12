#!/usr/bin/env python3
"""Generate balanced Method 14 LLM-like and Radamsa-like candidate CSVs."""

import argparse
import csv
import os
import random
import subprocess
from datetime import datetime


METHOD_ID = 14
LLM_SOURCE = "llm_real"
RADAMSA_SOURCE = "radamsa_real"
RADAMSA_BIN_SOURCE = "radamsa_bin"
HEADER = [
    "payload_source",
    "payload_label",
    "method_id",
    "payload_hex",
    "payload_len",
    "generation_strategy",
    "seed_payload_hex",
    "note",
]
BASE_SEEDS = ["01010101", "02020202", "00000000"]
COMMAND_VALUES = ["00", "01", "02", "03", "ff"]


def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def ensure_parent(path):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def normalize_hex(value):
    text = str(value or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    text = "".join(ch for ch in text if ch in "0123456789abcdef")
    if len(text) % 2 == 1:
        text = "0" + text
    return text


def payload_len(payload_hex):
    return len(bytes.fromhex(payload_hex))


def make_candidate(source, label, payload_hex, strategy, seed_payload_hex="", note=""):
    payload_hex = normalize_hex(payload_hex)
    return {
        "payload_source": source,
        "payload_label": label,
        "method_id": METHOD_ID,
        "payload_hex": payload_hex,
        "payload_len": payload_len(payload_hex),
        "generation_strategy": strategy,
        "seed_payload_hex": normalize_hex(seed_payload_hex),
        "note": note,
    }


def dedupe(candidates):
    rows = []
    seen = set()
    for item in candidates:
        payload_hex = item["payload_hex"]
        if payload_hex in seen:
            continue
        seen.add(payload_hex)
        rows.append(item)
    return rows


def select_candidates(candidates, count, seed):
    rows = dedupe(candidates)
    rng = random.Random(seed)
    priority = []
    rest = []
    priority_payloads = {"01010101", "02020202", "00000000"}
    for item in rows:
        if item["payload_hex"] in priority_payloads:
            priority.append(item)
        else:
            rest.append(item)
    rng.shuffle(rest)
    selected = priority + rest
    return selected[:count] if count > 0 else selected


def label_for_commands(values):
    names = {"00": "noop", "01": "open", "02": "close", "03": "invalid3", "ff": "boundaryff"}
    return "_".join(names.get(value, value) for value in values)


def llm_like_candidates():
    rows = []
    for a in COMMAND_VALUES:
        for b in COMMAND_VALUES:
            for c in COMMAND_VALUES:
                for d in COMMAND_VALUES:
                    values = [a, b, c, d]
                    payload = "".join(values)
                    if all(value in ("00", "01", "02") for value in values):
                        strategy = "semantic_all_door_command_combination"
                    elif any(value == "ff" for value in values):
                        strategy = "semantic_boundary_command_included"
                    else:
                        strategy = "semantic_invalid_enum_included"
                    rows.append(make_candidate(LLM_SOURCE, label_for_commands(values), payload, strategy, "", "four door command bytes"))

    semantic_patterns = [
        ("open_front_left", "01000000"),
        ("open_front_right", "00010000"),
        ("open_rear_left", "00000100"),
        ("open_rear_right", "00000001"),
        ("open_front_pair", "01010000"),
        ("open_rear_pair", "00000101"),
        ("mixed_open_close_1", "01020102"),
        ("mixed_open_close_2", "02010102"),
    ]
    for label, payload in semantic_patterns:
        rows.append(make_candidate(LLM_SOURCE, label, payload, "semantic_named_pattern", "", "named Method 14 command tuple"))

    for seed in BASE_SEEDS:
        rows.extend([
            make_candidate(LLM_SOURCE, "suffix_zero_{}".format(seed), seed + "00", "semantic_suffix_padding", seed),
            make_candidate(LLM_SOURCE, "suffix_ff_{}".format(seed), seed + "ff", "semantic_suffix_padding", seed),
            make_candidate(LLM_SOURCE, "prefix_zero_{}".format(seed), "00" + seed, "semantic_prefix_padding", seed),
            make_candidate(LLM_SOURCE, "prefix_ff_{}".format(seed), "ff" + seed, "semantic_prefix_padding", seed),
            make_candidate(LLM_SOURCE, "double_{}".format(seed), seed + seed, "semantic_duplication", seed),
            make_candidate(LLM_SOURCE, "truncated_1_{}".format(seed), seed[:2], "semantic_length_variation", seed),
            make_candidate(LLM_SOURCE, "truncated_2_{}".format(seed), seed[:4], "semantic_length_variation", seed),
            make_candidate(LLM_SOURCE, "truncated_3_{}".format(seed), seed[:6], "semantic_length_variation", seed),
        ])
    return dedupe(rows)


def mutate_bit(payload, bit_index):
    data = bytearray(bytes.fromhex(payload))
    if not data:
        return payload
    byte_index = bit_index % len(data)
    bit = (bit_index // len(data)) % 8
    data[byte_index] ^= 1 << bit
    return data.hex()


def mutate_byte(payload, index, value):
    data = bytearray(bytes.fromhex(payload))
    if not data:
        return payload
    data[index % len(data)] = value
    return data.hex()


def insert_byte(payload, index, value):
    data = bytearray(bytes.fromhex(payload))
    data.insert(index % (len(data) + 1), value)
    return data.hex()


def delete_byte(payload, index):
    data = bytearray(bytes.fromhex(payload))
    if not data:
        return payload
    del data[index % len(data)]
    return data.hex()


def radamsa_like_candidates(seed_value):
    rng = random.Random(seed_value)
    rows = []
    boundary_values = [0x00, 0x01, 0x02, 0x03, 0x7F, 0x80, 0xFE, 0xFF]

    for seed in BASE_SEEDS:
        rows.append(make_candidate(RADAMSA_SOURCE, "seed_{}".format(seed), seed, "seed", seed))
        for bit_index in range(32):
            rows.append(make_candidate(RADAMSA_SOURCE, "bit_flip_{}_{}".format(seed, bit_index), mutate_bit(seed, bit_index), "bit_flip", seed))
        for byte_index in range(4):
            for value in boundary_values:
                rows.append(make_candidate(RADAMSA_SOURCE, "byte_flip_{}_{}_{}".format(seed, byte_index, value), mutate_byte(seed, byte_index, value), "byte_flip", seed))
        for byte_index in range(5):
            for value in (0x00, 0x01, 0x02, 0xFF):
                rows.append(make_candidate(RADAMSA_SOURCE, "insert_{}_{}_{}".format(seed, byte_index, value), insert_byte(seed, byte_index, value), "byte_insertion", seed))
        for byte_index in range(4):
            rows.append(make_candidate(RADAMSA_SOURCE, "delete_{}_{}".format(seed, byte_index), delete_byte(seed, byte_index), "byte_deletion", seed))
        for length in range(0, 9):
            rows.append(make_candidate(RADAMSA_SOURCE, "truncate_{}_{}".format(seed, length), seed[: length * 2], "truncation", seed))
        rows.extend([
            make_candidate(RADAMSA_SOURCE, "duplicate_{}".format(seed), seed + seed, "duplication", seed),
            make_candidate(RADAMSA_SOURCE, "zero_padding_{}".format(seed), seed + "00000000", "long_padding", seed),
            make_candidate(RADAMSA_SOURCE, "ff_padding_{}".format(seed), seed + "ffffffff", "long_padding", seed),
            make_candidate(RADAMSA_SOURCE, "seed_concat_open_{}".format(seed), seed + "01010101", "seed_concat", seed),
            make_candidate(RADAMSA_SOURCE, "seed_concat_close_{}".format(seed), seed + "02020202", "seed_concat", seed),
        ])

    for index in range(80):
        length = rng.randint(0, 12)
        payload = bytes(rng.getrandbits(8) for _ in range(length)).hex()
        rows.append(make_candidate(RADAMSA_SOURCE, "deterministic_random_{}".format(index), payload, "deterministic_random_bytes", "", "radamsa-like random mutation"))
    for length in range(1, 17):
        rows.append(make_candidate(RADAMSA_SOURCE, "boundary_zero_fill_{}".format(length), "00" * length, "boundary_fill", "00000000"))
        rows.append(make_candidate(RADAMSA_SOURCE, "boundary_ff_fill_{}".format(length), "ff" * length, "boundary_fill", "01010101"))
    return dedupe(rows)


def radamsa_generated_candidates(radamsa_bin, seed_corpus, count):
    if not seed_corpus:
        raise ValueError("--radamsa-seed-corpus is required with --use-radamsa")
    seed_files = sorted(
        os.path.join(seed_corpus, name)
        for name in os.listdir(seed_corpus)
        if os.path.isfile(os.path.join(seed_corpus, name))
    )
    if not seed_files:
        raise ValueError("radamsa seed corpus is empty: {}".format(seed_corpus))

    rows = []
    for index in range(count):
        seed_path = seed_files[index % len(seed_files)]
        with open(seed_path, "rb") as f:
            proc = subprocess.run(
                [radamsa_bin],
                input=f.read(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
        payload_hex = proc.stdout.hex()
        rows.append(make_candidate(RADAMSA_BIN_SOURCE, "radamsa_{}".format(index + 1), payload_hex, "radamsa_binary", "", "seed_file={}".format(seed_path)))
    return dedupe(rows)


def write_csv(path, rows):
    ensure_parent(path)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)


def parse_args():
    parser = argparse.ArgumentParser(description="Generate real Method 14 LLM-like and Radamsa-like candidate CSVs.")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--balance", action="store_true")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--use-radamsa", action="store_true")
    parser.add_argument("--radamsa-bin", default="radamsa")
    parser.add_argument("--radamsa-seed-corpus", default="")
    parser.add_argument("--radamsa-count", type=int, default=200)
    return parser.parse_args()


def main():
    args = parse_args()
    if args.count <= 0:
        raise SystemExit("--count must be positive")

    stamp = timestamp()
    llm_all = llm_like_candidates()
    radamsa_all = (
        radamsa_generated_candidates(args.radamsa_bin, args.radamsa_seed_corpus, args.radamsa_count)
        if args.use_radamsa
        else radamsa_like_candidates(args.seed)
    )

    llm_selected = select_candidates(llm_all, args.count, args.seed)
    radamsa_selected = select_candidates(radamsa_all, args.count, args.seed + 1)

    common_count = min(len(llm_selected), len(radamsa_selected))
    if args.balance and common_count < args.count:
        print("warning: one source has fewer than requested count; balanced_count={}".format(common_count))
    balanced_count = common_count if args.balance else args.count
    llm_balanced = llm_selected[:balanced_count]
    radamsa_balanced = radamsa_selected[:balanced_count]

    llm_path = "results/method14_llm_candidates_real_{}.csv".format(stamp)
    radamsa_path = "results/method14_radamsa_candidates_real_{}.csv".format(stamp)
    balanced_path = "results/method14_candidates_balanced_{}.csv".format(stamp)

    write_csv(llm_path, llm_balanced if args.balance else llm_selected)
    write_csv(radamsa_path, radamsa_balanced if args.balance else radamsa_selected)
    write_csv(balanced_path, llm_balanced + radamsa_balanced)

    print("generated_llm_total={}".format(len(llm_all)))
    print("generated_radamsa_total={}".format(len(radamsa_all)))
    print("selected_llm={}".format(len(llm_balanced if args.balance else llm_selected)))
    print("selected_radamsa={}".format(len(radamsa_balanced if args.balance else radamsa_selected)))
    print("balanced_count_per_source={}".format(balanced_count))
    print("wrote {}".format(llm_path))
    print("wrote {}".format(radamsa_path))
    print("wrote {}".format(balanced_path))


if __name__ == "__main__":
    main()
