#!/usr/bin/env python3
"""Validate payload_hex and payload_len columns in a CSV file."""

import argparse
import csv
import re


HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


def read_rows(path):
    with open(path, "r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def normalized_text(value):
    return "" if value is None else str(value).strip()


def parse_len(value):
    text = normalized_text(value)
    if text == "":
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def validate_row(row, row_number, payload_col, len_col, method_col):
    payload_hex = normalized_text(row.get(payload_col, ""))
    payload_len_text = normalized_text(row.get(len_col, ""))
    method_id = normalized_text(row.get(method_col, "")) if method_col else ""

    is_hex = bool(HEX_RE.fullmatch(payload_hex))
    even_hex_length = len(payload_hex) % 2 == 0
    expected_len = len(payload_hex) // 2 if is_hex and even_hex_length else None
    actual_len = parse_len(payload_len_text)
    length_match = expected_len is not None and actual_len == expected_len

    return {
        "row_number": row_number,
        "method_id": method_id,
        "payload_hex": payload_hex,
        "payload_len": payload_len_text,
        "expected_payload_len": "" if expected_len is None else str(expected_len),
        "is_hex": str(is_hex),
        "even_hex_length": str(even_hex_length),
        "length_match": str(length_match),
    }


def print_bad_rows(results):
    bad_rows = [
        row for row in results
        if row["is_hex"] != "True" or row["even_hex_length"] != "True" or row["length_match"] != "True"
    ]
    if not bad_rows:
        print("bad row details: none")
        return

    print("bad row details:")
    header = [
        "row_number",
        "method_id",
        "payload_hex",
        "payload_len",
        "expected_payload_len",
        "is_hex",
        "even_hex_length",
        "length_match",
    ]
    print(",".join(header))
    for row in bad_rows:
        print(",".join(row[key] for key in header))


def print_summary(results):
    total_rows = len(results)
    is_hex_bad = sum(1 for row in results if row["is_hex"] != "True")
    even_bad = sum(1 for row in results if row["even_hex_length"] != "True")
    length_bad = sum(1 for row in results if row["length_match"] != "True")
    bad_rows = sum(
        1 for row in results
        if row["is_hex"] != "True" or row["even_hex_length"] != "True" or row["length_match"] != "True"
    )
    print("summary:")
    print("total_rows={}".format(total_rows))
    print("bad_rows={}".format(bad_rows))
    print("is_hex=False rows={}".format(is_hex_bad))
    print("even_hex_length=False rows={}".format(even_bad))
    print("length_match=False rows={}".format(length_bad))


def parse_args():
    parser = argparse.ArgumentParser(description="Check payload_hex/payload_len consistency in CSV.")
    parser.add_argument("--csv", required=True, help="Input CSV path.")
    parser.add_argument("--payload-col", default="payload_hex")
    parser.add_argument("--len-col", default="payload_len")
    parser.add_argument("--method-col", default="method_id")
    return parser.parse_args()


def main():
    args = parse_args()
    rows = read_rows(args.csv)
    results = [
        validate_row(row, index, args.payload_col, args.len_col, args.method_col)
        for index, row in enumerate(rows, start=2)
    ]
    print_bad_rows(results)
    print_summary(results)


if __name__ == "__main__":
    main()
