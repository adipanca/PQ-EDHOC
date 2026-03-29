#!/usr/bin/env python3
"""
run_ops_benchmark.py

Parse per-operation timing JSON lines emitted by the Zephyr OPS_BENCH
firmware build and write benchmarks_ops.csv.

Expected input: log files (or stdin) containing lines like
{"label":"Type 0 PQ: signature–signature","role":"initiator","ops":{"KeyGen":1,...}}

Output CSV columns: label, role, KeyGen, Encap, Decap, Signature, Verification, ECDH, HKDF
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Operations to benchmark (order matters for the CSV)
OPERATIONS: List[str] = [
    "KeyGen",
    "Encap",
    "Decap",
    "Signature",
    "Verification",
    "ECDH",
    "HKDF",
]

def _blank_ops() -> List[float]:
    return [float("nan")] * len(OPERATIONS)


def parse_logs(paths: List[Path]) -> Dict[str, Tuple[List[float], List[float]]]:
    data: Dict[str, Tuple[List[float], List[float]]] = {}

    def ensure_label(label: str):
        if label not in data:
            data[label] = (_blank_ops(), _blank_ops())

    for path in paths:
        if str(path) == "-":
            lines = sys.stdin.readlines()
        else:
            lines = path.read_text().splitlines()

        for idx, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            # Some benches print debug text before the JSON payload.
            json_start = line.find("{")
            if json_start < 0:
                continue
            line = line[json_start:]
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            label = obj.get("label")
            role = obj.get("role")
            ops = obj.get("ops", {})
            if not label or role not in ("initiator", "responder"):
                continue
            ensure_label(label)
            for i, op in enumerate(OPERATIONS):
                val = ops.get(op)
                if val is None:
                    continue
                if role == "initiator":
                    data[label][0][i] = float(val)
                else:
                    data[label][1][i] = float(val)
    return data


def write_csv(csv_path: Path, data: Dict[str, Tuple[List[float], List[float]]]) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        header = ["label", "role"] + OPERATIONS
        writer.writerow(header)
        for label, (ops_i, ops_r) in data.items():
            writer.writerow([label, "initiator", *ops_i])
            writer.writerow([label, "responder", *ops_r])
    print(f"Wrote ops benchmark CSV: {csv_path}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Parse ops benchmark JSON lines and emit CSV")
    parser.add_argument(
        "logs",
        nargs="*",
        default=[],
        help="Log files containing JSON lines (default: read none, expecting stdin only if '-' present)",
    )
    parser.add_argument("--write-csv", default="benchmarks_ops.csv", help="Output CSV path")
    args = parser.parse_args(argv)

    log_paths = [Path(p) if p != "-" else Path("-") for p in args.logs]
    data = parse_logs(log_paths)
    if not data:
        print("No valid JSON lines found; nothing written.")
        return 1

    csv_path = Path(args.write_csv).resolve()
    write_csv(csv_path, data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
