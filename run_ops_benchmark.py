#!/usr/bin/env python3
"""
run_ops_benchmark.py

Run OPS_BENCH variants (or parse existing logs) and write benchmarks_ops.csv.

Default mode (no positional logs):
- Build + run 5 variants with unified test-vector mapping:
  1) Type 3 Classic  -> SUITE_2  vector 5, method 3, libsodium fast
  2) Type 3 PQ       -> SUITE_9  vector 9, method 3 override (fallback)
  3) Type 3 Hybrid   -> SUITE_18 vector 18
  4) Type 0 Classic  -> SUITE_2  vector 2, method 0, libsodium fast
  5) Type 0 PQ       -> SUITE_9  vector 10, method 0

Parse mode (provide log files):
- Parse JSON lines emitted by OPS_BENCH and write CSV.
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from benchmark_profiles import get_ops_profiles, profile_to_cmake_flags

ROOT = Path(__file__).resolve().parent
APP_DIR = ROOT / "test_pq_mem"

OPERATIONS: List[str] = [
    "KeyGen",
    "Encap",
    "Decap",
    "Signature",
    "Verification",
    "ECDH",
    "HKDF",
]


@dataclass(frozen=True)
class Variant:
    key: str
    label: str
    cmake_flags: List[str]


OPS_TYPE3_PQ_LABEL_KEYS = {
    p.key for p in get_ops_profiles() if p.ops_type3_pq_label
}

VARIANTS: List[Variant] = [
    Variant(
        key=p.key,
        label=p.label,
        cmake_flags=profile_to_cmake_flags(p, include_use_test_edhoc=False),
    )
    for p in get_ops_profiles()
]


def _blank_ops() -> List[float]:
    return [float("nan")] * len(OPERATIONS)


def run_cmd(cmd: List[str], cwd: Path) -> str:
    result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result.stdout


def parse_lines_to_data(lines: List[str], data: Dict[str, Tuple[List[float], List[float]]]) -> None:
    def ensure_label(label: str) -> None:
        if label not in data:
            data[label] = (_blank_ops(), _blank_ops())

    for line in lines:
        line = line.strip()
        if not line:
            continue
        start = line.find("{")
        if start < 0:
            continue
        try:
            obj = json.loads(line[start:])
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


def parse_logs(paths: List[Path]) -> Dict[str, Tuple[List[float], List[float]]]:
    data: Dict[str, Tuple[List[float], List[float]]] = {}
    for path in paths:
        if str(path) == "-":
            lines = sys.stdin.readlines()
        else:
            lines = path.read_text().splitlines()
        parse_lines_to_data(lines, data)
    return data


def build_and_run_variant(variant: Variant, board: str, build_type: str) -> List[str]:
    collected: List[str] = []

    for role in ("initiator", "responder"):
        build_dir = ROOT / "build_ops_runtime" / f"{variant.key}-{role}"
        if build_dir.exists():
            shutil.rmtree(build_dir)

        role_flags = ["-DINITIATOR=1"] if role == "initiator" else ["-DRESPONDER=1"]
        extra_cflags = "-DOPS_BENCH"
        if variant.key in OPS_TYPE3_PQ_LABEL_KEYS:
            extra_cflags += " -DOPS_TYPE3_PQ_LABEL"
        cmake_cmd = [
            "cmake",
            "-S",
            str(APP_DIR),
            "-B",
            str(build_dir),
            f"-DBOARD={board}",
            f"-DCMAKE_BUILD_TYPE={build_type}",
            "-DUSE_TEST_EDHOC=1",
            f"-DEXTRA_CFLAGS={extra_cflags}",
            *role_flags,
            *variant.cmake_flags,
        ]
        run_cmd(cmake_cmd, ROOT)
        run_cmd(["cmake", "--build", str(build_dir), "-j"], ROOT)

        exe = build_dir / "zephyr" / "zephyr.exe"
        if not exe.exists():
            raise FileNotFoundError(f"Missing executable: {exe}")

        res = subprocess.run([str(exe)], cwd=str(APP_DIR), capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(
                f"OPS run failed for {variant.key}/{role} (exit {res.returncode})\n"
                f"stdout:\n{res.stdout}\n"
                f"stderr:\n{res.stderr}"
            )
        collected.extend(res.stdout.splitlines())

    return collected


def write_csv(csv_path: Path, data: Dict[str, Tuple[List[float], List[float]]]) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["label", "role", *OPERATIONS])
        for label, (ops_i, ops_r) in data.items():
            writer.writerow([label, "initiator", *ops_i])
            writer.writerow([label, "responder", *ops_r])
    print(f"Wrote ops benchmark CSV: {csv_path}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run or parse OPS benchmark and emit CSV")
    parser.add_argument(
        "logs",
        nargs="*",
        default=[],
        help="Optional log files to parse; if empty script will build+run OPS bench",
    )
    parser.add_argument("--board", default="native_posix_64")
    parser.add_argument(
        "--build-type",
        choices=["Debug", "Release", "RelWithDebInfo", "MinSizeRel"],
        default="Release",
        help="CMake build type for benchmark runs (default: Release)",
    )
    parser.add_argument("--write-csv", default="benchmarks_ops.csv", help="Output CSV path")
    args = parser.parse_args(argv)

    if args.logs:
        log_paths = [Path(p) if p != "-" else Path("-") for p in args.logs]
        data = parse_logs(log_paths)
    else:
        print("[INFO] Running OPS benchmark variants with unified test vectors")
        data: Dict[str, Tuple[List[float], List[float]]] = {}
        for variant in VARIANTS:
            print(f"[BUILD+RUN] {variant.label}")
            lines = build_and_run_variant(variant, args.board, args.build_type)
            parse_lines_to_data(lines, data)

    if not data:
        print("No valid JSON lines found; nothing written.")
        return 1

    csv_path = Path(args.write_csv).resolve()
    write_csv(csv_path, data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
