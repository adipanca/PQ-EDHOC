#!/usr/bin/env python3
"""
Run Zephyr EDHOC handshake timing benchmark and write benchmark_timing.csv.

Measured components per role (ms):
- processing
- txrx
- precomp
- total

Output rows order:
1) Edhoc type 3 Classic
2) Edhoc type 3 PQ
3) Edhoc type 3 Hybrid
4) Edhoc type 0 Classic
5) Edhoc type 0 PQ

Note:
- Current bundled vectors only provide true method=3 (MAC/MAC) for SUITE_2.
- PQ/hybrid entries therefore use the closest available vectors (method=0)
    until method=3 vectors for those suites are added.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import subprocess
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from benchmark_profiles import get_handshake_timing_profiles, profile_to_cmake_flags


ROOT = Path(__file__).resolve().parent
APP_DIR = ROOT / "test_pq_mem"


@dataclass(frozen=True)
class Variant:
    key: str
    label: str
    cmake_flags: List[str]


VARIANTS: List[Variant] = [
    Variant(
        key=p.key,
        label=p.label,
        cmake_flags=profile_to_cmake_flags(p, include_use_test_edhoc=False),
    )
    for p in get_handshake_timing_profiles()
]


def run_cmd(cmd: List[str], cwd: Path) -> str:
    result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result.stdout


def build_variant(variant: Variant, board: str) -> Path:
    build_dir = ROOT / "build_timing" / variant.key
    extra_cflags = ["-DHANDSHAKE_TIMING_BENCH"]

    # Ensure we don't reuse cached CMake options from other variants
    if build_dir.exists():
        shutil.rmtree(build_dir)

    cmake_cmd = [
        "cmake",
        "-S",
        str(APP_DIR),
        "-B",
        str(build_dir),
        f"-DBOARD={board}",
        "-DUSE_TEST_EDHOC=1",
        "-DINITIATOR=1",
        "-DRESPONDER=1",
        f"-DEXTRA_CFLAGS={' '.join(extra_cflags)}",
        *variant.cmake_flags,
    ]
    run_cmd(cmake_cmd, ROOT)
    run_cmd(["cmake", "--build", str(build_dir), "-j"], ROOT)
    exe = build_dir / "zephyr" / "zephyr.exe"
    if not exe.exists():
        raise FileNotFoundError(f"Missing executable: {exe}")
    return exe


def parse_timing_json(output: str) -> Dict[str, float]:
    for line in output.splitlines():
        line = line.strip()
        if not line or "\"initiator\"" not in line or "\"responder\"" not in line:
            continue
        start = line.find("{")
        if start < 0:
            continue
        try:
            obj = json.loads(line[start:])
        except json.JSONDecodeError:
            continue
        ini = obj.get("initiator", {})
        rsp = obj.get("responder", {})
        ini_valid = bool(ini.get("valid", True))
        rsp_valid = bool(rsp.get("valid", True))
        return {
            "initiator_valid": ini_valid,
            "responder_valid": rsp_valid,
            "initiator_processing": float(ini.get("processing_ms", 0.0)) if ini_valid else math.nan,
            "initiator_txrx": float(ini.get("txrx_ms", 0.0)) if ini_valid else math.nan,
            "initiator_precomp": float(ini.get("precomp_ms", 0.0)) if ini_valid else math.nan,
            "initiator_total": float(ini.get("total_ms", 0.0)) if ini_valid else math.nan,
            "responder_processing": float(rsp.get("processing_ms", 0.0)) if rsp_valid else math.nan,
            "responder_txrx": float(rsp.get("txrx_ms", 0.0)) if rsp_valid else math.nan,
            "responder_precomp": float(rsp.get("precomp_ms", 0.0)) if rsp_valid else math.nan,
            "responder_total": float(rsp.get("total_ms", 0.0)) if rsp_valid else math.nan,
        }
    raise ValueError("No handshake timing JSON found in run output")


def run_variant(exe: Path, runs: int, timeout: int, max_attempts: int) -> Dict[str, float]:
    samples: Dict[str, List[float]] = {
        "initiator_processing": [],
        "initiator_txrx": [],
        "initiator_precomp": [],
        "initiator_total": [],
        "responder_processing": [],
        "responder_txrx": [],
        "responder_precomp": [],
        "responder_total": [],
    }

    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        try:
            result = subprocess.run([str(exe)], cwd=str(APP_DIR), capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f"  run {attempts}: timeout after {timeout}s, retrying")
            continue
        if result.returncode != 0:
            # Skip transient failed runs and keep trying.
            print(f"  run {attempts}: failed (exit {result.returncode}), retrying")
            continue
        parsed = parse_timing_json(result.stdout)
        if not parsed["initiator_valid"] or not parsed["responder_valid"]:
            print(
                f"  run {attempts}: invalid handshake "
                f"(initiator_valid={parsed['initiator_valid']}, responder_valid={parsed['responder_valid']}), retrying"
            )
            continue

        for k, v in parsed.items():
            if k.endswith("_valid"):
                continue
            if not math.isnan(v):
                samples[k].append(v)
        print(f"  run {attempts}: init_total={parsed['initiator_total']:.6f} ms, resp_total={parsed['responder_total']:.6f} ms")

        enough_i = len(samples["initiator_total"]) >= runs
        enough_r = len(samples["responder_total"]) >= runs
        if enough_i and enough_r:
            break

    out: Dict[str, float] = {}
    for k, vals in samples.items():
        if not vals:
            raise RuntimeError(
                f"No valid timing samples collected for '{exe}' field '{k}' after {max_attempts} attempts"
            )
        out[k] = statistics.median(vals)

    return out


def write_csv(path: Path, rows: List[Dict[str, float]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "label",
                "initiator_processing_ms",
                "initiator_txrx_ms",
                "initiator_precomp_ms",
                "initiator_total_ms",
                "responder_processing_ms",
                "responder_txrx_ms",
                "responder_precomp_ms",
                "responder_total_ms",
            ]
        )
        for r in rows:
            def fmt(v: float) -> str:
                return f"{v:.6f}"

            writer.writerow(
                [
                    r["label"],
                    fmt(r["initiator_processing"]),
                    fmt(r["initiator_txrx"]),
                    fmt(r["initiator_precomp"]),
                    fmt(r["initiator_total"]),
                    fmt(r["responder_processing"]),
                    fmt(r["responder_txrx"]),
                    fmt(r["responder_precomp"]),
                    fmt(r["responder_total"]),
                ]
            )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run EDHOC handshake timing benchmark and write benchmark_timing.csv")
    parser.add_argument("--board", default="native_posix_64")
    parser.add_argument("--runs", type=int, default=5, help="Runs per variant (median used)")
    parser.add_argument("--timeout", type=int, default=20, help="Per-run timeout seconds (increase for slower PQ builds)")
    parser.add_argument("--max-attempts", type=int, default=40, help="Max process attempts per variant to gather valid initiator+responder samples")
    parser.add_argument("--write-csv", default="benchmark_timing.csv")
    parser.add_argument("--skip-pq", action="store_true", help="Skip PQ-only variants (suite 7/17)")
    parser.add_argument("--skip-hybrid", action="store_true", help="Skip hybrid variants (suite 18)")
    args = parser.parse_args()

    print(
        "[INFO] Vector limitation: only SUITE_2 has method=3 test vectors in this repo; "
        "Type 3 PQ/Hybrid rows use closest available vectors until method=3 PQ/Hybrid vectors are added."
    )

    rows: List[Dict[str, float]] = []

    for variant in VARIANTS:
        if args.skip_pq and ("pq" in variant.key and "hybrid" not in variant.key and "classic" not in variant.key):
            print(f"[SKIP] {variant.label} (skip-pq)")
            continue
        if args.skip_hybrid and ("hybrid" in variant.key):
            print(f"[SKIP] {variant.label} (skip-hybrid)")
            continue
        print(f"[BUILD] {variant.label}")
        exe = build_variant(variant, args.board)
        print(f"[RUN] {variant.label}")
        med = run_variant(exe, runs=max(1, args.runs), timeout=args.timeout, max_attempts=max(1, args.max_attempts))
        rows.append({"label": variant.label, **med})

    csv_path = Path(args.write_csv).resolve()
    write_csv(csv_path, rows)
    print(f"Wrote {len(rows)} rows to {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
