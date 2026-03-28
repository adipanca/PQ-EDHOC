#!/usr/bin/env python3
"""
run_edhoc_benchmark.py

Build and size EDHOC/OSCORE Zephyr app for multiple cipher-suite variants,
then emit CSV-ready rows (label,runs,median_cpu_initiator,median_cpu_responder,median_mem_init_kb,median_mem_resp_kb).
Optional: run the produced binary and measure wall-clock time as CPU proxy (native_posix_64 host), filling both CPU columns.
Memory is derived from `size zephyr.elf` (data+bss, in KiB) after each build.

Defaults match the five variants requested:
  1. Type 0 PQ (signature–signature)          -> SUIT_7   + X5T
  2. Type 3 PQ (mac–mac)                      -> SUIT_17  + X5T
  3. Type 3 Hybrid (mac–mac)                  -> SUIT_18  + X5T
  4. Type 0 Classic x25519 (signature–sig)    -> SUIT_2   + X5T
  5. Type 3 Classic x25519 (mac–mac)          -> SUIT_2   + X5CHAIN

Usage examples:
    python3 run_edhoc_benchmark.py                          # build all, print rows
    python3 run_edhoc_benchmark.py --variant classic-mac    # build one variant
    python3 run_edhoc_benchmark.py --run-cpu                # build+run to measure time
    python3 run_edhoc_benchmark.py --write-csv benchmarks_edhoc.csv

Ensure ZEPHYR_BASE is set and toolchain is accessible (host toolchain on native_posix_64).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


ROOT = Path(__file__).resolve().parent
TEST_APP = ROOT / "test_pq_mem"
ELF_PATH = TEST_APP / "build" / "zephyr" / "zephyr.elf"


@dataclass
class Variant:
    key: str
    label: str
    cmake_flags: List[str]


VARIANTS: List[Variant] = [
    Variant(
        key="pq-sign",
        label="Edhoc type 0 PQ",
        cmake_flags=["-DUSE_SUIT_7=ON", "-DUSE_X5T=1", "-DUSE_TEST_EDHOC=1"],
    ),
    Variant(
        key="pq-mac",
        label="Edhoc type 3 PQ",
        cmake_flags=["-DUSE_SUIT_17=ON", "-DUSE_X5T=1", "-DUSE_TEST_EDHOC=1"],
    ),
    Variant(
        key="hybrid-mac",
        label="Edhoc type 3 Hybrid",
        cmake_flags=["-DUSE_SUIT_18=ON", "-DUSE_X5T=1", "-DUSE_TEST_EDHOC=1"],
    ),
    Variant(
        key="classic-sign",
        label="Edhoc type 0 Classic x25519",
        cmake_flags=["-DUSE_SUIT_2=ON", "-DUSE_X5T=1", "-DUSE_TEST_EDHOC=1"],
    ),
    Variant(
        key="classic-mac",
        label="Edhoc type 3 Classic x25519",
        cmake_flags=["-DUSE_SUIT_2=ON", "-DUSE_X5CHAIN=1", "-DUSE_TEST_EDHOC=1"],
    ),
]


def run_cmd(cmd: Sequence[str], cwd: Path, *, capture: bool = True) -> str:
    if capture:
        result = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    else:
        result = subprocess.run(cmd, cwd=str(cwd), text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed (exit {result.returncode}): {' '.join(cmd)}\n" f"stdout:\n{getattr(result, 'stdout', '')}\nstderr:\n{getattr(result, 'stderr', '')}"
        )
    return getattr(result, "stdout", "")


def build_variant(variant: Variant, board: str, pristine: bool, show_output: bool, role: str) -> None:
    cmd = ["west", "build", "-b", board]
    if pristine:
        cmd += ["-p", "always"]
    # Define only the active role; avoid defining the other, since the code uses
    # `#ifdef INITIATOR` / `#ifdef RESPONDER` and even `-DRESPONDER=0` counts as
    # defined. This keeps the initiator-only and responder-only builds distinct.
    role_flags = ["-DINITIATOR=1"] if role == "initiator" else ["-DRESPONDER=1"]
    cmd += ["--"] + variant.cmake_flags + role_flags
    run_cmd(cmd, cwd=TEST_APP, capture=not show_output)


def parse_size_output(text: str) -> tuple[int, int, int]:
    """Return (text, data, bss) in bytes from `size` output."""
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 6 and parts[-1].endswith("zephyr.elf"):
            text_b, data_b, bss_b = map(int, parts[0:3])
            return text_b, data_b, bss_b
    raise ValueError("Could not parse size output for zephyr.elf")


def kb(val_bytes: int) -> float:
    return round(val_bytes / 1024.0, 1)


def format_row(label: str, cpu_i: float | None, cpu_r: float | None, mem_i: float, mem_r: float) -> str:
    # runs=1
    cpu_i_val = 0.0 if cpu_i is None else max(cpu_i, 0.0001)
    cpu_r_val = 0.0 if cpu_r is None else max(cpu_r, 0.0001)
    return f"{label},1,{cpu_i_val:.3f},{cpu_r_val:.3f},{mem_i:.1f},{mem_r:.1f}"


def run_binary(exe_path: Path, timeout: int, print_output: bool) -> Tuple[float | None, bool]:
    """Run zephyr.exe once, return (seconds, timed_out)."""
    t0 = time.perf_counter()
    stdout_opt = subprocess.PIPE if print_output else subprocess.DEVNULL
    proc = subprocess.Popen(
        [str(exe_path)],
        cwd=str(TEST_APP),
        stdout=stdout_opt,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        print(f"  run timed out after {timeout}s; using timeout as CPU placeholder")
        if print_output and proc.stdout:
            try:
                print(proc.stdout.read())
            except Exception:  # pragma: no cover - best effort
                pass
        return float(timeout), True
    except KeyboardInterrupt:
        proc.kill()
        proc.wait()
        print("  run interrupted (Ctrl+C); skipping CPU time for this variant")
        return None, False

    duration = time.perf_counter() - t0
    if proc.returncode != 0:
        if print_output and proc.stdout:
            try:
                print(proc.stdout.read())
            except Exception:
                pass
        print(f"  run failed with exit {proc.returncode}; skipping CPU time")
        return None, False
    if print_output and proc.stdout:
        try:
            print(proc.stdout.read())
        except Exception:
            pass
    return duration, False


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build EDHOC Zephyr variants and report memory usage")
    parser.add_argument("--board", default="native_posix_64", help="Zephyr board (default: native_posix_64)")
    parser.add_argument("--variant", choices=[v.key for v in VARIANTS], nargs="*", help="Run only these variants")
    parser.add_argument("--no-pristine", action="store_true", help="Skip -p always to speed up rebuilds")
    parser.add_argument("--run-cpu", action="store_true", help="Run zephyr.exe and time it (wall clock seconds)")
    parser.add_argument("--cpu-runs", type=int, default=3, help="How many times to run zephyr.exe when measuring CPU (median taken)")
    parser.add_argument("--timeout", type=int, default=180, help="Timeout seconds for run (default: 180)")
    parser.add_argument("--print-run-output", action="store_true", help="Print stdout from the run when measuring CPU")
    parser.add_argument("--show-build-output", action="store_true", help="Stream west build output (less silent)")
    parser.add_argument("--write-csv", metavar="PATH", help="Write rows to CSV file (e.g., benchmarks_edhoc.csv)")
    parser.add_argument("--overwrite-csv", action="store_true", help="Rewrite CSV (header + rows) instead of appending")
    parser.add_argument("--skip-timeouts", action="store_true", help="Skip rows where run hit timeout placeholder")
    args = parser.parse_args(argv)

    if "ZEPHYR_BASE" not in os.environ:
        print("WARNING: ZEPHYR_BASE is not set; ensure environment is prepared", file=sys.stderr)

    selected = {v.key: v for v in VARIANTS}
    if args.variant:
        selected = {k: v for k, v in selected.items() if k in set(args.variant)}

    pristine = not args.no_pristine
    rows: List[str] = []

    for v in selected.values():
        cpu_i = cpu_r = None
        mem_i = mem_r = 0.0
        timed_out_any = False

        for role in ("initiator", "responder"):
            try:
                print(f"[BUILD] {v.label} ({v.key}) role={role}", flush=True)
                build_variant(v, board=args.board, pristine=pristine, show_output=args.show_build_output, role=role)
                size_out = run_cmd(["size", str(ELF_PATH)], cwd=TEST_APP / "build" / "zephyr")
                text_b, data_b, bss_b = parse_size_output(size_out)
                ram_kb = kb(data_b + bss_b)

                cpu_sec = None
                timed_out = False
                if args.run_cpu:
                    exe_path = TEST_APP / "build" / "zephyr" / "zephyr.exe"
                    durations: List[float] = []
                    for i in range(max(1, args.cpu_runs)):
                        run_dur, to = run_binary(
                            exe_path,
                            timeout=args.timeout,
                            print_output=args.print_run_output,
                        )
                        if to:
                            timed_out = True
                            break
                        if run_dur is not None:
                            durations.append(run_dur)
                            print(f"  run {i+1}/{args.cpu_runs}: {run_dur:.3f} s")
                    if durations:
                        cpu_sec = statistics.median(durations)
                        print(f"  median run time: {cpu_sec:.3f} s")
                    elif timed_out:
                        cpu_sec = float(args.timeout)

                if role == "initiator":
                    cpu_i = cpu_sec
                    mem_i = ram_kb
                else:
                    cpu_r = cpu_sec
                    mem_r = ram_kb

                timed_out_any = timed_out_any or timed_out
                print(f"  text={text_b} data={data_b} bss={bss_b} -> RAM={ram_kb} KB")
            except KeyboardInterrupt:
                print(f"\nInterrupted during {v.label} ({role}); writing collected rows and exiting early.")
                break

        row_label = v.label if "Zephyr" in v.label else f"{v.label} (Zephyr {args.board})"
        if args.skip_timeouts and timed_out_any:
            print(f"  skipping row (timeout placeholder)")
        else:
            row = format_row(row_label, cpu_i, cpu_r, mem_i, mem_r)
            rows.append(row)

    print("\nCSV rows:")
    for r in rows:
        print(r)

    if args.write_csv:
        csv_path = Path(args.write_csv)
        header = "label,runs,median_cpu_initiator,median_cpu_responder,median_mem_init_kb,median_mem_resp_kb\n"
        write_mode = "w" if args.overwrite_csv or not csv_path.exists() else "a"
        need_header = write_mode == "w"
        with csv_path.open(write_mode, encoding="utf-8") as f:
            if need_header:
                f.write(header)
            for r in rows:
                f.write(r + "\n")
        verb = "Wrote" if write_mode == "w" else "Appended"
        print(f"{verb} {len(rows)} rows to {csv_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
