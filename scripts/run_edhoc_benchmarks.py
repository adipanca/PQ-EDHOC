#!/usr/bin/env python3
"""
Run EDHOC responder/initiator binaries for five variants and record CPU and
memory usage (from /usr/bin/time -v) into benchmarks_edhoc.csv.

Variants:
1. Edhoc type 0 PQ        -> samples/linux_pq_edhoc/<role>/build/<binary>
2. Edhoc type 3 PQ        -> linux_template (PQ-only, KYBER level 3, METHOD_3)
3. Edhoc type 3 Hybrid    -> linux_template (PQ_T_HYBRID on, KYBER level 3)
4. Edhoc type 0 Classic   -> linux_template (SUITE_0, METHOD_0)
5. Edhoc type 3 Classic   -> linux_template (SUITE_0, METHOD_3)

Assumptions: the binaries are built from clean trees with the feature flags
specified below, and LD_LIBRARY_PATH includes the repo build/ directory.
"""
from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
import time
import signal
import statistics
from pathlib import Path
from typing import Dict, Tuple, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
TIME_BIN = "/usr/bin/time"
LD_PATH = str(REPO_ROOT / "build")
OUT_CSV = REPO_ROOT / "benchmarks_edhoc.csv"
LOG_DIR = REPO_ROOT / "bench_logs"
LOG_DIR.mkdir(exist_ok=True)
BENCH_BIN_DIR = REPO_ROOT / "bench_bins"
BENCH_BIN_DIR.mkdir(exist_ok=True)

Variant = Dict[str, object]

VARIANTS: Tuple[Variant, ...] = (
    {
        "label": "Edhoc type 0 PQ",
        "responder": REPO_ROOT
        / "samples/linux_pq_edhoc/responder/build/responder",
        "initiator": REPO_ROOT
        / "samples/linux_pq_edhoc/initiator/build/initiator",
    },
    {
        "label": "Edhoc type 3 PQ",
        "responder": BENCH_BIN_DIR / "type3_pq/responder",
        "initiator": BENCH_BIN_DIR / "type3_pq/initiator",
    },
    {
        "label": "Edhoc type 3 Hybrid",
        "responder": BENCH_BIN_DIR / "type3_hybrid/responder",
        "initiator": BENCH_BIN_DIR / "type3_hybrid/initiator",
    },
    {
        "label": "Edhoc type 0 Classic",
        "responder": BENCH_BIN_DIR / "type0_classic/responder",
        "initiator": BENCH_BIN_DIR / "type0_classic/initiator",
    },
    {
        "label": "Edhoc type 3 Classic",
        "responder": BENCH_BIN_DIR / "type3_classic/responder",
        "initiator": BENCH_BIN_DIR / "type3_classic/initiator",
    },
)

TIME_USER_RE = re.compile(r"User time .*: ([0-9.]+)")
TIME_SYS_RE = re.compile(r"System time .*: ([0-9.]+)")
TIME_RSS_RE = re.compile(r"Maximum resident set size \(kbytes\): ([0-9]+)")


def parse_time_output(path: Path) -> Tuple[float, int]:
    user = sys = rss = None
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if user is None:
                m = TIME_USER_RE.search(line)
                if m:
                    user = float(m.group(1))
                    continue
            if sys is None:
                m = TIME_SYS_RE.search(line)
                if m:
                    sys = float(m.group(1))
                    continue
            if rss is None:
                m = TIME_RSS_RE.search(line)
                if m:
                    rss = int(m.group(1))
                    continue
    if user is None or sys is None or rss is None:
        raise RuntimeError(f"Failed to parse time output from {path}")
    return user + sys, rss


def run_timed(cmd: Path, log_prefix: str, env: Dict[str, str]) -> Tuple[int, float, int]:
    stdout_path = LOG_DIR / f"{log_prefix}.out"
    time_path = LOG_DIR / f"{log_prefix}.time"
    with stdout_path.open("w") as out, time_path.open("w") as terr:
        proc = subprocess.Popen(
            [TIME_BIN, "-v", str(cmd)], stdout=out, stderr=terr, env=env, cwd=cmd.parent
        )
        rc = proc.wait()
    cpu, rss = parse_time_output(time_path)
    return rc, cpu, rss


def _ps_stats(pid: int) -> Tuple[float, int]:
    """Return (cpu_seconds, rss_kb) for a running process via ps."""
    ps = subprocess.check_output(["ps", "-p", str(pid), "-o", "cputime=", "-o", "rss="])
    parts = ps.decode().strip().split()
    if len(parts) != 2:
        raise RuntimeError(f"Unexpected ps output: {ps}")
    cputime_str, rss_kb_str = parts
    # cputime format [[dd-]hh:]mm:ss
    t_fields = cputime_str.split(":")
    if len(t_fields) == 3:
        hh, mm, ss = t_fields
        days = 0
    elif len(t_fields) == 4:  # dd-hh:mm:ss
        days_hh, mm, ss = t_fields[0], t_fields[1], t_fields[2]
        days, hh = days_hh.split("-")
    else:
        raise RuntimeError(f"Unexpected cputime format: {cputime_str}")
    total_seconds = int(days) * 24 * 3600 + int(hh) * 3600 + int(mm) * 60 + int(ss)
    return float(total_seconds), int(rss_kb_str)


def _configure_template_features(feature_additions: List[str]) -> str:
    """Rewrite makefile_config.mk with provided feature additions. Returns backup."""
    cfg_path = REPO_ROOT / "makefile_config.mk"
    original = cfg_path.read_text()
    lines = []
    for line in original.splitlines():
        if any(
            marker in line
            for marker in (
                "-DPQ_T_HYBRID",
                "-DFALCON_LEVEL_1",
                "-DKYBER_LEVEL_1",
                "-DKYBER_LEVEL_3",
                "-DEDHOC_SUITE_LABEL",
                "-DEDHOC_METHOD",
            )
        ):
            continue
        lines.append(line)

    lines.extend(feature_additions)

    cfg_path.write_text("\n".join(lines) + "\n")
    return original


def _run_cmd(cmd: List[str], cwd: Path):
    proc = subprocess.run(cmd, cwd=str(cwd))
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")


def build_template_variant(name: str, feature_additions: List[str], dest_dir: Path):
    """Build linux_template with provided feature additions and copy binaries."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    responder_dir = REPO_ROOT / "samples/linux_template/responder"
    initiator_dir = REPO_ROOT / "samples/linux_template/initiator"

    backup = _configure_template_features(feature_additions)
    try:
        _run_cmd(["make", "clean"], responder_dir)
        _run_cmd(["make", "-j4"], responder_dir)
        _run_cmd(["make", "clean"], initiator_dir)
        _run_cmd(["make", "-j4"], initiator_dir)

        shutil.copy(responder_dir / "build/responder", dest_dir / "responder")
        shutil.copy(initiator_dir / "build/initiator", dest_dir / "initiator")
    finally:
        # restore original config
        (REPO_ROOT / "makefile_config.mk").write_text(backup)


def run_variant(variant: Variant, env: Dict[str, str], run_index: Optional[int] = None):
    label = variant["label"]
    resp_cmd: Path = variant["responder"]
    init_cmd: Path = variant["initiator"]

    if not resp_cmd.exists() or not init_cmd.exists():
        raise FileNotFoundError(f"Missing binaries for {label}: {resp_cmd} or {init_cmd}")

    # Run responder timed in background
    suffix = f"_run{run_index}" if run_index is not None else ""
    resp_prefix = label.replace(" ", "_") + "_resp" + suffix
    resp_out = LOG_DIR / f"{resp_prefix}.out"
    resp_time = LOG_DIR / f"{resp_prefix}.time"
    with resp_out.open("w") as resp_out_f, resp_time.open("w") as resp_time_f:
        resp_proc = subprocess.Popen(
            [TIME_BIN, "-v", str(resp_cmd)],
            stdout=resp_out_f,
            stderr=resp_time_f,
            env=env,
            cwd=resp_cmd.parent,
        )

        # Give responder a moment to bind
        time.sleep(1.0)

        # Run initiator timed (foreground)
        init_rc, init_cpu, init_rss = run_timed(
            init_cmd, label.replace(" ", "_") + "_init" + suffix, env
        )

    # Allow a short settle
    time.sleep(0.3)

    # Try to signal the responder child (so /usr/bin/time can finish cleanly)
    child_pids = []
    try:
        out = subprocess.check_output(["pgrep", "-P", str(resp_proc.pid)])
        child_pids = [int(p) for p in out.decode().strip().split()] if out else []
    except subprocess.CalledProcessError:
        pass
    for cpid in child_pids:
        try:
            os.kill(cpid, signal.SIGINT)
        except ProcessLookupError:
            pass

    # Wait for time wrapper
    try:
        resp_rc = resp_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        resp_proc.kill()
        resp_rc = resp_proc.wait()

    try:
        resp_cpu, resp_rss = parse_time_output(resp_time)
    except Exception:
        # Fallback: if time output missing, use ps on first child if any, else time proc
        target_pid = child_pids[0] if child_pids else resp_proc.pid
        resp_cpu, resp_rss = _ps_stats(target_pid)

    if init_rc != 0:
        raise RuntimeError(f"Initiator failed for {label} rc={init_rc}")

    return init_cpu, resp_cpu, init_rss, resp_rss


def main():
    parser = argparse.ArgumentParser(description="Run EDHOC benchmarks")
    parser.add_argument(
        "--runs",
        type=int,
        default=10000,
        help="Number of handshakes per variant (default: 10000)",
    )
    args = parser.parse_args()

    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = LD_PATH

    # Build template variants once per run
    print("Building Type 3 PQ (PQ-only)...")
    build_template_variant(
        "type3_pq",
        feature_additions=[
            # PQ-only: remove PQ_T_HYBRID so only the PQ KEM is used
            "FEATURES += -DKYBER_LEVEL_3",
            "FEATURES += -DEDHOC_SUITE_LABEL=SUITE_21",
            "FEATURES += -DEDHOC_METHOD=METHOD_3",
        ],
        dest_dir=BENCH_BIN_DIR / "type3_pq",
    )
    print("Building Type 3 Hybrid (hybrid on)...")
    build_template_variant(
        "type3_hybrid",
        feature_additions=[
            "FEATURES += -DPQ_T_HYBRID",
            "FEATURES += -DKYBER_LEVEL_3",
            "FEATURES += -DEDHOC_SUITE_LABEL=SUITE_21",
            "FEATURES += -DEDHOC_METHOD=METHOD_3",
        ],
        dest_dir=BENCH_BIN_DIR / "type3_hybrid",
    )
    print("Building Type 0 Classic (x25519/EdDSA, method 0)...")
    build_template_variant(
        "type0_classic",
        feature_additions=[
            "FEATURES += -DEDHOC_SUITE_LABEL=SUITE_0",
            "FEATURES += -DEDHOC_METHOD=METHOD_0",
        ],
        dest_dir=BENCH_BIN_DIR / "type0_classic",
    )
    print("Building Type 3 Classic (x25519/EdDSA, method 3)...")
    build_template_variant(
        "type3_classic",
        feature_additions=[
            "FEATURES += -DEDHOC_SUITE_LABEL=SUITE_0",
            "FEATURES += -DEDHOC_METHOD=METHOD_3",
        ],
        dest_dir=BENCH_BIN_DIR / "type3_classic",
    )

    rows = []
    for variant in VARIANTS:
        label = variant["label"]
        print(f"Running variant: {label} for {args.runs} handshakes")
        init_cpus: List[float] = []
        resp_cpus: List[float] = []
        init_mem: List[int] = []
        resp_mem: List[int] = []

        progress_every = max(1, args.runs // 10)

        for i in range(args.runs):
            if (i + 1) % progress_every == 0 or i == 0:
                print(f"  run {i+1}/{args.runs}")
            init_cpu, resp_cpu, init_rss, resp_rss = run_variant(variant, env, i + 1)
            init_cpus.append(init_cpu)
            resp_cpus.append(resp_cpu)
            init_mem.append(init_rss)
            resp_mem.append(resp_rss)

        rows.append(
            {
                "label": label,
                "runs": args.runs,
                "median_cpu_initiator": statistics.median(init_cpus),
                "median_cpu_responder": statistics.median(resp_cpus),
                "median_mem_init_kb": int(statistics.median(init_mem)),
                "median_mem_resp_kb": int(statistics.median(resp_mem)),
            }
        )

    with OUT_CSV.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "label",
                "runs",
                "median_cpu_initiator",
                "median_cpu_responder",
                "median_mem_init_kb",
                "median_mem_resp_kb",
            ],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"Results written to {OUT_CSV}")


if __name__ == "__main__":
    main()
