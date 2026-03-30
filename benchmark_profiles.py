#!/usr/bin/env python3
"""Shared benchmark profile definitions for EDHOC benchmark runners.

This module centralizes suite/vector/method mapping so:
- `run_handshake_timing_benchmark.py`
- `run_edhoc_benchmark.py`
- `run_ops_benchmark.py`

all use one canonical source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Literal


MethodType = Literal[0, 3]


@dataclass(frozen=True)
class BenchmarkProfile:
    key: str
    label: str
    suite: int
    vector: int
    force_method: MethodType | None = None
    classic_fast: bool = False
    ops_type3_pq_label: bool = False


def profile_to_cmake_flags(profile: BenchmarkProfile, *, include_use_test_edhoc: bool) -> List[str]:
    flags: List[str] = [
        f"-DUSE_SUIT_{profile.suite}=ON",
        "-DUSE_X5T=1",
        f"-DTEST_VECTOR_IDX_OVERRIDE={profile.vector}",
    ]
    if include_use_test_edhoc:
        flags.append("-DUSE_TEST_EDHOC=1")
    if profile.classic_fast:
        flags.extend([
            "-DUSE_LIBSODIUM_CLASSIC=ON",
            "-DUSE_CLASSIC_FAST_BENCH=ON",
        ])
    if profile.force_method == 0:
        flags.append("-DFORCE_METHOD_TYPE_0=ON")
    elif profile.force_method == 3:
        flags.append("-DFORCE_METHOD_TYPE_3=ON")
    return flags


def get_handshake_timing_profiles() -> List[BenchmarkProfile]:
    return [
        BenchmarkProfile(
            key="type3-classic",
            label="Edhoc type 3 Classic",
            suite=2,
            vector=5,
            force_method=3,
            classic_fast=True,
        ),
        BenchmarkProfile(
            key="type3-pq",
            label="Edhoc type 3 PQ",
            suite=9,
            vector=9,
        ),
        BenchmarkProfile(
            key="type3-hybrid",
            label="Edhoc type 3 Hybrid",
            suite=18,
            vector=18,
        ),
        BenchmarkProfile(
            key="type0-classic",
            label="Edhoc type 0 Classic",
            suite=2,
            vector=2,
            force_method=0,
            classic_fast=True,
        ),
        BenchmarkProfile(
            key="type0-pq",
            label="Edhoc type 0 PQ",
            suite=9,
            vector=10,
            force_method=0,
        ),
    ]


def get_edhoc_profiles() -> List[BenchmarkProfile]:
    return [
        BenchmarkProfile(
            key="pq-sign",
            label="Edhoc type 0 PQ",
            suite=9,
            vector=10,
            force_method=0,
        ),
        BenchmarkProfile(
            key="pq-mac",
            label="Edhoc type 3 PQ",
            suite=9,
            vector=9,
        ),
        BenchmarkProfile(
            key="hybrid-mac",
            label="Edhoc type 3 Hybrid",
            suite=18,
            vector=18,
        ),
        BenchmarkProfile(
            key="classic-sign",
            label="Edhoc type 0 Classic x25519",
            suite=2,
            vector=2,
            force_method=0,
            classic_fast=True,
        ),
        BenchmarkProfile(
            key="classic-mac",
            label="Edhoc type 3 Classic x25519",
            suite=2,
            vector=5,
            force_method=3,
            classic_fast=True,
        ),
    ]


def get_ops_profiles() -> List[BenchmarkProfile]:
    return [
        BenchmarkProfile(
            key="type3-classic",
            label="Type 3 Classic",
            suite=2,
            vector=5,
            force_method=3,
            classic_fast=True,
        ),
        BenchmarkProfile(
            key="type3-pq",
            label="Type 3 PQ",
            suite=9,
            vector=9,
            ops_type3_pq_label=True,
        ),
        BenchmarkProfile(
            key="type3-hybrid",
            label="Type 3 Hybrid",
            suite=18,
            vector=18,
        ),
        BenchmarkProfile(
            key="type0-classic",
            label="Type 0 Classic",
            suite=2,
            vector=2,
            force_method=0,
            classic_fast=True,
        ),
        BenchmarkProfile(
            key="type0-pq",
            label="Type 0 PQ",
            suite=9,
            vector=10,
            force_method=0,
        ),
    ]
