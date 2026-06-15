#!/usr/bin/env python3
"""Dump stats from trinity's ~/.cache/trinity/ persisted artifacts.

Parses three on-disk formats version-aware:
  - kcov-bitmap        magic "KCBV", versions 4, 5, 6, 7
  - corpus/<arch>      magic "TRNC", version 3
  - cmp-hints          magic "CHP_", version 4

Two modes:
  stats <cache-dir>            single-kernel summary
  diff  <cacheA> <cacheB>      cross-kernel proxies (not edge-level)

Edge-level diff across kernels is impossible from saved files: the bitmap is a
hashed, non-invertible bucket table that is kernel-build-specific (different
inlining/layout maps the same source-level edge to a different slot). diff mode
prints proxies only, and labels them as such.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import zlib
from dataclasses import dataclass, field
from typing import Optional

KCOV_MAGIC = 0x4B434256
CORPUS_MAGIC = 0x54524E43
CMP_HINTS_MAGIC = 0x4348505F

KCOV_NUM_EDGES = 1 << 23
KCOV_NUM_BUCKETS = 8
MAX_NR_SYSCALL = 1024
CORPUS_RING_SIZE = 32
CMP_HINTS_PER_SYSCALL = 16

KCOV_HDR_COMMON = "<IIIIQQII32sII"
KCOV_HDR_COMMON_SIZE = struct.calcsize(KCOV_HDR_COMMON)
KCOV_HDR_V4_SIZE = 120
KCOV_HDR_V5_SIZE = 88
KCOV_HDR_V7_SIZE = 96
KCOV_HDR_V7_TRAILER_FMT = "<II"

KCOV_NR_STRATEGIES = 3
KCOV_STRATEGY_NAMES = ("HEURISTIC", "RANDOM", "FRONTIER")
KCOV_STRAT_BLOCK_FMT = f"<{KCOV_NR_STRATEGIES * 2}Q"
KCOV_STRAT_BLOCK_SIZE = struct.calcsize(KCOV_STRAT_BLOCK_FMT)

CORPUS_HDR_FMT = "<IIIIII65s65s"
CORPUS_HDR_SIZE_RAW = struct.calcsize(CORPUS_HDR_FMT)
CORPUS_HDR_SIZE = (CORPUS_HDR_SIZE_RAW + 3) & ~3
CORPUS_ENTRY_FMT = "<II6QII"
CORPUS_ENTRY_SIZE = struct.calcsize(CORPUS_ENTRY_FMT)

CMP_HINTS_HDR_FMT = "<IIIIIIQ32sQ"
CMP_HINTS_HDR_SIZE = struct.calcsize(CMP_HINTS_HDR_FMT)
CMP_HINTS_ENTRY_FMT = "<QQIIQ"
CMP_HINTS_ENTRY_SIZE = struct.calcsize(CMP_HINTS_ENTRY_FMT)
CMP_HINTS_POOL_SIZE = 4 + 4 + CMP_HINTS_PER_SYSCALL * CMP_HINTS_ENTRY_SIZE


def warn(msg: str) -> None:
    print(f"warn: {msg}", file=sys.stderr)


def cstr(b: bytes) -> str:
    end = b.find(b"\x00")
    if end >= 0:
        b = b[:end]
    return b.decode("utf-8", errors="replace")


def fmt_pct(num: float) -> str:
    return f"{num * 100:.4f}%"


def script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def load_syscall_names(arch: str) -> dict[int, str]:
    """Best-effort: parse ../include/syscalls-<arch>.h for an nr->name map.

    Returns {} when the table is unavailable; callers fall back to "nr=N".
    """
    table = os.path.join(script_dir(), os.pardir, "include", f"syscalls-{arch}.h")
    table = os.path.normpath(table)
    if not os.path.isfile(table):
        return {}
    names: dict[int, str] = {}
    nr = 0
    started = False
    with open(table) as fh:
        for line in fh:
            stripped = line.strip()
            if not started:
                if stripped.startswith(f"struct syscalltable syscalls_{arch}[]"):
                    started = True
                continue
            if stripped.startswith("};"):
                break
            if ".entry" not in stripped or "syscall_" not in stripped:
                continue
            sym_start = stripped.find("syscall_")
            sym = stripped[sym_start + len("syscall_") :]
            sym = sym.split()[0].rstrip(",}).;")
            if sym:
                names[nr] = sym
            nr += 1
    return names


def arch_from_dirname(name: str) -> Optional[str]:
    """Cache subdir names look like 'x86_64-7.1.0-rc7-gen10+'; arch is the
    leading component up to the first '-' (or the whole name if no dash).
    """
    if not name:
        return None
    return name.split("-", 1)[0]


@dataclass
class KcovData:
    path: str
    version: int
    edges_found: int
    distinct_edges: int
    payload_crc32: int
    priors_crc32: int
    max_nr_syscall: int
    kallsyms_sha256: bytes
    bitmap_popcount: int
    bitmap_nonzero: int
    kaslr_base: Optional[int]
    boot_id: Optional[str]
    per_syscall_edges: list[int]
    per_syscall_calls: list[int]
    diag_present: bool
    diag_bucket_bits_real: list[int] = field(default_factory=list)
    diag_distinct_pcs: list[int] = field(default_factory=list)
    diag_crc32: Optional[int] = None
    strat_present: bool = False
    strat_crc32: Optional[int] = None
    strat_calls_by_strategy: list[int] = field(default_factory=list)
    strat_count_by_strategy: list[int] = field(default_factory=list)
    crc_ok: bool = True
    notes: list[str] = field(default_factory=list)


def load_kcov(path: str) -> Optional[KcovData]:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        warn(f"kcov: open {path}: {exc}")
        return None

    if len(raw) < KCOV_HDR_V5_SIZE:
        warn(f"kcov: {path}: file too small ({len(raw)} bytes)")
        return None

    magic, version = struct.unpack_from("<II", raw, 0)
    if magic != KCOV_MAGIC:
        warn(f"kcov: {path}: bad magic 0x{magic:08x}")
        return None
    if version not in (4, 5, 6, 7):
        warn(f"kcov: {path}: unsupported version {version}")
        return None

    (
        magic,
        version,
        num_edges,
        num_buckets,
        edges_found,
        distinct_edges,
        payload_crc32,
        hdr_pad_or_diag_crc,
        kallsyms_sha256,
        max_nr_syscall,
        priors_crc32,
    ) = struct.unpack_from(KCOV_HDR_COMMON, raw, 0)

    if num_edges != KCOV_NUM_EDGES:
        warn(f"kcov: {path}: unexpected num_edges {num_edges}")
        return None
    if num_buckets != KCOV_NUM_BUCKETS:
        warn(f"kcov: {path}: unexpected num_buckets {num_buckets}")
        return None

    boot_id: Optional[str] = None
    kaslr_base: Optional[int] = None
    diag_crc32: Optional[int] = None
    strat_crc32: Optional[int] = None

    if version == 4:
        # v4 trails the common prefix with a 40-byte boot-id block instead of
        # a u64 kaslr_base; hdr_pad_or_diag_crc is still the leading u32 pad.
        boot_block = raw[KCOV_HDR_COMMON_SIZE : KCOV_HDR_COMMON_SIZE + 40]
        if len(boot_block) < 40:
            warn(f"kcov: {path}: truncated v4 header")
            return None
        boot_id = cstr(boot_block[:37])
        hdr_size = KCOV_HDR_V4_SIZE
    else:
        (kaslr_base,) = struct.unpack_from("<Q", raw, KCOV_HDR_COMMON_SIZE)
        hdr_size = KCOV_HDR_V5_SIZE
        if version >= 6:
            diag_crc32 = hdr_pad_or_diag_crc
        if version >= 7:
            if len(raw) < KCOV_HDR_V7_SIZE:
                warn(f"kcov: {path}: truncated v7 header")
                return None
            (strat_crc32, _pad2) = struct.unpack_from(
                KCOV_HDR_V7_TRAILER_FMT, raw, KCOV_HDR_V5_SIZE
            )
            hdr_size = KCOV_HDR_V7_SIZE

    payload_end = hdr_size + KCOV_NUM_EDGES
    priors_end = payload_end + 2 * MAX_NR_SYSCALL * 8

    if len(raw) < priors_end:
        warn(f"kcov: {path}: short payload (have {len(raw)}, want >= {priors_end})")
        return None

    bitmap = raw[hdr_size:payload_end]
    priors = raw[payload_end:priors_end]

    calc_payload_crc = zlib.crc32(bitmap) & 0xFFFFFFFF
    calc_priors_crc = zlib.crc32(priors) & 0xFFFFFFFF

    crc_ok = True
    notes: list[str] = []
    if calc_payload_crc != payload_crc32:
        crc_ok = False
        notes.append(
            f"payload_crc32 mismatch: file=0x{payload_crc32:08x} "
            f"calc=0x{calc_payload_crc:08x}"
        )
    if calc_priors_crc != priors_crc32:
        crc_ok = False
        notes.append(
            f"priors_crc32 mismatch: file=0x{priors_crc32:08x} "
            f"calc=0x{calc_priors_crc:08x}"
        )

    bitmap_int = int.from_bytes(bitmap, "little")
    bitmap_popcount = bitmap_int.bit_count()
    bitmap_nonzero = KCOV_NUM_EDGES - bitmap.count(0)

    per_edges = list(struct.unpack(f"<{MAX_NR_SYSCALL}Q", priors[: MAX_NR_SYSCALL * 8]))
    per_calls = list(struct.unpack(f"<{MAX_NR_SYSCALL}Q", priors[MAX_NR_SYSCALL * 8 :]))

    diag_present = False
    diag_bucket_bits_real: list[int] = []
    diag_distinct_pcs: list[int] = []
    diag_end = priors_end

    if version >= 6:
        diag_bytes = MAX_NR_SYSCALL * 2 * 16
        diag_end = priors_end + diag_bytes
        if len(raw) < diag_end:
            warn(
                f"kcov: {path}: v6 diag block truncated "
                f"(have {len(raw)}, want >= {diag_end})"
            )
            diag_end = priors_end
        else:
            diag = raw[priors_end:diag_end]
            calc_diag_crc = zlib.crc32(diag) & 0xFFFFFFFF
            if diag_crc32 is not None and calc_diag_crc != diag_crc32:
                crc_ok = False
                notes.append(
                    f"diag_crc32 mismatch: file=0x{diag_crc32:08x} "
                    f"calc=0x{calc_diag_crc:08x}"
                )
            flat = struct.unpack(f"<{MAX_NR_SYSCALL * 2 * 2}Q", diag)
            for i in range(MAX_NR_SYSCALL):
                base = i * 4
                diag_bucket_bits_real.append(flat[base] + flat[base + 2])
                diag_distinct_pcs.append(flat[base + 1] + flat[base + 3])
            diag_present = True

    strat_present = False
    strat_calls_by_strategy: list[int] = []
    strat_count_by_strategy: list[int] = []

    if version >= 7:
        strat_end = diag_end + KCOV_STRAT_BLOCK_SIZE
        if len(raw) < strat_end:
            notes.append(
                f"v7 strat block truncated " f"(have {len(raw)}, want >= {strat_end})"
            )
        else:
            strat_blob = raw[diag_end:strat_end]
            calc_strat_crc = zlib.crc32(strat_blob) & 0xFFFFFFFF
            if strat_crc32 is not None and calc_strat_crc != strat_crc32:
                notes.append(
                    f"strat_crc32 mismatch: file=0x{strat_crc32:08x} "
                    f"calc=0x{calc_strat_crc:08x} (strat block skipped)"
                )
            else:
                vals = struct.unpack(KCOV_STRAT_BLOCK_FMT, strat_blob)
                strat_calls_by_strategy = list(vals[:KCOV_NR_STRATEGIES])
                strat_count_by_strategy = list(vals[KCOV_NR_STRATEGIES:])
                strat_present = True

    if bitmap_popcount != edges_found:
        notes.append(f"popcount {bitmap_popcount} != edges_found {edges_found}")
    if bitmap_nonzero != distinct_edges:
        notes.append(
            f"nonzero bytes {bitmap_nonzero} != distinct_edges {distinct_edges}"
        )

    return KcovData(
        path=path,
        version=version,
        edges_found=edges_found,
        distinct_edges=distinct_edges,
        payload_crc32=payload_crc32,
        priors_crc32=priors_crc32,
        max_nr_syscall=max_nr_syscall,
        kallsyms_sha256=kallsyms_sha256,
        bitmap_popcount=bitmap_popcount,
        bitmap_nonzero=bitmap_nonzero,
        kaslr_base=kaslr_base,
        boot_id=boot_id,
        per_syscall_edges=per_edges,
        per_syscall_calls=per_calls,
        diag_present=diag_present,
        diag_bucket_bits_real=diag_bucket_bits_real,
        diag_distinct_pcs=diag_distinct_pcs,
        diag_crc32=diag_crc32,
        strat_present=strat_present,
        strat_crc32=strat_crc32,
        strat_calls_by_strategy=strat_calls_by_strategy,
        strat_count_by_strategy=strat_count_by_strategy,
        crc_ok=crc_ok,
        notes=notes,
    )


@dataclass
class CorpusData:
    path: str
    version: int
    kernel_major: int
    kernel_minor: int
    max_nr_syscall: int
    kernel_release: str
    kernel_version: str
    entries_total: int
    entries_valid: int
    per_syscall_count: dict[int, int]
    arg_histograms: dict[int, list[dict[int, int]]]
    notes: list[str] = field(default_factory=list)


def load_corpus(path: str) -> Optional[CorpusData]:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        warn(f"corpus: open {path}: {exc}")
        return None

    if len(raw) < CORPUS_HDR_SIZE:
        warn(f"corpus: {path}: file too small ({len(raw)} bytes)")
        return None

    (
        magic,
        version,
        kernel_major,
        kernel_minor,
        max_nr_syscall,
        _reserved,
        release_b,
        version_b,
    ) = struct.unpack_from(CORPUS_HDR_FMT, raw, 0)
    if magic != CORPUS_MAGIC:
        warn(f"corpus: {path}: bad magic 0x{magic:08x}")
        return None
    if version != 3:
        warn(f"corpus: {path}: unsupported version {version}")
        return None
    if max_nr_syscall != MAX_NR_SYSCALL:
        warn(f"corpus: {path}: unexpected max_nr_syscall {max_nr_syscall}")

    kernel_release = cstr(release_b)
    kernel_version = cstr(version_b)

    body = raw[CORPUS_HDR_SIZE:]
    notes: list[str] = []
    if len(body) % CORPUS_ENTRY_SIZE != 0:
        notes.append(f"trailing partial entry: {len(body) % CORPUS_ENTRY_SIZE} bytes")

    per_syscall_count: dict[int, int] = {}
    arg_histograms: dict[int, list[dict[int, int]]] = {}
    entries_total = 0
    entries_valid = 0

    for off in range(0, len(body) - (len(body) % CORPUS_ENTRY_SIZE), CORPUS_ENTRY_SIZE):
        entries_total += 1
        ent = struct.unpack_from(CORPUS_ENTRY_FMT, body, off)
        nr, num_args = ent[0], ent[1]
        args = ent[2:8]
        crc_field = ent[8]
        payload = body[off : off + CORPUS_ENTRY_SIZE - 8]
        calc_crc = zlib.crc32(payload) & 0xFFFFFFFF
        if calc_crc != crc_field:
            continue
        entries_valid += 1
        per_syscall_count[nr] = per_syscall_count.get(nr, 0) + 1
        if nr not in arg_histograms:
            arg_histograms[nr] = [{} for _ in range(6)]
        capped = min(num_args, 6)
        for i in range(capped):
            arg_histograms[nr][i][args[i]] = arg_histograms[nr][i].get(args[i], 0) + 1

    return CorpusData(
        path=path,
        version=version,
        kernel_major=kernel_major,
        kernel_minor=kernel_minor,
        max_nr_syscall=max_nr_syscall,
        kernel_release=kernel_release,
        kernel_version=kernel_version,
        entries_total=entries_total,
        entries_valid=entries_valid,
        per_syscall_count=per_syscall_count,
        arg_histograms=arg_histograms,
        notes=notes,
    )


@dataclass
class CmpHintsData:
    path: str
    version: int
    max_syscall: int
    per_syscall: int
    entry_size: int
    payload_crc32: int
    payload_bytes: int
    kallsyms_sha256: bytes
    kaslr_base: int
    per_syscall_filled: list[int]
    pool_dim_filled: list[list[int]]
    total_constants: int
    most_recent_last_used: int
    crc_ok: bool
    notes: list[str] = field(default_factory=list)


def load_cmp_hints(path: str) -> Optional[CmpHintsData]:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        warn(f"cmp-hints: open {path}: {exc}")
        return None

    if len(raw) < CMP_HINTS_HDR_SIZE:
        warn(f"cmp-hints: {path}: file too small ({len(raw)} bytes)")
        return None

    (
        magic,
        version,
        max_syscall,
        per_syscall,
        entry_size,
        payload_crc32,
        payload_bytes,
        kallsyms_sha256,
        kaslr_base,
    ) = struct.unpack_from(CMP_HINTS_HDR_FMT, raw, 0)
    if magic != CMP_HINTS_MAGIC:
        warn(f"cmp-hints: {path}: bad magic 0x{magic:08x}")
        return None
    if version != 5:
        warn(f"cmp-hints: {path}: unsupported version {version}")
        return None
    if entry_size != CMP_HINTS_ENTRY_SIZE:
        warn(f"cmp-hints: {path}: unexpected entry_size {entry_size}")
        return None
    if per_syscall != CMP_HINTS_PER_SYSCALL:
        warn(f"cmp-hints: {path}: unexpected per_syscall {per_syscall}")
        return None

    expected_payload = max_syscall * 2 * CMP_HINTS_POOL_SIZE
    if payload_bytes != expected_payload:
        warn(
            f"cmp-hints: {path}: payload_bytes {payload_bytes} "
            f"!= expected {expected_payload}"
        )

    payload = raw[CMP_HINTS_HDR_SIZE : CMP_HINTS_HDR_SIZE + payload_bytes]
    if len(payload) < payload_bytes:
        warn(f"cmp-hints: {path}: payload truncated")
        return None

    calc_crc = zlib.crc32(payload) & 0xFFFFFFFF
    crc_ok = calc_crc == payload_crc32
    notes: list[str] = []
    if not crc_ok:
        notes.append(
            f"payload_crc32 mismatch: file=0x{payload_crc32:08x} calc=0x{calc_crc:08x}"
        )

    per_syscall_filled = [0] * max_syscall
    pool_dim_filled = [[0, 0] for _ in range(max_syscall)]
    total_constants = 0
    most_recent_last_used = 0

    for i in range(max_syscall):
        for a in range(2):
            base = (i * 2 + a) * CMP_HINTS_POOL_SIZE
            count, _generation = struct.unpack_from("<II", payload, base)
            if count > per_syscall:
                count = per_syscall
            pool_dim_filled[i][a] = count
            per_syscall_filled[i] += count
            total_constants += count
            for j in range(count):
                eoff = base + 8 + j * CMP_HINTS_ENTRY_SIZE
                _value, _cmp_ip, _size, _pad, last_used = struct.unpack_from(
                    CMP_HINTS_ENTRY_FMT, payload, eoff
                )
                if last_used > most_recent_last_used:
                    most_recent_last_used = last_used

    return CmpHintsData(
        path=path,
        version=version,
        max_syscall=max_syscall,
        per_syscall=per_syscall,
        entry_size=entry_size,
        payload_crc32=payload_crc32,
        payload_bytes=payload_bytes,
        kallsyms_sha256=kallsyms_sha256,
        kaslr_base=kaslr_base,
        per_syscall_filled=per_syscall_filled,
        pool_dim_filled=pool_dim_filled,
        total_constants=total_constants,
        most_recent_last_used=most_recent_last_used,
        crc_ok=crc_ok,
        notes=notes,
    )


@dataclass
class CacheBundle:
    cache_dir: str
    kernel_label: str
    arch: Optional[str]
    syscall_names: dict[int, str]
    kcov: Optional[KcovData]
    corpus: Optional[CorpusData]
    cmp_hints: Optional[CmpHintsData]


def syscall_label(names: dict[int, str], nr: int) -> str:
    name = names.get(nr)
    if name:
        return f"nr={nr:<4d} {name}"
    return f"nr={nr:<4d} <unnamed>"


def find_artifact(
    root: str, top: str, kernel: Optional[str] = None
) -> tuple[Optional[str], Optional[str]]:
    """Resolve an artifact path under the cache root.

    Layouts handled:
      root/<top>                 -- file (flat single-kernel layout).
      root/<top>/<file>          -- per-kernel files named like
                                    'x86_64-7.1.0-rc7-gen10+'.
    When the directory holds several per-kernel files, pick the one whose
    name contains <kernel> (a substring such as '7.1.0-rc7'); with no
    kernel hint, pick the newest by mtime.  Returns (path, arch_hint);
    arch_hint is the leading arch component of the chosen filename.
    """
    candidate = os.path.join(root, top)
    if os.path.isfile(candidate):
        return candidate, None
    if os.path.isdir(candidate):
        files = [
            s
            for s in os.listdir(candidate)
            if os.path.isfile(os.path.join(candidate, s))
        ]
        if kernel is not None:
            files = [s for s in files if kernel in s]
        if not files:
            return None, None
        chosen = max(files, key=lambda s: os.path.getmtime(os.path.join(candidate, s)))
        return os.path.join(candidate, chosen), arch_from_dirname(chosen)
    return None, None


def load_bundle(cache_dir: str, kernel: Optional[str] = None) -> CacheBundle:
    cache_dir = os.path.abspath(cache_dir)
    base = os.path.basename(cache_dir.rstrip("/"))

    kcov_path, kcov_arch = find_artifact(cache_dir, "kcov-bitmap", kernel)
    corpus_path, corpus_arch = find_artifact(cache_dir, "corpus", kernel)
    cmp_path, cmp_arch = find_artifact(cache_dir, "cmp-hints", kernel)

    arch = corpus_arch or kcov_arch or cmp_arch or arch_from_dirname(base)
    syscall_names = load_syscall_names(arch) if arch else {}

    kcov = load_kcov(kcov_path) if kcov_path else None
    corpus = load_corpus(corpus_path) if corpus_path else None
    cmp_hints = load_cmp_hints(cmp_path) if cmp_path else None

    if corpus is not None:
        kernel_label = corpus.kernel_release
    else:
        kernel_label = base

    return CacheBundle(
        cache_dir=cache_dir,
        kernel_label=kernel_label,
        arch=arch,
        syscall_names=syscall_names,
        kcov=kcov,
        corpus=corpus,
        cmp_hints=cmp_hints,
    )


def section(title: str) -> None:
    print()
    print(f"== {title} ==")


def print_kcov_stats(b: CacheBundle, top_n: int) -> None:
    section("kcov-bitmap")
    k = b.kcov
    if k is None:
        print("  (no kcov-bitmap loaded)")
        return
    density = k.bitmap_popcount / (KCOV_NUM_EDGES * KCOV_NUM_BUCKETS)
    distinct_density = k.distinct_edges / KCOV_NUM_EDGES
    print(f"  file:            {k.path}")
    print(f"  version:         {k.version}")
    print(f"  edges_found:     {k.edges_found}")
    print(f"  distinct_edges:  {k.distinct_edges}")
    print(
        f"  bitmap popcount: {k.bitmap_popcount}  (bucket-bits set out of "
        f"{KCOV_NUM_EDGES * KCOV_NUM_BUCKETS})"
    )
    print(f"  bitmap density:  {fmt_pct(density)}  (bucket-bits)")
    print(f"  distinct/8M:     {fmt_pct(distinct_density)}  (slot coverage)")
    if k.kaslr_base is not None:
        mode = "canonicalised" if k.kaslr_base != 0 else "raw PCs"
        print(f"  kaslr_base:      0x{k.kaslr_base:016x}  ({mode})")
    if k.boot_id is not None:
        print(f"  boot_id:         {k.boot_id}  (v4 raw-PC mode)")
    crc_state = "OK" if k.crc_ok else "MISMATCH"
    print(f"  crc:             {crc_state}")
    for n in k.notes:
        print(f"  note: {n}")

    if k.diag_present:
        section("top syscalls by edges (v6 diag: bucket_bits_real)")
        ranked = sorted(
            (
                (
                    nr,
                    k.diag_bucket_bits_real[nr],
                    k.diag_distinct_pcs[nr],
                    k.per_syscall_calls[nr],
                )
                for nr in range(MAX_NR_SYSCALL)
                if k.diag_bucket_bits_real[nr] > 0
            ),
            key=lambda t: t[1],
            reverse=True,
        )
        if not ranked:
            print("  (diag block present but empty)")
        else:
            print(
                f"  {'syscall':<28s} {'edges':>12s} "
                f"{'distinct_pcs':>14s} {'calls':>10s}"
            )
            for nr, edges, pcs, calls in ranked[:top_n]:
                print(
                    f"  {syscall_label(b.syscall_names, nr):<28s} "
                    f"{edges:>12d} {pcs:>14d} {calls:>10d}"
                )
    else:
        section("top syscalls by PRODUCTIVE-CALL count (proxy; not edge totals)")
        print("  NOTE: 'productive calls' = number of calls that found >=1 new")
        print("  edge (per_syscall_edges semantics). True per-syscall edge")
        print("  totals are not on disk for kcov v4/v5; needs v6 diag block.")
        ranked = sorted(
            (
                (nr, k.per_syscall_edges[nr], k.per_syscall_calls[nr])
                for nr in range(MAX_NR_SYSCALL)
                if k.per_syscall_edges[nr] > 0
            ),
            key=lambda t: (t[1], t[2]),
            reverse=True,
        )
        if not ranked:
            print("  (no productive calls recorded)")
        else:
            print(
                f"  {'syscall':<28s} {'prod.calls':>12s} {'total.calls':>12s} "
                f"{'ratio':>10s}"
            )
            for nr, prod, calls in ranked[:top_n]:
                ratio = (prod / calls) if calls else 0.0
                print(
                    f"  {syscall_label(b.syscall_names, nr):<28s} "
                    f"{prod:>12d} {calls:>12d} {ratio:>10.4f}"
                )

    section("heavily-called but never-productive syscalls")
    wasted = sorted(
        (
            (nr, k.per_syscall_calls[nr])
            for nr in range(MAX_NR_SYSCALL)
            if k.per_syscall_calls[nr] > 0 and k.per_syscall_edges[nr] == 0
        ),
        key=lambda t: t[1],
        reverse=True,
    )
    if not wasted:
        print("  (none; every called syscall produced >=1 new edge at some point)")
    else:
        print(f"  {'syscall':<28s} {'calls':>12s}")
        for nr, calls in wasted[:top_n]:
            print(f"  {syscall_label(b.syscall_names, nr):<28s} {calls:>12d}")

    if k.version >= 7:
        section("per-strategy coverage (v7)")
        if not k.strat_present:
            print("  v7 strat block absent")
        else:
            print(f"  {'strategy':<12s} {'prod-calls':>14s} {'edges(real)':>14s}")
            for s, name in enumerate(KCOV_STRATEGY_NAMES):
                print(
                    f"  {name:<12s} "
                    f"{k.strat_calls_by_strategy[s]:>14d} "
                    f"{k.strat_count_by_strategy[s]:>14d}"
                )


def print_corpus_stats(b: CacheBundle, top_n: int) -> None:
    section("corpus")
    c = b.corpus
    if c is None:
        print("  (no corpus loaded)")
        return
    full_rings = sum(1 for v in c.per_syscall_count.values() if v >= CORPUS_RING_SIZE)
    print(f"  file:            {c.path}")
    print(f"  kernel_release:  {c.kernel_release}")
    print(f"  kernel_version:  {c.kernel_version}")
    print(f"  entries total:   {c.entries_total} ({c.entries_valid} CRC-valid)")
    print(f"  distinct sys:    {len(c.per_syscall_count)}")
    print(f"  full rings:      {full_rings}  (ring_size={CORPUS_RING_SIZE})")
    for n in c.notes:
        print(f"  note: {n}")

    section("top syscalls by retained interesting sequences")
    ranked = sorted(c.per_syscall_count.items(), key=lambda t: t[1], reverse=True)
    print(
        f"  {'syscall':<28s} {'kept':>6s}  arg-value histograms (top entry / "
        "distinct)"
    )
    for nr, kept in ranked[:top_n]:
        hist = c.arg_histograms.get(nr, [])
        cells: list[str] = []
        for i, h in enumerate(hist):
            if not h:
                continue
            top_val, top_count = max(h.items(), key=lambda kv: kv[1])
            cells.append(f"a{i}:0x{top_val:x}x{top_count}/{len(h)}d")
        print(
            f"  {syscall_label(b.syscall_names, nr):<28s} {kept:>6d}  "
            f"{' '.join(cells)}"
        )


def print_cmp_hints_stats(b: CacheBundle, top_n: int) -> None:
    section("cmp-hints")
    h = b.cmp_hints
    if h is None:
        print("  (no cmp-hints loaded)")
        return
    capacity = h.max_syscall * 2 * h.per_syscall
    fill = h.total_constants / capacity if capacity else 0.0
    nonempty = sum(1 for v in h.per_syscall_filled if v > 0)
    print(f"  file:            {h.path}")
    print(f"  version:         {h.version}")
    print(f"  total constants: {h.total_constants} of {capacity}  ({fmt_pct(fill)})")
    print(f"  syscalls w/ hints:{nonempty}")
    print(f"  most-recent last_used clock: {h.most_recent_last_used}")
    mode = "canonical cmp_ip" if h.kaslr_base != 0 else "raw cmp_ip"
    print(f"  kaslr_base:      0x{h.kaslr_base:016x}  ({mode})")
    print(f"  crc:             {'OK' if h.crc_ok else 'MISMATCH'}")
    for n in h.notes:
        print(f"  note: {n}")

    section("top syscalls by learned-constant count")
    ranked = sorted(
        (
            (nr, h.per_syscall_filled[nr], h.pool_dim_filled[nr])
            for nr in range(h.max_syscall)
            if h.per_syscall_filled[nr] > 0
        ),
        key=lambda t: t[1],
        reverse=True,
    )
    if not ranked:
        print("  (no learned constants recorded)")
    else:
        print(f"  {'syscall':<28s} {'total':>6s} {'do32':>6s} {'do64':>6s}")
        for nr, total, dims in ranked[:top_n]:
            print(
                f"  {syscall_label(b.syscall_names, nr):<28s} "
                f"{total:>6d} {dims[0]:>6d} {dims[1]:>6d}"
            )


def _kernel_mtime(cache_dir: str, fname: str) -> float:
    for top in ("kcov-bitmap", "corpus", "cmp-hints"):
        p = os.path.join(cache_dir, top, fname)
        if os.path.isfile(p):
            return os.path.getmtime(p)
    return 0.0


def available_kernels(cache_dir: str) -> list[str]:
    """Distinct per-kernel artifact filenames present under cache_dir."""
    labels: set[str] = set()
    for top in ("kcov-bitmap", "corpus", "cmp-hints"):
        d = os.path.join(cache_dir, top)
        if os.path.isdir(d):
            for s in os.listdir(d):
                if os.path.isfile(os.path.join(d, s)):
                    labels.add(s)
    return sorted(labels)


def resolve_kernel(
    cache_dir: str, requested: Optional[str], announce: bool = True
) -> Optional[str]:
    """Map a --kernel substring to a concrete cache filename.

    Returns the chosen filename (used as the artifact filter), or None for
    a flat single-kernel cache.  Exits with a listing on no match.
    """
    kernels = available_kernels(cache_dir)
    if not kernels:
        return None
    if requested is not None:
        matched = [s for s in kernels if requested in s]
        if not matched:
            sys.stderr.write(f"no cache files match kernel {requested!r}; available:\n")
            for s in kernels:
                sys.stderr.write(f"  {s}\n")
            sys.exit(2)
        return max(matched, key=lambda s: _kernel_mtime(cache_dir, s))
    if len(kernels) == 1:
        return kernels[0]
    newest = max(kernels, key=lambda s: _kernel_mtime(cache_dir, s))
    if announce:
        print(f"note: {len(kernels)} kernels in cache; showing newest ({newest}).")
        print("      pass -k <substr> (e.g. -k 7.1.0-rc6) to pick another:")
        for s in kernels:
            print(f"        {s}")
        print()
    return newest


def cmd_stats(args: argparse.Namespace) -> int:
    cache_dir = os.path.abspath(args.cache_dir)
    kernel = resolve_kernel(cache_dir, args.kernel)
    b = load_bundle(cache_dir, kernel)
    print(f"trinity cache stats: {b.cache_dir}")
    print(f"kernel label:        {b.kernel_label}")
    print(
        f"arch:                {b.arch or '<unknown>'}  "
        f"(syscall table: {len(b.syscall_names)} entries)"
    )
    print_kcov_stats(b, args.top)
    print_corpus_stats(b, args.top)
    print_cmp_hints_stats(b, args.top)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    cache_a = os.path.abspath(args.cache_a)
    cache_b = os.path.abspath(args.cache_b) if args.cache_b else cache_a
    a = load_bundle(cache_a, resolve_kernel(cache_a, args.kernel_a, announce=False))
    b = load_bundle(cache_b, resolve_kernel(cache_b, args.kernel_b, announce=False))
    print("trinity cache diff (cross-kernel PROXIES ONLY)")
    print(f"  A: {a.cache_dir}  [{a.kernel_label}]")
    print(f"  B: {b.cache_dir}  [{b.kernel_label}]")
    print()
    print("DISCLAIMER: edge-level diff is impossible from saved files. The")
    print("kcov bitmap is a hashed, non-invertible bucket table that is")
    print("kernel-build-specific (different inlining/layout maps the same")
    print("source-level edge to a different bucket). Treat every diff below")
    print("as syscall-granularity *productivity / composition* proxies, not")
    print("'edges gained' or 'edges lost'.")

    names = a.syscall_names or b.syscall_names

    if a.kcov is not None and b.kcov is not None:
        section("aggregate density delta (magnitude-only; not bit-comparable)")
        density_a = a.kcov.bitmap_popcount / (KCOV_NUM_EDGES * KCOV_NUM_BUCKETS)
        density_b = b.kcov.bitmap_popcount / (KCOV_NUM_EDGES * KCOV_NUM_BUCKETS)
        ef_delta = b.kcov.edges_found - a.kcov.edges_found
        de_delta = b.kcov.distinct_edges - a.kcov.distinct_edges
        print(
            f"  edges_found:     A={a.kcov.edges_found:>12d}  "
            f"B={b.kcov.edges_found:>12d}  delta={ef_delta:>+d}"
        )
        print(
            f"  distinct_edges:  A={a.kcov.distinct_edges:>12d}  "
            f"B={b.kcov.distinct_edges:>12d}  delta={de_delta:>+d}"
        )
        print(
            f"  bitmap density:  A={fmt_pct(density_a):>10s}  "
            f"B={fmt_pct(density_b):>10s}"
        )

        section("per-syscall productivity delta (productive-call count)")
        rows: list[tuple[int, int, int, int]] = []
        for nr in range(MAX_NR_SYSCALL):
            pa = a.kcov.per_syscall_edges[nr]
            pb = b.kcov.per_syscall_edges[nr]
            ca = a.kcov.per_syscall_calls[nr]
            cb = b.kcov.per_syscall_calls[nr]
            if pa == 0 and pb == 0 and ca == 0 and cb == 0:
                continue
            rows.append((nr, pb - pa, pa, pb))
        rows.sort(key=lambda t: abs(t[1]), reverse=True)
        if not rows:
            print("  (no per-syscall data on either side)")
        else:
            print(f"  {'syscall':<28s} {'delta':>8s} {'A':>8s} {'B':>8s}")
            for nr, delta, pa, pb in rows[: args.top]:
                print(
                    f"  {syscall_label(names, nr):<28s} {delta:>+8d} "
                    f"{pa:>8d} {pb:>8d}"
                )

        saturated_a = {
            nr
            for nr in range(MAX_NR_SYSCALL)
            if a.kcov.per_syscall_calls[nr] > 0 and a.kcov.per_syscall_edges[nr] == 0
        }
        productive_b = {
            nr for nr in range(MAX_NR_SYSCALL) if b.kcov.per_syscall_edges[nr] > 0
        }
        novel_on_b = saturated_a & productive_b
        prod_b_total = len(productive_b)
        ratio = (len(novel_on_b) / prod_b_total) if prod_b_total else 0.0
        section("syscall novelty %  (productive on B, saturated on A)")
        print(
            f"  novelty: {len(novel_on_b)} / {prod_b_total} productive-on-B "
            f"syscalls were saturated-on-A  ({fmt_pct(ratio)})"
        )
        if novel_on_b:
            sample = sorted(novel_on_b)[: args.top]
            for nr in sample:
                print(f"    {syscall_label(names, nr)}")

        if a.kcov.strat_present and b.kcov.strat_present:
            section("per-strategy edge delta (v7)")
            print(
                f"  {'strategy':<12s} "
                f"{'A.edges':>12s} {'B.edges':>12s} {'delta':>10s} "
                f"{'A.calls':>12s} {'B.calls':>12s}"
            )
            for s, name in enumerate(KCOV_STRATEGY_NAMES):
                ea = a.kcov.strat_count_by_strategy[s]
                eb = b.kcov.strat_count_by_strategy[s]
                ca = a.kcov.strat_calls_by_strategy[s]
                cb = b.kcov.strat_calls_by_strategy[s]
                print(
                    f"  {name:<12s} "
                    f"{ea:>12d} {eb:>12d} {eb - ea:>+10d} "
                    f"{ca:>12d} {cb:>12d}"
                )

    if a.corpus is not None and b.corpus is not None:
        section("corpus-composition delta")
        all_nr = sorted(
            set(a.corpus.per_syscall_count) | set(b.corpus.per_syscall_count)
        )
        rows = []
        for nr in all_nr:
            ca = a.corpus.per_syscall_count.get(nr, 0)
            cb = b.corpus.per_syscall_count.get(nr, 0)
            rows.append((nr, cb - ca, ca, cb))
        rows.sort(key=lambda t: abs(t[1]), reverse=True)
        gained = [r for r in rows if r[2] == 0 and r[3] > 0]
        lost = [r for r in rows if r[2] > 0 and r[3] == 0]
        print(f"  syscalls only in A: {len(lost)}   only in B: {len(gained)}")
        print(f"  {'syscall':<28s} {'delta':>8s} {'A':>6s} {'B':>6s}")
        for nr, delta, ca, cb in rows[: args.top]:
            print(
                f"  {syscall_label(names, nr):<28s} {delta:>+8d} " f"{ca:>6d} {cb:>6d}"
            )

    if a.cmp_hints is not None and b.cmp_hints is not None:
        section("cmp-hints pool delta")
        rows = []
        for nr in range(min(a.cmp_hints.max_syscall, b.cmp_hints.max_syscall)):
            pa = a.cmp_hints.per_syscall_filled[nr]
            pb = b.cmp_hints.per_syscall_filled[nr]
            if pa == 0 and pb == 0:
                continue
            rows.append((nr, pb - pa, pa, pb))
        rows.sort(key=lambda t: abs(t[1]), reverse=True)
        print(
            f"  total constants: A={a.cmp_hints.total_constants}  "
            f"B={b.cmp_hints.total_constants}  "
            f"delta={b.cmp_hints.total_constants - a.cmp_hints.total_constants:+d}"
        )
        if rows:
            print(f"  {'syscall':<28s} {'delta':>8s} {'A':>6s} {'B':>6s}")
            for nr, delta, pa, pb in rows[: args.top]:
                print(
                    f"  {syscall_label(names, nr):<28s} {delta:>+8d} "
                    f"{pa:>6d} {pb:>6d}"
                )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="dump stats from trinity's ~/.cache/trinity/ cache files"
    )
    p.add_argument(
        "--top",
        type=int,
        default=20,
        help="max rows per ranked table (default: 20)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    p_stats = sub.add_parser("stats", help="single-kernel summary")
    p_stats.add_argument("cache_dir")
    p_stats.add_argument(
        "-k",
        "--kernel",
        help="kernel substring to select when the cache holds several "
        "(e.g. -k 7.1.0-rc7); default: newest",
    )
    p_stats.set_defaults(func=cmd_stats)
    p_diff = sub.add_parser("diff", help="cross-kernel proxies (not edges)")
    p_diff.add_argument("cache_a")
    p_diff.add_argument(
        "cache_b",
        nargs="?",
        default=None,
        help="second cache dir (default: same as cache_a)",
    )
    p_diff.add_argument(
        "-a", "--kernel-a", dest="kernel_a", help="kernel substring for side A"
    )
    p_diff.add_argument(
        "-b", "--kernel-b", dest="kernel_b", help="kernel substring for side B"
    )
    p_diff.set_defaults(func=cmd_diff)
    return p


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
