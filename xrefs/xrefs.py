import re
import struct

from ib.decode import decode_one, call_target
from pe.pe import parse_sections

lea_xref_cache = {}


_LEA_RIP_RE = re.compile(rb'[\x40-\x4f]?\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]')


def _build_lea_xref_map(image):
    xref_map = {}
    sections = parse_sections(image)
    exec_ranges = [
        (info["start"], min(info["end"], len(image)))
        for info in sections.values()
        if info["characteristics"] & 0x20000000
    ]
    exec_ranges = [(lo, hi) for lo, hi in exec_ranges if 0 <= lo < hi]
    exec_map = {}
    other_map = {}

    def _scan(lo, hi, sink):
        if hi - lo < 6:
            return
        for m in _LEA_RIP_RE.finditer(image, lo, hi):
            start = m.start()
            has_rex = image[start] != 0x8D
            op = start + 1 if has_rex else start
            if op + 6 > len(image):
                continue
            disp = struct.unpack_from("<i", image, op + 2)[0]
            target = op + 6 + disp
            if 0 <= target < len(image):

                sink.setdefault(target, []).append(start if has_rex else op)

    for lo, hi in exec_ranges:
        _scan(lo, hi, exec_map)
    _scan(0, len(image), other_map)

    for target, hits in other_map.items():
        merged = exec_map.get(target)
        xref_map[target] = sorted(set(merged)) if merged else sorted(set(hits))
    for target, hits in exec_map.items():
        xref_map.setdefault(target, sorted(set(hits)))
    return xref_map


def _cached_xref_map(image):
    global lea_xref_cache
    key = id(image)
    entry = lea_xref_cache.get(key)
    if entry is not None and entry[0] is image:
        return entry[1]
    xref_map = _build_lea_xref_map(image)
    if len(lea_xref_cache) > 2:
        lea_xref_cache.clear()
    lea_xref_cache[key] = (image, xref_map)
    return xref_map


def find_lea_xref(image, base, target_rva, search_start_rva=0, search_end_rva=None,
                  max_scan=0x500000):
    hits = _cached_xref_map(image).get(target_rva)
    if not hits:
        return None
    return base + hits[0]


def find_nth_lea_xref(image, base, target_rva, n=1, max_scan=0x500000):
    xref_map = _cached_xref_map(image)
    hits = xref_map.get(target_rva)
    if not hits or len(hits) < n:
        return None
    return base + hits[n - 1]


def find_next(image, base, start_va, mnem_filter, limit_bytes=500):
    va = start_va
    end_va = start_va + limit_bytes
    while va < end_va:
        ins = decode_one(image, va, base)
        if ins is None: va += 1; continue
        if ins.mnem.lower().startswith(mnem_filter.lower()):
            return ins
        va += ins.size
    return None


def find_prev(image, base, start_va, mnem_filter, limit_bytes=500):

    scan_start = max(base, start_va - limit_bytes)
    va = scan_start
    last_match = None
    while va < start_va:
        ins = decode_one(image, va, base)
        if ins is None: va += 1; continue
        if ins.mnem.lower().startswith(mnem_filter.lower()):
            last_match = ins
        va += ins.size
    return last_match


def collect_calls(image, base, start_va, end_va):
    results = []
    va = start_va
    while va < end_va:
        ins = decode_one(image, va, base)
        if ins is None: va += 1; continue
        if ins.mnem == "call":
            tgt = call_target(ins)
            if tgt:
                results.append((va, tgt - base))
        va += ins.size
    return results


def func_end(image, base, start_va, max_bytes=0x400):
    va = start_va
    end = start_va + max_bytes
    while va < end:
        ins = decode_one(image, va, base)
        if ins is None: va += 1; continue
        if ins.mnem == "ret":
            return va + ins.size
        va += ins.size
    return va
