import struct

from offsets.tables import _MAX_OFFSET
from memory.utils import _valid_ptr, _rbx_read_string, read_mem_u64

_SCAN_FMT = {
    "float":   ("<f", 4),
    "double":  ("<d", 8),
    "int":     ("<i", 4),
    "int16":   ("<h", 2),
    "uint8":   ("<B", 1),
    "u64":     ("<Q", 8),
    "bool":    ("<B", 1),
    "v2":      ("<ff", 8),
    "v3":      ("<fff", 12),
    "color3":  ("<fff", 12),
    "coloru8": ("<BBB", 3),
    "udim2":   ("<fiif", 16),
    "mat3":    ("<fffffffff", 36),
}


_SCAN_ALIGN = {
    "float": 4, "double": 8, "int": 4, "int16": 2, "uint8": 1, "bool": 1,
    "u64": 8, "v2": 4, "v3": 4, "color3": 4, "coloru8": 1,
    "udim2": 4, "mat3": 4,
}

_INT_KINDS = ("int", "int16", "uint8", "u64", "bool")
_FLT_KINDS = ("float", "double")


def _scan_value_matches(vals, kind, expected, eps):
    if kind in _FLT_KINDS:
        v = vals[0]
        if v != v or abs(v - expected) > eps:
            return False
        return True
    if kind in _INT_KINDS:
        if kind == "bool":
            return bool(vals[0]) == bool(expected)
        return vals[0] == expected

    for got, exp in zip(vals, expected):
        if got != got or abs(got - exp) > eps:
            return False
    return True


def _scan_block_candidates(block, kind, expected, eps, step):
    fmt, size = _SCAN_FMT[kind]
    out = []
    if len(block) < size:
        return out

    n = (len(block) - size) // step + 1
    if n <= 0:
        return out
    unpack = struct.unpack_from
    for i in range(n):
        off = i * step
        if _scan_value_matches(unpack(fmt, block, off), kind, expected, eps):
            out.append(off)
    return out


def _string_candidates(reader, addr, span, expected, step, double_read):
    block = reader.try_read(addr, span)
    if not block:
        return []
    cands = []
    if double_read:
        resolved = {}
        for off in range(0, len(block) - 7, 4):
            ptr = struct.unpack_from("<Q", block, off)[0]
            if not _valid_ptr(ptr):
                continue
            if ptr not in resolved:
                resolved[ptr] = _rbx_read_string(reader, ptr, max_len=1024)
                if len(resolved) > 4096:
                    break
            if resolved[ptr] == expected:
                cands.append(off)
    else:
        want = len(expected.encode("utf-8", "replace"))
        for off in range(0, len(block) - 23, max(1, step)):
            if struct.unpack_from("<Q", block, off + 16)[0] == want:
                cands.append(off)
    if not cands:
        return []
    return [o for o in cands
            if _value_at_matches(reader, addr + o, "string", expected, 0.0,
                                 double_read)]


def _value_at_matches(reader, addr, kind, expected, eps, double_read):
    if kind == "string":
        ptr = read_mem_u64(reader, addr) if double_read else addr
        return _rbx_read_string(reader, ptr, max_len=1024) == expected
    fmt, size = _SCAN_FMT[kind]
    data = reader.try_read(addr, size)
    if not data or len(data) < size:
        return False
    return _scan_value_matches(struct.unpack_from(fmt, data, 0), kind, expected, eps)


def scan_for_value(reader, store, name, category, targets, expected, kind="float",
                  start=0, end=_MAX_OFFSET, step=1, eps=0.001, double_read=False):
    targets = [t for t in targets if t]
    expected = list(expected)
    if not targets:
        return 0
    if len(targets) != len(expected):
        expected = expected[:len(targets)]

    span = end - start


    eff_step = step
    if eff_step == 1 and kind in _SCAN_ALIGN:
        eff_step = _SCAN_ALIGN[kind]
    cands = None
    for idx, tgt in enumerate(targets):
        exp = expected[idx]
        if cands is None:
            if kind == "string":
                cands = _string_candidates(reader, tgt + start, span, exp,
                                           eff_step, double_read)
            else:
                block = reader.try_read(tgt + start, span)
                cands = (_scan_block_candidates(block, kind, exp, eps, eff_step)
                         if block else [])
        else:
            if not cands:
                break
            cands = [o for o in cands
                     if _value_at_matches(reader, tgt + start + o, kind, exp,
                                          eps, double_read)]

    if not cands:
        return 0

    off = cands[0] + start


    if len(cands) > UNCERTAIN_MIN_CANDIDATES:
        guess = _report_uncertain(off)
        if guess is None:
            return 0
        store.setdefault(category, {})[name] = guess
        return guess
    store.setdefault(category, {})[name] = off
    return off


def store_offset(store, category, name, value, allow_zero=False):
    if value is None:
        return 0
    if value == 0 and not allow_zero:
        return 0
    store.setdefault(category, {})[name] = value
    return value


def _matrix3x3_to_euler(d):
    y = _asin(max(-1.0, min(1.0, d[6])))
    if abs(d[6]) < 0.9999:
        x = _atan2(-d[7], d[8])
        z = _atan2(-d[3], d[0])
    else:
        x = 0.0
        z = _atan2(d[1], d[4])
    return (x * 57.29577951308232, y * 57.29577951308232,
            z * 57.29577951308232)


def _asin(x):
    import math
    return math.asin(x)


def _atan2(y, x):
    import math
    return math.atan2(y, x)


def _tan(x):
    import math
    return math.tan(x)


_RBX_CLASS_ALIASES = {
    "Bloom": "BloomEffect",
    "Blur": "BlurEffect",
    "DepthOfField": "DepthOfFieldEffect",
    "SunRays": "SunRaysEffect",
    "ColorCorrection": "ColorCorrectionEffect",
    "ColorGrading": "ColorGradingEffect",
    "Mesh": "SpecialMesh",
    "Clothing": "Shirt",
}

UNCERTAIN_MIN_CANDIDATES = 8

_STRICT_UNCERTAIN = False


def set_strict_uncertain(flag):
    global _STRICT_UNCERTAIN
    _STRICT_UNCERTAIN = bool(flag)


def _report_uncertain(off):
    if not _STRICT_UNCERTAIN:
        return off
    return None
