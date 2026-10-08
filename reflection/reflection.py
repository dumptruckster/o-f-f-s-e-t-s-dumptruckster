import struct

from memory.utils import _valid_ptr
from pe.pe import parse_sections

_CLASS_NAMES = {"BasePart", "Humanoid", "Instance", "Model", "Part",
                "UserInputService", "Workspace"}
_NAME_TABLE = 0x50
_MIN_ENTRIES = 64
_ENTRY_STRIDE = 0x10
_MAX_READ = 0x4000


def _read_cstr(reader, addr, limit=64):
    data = reader.try_read(addr, limit)
    if not data:
        return None
    end = data.find(b"\x00")
    if end <= 0:
        return None
    chunk = data[:end]
    if not all(32 <= c < 127 for c in chunk):
        return None
    try:
        return chunk.decode("ascii")
    except Exception:
        return None


def _name_table(reader, registry):
    head = reader.try_read(registry + _NAME_TABLE, 16)
    if not head or len(head) < 16:
        return 0, 0
    start, end = struct.unpack_from("<QQ", head, 0)
    if not _valid_ptr(start) or not _valid_ptr(end):
        return 0, 0
    if end <= start or (end - start) > 0x800000 or (end - start) % _ENTRY_STRIDE:
        return 0, 0
    return start, (end - start) // _ENTRY_STRIDE


def _class_hits(reader, start, count):
    block = reader.try_read(start, min(count * _ENTRY_STRIDE, _MAX_READ))
    if not block:
        return 0
    hits = 0
    for off in range(0, len(block) - 15, _ENTRY_STRIDE):
        key = struct.unpack_from("<Q", block, off)[0]
        if _valid_ptr(key) and _read_cstr(reader, key) in _CLASS_NAMES:
            hits += 1
    return hits


def dump_reflection_offsets(reader, image, base, store):
    limit = base + len(image)
    candidates = []
    for section in parse_sections(image).values():
        if not (section["characteristics"] & 0x80000000):
            continue
        lo = max(0, section["start"])
        hi = min(section["end"], len(image))
        for off in range(lo, hi - 7, 8):
            value = struct.unpack_from("<Q", image, off)[0]
            if not _valid_ptr(value):
                continue
            if base <= value < limit:
                continue
            start, count = _name_table(reader, value)
            if count >= _MIN_ENTRIES:
                candidates.append((off, start, count))
    best = 0
    best_score = (0, 0)
    for off, start, count in candidates:
        hits = _class_hits(reader, start, count)
        if not hits:
            continue
        score = (hits, count)
        if score > best_score:
            best_score = score
            best = off
    if best:
        store.setdefault(("Reflection",), {})["NameRegistry"] = best
    return store
