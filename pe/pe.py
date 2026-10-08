import struct
import hashlib

from offsets.tables import image_bytes, fmt_hex


def parse_sections(image):
    try:
        if image[:2] != b"MZ":
            return {}
        pe = struct.unpack_from("<I", image, 0x3C)[0]
        if image[pe:pe + 4] != b"PE\0\0":
            return {}
        count = struct.unpack_from("<H", image, pe + 6)[0]
        opt_size = struct.unpack_from("<H", image, pe + 20)[0]
        table = pe + 24 + opt_size
        out = {}
        for i in range(count):
            entry = table + i * 40
            if entry + 40 > len(image):
                break
            name = image[entry:entry + 8].rstrip(b"\0").decode("latin-1")
            vsize = struct.unpack_from("<I", image, entry + 8)[0]
            vaddr = struct.unpack_from("<I", image, entry + 12)[0]
            characteristics = struct.unpack_from("<I", image, entry + 36)[0]
            out[name] = {
                "start": vaddr,
                "end": vaddr + vsize,
                "characteristics": characteristics
            }
        return out
    except Exception:
        return {}


def pe_fingerprint(image):
    try:
        if image[:2] != b"MZ":
            return None
        pe = struct.unpack_from("<I", image, 0x3C)[0]
        if image[pe:pe + 4] != b"PE\0\0":
            return None
        timestamp = struct.unpack_from("<I", image, pe + 8)[0]
        opt = pe + 24
        entry = struct.unpack_from("<I", image, opt + 0x10)[0]
        size_of_image = struct.unpack_from("<I", image, opt + 0x38)[0]
        checksum = struct.unpack_from("<I", image, opt + 0x40)[0]
        blob = struct.pack("<IIII", timestamp, entry, size_of_image, checksum)
        return {
            "timestamp": timestamp,
            "entry_point": entry,
            "size_of_image": size_of_image,
            "checksum": checksum,
            "id": hashlib.sha256(blob).hexdigest()[:16],
        }
    except Exception:
        return None


def is_executable(ea, base, sections):
    rva = ea - base
    for name, info in sections.items():
        if info["start"] <= rva < info["end"]:
            if info["characteristics"] & 0x20000000:
                return True
    return False


def is_valid_vtable(vtable_va, base, sections):
    if not (base <= vtable_va < base + len(image_bytes)):
        return False
    if is_executable(vtable_va, base, sections):
        return False
    first_fn = fmt_hex(vtable_va)
    if first_fn and is_executable(first_fn, base, sections):
        return True
    return False
