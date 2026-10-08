import struct

from offsets.tables import (TYPE_PREFIX, COL_TYPE_DESCRIPTOR_RVA,
                              COL_CLASS_DESCRIPTOR_RVA, TYPE_DESCRIPTOR_NAME_OFFSET,
                              FN_OFFS, TARGET, image_bytes, image_base)
from offsets.tables import find_all
from pe.pe import parse_sections
from memory.utils import _valid_ptr


def _rtti_demangle(raw):
    if not raw:
        return ""
    name = raw
    if name.startswith(".?AV") or name.startswith(".?AU"):
        name = name[4:]
    parts = [p for p in name.split("@") if p]
    if not parts:
        return raw
    return "::".join(reversed(parts))


def read_mangled_name(image, pos, limit=256):
    end = image.find(b"\x00", pos, pos + limit)
    if end == -1:
        return None
    return image[pos:end]


def read_vtable_slots(image, base, sections, table_rva, count=192):
    from ib.decode import read_u64
    slots = {}
    if table_rva is None or table_rva + 8 > len(image):
        return slots
    for slot in range(count):
        entry = read_u64(image, table_rva + slot * 8)
        if not (base <= entry < base + len(image)):
            break
        if not is_executable(entry, base, sections):
            break
        slots[slot] = entry - base
    return slots


def _rtti_class_name(reader, addr):
    from memory.utils import read_mem_u64
    if not _valid_ptr(addr):
        return None
    vtable = read_mem_u64(reader, addr)
    if not _valid_ptr(vtable):
        return None
    col = read_mem_u64(reader, vtable - 8)
    if not _valid_ptr(col):
        return None
    data = reader.try_read(col, 24)
    if not data or len(data) < 24:
        return None
    type_desc_rva = struct.unpack_from("<I", data, 12)[0]
    name_off = type_desc_rva + 0x10
    if not (0 <= name_off < len(image_bytes) - 1):
        return None
    raw = fmt_cstr(image_base + name_off, n=192)
    return _rtti_demangle(raw) or None


def _in_any(ranges, offset):
    for start, end in ranges:
        if start <= offset < end:
            return True
    return False


def find_type_descriptors(image, base, name=TYPE_PREFIX):
    out = []
    seen = set()
    for pos in find_all(image, name):
        full = read_mangled_name(image, pos)
        if not full:
            continue
        if name.endswith(b"@") and not full.endswith(b"@@"):
            continue
        descriptor = pos - TYPE_DESCRIPTOR_NAME_OFFSET
        if descriptor < 0 or descriptor in seen:
            continue
        seen.add(descriptor)
        out.append(base + descriptor)
    return out


def find_complete_object_locators(image, base, descriptor_va, sections=None):
    lo = sections[0][0] if sections else 0
    hi = sections[-1][1] if sections else len(image)
    key = struct.pack("<I", descriptor_va - base)
    out = []
    for pos in find_all(image, key, lo, hi):
        col = pos - COL_TYPE_DESCRIPTOR_RVA
        if col < 0 or col + 24 > len(image):
            continue
        signature = struct.unpack_from("<I", image, col)[0]
        if signature not in (0, 1):
            continue
        chd = struct.unpack_from("<I", image, col + COL_CLASS_DESCRIPTOR_RVA)[0]
        if chd == 0 or chd >= len(image):
            continue
        if sections and not _in_any(sections, col):
            continue
        out.append(base + col)
    return out


def find_vtables(image, base, locator_va, sections=None, code=None):
    lo = sections[0][0] if sections else 0
    hi = sections[-1][1] if sections else len(image)
    key = struct.pack("<Q", locator_va)
    out = []
    for pos in find_all(image, key, lo, hi):
        vtable = pos + 8
        if vtable + 8 > len(image):
            continue
        first = struct.unpack_from("<Q", image, vtable)[0]
        if not (base <= first < base + len(image)):
            continue
        if code and not _in_any(code, first - base):
            continue
        locator_off = locator_va - base
        if locator_off <= pos < locator_off + 0x20:
            continue
        if sections and not _in_any(sections, pos):
            continue
        out.append(base + vtable)
    return out


def resolve_rtti_vtables(image, base, prefix):
    sec_map = parse_sections(image)
    rdata = [(v["start"], v["end"]) for k, v in sec_map.items() if k == ".rdata"]
    code = [(v["start"], v["end"]) for k, v in sec_map.items() if k == ".text"]

    descriptors = find_type_descriptors(image, base, prefix)
    if not descriptors:
        return []
    locators = []
    for descriptor in descriptors:
        locators.extend(find_complete_object_locators(image, base, descriptor, rdata))
    vtables = []
    for locator in locators:
        for table in find_vtables(image, base, locator, rdata, code):
            rva = table - base
            if rva not in vtables:
                vtables.append(rva)
    return vtables


def _resolve_rtti_vtable(image, base, prefix):
    vtables = resolve_rtti_vtables(image, base, prefix)
    return vtables[0] if vtables else None


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


def resolve_fastcluster_vtable(image, base):
    result = {"vtable_rva": None, "error": None, "mangled_name": None}

    sec_map = parse_sections(image)
    descriptors = find_type_descriptors(image, base, TYPE_PREFIX)
    if descriptors:
        first = descriptors[0] - base + TYPE_DESCRIPTOR_NAME_OFFSET
        full = read_mangled_name(image, first)
        if full:
            result["mangled_name"] = full.decode("latin-1")
    if not descriptors:
        result["error"] = "FastClusterEntity RTTI not found"

    rdata = [(v["start"], v["end"]) for k, v in sec_map.items() if k == ".rdata"]
    code = [(v["start"], v["end"]) for k, v in sec_map.items() if k == ".text"]
    locators = []
    for descriptor in descriptors:
        locators.extend(find_complete_object_locators(image, base, descriptor, rdata))
    if not locators:
        result["error"] = "complete object locator not found"
        return result

    vtables = []
    for locator in locators:
        vtables.extend(find_vtables(image, base, locator, rdata, code))
    if not vtables:
        result["error"] = "vtable not found"
        return result

    result["vtable_rva"] = vtables[0] - base
    return result


def fmt_hex(ea):
    offset = ea - image_base
    if 0 <= offset <= len(image_bytes) - 8:
        return struct.unpack_from("<Q", image_bytes, offset)[0]
    return 0


def fmt_cstr(ea, n=96):
    if not ea:
        return ""
    offset = ea - image_base
    if 0 <= offset < len(image_bytes):
        limit = min(n, len(image_bytes) - offset)
        chunk = image_bytes[offset : offset + limit]
        zero_idx = chunk.find(b"\x00")
        if zero_idx != -1:
            chunk = chunk[:zero_idx]
        if all(32 <= c < 127 for c in chunk):
            try:
                return chunk.decode('ascii')
            except Exception:
                pass
    return ""


def find_raycast_descriptor_by_brute_force(reader, image, base, sections):
    def read_live_cstr(ea, n=96):
        if not ea:
            return ""
        data = reader.try_read(ea, n)
        if data:
            zero_idx = data.find(b"\x00")
            if zero_idx != -1:
                data = data[:zero_idx]
            if all(32 <= c < 127 for c in data):
                try:
                    return data.decode('ascii')
                except Exception:
                    pass
        return ""

    candidates = []
    for sec_name, info in sections.items():
        if info["characteristics"] & 0x20000000:
            continue

        start_rva = info["start"]
        end_rva = info["end"]

        for rva in range(start_rva, end_rva - 128, 8):
            va = base + rva
            vtable = fmt_hex(va)
            if not is_valid_vtable(vtable, base, sections):
                continue

            for fn_off in FN_OFFS:
                fn_ptr = fmt_hex(va + fn_off)
                if fn_ptr and is_executable(fn_ptr, base, sections):
                    candidates.append((va, vtable, fn_off, fn_ptr, sec_name))
                    break


    raycast_str_positions = list(find_all(image, b"Raycast\x00"))

    resolved_layout = None
    for va, vtable, fn_off, fn_ptr, sec_name in candidates:
        matched = False
        name_offset = 0
        is_sso = False
        is_name_32 = False


        for offset in range(8, 64, 8):
            val = fmt_hex(va + offset)
            s = read_live_cstr(val)
            if s == TARGET:
                matched = True
                name_offset = offset
                is_sso = False
                is_name_32 = False
                break


            s_img = fmt_cstr(val)
            if s_img == TARGET:
                matched = True
                name_offset = offset
                is_sso = False
                is_name_32 = False
                break

            val_32 = struct.unpack_from("<I", image, va + offset - base)[0]
            val_32_va = base + val_32
            s = read_live_cstr(val_32_va)
            if s == TARGET:
                matched = True
                name_offset = offset
                is_sso = False
                is_name_32 = True
                break


            s_img = fmt_cstr(val_32_va)
            if s_img == TARGET:
                matched = True
                name_offset = offset
                is_sso = False
                is_name_32 = True
                break

        if not matched:

            for offset in range(8, 64, 8):
                s = read_live_cstr(va + offset, n=15)
                if s == TARGET:
                    matched = True
                    name_offset = offset
                    is_sso = True
                    is_name_32 = False
                    break


                s_img = fmt_cstr(va + offset, n=15)
                if s_img == TARGET:
                    matched = True
                    name_offset = offset
                    is_sso = True
                    is_name_32 = False
                    break

        if matched:
            resolved_layout = {
                "desc_va": va,
                "name_offset": name_offset,
                "is_name_32": is_name_32,
                "is_sso": is_sso,
                "fn_offset": fn_off,
                "is_fn_32": False,
            }
            break


    if not resolved_layout and raycast_str_positions:
        resolved_layout = _find_descriptor_from_string_positions(
            reader, image, base, sections, raycast_str_positions
        )

    return resolved_layout, candidates


def _find_descriptor_from_string_positions(reader, image, base, sections, str_positions):
    def read_live_cstr(ea, n=96):
        if not ea:
            return ""
        data = reader.try_read(ea, n)
        if data:
            zero_idx = data.find(b"\x00")
            if zero_idx != -1:
                data = data[:zero_idx]
            if all(32 <= c < 127 for c in data):
                try:
                    return data.decode('ascii')
                except Exception:
                    pass
        return ""

    for rc_pos in str_positions[:4]:
        rc_va = base + rc_pos


        needle64 = struct.pack("<Q", rc_va)
        for ref_pos in find_all(image, needle64):
            ref_va = base + ref_pos


            for back in range(0, 64, 8):
                desc_va = ref_va - back
                if desc_va < base:
                    break

                vtable = fmt_hex(desc_va)
                if not is_valid_vtable(vtable, base, sections):
                    continue


                for fn_off in FN_OFFS:
                    fn_ptr = fmt_hex(desc_va + fn_off)
                    if fn_ptr and is_executable(fn_ptr, base, sections):

                        name_va = fmt_hex(desc_va + back)
                        s = read_live_cstr(name_va) or fmt_cstr(name_va)
                        if s == TARGET:
                            return {
                                "desc_va": desc_va,
                                "name_offset": back,
                                "is_name_32": False,
                                "is_sso": False,
                                "fn_offset": fn_off,
                                "is_fn_32": False,
                            }


        rva = rc_va - base
        if 0 <= rva < 0x100000000:
            needle32 = struct.pack("<I", rva)
            for ref_pos in find_all(image, needle32):
                ref_va = base + ref_pos

                for back in range(0, 32, 4):
                    desc_va = ref_va - back
                    if desc_va < base:
                        break

                    vtable = fmt_hex(desc_va)
                    if not is_valid_vtable(vtable, base, sections):
                        continue

                    for fn_off in FN_OFFS:
                        fn_ptr = fmt_hex(desc_va + fn_off)
                        if fn_ptr and is_executable(fn_ptr, base, sections):
                            name_rva = struct.unpack_from("<I", image, ref_va - base)[0]
                            s = fmt_cstr(base + name_rva)
                            if s == TARGET:
                                return {
                                    "desc_va": desc_va,
                                    "name_offset": back,
                                    "is_name_32": True,
                                    "is_sso": False,
                                    "fn_offset": fn_off,
                                    "is_fn_32": False,
                                }

    return None


