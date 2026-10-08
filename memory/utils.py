import glob
import os
import re
import struct

from offsets.tables import _MAX_OFFSET


def read_mem_u64(reader, addr):
    data = reader.try_read(addr, 8)
    if not data or len(data) < 8:
        return 0
    return struct.unpack_from("<Q", data)[0]


def read_mem_float(reader, addr):
    data = reader.try_read(addr, 4)
    if not data or len(data) < 4:
        return None
    return struct.unpack_from("<f", data)[0]

def _rbx_read_string(reader, ptr, max_len=255):
    MAX_SIMPLE = 15
    STR_LEN_OFF = 16
    if not ptr:
        return None
    sz_data = reader.try_read(ptr + STR_LEN_OFF, 8)
    if not sz_data or len(sz_data) < 8:
        return None
    sz = struct.unpack_from("<Q", sz_data)[0]
    if sz > max_len:
        return None
    read_ptr = ptr
    if sz > MAX_SIMPLE:
        read_ptr = read_mem_u64(reader, ptr)
        if not read_ptr:
            return None
    raw = reader.try_read(read_ptr, sz)
    if not raw:
        return None
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None

def _check_class_name(reader, instance_addr, class_desc_off):
    cd_ptr = read_mem_u64(reader, instance_addr + class_desc_off)
    if not cd_ptr:
        return None
    name_ptr = read_mem_u64(reader, cd_ptr + 0x8)
    if not name_ptr:
        return None
    return _rbx_read_string(reader, name_ptr)

def _get_roblox_log_ids():
    local_app = os.environ.get("LOCALAPPDATA", "")
    log_dir = os.path.join(local_app, "Roblox", "logs")
    try:
        logs = sorted(glob.glob(os.path.join(log_dir, "*.log")),
                      key=os.path.getmtime, reverse=True)
    except Exception:
        return None, None

    place_re = re.compile(r"(?:placeIds?|placeId)[=:](\d+)", re.IGNORECASE)
    user_re  = re.compile(r'"?userId"?\s*[=:]\s*(\d+)', re.IGNORECASE)

    for log in logs[:5]:
        place_id = user_id = None
        try:
            with open(log, "r", errors="replace") as f:
                for line in f:
                    m = place_re.search(line)
                    if m:
                        place_id = int(m.group(1))
                    m = user_re.search(line)
                    if m:
                        user_id = int(m.group(1))
        except Exception:
            continue
        if place_id or user_id:
            return place_id, user_id
    return None, None


def _scan_locale_id(reader, player):
    block = reader.try_read(player, _MAX_OFFSET)
    if not block:
        return None
    want = 2
    for off in range(0, len(block) - 23):
        if struct.unpack_from("<Q", block, off + 16)[0] != want:
            continue
        c0 = block[off]
        c1 = block[off + 1]
        if 0x41 <= c0 <= 0x5A and 0x41 <= c1 <= 0x5A:
            return chr(c0) + chr(c1)
    return None


def _valid_ptr(addr):
    return bool(addr) and 0x400000 < addr < 0x8000000000000000 \
        and addr != 0xCCCCCCCCCCCCCCCC


def _scan_field(reader, addr, size, fmt, pred, step=1):
    block = reader.try_read(addr, size)
    if not block:
        return None
    fs = struct.calcsize(fmt)
    for off in range(0, len(block) - fs + 1, step):
        if pred(struct.unpack_from(fmt, block, off)[0]):
            return off
    return None
