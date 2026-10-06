import ctypes
import hashlib
import os
import re
import struct
import sys
import time

from ctypes import wintypes, windll, byref, sizeof, c_void_p, c_size_t, POINTER

NTSTATUS = ctypes.c_long

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

ntdll = ctypes.WinDLL("ntdll")

NtReadVirtualMemory = ntdll.NtReadVirtualMemory
NtReadVirtualMemory.restype = NTSTATUS
NtReadVirtualMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID,
    ctypes.c_size_t, POINTER(ctypes.c_size_t),
]

MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01

READABLE_PROTECTIONS = (0x02, 0x04, 0x08, 0x20, 0x40, 0x80)


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", ctypes.c_ulong),
        ("__alignment1", ctypes.c_ulong),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
        ("__alignment2", ctypes.c_ulong),
    ]


VERBOSE = False


def set_verbose(flag):
    global VERBOSE
    VERBOSE = bool(flag)


def scrub_paths(message):
    home = os.path.expanduser("~")
    if home and home not in ("\\", "/"):
        message = message.replace(home, "~")
    return message.replace(os.path.abspath(__file__), os.path.basename(__file__))


def debug_log(message=""):
    if VERBOSE:
        print(scrub_paths(message))


def warn(message):
    print(scrub_paths(message))


def read_u8(buf, off):  return buf[off] if off < len(buf) else 0
def read_s8(buf, off):  v = read_u8(buf, off); return v - 256 if v >= 128 else v
def read_u32(buf, off): return struct.unpack_from("<I", buf, off)[0] if off + 4 <= len(buf) else 0
def read_s32(buf, off): return struct.unpack_from("<i", buf, off)[0] if off + 4 <= len(buf) else 0
def read_u64(buf, off): return struct.unpack_from("<Q", buf, off)[0] if off + 8 <= len(buf) else 0

_REG64 = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
          "r8","r9","r10","r11","r12","r13","r14","r15"]
_REG32 = ["eax","ecx","edx","ebx","esp","ebp","esi","edi",
          "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"]

class Instruction:
    __slots__ = ("addr","size","mnem","ops","raw")
    def __init__(self, addr, size, mnem, ops, raw=b""):
        self.addr = addr; self.size = size
        self.mnem = mnem; self.ops  = ops; self.raw = raw

def _modrm(buf, pos, rex_b, rex_r, rex_x, w64):
    if pos >= len(buf): return ("?", "?", pos)
    modrm = buf[pos]; pos += 1
    mod = (modrm >> 6) & 3
    reg = ((modrm >> 3) & 7) | (8 if rex_r else 0)
    rm  = (modrm & 7)       | (8 if rex_b else 0)

    reg_s = (_REG64 if w64 else _REG32)[reg & 15]

    if mod == 3:
        rm_s = (_REG64 if w64 else _REG32)[rm & 15]
        return (rm_s, reg_s, pos)


    sib_used = False
    base_reg = rm & 7
    disp = 0

    if (rm & 7) == 4:
        if pos >= len(buf): return ("?", reg_s, pos)
        sib = buf[pos]; pos += 1
        scale = 1 << ((sib >> 6) & 3)
        idx   = ((sib >> 3) & 7) | (8 if rex_x else 0)
        base  = (sib & 7)        | (8 if rex_b else 0)
        base_reg = base & 7
        sib_used = True

        if mod == 0 and base_reg == 5:
            disp = read_s32(buf, pos); pos += 4
            if idx & 7 == 4:
                rm_s = "[0x%x]" % (disp & 0xFFFFFFFFFFFFFFFF)
            else:
                rm_s = "[%s*%d + 0x%x]" % (_REG64[idx & 15], scale, disp & 0xFFFFFFFFFFFFFFFF)
        else:
            base_s = _REG64[base & 15]
            if idx & 7 == 4:
                idx_part = ""
            else:
                idx_s = _REG64[idx & 15]
                idx_part = " + %s*%d" % (idx_s, scale) if scale > 1 else " + %s" % idx_s
            if mod == 1:
                disp = read_s8(buf, pos); pos += 1
            elif mod == 2:
                disp = read_s32(buf, pos); pos += 4
            if disp > 0:
                rm_s = "[%s%s + 0x%x]" % (base_s, idx_part, disp)
            elif disp < 0:
                rm_s = "[%s%s - 0x%x]" % (base_s, idx_part, -disp)
            else:
                rm_s = "[%s%s]" % (base_s, idx_part)
    elif mod == 0 and base_reg == 5:
        disp = read_s32(buf, pos); pos += 4
        rm_s = "[rip + 0x%x]" % (disp & 0xFFFFFFFFFFFFFFFF) if disp >= 0 else "[rip - 0x%x]" % (-disp)
    else:
        base_s = _REG64[rm & 15]
        if mod == 1:
            disp = read_s8(buf, pos); pos += 1
        elif mod == 2:
            disp = read_s32(buf, pos); pos += 4
        if disp > 0:
            rm_s = "[%s + 0x%x]" % (base_s, disp)
        elif disp < 0:
            rm_s = "[%s - 0x%x]" % (base_s, -disp)
        else:
            rm_s = "[%s]" % base_s

    return (rm_s, reg_s, pos)

def decode_one(image, va, base):
    off = va - base
    if off < 0 or off >= len(image): return None
    buf = image
    start = off
    rex = 0; rex_w = rex_r = rex_x = rex_b = False
    pfx66 = pfxF2 = pfxF3 = False


    while off < len(buf):
        b = buf[off]
        if b == 0x66: pfx66 = True; off += 1
        elif b == 0xF2: pfxF2 = True; off += 1
        elif b == 0xF3: pfxF3 = True; off += 1
        elif b in (0x2E,0x3E,0x26,0x64,0x65,0x36): off += 1
        elif 0x40 <= b <= 0x4F:
            rex = b; rex_w = bool(b & 8); rex_r = bool(b & 4)
            rex_x = bool(b & 2); rex_b = bool(b & 1); off += 1
        else:
            break

    if off >= len(buf): return None
    b = buf[off]; off += 1
    w64 = rex_w

    def emit(mnem, ops):
        size = off - start
        return Instruction(va, size, mnem, ops, bytes(buf[start:off]))


    if b == 0xE8:
        rel = read_s32(buf, off); off += 4
        target = (va + (off - start) + rel) & 0xFFFFFFFFFFFFFFFF
        return emit("call", "0x%x" % target)


    if b == 0xE9:
        rel = read_s32(buf, off); off += 4
        target = (va + (off - start) + rel) & 0xFFFFFFFFFFFFFFFF
        return emit("jmp", "0x%x" % target)


    if b == 0xEB:
        rel = read_s8(buf, off); off += 1
        target = (va + (off - start) + rel) & 0xFFFFFFFFFFFFFFFF
        return emit("jmp", "0x%x" % target)


    if 0x70 <= b <= 0x7F:
        cc = ["jo","jno","jb","jnb","je","jne","jbe","ja",
              "js","jns","jp","jnp","jl","jge","jle","jg"][b & 0xF]
        rel = read_s8(buf, off); off += 1
        target = (va + (off - start) + rel) & 0xFFFFFFFFFFFFFFFF
        return emit(cc, "0x%x" % target)


    if b == 0x0F:
        if off >= len(buf): return None
        b2 = buf[off]; off += 1


        if 0x80 <= b2 <= 0x8F:
            cc = ["jo","jno","jb","jnb","je","jne","jbe","ja",
                  "js","jns","jp","jnp","jl","jge","jle","jg"][b2 & 0xF]
            rel = read_s32(buf, off); off += 4
            target = (va + (off - start) + rel) & 0xFFFFFFFFFFFFFFFF
            return emit(cc, "0x%x" % target)


        if b2 in (0xB6, 0xB7):
            rm_s, reg_s, off = _modrm(buf, off, rex_b, rex_r, rex_x, w64)
            return emit("movzx", "%s, %s" % (reg_s, rm_s))


        if b2 in (0x28, 0x29):
            rm_s, reg_s, off = _modrm(buf, off, rex_b, rex_r, rex_x, False)
            if b2 == 0x28:
                return emit("movaps", "%s, %s" % (reg_s, rm_s))
            else:
                return emit("movaps", "%s, %s" % (rm_s, reg_s))


        if b2 == 0xAF:
            rm_s, reg_s, off = _modrm(buf, off, rex_b, rex_r, rex_x, w64)
            return emit("imul", "%s, %s" % (reg_s, rm_s))


        return emit("db", "0f 0x%02x" % b2)


    if b == 0x63:
        rm_s, reg_s, off = _modrm(buf, off, rex_b, rex_r, rex_x, False)
        reg64 = _REG64[_REG32.index(reg_s)] if reg_s in _REG32 else reg_s
        return emit("movsxd", "%s, %s" % (reg64, rm_s))


    if b == 0x8D:
        rm_s, reg_s, off = _modrm(buf, off, rex_b, rex_r, rex_x, w64)
        return emit("lea", "%s, %s" % (reg_s, rm_s))


    if b in (0x88, 0x89, 0x8A, 0x8B):
        is8 = b in (0x88, 0x8A)
        rm_s, reg_s, off = _modrm(buf, off, rex_b, rex_r, rex_x, w64 and not is8)
        if b in (0x89, 0x88): return emit("mov", "%s, %s" % (rm_s, reg_s))
        else:                  return emit("mov", "%s, %s" % (reg_s, rm_s))


    if 0xB8 <= b <= 0xBF:
        reg = (b & 7) | (8 if rex_b else 0)
        if w64:
            imm = read_u64(buf, off); off += 8
            return emit("mov", "%s, 0x%x" % (_REG64[reg], imm))
        else:
            imm = read_u32(buf, off); off += 4
            return emit("mov", "%s, 0x%x" % (_REG32[reg], imm))


    if b == 0xC7:
        rm_s, reg_s, off = _modrm(buf, off, rex_b, rex_r, rex_x, w64)
        imm = read_s32(buf, off); off += 4
        return emit("mov", "%s, 0x%x" % (rm_s, imm & 0xFFFFFFFF))


    if 0x50 <= b <= 0x57:
        reg = (b & 7) | (8 if rex_b else 0)
        return emit("push", _REG64[reg])


    if b == 0x6A:
        imm = read_s8(buf, off); off += 1
        return emit("push", "0x%x" % (imm & 0xFF))
    if b == 0x68:
        imm = read_u32(buf, off); off += 4
        return emit("push", "0x%x" % imm)


    if b in (0x81, 0x83):
        rm_s, _, off = _modrm(buf, off, rex_b, False, rex_x, w64)
        if b == 0x83:
            imm = read_s8(buf, off); off += 1
        else:
            imm = read_s32(buf, off); off += 4

        return emit("arith", "%s, 0x%x" % (rm_s, imm & 0xFFFFFFFF))


    if b in (0x39, 0x3B):
        rm_s, reg_s, off = _modrm(buf, off, rex_b, rex_r, rex_x, w64)
        if b == 0x39: return emit("cmp", "%s, %s" % (rm_s, reg_s))
        else:         return emit("cmp", "%s, %s" % (reg_s, rm_s))


    if b == 0x80:
        rm_s, _, off = _modrm(buf, off, rex_b, False, rex_x, False)
        imm = read_u8(buf, off); off += 1
        return emit("cmp", "%s, 0x%x" % (rm_s, imm))


    if b in (0x31, 0x33):
        rm_s, reg_s, off = _modrm(buf, off, rex_b, rex_r, rex_x, w64)
        if b == 0x31: return emit("xor", "%s, %s" % (rm_s, reg_s))
        else:         return emit("xor", "%s, %s" % (reg_s, rm_s))


    if b == 0xC3: return emit("ret", "")
    if b == 0xC2: imm = _u16 = read_u32(buf, off) & 0xFFFF; off += 2; return emit("ret", "0x%x" % imm)


    if b == 0x90: return emit("nop", "")


    if b == 0x85:
        rm_s, reg_s, off = _modrm(buf, off, rex_b, rex_r, rex_x, w64)
        return emit("test", "%s, %s" % (rm_s, reg_s))


    return emit("db", "0x%02x" % b)


def rip_target(insn, base):
    ops = insn.ops

    m = re.search(r'\[rip\s*([+-])\s*0x([0-9a-f]+)\]', ops, re.IGNORECASE)
    if not m: return None
    disp = int(m.group(2), 16)
    if m.group(1) == '-': disp = -disp
    next_va = insn.addr + insn.size
    return (next_va + disp) - base


def call_target(insn):
    if insn.mnem != "call": return None
    try:
        return int(insn.ops, 16)
    except ValueError:
        return None


def scan_string_rva(image, s, require_null=True):
    needle = s.encode() + (b"\x00" if require_null else b"")
    pos = image.find(needle)
    if pos == -1:

        pos = image.find(s.encode())
    return pos if pos != -1 else None


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


_SIGNATURE_CACHE = {}


def _signature_regex(signature):
    regex = _SIGNATURE_CACHE.get(signature)
    if regex is None:
        tokens = signature.split()
        regex = re.compile(b"(?s)" + b"".join(
            b"." if token in ("??", "?") else re.escape(bytes([int(token, 16)]))
            for token in tokens))
        _SIGNATURE_CACHE[signature] = regex
    return regex


def pattern_scan(image, pattern_str):
    tokens = pattern_str.strip().split()
    if not tokens:
        return None
    if len(tokens) > len(image):
        return None
    if all(token in ("??", "?") for token in tokens):
        return 0
    match = _signature_regex(" ".join(tokens)).search(image)
    return match.start() if match else None


_LUAC_GUIDES = {
    "luaC_step": (
        "InvalidInstance", 2,
        ["48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? "
         "41 54 41 56 41 57 48 83 EC 30 48 8B 59 ? 0F B6 FA"],
        "func_start",
    ),
    "gcstep": (
        "InvalidInstance", 2,
        ["48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 48 89 7C 24 ? "
         "41 54 41 56 41 57 48 83 EC 30 48 8B 59 ? 0F B6 FA"],
        "movsxd_movaps_call",
    ),
    "lua_checkstack": (
        "Attempt to migrate WeakObjectRef across VM boundary", 1,
        [], "func_start",
    ),
    "pseudo2addr": (
        "Attempt to migrate WeakObjectRef across VM boundary", 1,
        [], "rip_global",
    ),
    "luaO_NilObject": (
        "Attempt to migrate WeakObjectRef across VM boundary", 1,
        [], "rip_near",
    ),
    "luaD_Throw": (
        "resulting string too large", 1,
        ["48 83 EC 58 44 8B C2 48 8B D1"],
        "func_start",
    ),
    "luaO_pushfstring": (
        "AuroraStruct<%s>", 1,
        ["48 89 54 24 ? 4C 89 44 24 ? 4C 89 4C 24 ? 53 48 83 EC 20 48 8B 51"],
        "func_start",
    ),
    "luaL_loadsafe": (
        "%s: bytecode corrupted", 1,
        ["48 89 54 24 ? 48 89 4C 24 ? 55 53 56 57 41 54 41 55 41 56 41 57 "
         "48 8D AC 24 ? ? ? ? 48 81 EC 58 0B 00 00"],
        "func_start",
    ),
    "dumpgco": (
        '"0":{"type":"userdata","cat":0,"size":0}', 1,
        ["48 89 5C 24 ? 57 48 83 EC 20 48 8D 15"],
        "third_arg",
    ),
    "lua_newstate": (
        "Failed to create Lua state", 2,
        ["48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 41 56 41 57 "
         "48 8D AC 24 ? ? ? ? 48 81 EC 50 02 00 00 4C 8B F2"],
        "func_start",
    ),
    "ktable": (
        "Trying to call method on object of type: `%s` with incorrect arguments",
        1, [], "rip_global",
    ),
    "luaB_table": (
        "iterate over", 1, [], "many_xref_func",
    ),
    "Print": (
        "Current identity is %d", 1, [], "next_call",
    ),
}


def _func_start_before(image, base, xref_va, window=0x2000):
    lo = max(base, xref_va - window)
    best = None
    va = lo
    prev_was_gap = True
    while va < xref_va:
        ins = decode_one(image, va, base)
        if ins is None:
            va += 1
            continue
        if ins.mnem == "int3" or ins.mnem == "nop":
            va += ins.size
            continue
        if prev_was_gap and ins.mnem in ("push", "mov", "sub", "lea", "endbr64"):
            best = ins.addr
        prev_was_gap = ins.mnem in ("ret",)
        va += ins.size
    return best


def _all_rip_targets(image, base, func_va, window=0x400):
    out = []
    va = func_va
    end = func_va + window
    while va < end:
        ins = decode_one(image, va, base)
        if ins is None:
            va += 1
            continue
        if ins.mnem == "lea":
            tgt = rip_target(ins, base)
            if tgt is not None and base <= tgt < base + len(image):
                out.append(tgt)
        if ins.mnem == "ret":
            break
        va += ins.size
    return out


def _resolve_guide(image, base, key, note=None):
    entry = _LUAC_GUIDES.get(key)
    if entry is None:
        return None
    anchor, nth, sigs, selector = entry


    for pat in sigs:
        rva = pattern_scan(image, pat)
        if rva is not None:
            if note:
                note("%s (via signature)" % key)
            return rva


    s_rva = scan_string_rva(image, anchor)
    if s_rva is None:
        if note:
            note("%s FAILED: anchor string not in image" % key)
        return None
    xref_va = find_nth_lea_xref(image, base, s_rva, nth)
    if xref_va is None:
        if note:
            note("%s FAILED: no %d xref of %r"
                 % (key, nth, anchor[:32]))
        return None

    func_va = _func_start_before(image, base, xref_va)
    if func_va is None:
        func_va = xref_va

    if selector == "func_start":
        rva = func_va - base
    elif selector == "next_call":
        call_ins = find_next(image, base, xref_va, "call", limit_bytes=100)
        if call_ins is None:
            if note:
                note("%s FAILED: no call after xref" % key)
            return None
        tgt = call_target(call_ins)
        rva = (tgt - base) if tgt else None
    elif selector == "rip_global":


        for tgt in _all_rip_targets(image, base, func_va):
            if 0 <= tgt - base < len(image):
                rva = tgt - base
                break
        else:
            rva = None
    elif selector == "rip_near":
        cands = [t - base for t in _all_rip_targets(image, base, func_va)]
        rva = cands[0] if cands else None
    elif selector == "movsxd_movaps_call":
        va, movsxd_seen, movaps_seen = func_va, False, False
        rva = None
        for _ in range(300):
            ins = decode_one(image, va, base)
            if ins is None:
                break
            if ins.mnem == "movsxd":
                movsxd_seen = True
            elif movsxd_seen and ins.mnem == "movaps":
                movaps_seen = True
            elif movsxd_seen and movaps_seen and ins.mnem == "call":
                tgt = call_target(ins)
                if tgt:
                    rva = tgt - base
                break
            va += ins.size
    elif selector == "third_arg":

        call_ins = find_next(image, base, xref_va, "call", limit_bytes=64)
        rva = None
        if call_ins:
            va = max(func_va, call_ins.addr - 0x60)
            while va < call_ins.addr:
                ins = decode_one(image, va, base)
                if ins is None:
                    va += 1
                    continue
                if ins.mnem == "lea" and "rcx" in ins.ops:
                    tgt = rip_target(ins, base)
                    if tgt is not None:
                        rva = tgt - base
                        break
                va += ins.size
    elif selector == "many_xref_func":


        helper_rva = func_va - base
        best, best_score = None, -1
        for site in _scan_call_sites_to(image, base, helper_rva):
            score = sum(1 for t in _all_rip_targets(image, base, site, 0x2000)
                        if _looks_like_string(image, base, t))
            if score > best_score:
                best, best_score = site, score
        rva = (best - base) if best is not None else None
    else:
        rva = None

    if note:
        note("%s%s" % (key, "" if rva else " FAILED"))
    return rva


def _scan_call_sites_to(image, base, target_rva):
    want = (target_rva + 5) & 0xFFFFFFFF
    out = []
    pos = 0
    n = len(image)
    while True:
        off = image.find(b"\xE8", pos)
        if off == -1 or off + 5 > n:
            break
        pos = off + 1
        rel = struct.unpack_from("<i", image, off + 1)[0]
        if ((off + 5 + rel) & 0xFFFFFFFF) == want:
            out.append(base + off)
    return out


def _looks_like_string(image, base, target_va):
    off = target_va - base
    if off < 0 or off >= len(image):
        return False
    ch = image[off:off + 1]
    return bool(ch) and 0x20 <= ch[0] < 0x7F


def _resolve_luac_step(image, base, note=None):
    luac_step_rva = _resolve_guide(image, base, "luaC_step", note)
    gcstep_rva = _resolve_guide(image, base, "gcstep", note)

    if luac_step_rva is None:

        s_rva = scan_string_rva(
            image, "Attempt to load a function from a different Lua VM")
        if s_rva is None:
            return None, None
        xref_va = find_lea_xref(image, base, s_rva)
        if xref_va is None:
            return None, None
        call1 = find_next(image, base, xref_va, "call", limit_bytes=100)
        if call1 is None:
            return None, None
        wrapper_va = call_target(call1)
        if wrapper_va is None:
            return None, None
        call2 = find_next(image, base, wrapper_va, "call", limit_bytes=100)
        if call2 is None:
            return None, None
        luac_step_rva = (call_target(call2) or 0) - base
        if note:
            note("luaC_step (via legacy call chain)")

    if gcstep_rva is None:
        gcstep_va, gcstep_rva = _legacy_gcstep(image, base,
                                                base + luac_step_rva)
    else:
        gcstep_va = None

    return base + luac_step_rva, gcstep_va


def _legacy_gcstep(image, base, luac_step_va):
    gcstep_va = None
    va = luac_step_va
    movsxd_seen = movaps_seen = False
    for _ in range(300):
        ins = decode_one(image, va, base)
        if ins is None:
            break
        if ins.mnem == "movsxd":
            movsxd_seen = True
        elif movsxd_seen and ins.mnem == "movaps":
            movaps_seen = True
        elif movsxd_seen and movaps_seen and ins.mnem == "call":
            tgt = call_target(ins)
            if tgt:
                gcstep_va = tgt
            break
        va += ins.size
    return gcstep_va, (gcstep_va - base if gcstep_va else None)


def dump_luau_offsets(image, base):

    out = {}

    def _note(name, rva):
        if rva:
            out[name] = rva
            debug_log("  [luau] %-30s 0x%X" % (name, rva))


    for pat in [
        "49 8B F0 4C 63 82 98 00 00 00 48 8B DA 48 8B 52 68 48 8B F9",
        "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 44 0F B6 4A ? 49 8B F0",
        "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 44 0F B6 4A",
    ]:
        rva = pattern_scan(image, pat)
        if rva is not None:
            _note("luaF_freeproto", rva)
            break


    for pat in [
        "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 8B EA 49 8B F8 44 0F B6 41 04 49 8B F1 48 63 D2 48 8B D9 48 83 C2 02 48 C1 E2 04 E8 ?? ?? ?? ??",
        "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8B EA 49 8B F8",
    ]:
        rva = pattern_scan(image, pat)
        if rva is not None:
            _note("luaF_newLClosure", rva)
            break


    for pat in [
        "48 89 5C 24 ? 57 48 83 EC ? 48 8B FA 48 8B D9 E8 ? ? ? ? 48 8B CB 84 C0 74 ? 48 8B D7",
        "48 89 5C 24 ? 57 48 83 EC ? 48 8B FA 48 8B D9 E8 ? ? ? ? 48 8B CB 84 C0",
        "48 89 5C 24 08 57 48 83 EC 20 48 8B FA 48 8B D9 E8 ? ? ? ? 48 8B CB 84 C0 74 12 48 8B D7 48 8B 5C 24 30 48 83 C4 20 5F E9 ? ? ? ?",
        "48 8B FA 48 8B D9 E8 ? ? ? ? 48 8B CB 84 C0 74 ? 48 8B D7",
    ]:
        rva = pattern_scan(image, pat)
        if rva is not None:
            _note("PushInstance", rva)
            break


    for pat in [
        "40 53 56 57 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 84 24 ? ? ? ? 45 8B F9",
        "40 53 56 57 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48 33 C4 48 89",
        "40 53 56 57 41 56 41 57 48 81 EC ? ? ? ? 48 8B 05 ? ? ? ? 48",
    ]:
        rva = pattern_scan(image, pat)
        if rva is not None:
            _note("LuaVMLoad", rva)
            break


    s_rva = scan_string_rva(image, "'__index' chain too long; possible loop")
    if s_rva is not None:
        target_rva = s_rva + 0xA8

        xref_va = find_lea_xref(image, base, target_rva, max_scan=0x800000)
        if xref_va is not None:
            ins = decode_one(image, xref_va, base)
            if ins and ins.mnem == "lea":
                tgt = rip_target(ins, base)
                if tgt is not None:
                    _note("luaO_nilobject", tgt)


    s_rva = scan_string_rva(image, "no value")
    if s_rva is not None:
        xref_va = find_lea_xref(image, base, s_rva, max_scan=0x800000)
        if xref_va is not None:

            va = xref_va
            movsxd_found = False
            for _ in range(40):
                ins = decode_one(image, va, base)
                if ins is None: break
                if ins.mnem == "movsxd":
                    movsxd_found = True
                elif movsxd_found and ins.mnem == "lea":
                    tgt = rip_target(ins, base)
                    if tgt is not None:
                        _note("luaT_typenames", tgt)
                    break
                va += ins.size


    s_rva = scan_string_rva(image, '{"type":"table","cat":%d,"size":%d')
    if s_rva is None:
        s_rva = scan_string_rva(image, '{"type":"table"')
    if s_rva is not None:
        xref_va = find_lea_xref(image, base, s_rva, max_scan=0x800000)
        if xref_va is not None:

            scan_back = max(base, xref_va - 300)
            func_start_va = None

            va = scan_back
            while va < xref_va:
                ins = decode_one(image, va, base)
                if ins is None: va += 1; continue
                if ins.mnem == "push":

                    ins2 = decode_one(image, va + ins.size, base)
                    ins3 = decode_one(image, va + ins.size + (ins2.size if ins2 else 1), base)
                    if ins2 and ins3 and ins2.mnem in ("push","sub") and ins3.mnem in ("push","sub","mov"):
                        func_start_va = va
                        break
                va += ins.size
            search_from = func_start_va if func_start_va else xref_va - 80

            lea_ins = find_next(image, base, search_from, "lea", limit_bytes=80)
            if lea_ins:
                tgt = rip_target(lea_ins, base)
                if tgt is not None:
                    _note("luaH_dummynode", tgt)


    s_rva = scan_string_rva(image, "Failed to create Lua state")
    if s_rva is not None:

        xref_va = (find_nth_lea_xref(image, base, s_rva, 2)
                   or find_lea_xref(image, base, s_rva))
        if xref_va is not None:

            scan_start = max(base, xref_va - 10000)
            func_start_va = None
            va = scan_start
            while va < xref_va:
                ins = decode_one(image, va, base)
                if ins is None: va += 1; continue
                if ins.mnem == "push":
                    ins2 = decode_one(image, va + ins.size, base)
                    if ins2 and ins2.mnem == "push":
                        func_start_va = va
                va += ins.size
            if func_start_va is None:
                func_start_va = max(base, xref_va - 200)

            va = func_start_va
            lea_seen = False
            for _ in range(200):
                ins = decode_one(image, va, base)
                if ins is None: break
                if ins.mnem == "lea":
                    lea_seen = True
                elif lea_seen and ins.mnem == "call":
                    tgt = call_target(ins)
                    if tgt:
                        _note("lua_newstate", tgt - base)
                    break
                va += ins.size


    print_strings = [


        "Current identity is %d",
        "Unable to add SDL controller mappings because %s",
        "Invalid state passed to SetStateEnabled.",
        "Instance '%s' is not predicted.",
        "RoMarkError: Turn over pattern can't be parsed.",
        "AnalyticsService: %s event fired.",
        "Invalid player to teleport.",
        "Failed to load video %s: %s",
        "Key %s not found in map of player data.",
        "Failed to resume waiting thread: out of stack space",
        "Sitting is not enabled yet",
    ]
    for ps in print_strings:
        s_rva = scan_string_rva(image, ps)
        if s_rva is None: continue
        xref_va = find_lea_xref(image, base, s_rva, max_scan=0x800000)
        if xref_va is None: continue

        call_ins = find_next(image, base, xref_va, "call", limit_bytes=100)
        if call_ins:
            tgt = call_target(call_ins)
            if tgt:
                _note("Print", tgt - base)
                break


    s_rva = scan_string_rva(image, "Can't resume script in this context")
    if s_rva is not None:
        xref_va = find_lea_xref(image, base, s_rva, max_scan=0x800000)
        if xref_va is not None:

            push_rbx = find_prev(image, base, xref_va, "push", limit_bytes=1000)
            if push_rbx and "rbx" in push_rbx.ops:
                _note("ScriptContextResume", push_rbx.addr - base)


    s_rva = scan_string_rva(image, "RBXCRASH: {}\n")
    if s_rva is None:
        s_rva = scan_string_rva(image, "RBXCRASH: {}")
    if s_rva is not None:
        xref_va = find_lea_xref(image, base, s_rva, max_scan=0x800000)
        if xref_va is not None:
            push_rbp = find_prev(image, base, xref_va, "push", limit_bytes=670)
            if push_rbp and "rbp" in push_rbp.ops:
                result_va = push_rbp.addr - 0xA
                _note("GetProperty", result_va - base)


    s_rva = scan_string_rva(image, "NewInstance")
    if s_rva is not None:
        xref_va = find_lea_xref(image, base, s_rva, max_scan=0x800000)
        if xref_va is not None:

            va = max(base, xref_va - 500)
            best_start = None
            movs = 0
            while va < xref_va:
                ins = decode_one(image, va, base)
                if ins is None: va += 1; continue
                if ins.mnem == "mov": movs += 1
                elif ins.mnem == "push" and movs >= 2:
                    best_start = ins.addr
                    movs = 0
                else:
                    movs = 0
                va += ins.size
            if best_start:
                _note("NewInstance", best_start - 0xA - base)


    s_rva = scan_string_rva(image, "The metatable is locked")
    if s_rva is not None:
        xref_va = find_lea_xref(image, base, s_rva, max_scan=0x800000)
        if xref_va is not None:
            call_ins = find_next(image, base, xref_va, "call", limit_bytes=50)
            if call_ins:
                tgt = call_target(call_ins)
                if tgt: _note("lua_pushstring", tgt - base)
            jmp_ins = find_next(image, base, xref_va, "jmp", limit_bytes=200)
            if jmp_ins:
                tgt = call_target(jmp_ins)
                if tgt is None:
                    try: tgt = int(jmp_ins.ops, 16)
                    except: pass
                if tgt: _note("lua_setfield", tgt - base)


    s_rva = scan_string_rva(image, "%s: bytecode corrupted")
    if s_rva is not None:
        xref_va = find_lea_xref(image, base, s_rva, max_scan=0x800000)
        if xref_va is not None:
            _note("Bytecode_xref", xref_va - base)


    freeproto_rva = out.get("luaF_freeproto")
    if freeproto_rva is not None:
        freeproto_va = base + freeproto_rva
        end_va = func_end(image, base, freeproto_va, max_bytes=0x200)

        calls_in_func = collect_calls(image, base, freeproto_va, end_va)


        va = freeproto_va
        movzx_insns = []
        mov_rdx_insns = []
        while va < end_va:
            ins = decode_one(image, va, base)
            if ins is None: va += 1; continue
            if ins.mnem == "movzx":
                movzx_insns.append(ins)
            if ins.mnem == "mov" and any(r in ins.ops for r in ("rdx","rcx")) and "[" in ins.ops:
                mov_rdx_insns.append(ins)
            va += ins.size

        def _parse_struct_offset(insn):
            m = re.search(r'\[\w+\s*\+\s*0x([0-9a-f]+)\]', insn.ops, re.IGNORECASE)
            if m: return int(m.group(1), 16)
            m = re.search(r'\[\w+\s*\+\s*(\d+)\]', insn.ops)
            if m: return int(m.group(1))
            return None

        if movzx_insns:
            off = _parse_struct_offset(movzx_insns[0])
            if off is not None: _note("Proto_memcat", off)

        if len(mov_rdx_insns) >= 1:
            off = _parse_struct_offset(mov_rdx_insns[0])
            if off is not None: _note("Proto_code", off)
        if len(mov_rdx_insns) >= 2:
            off = _parse_struct_offset(mov_rdx_insns[1])
            if off is not None: _note("Proto_p", off)
        if len(mov_rdx_insns) >= 3:
            off = _parse_struct_offset(mov_rdx_insns[2])
            if off is not None: _note("Proto_k", off)


        def _first_mem_mov_after(call_idx):
            if call_idx >= len(calls_in_func): return None
            call_va, _ = calls_in_func[call_idx]

            ins = decode_one(image, call_va, base)
            if ins is None: return None
            after_va = call_va + ins.size
            for _ in range(8):
                i = decode_one(image, after_va, base)
                if i is None: break
                if i.mnem == "mov" and "[" in i.ops:
                    return _parse_struct_offset(i)
                after_va += i.size
            return None

        for idx, name in enumerate(("Proto_lineinfo","Proto_locvars","Proto_upvalues","Proto_debuginsn"), start=2):
            off = _first_mem_mov_after(idx)
            if off is not None: _note(name, off)


    def _gnote(msg):
        debug_log("  [guide] %s" % msg)

    for key in ("lua_newstate", "luaD_Throw", "luaO_pushfstring",
                "luaL_loadsafe", "dumpgco", "lua_checkstack", "pseudo2addr",
                "luaO_NilObject", "ktable", "Print"):
        rva = _resolve_guide(image, base, key, _gnote)
        if rva and key not in out:
            out[key] = rva
            debug_log("  [luau] %-30s 0x%X" % (key, rva))

    return out


def dump_luau_global_offsets(image, base):
    out = {}

    def _note(name, val):
        if val is not None:
            out[name] = val
            debug_log("  [struct] %-30s 0x%X" % (name, val))

    def _parse_mem_offset(insn):
        m = re.search(r'\[\w+\s*[+\-]\s*0x([0-9a-f]+)\]', insn.ops, re.IGNORECASE)
        if m: return int(m.group(1), 16)
        m = re.search(r'\[(\w+)\]', insn.ops)
        return None


    _gcstep_hint_rva = [None]

    def _snote(msg):
        debug_log("  [struct] %s" % msg)

    luac_step_va, _gcstep_hint = _resolve_luac_step(image, base, _snote)
    if luac_step_va is None:
        debug_log("  [struct] luaC_step unresolved - global_State struct "
              "offsets skipped")
        return out
    if not (base <= luac_step_va < base + len(image)):
        return out

    luac_step_rva = luac_step_va - base
    debug_log("  [struct] luaC_step (derived)          0x%X" % luac_step_rva)


    va = luac_step_va
    push_seen = sub_seen = False
    for _ in range(100):
        ins = decode_one(image, va, base)
        if ins is None: break
        if ins.mnem == "push": push_seen = True
        elif push_seen and ins.mnem in ("arith","sub"): sub_seen = True
        elif push_seen and sub_seen and ins.mnem == "mov":
            m = re.search(r'\[\w+\s*\+\s*0x([0-9a-f]+)\]', ins.ops, re.IGNORECASE)
            if m:
                _note("L_global_offset", int(m.group(1), 16))
                break
        va += ins.size


    va = luac_step_va
    _luac_ceil = luac_step_va + 0x500
    movzx_seen = movaps_seen = False
    for _ in range(60):
        if va >= _luac_ceil: break
        ins = decode_one(image, va, base)
        if ins is None: break
        if ins.mnem in ("ret",): break
        if ins.mnem == "movzx": movzx_seen = True
        elif movzx_seen and ins.mnem == "movaps": movaps_seen = True
        elif movzx_seen and movaps_seen and ins.mnem == "mov":
            m = re.search(r'\[\w+\s*\+\s*0x([0-9a-f]+)\]', ins.ops, re.IGNORECASE)
            if m:
                _note("g_gcstepmul", int(m.group(1), 16))

                ins2 = decode_one(image, va + ins.size, base)
                if ins2 and ins2.mnem == "mov":
                    m2 = re.search(r'\[\w+\s*\+\s*0x([0-9a-f]+)\]', ins2.ops, re.IGNORECASE)
                    if m2: _note("g_gcstepsize", int(m2.group(1), 16))
                break
        va += ins.size


    gcstep_va = _gcstep_hint
    if gcstep_va is None:
        va = luac_step_va
        _luac_end = luac_step_va + 0x1000
        movsxd_seen = movaps_seen2 = False
        for _ in range(250):
            if va >= _luac_end: break
            ins = decode_one(image, va, base)
            if ins is None: break
            if ins.mnem in ("ret",): break
            if ins.mnem == "movsxd": movsxd_seen = True
            elif movsxd_seen and ins.mnem == "movaps": movaps_seen2 = True
            elif movsxd_seen and movaps_seen2 and ins.mnem == "call":
                tgt = call_target(ins)
                if tgt and base <= tgt < base + len(image):
                    gcstep_va = tgt; break
            va += ins.size

    if gcstep_va and base <= gcstep_va < base + len(image):
        gcstep_rva = gcstep_va - base
        debug_log("  [struct] gcstep (derived)             0x%X" % gcstep_rva)


        va = gcstep_va
        for _ in range(150):
            ins = decode_one(image, va, base)
            if ins is None: break
            if ins.mnem == "movzx":
                m = re.search(r'\[\w+\s*\+\s*0x([0-9a-f]+)\]', ins.ops, re.IGNORECASE)
                if m: _note("g_gcstate", int(m.group(1), 16)); break
            va += ins.size


        va = gcstep_va
        _gcstep_end = gcstep_va + 0x2000
        for _ in range(0x200):
            if va >= _gcstep_end: break
            ins = decode_one(image, va, base)
            if ins is None: break
            if ins.mnem in ("ret", "jmp"): break
            if ins.mnem == "je":
                try:
                    je_target = int(ins.ops, 16)
                except ValueError:
                    va += ins.size; continue

                if not (base <= je_target < base + len(image)):
                    va += ins.size; continue
                call_ins = find_next(image, base, je_target, "call", limit_bytes=0x100)
                if call_ins:
                    markroot_va = call_target(call_ins)
                    if markroot_va and base <= markroot_va < base + len(image):
                        markroot_rva = markroot_va - base
                        debug_log("  [struct] markroot (derived)           0x%X" % markroot_rva)

                        mr_va = markroot_va
                        r10movs = []
                        for _ in range(0x200):
                            i = decode_one(image, mr_va, base)
                            if i is None: break
                            if i.mnem == "xor" and "r10" in i.ops.lower():

                                scan_va = max(markroot_va, mr_va - 0x20)
                                while scan_va <= mr_va:
                                    si = decode_one(image, scan_va, base)
                                    if si and si.mnem == "mov" and si.ops.startswith("[rbx +"):
                                        r10movs.append(si)
                                    scan_va += (si.size if si else 1)
                                break
                            mr_va += i.size
                        for idx, gname in enumerate(("g_gray","g_grayagain","g_weak")):
                            if idx < len(r10movs):
                                m = re.search(r'\[\w+\s*\+\s*0x([0-9a-f]+)\]', r10movs[idx].ops, re.IGNORECASE)
                                if m: _note(gname, int(m.group(1), 16))
                        break
            va += ins.size

    return out


TARGET = "Raycast"
FN_OFFS = (0x80, 0x78, 0x88, 0x70, 0x90, 0x68, 0x98)


FIELD_OFFSETS = {
    "ContextPtr": 0x08,
    "RenderQueueId": 0x10,
    "AlphaByte": 0x14,
    "MaterialPtr": 0x20,
    "DecalMaterialPtr": 0x48,
    "TechniqueArrayPtr": 0x70,
    "PrimitiveIndexArrayPtr": 0x80,
    "BBoxMinX": 0x98,
    "BBoxMinY": 0x9C,
    "BBoxMinZ": 0xA0,
    "BBoxMaxX": 0xA4,
    "BBoxMaxY": 0xA8,
    "BBoxMaxZ": 0xAC,
}
TECHNIQUE_ARRAY = {"BeginOffset": 0x00, "EndOffset": 0x08, "EntryStride": 136}
MATERIAL_LAYER = {
    "Stride": 136,
    "FillModeByte": 0x11,
    "MatFlags": 0x18,
    "Param": 0x1C,
    "Flags2": 0x20,
    "ColorData": 0x24,
}

TYPE_PREFIX = b".?AVFastClusterEntity@"
COL_TYPE_DESCRIPTOR_RVA = 0x0C
COL_CLASS_DESCRIPTOR_RVA = 0x10
TYPE_DESCRIPTOR_NAME_OFFSET = 0x10

image_bytes = b""
image_base = 0


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


def find_all(haystack, needle, start=0):
    pos = haystack.find(needle, start)
    while pos != -1:
        yield pos
        pos = haystack.find(needle, pos + 1)


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


def read_mangled_name(image, pos, limit=256):
    end = image.find(b"\x00", pos, pos + limit)
    if end == -1:
        return None
    return image[pos:end]


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
    key = struct.pack("<I", descriptor_va - base)
    out = []
    for pos in find_all(image, key):
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
    key = struct.pack("<Q", locator_va)
    out = []
    for pos in find_all(image, key):
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


def _resolve_rtti_vtable(image, base, prefix):
    sec_map = parse_sections(image)
    rdata = [(v["start"], v["end"]) for k, v in sec_map.items() if k == ".rdata"]
    code = [(v["start"], v["end"]) for k, v in sec_map.items() if k == ".text"]

    descriptors = find_type_descriptors(image, base, prefix)
    if not descriptors:
        return None
    locators = []
    for descriptor in descriptors:
        locators.extend(find_complete_object_locators(image, base, descriptor, rdata))
    if not locators:
        return None
    vtables = []
    for locator in locators:
        vtables.extend(find_vtables(image, base, locator, rdata, code))
    return vtables[0] - base if vtables else None


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
        return result

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


def find_roblox_process(name=b"RobloxPlayerBeta.exe"):
    try:
        import pymem.process
        for p in pymem.process.list_processes():
            try:
                if name in p.szExeFile:
                    return p.th32ProcessID
            except Exception:
                continue
        return None
    except ImportError:
        return _find_process_toolhelp(name)


def _find_process_toolhelp(name=b"RobloxPlayerBeta.exe"):
    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.c_ulong),
            ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
            ("szExeFile", ctypes.c_char * 260),
        ]

    snapshot = windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        return None
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        if not windll.kernel32.Process32First(snapshot, byref(entry)):
            return None
        while True:
            if name in entry.szExeFile:
                return entry.th32ProcessID
            if not windll.kernel32.Process32Next(snapshot, byref(entry)):
                return None
    finally:
        windll.kernel32.CloseHandle(snapshot)


def get_module_base(pid):
    handle = windll.kernel32.OpenProcess(0x0410, False, pid)
    if not handle:
        return None
    try:
        modules = (c_void_p * 1)()
        needed = c_size_t()
        if windll.psapi.EnumProcessModules(
                handle, byref(modules), sizeof(modules), byref(needed)):
            return int(modules[0])
    finally:
        windll.kernel32.CloseHandle(handle)
    return None


class Reader:

    def __init__(self, pid):
        self.process_id = pid
        self.handle = windll.kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not self.handle:
            raise Exception("failed to open process")
        self.base_address = get_module_base(pid)
        if not self.base_address:
            windll.kernel32.CloseHandle(self.handle)
            self.handle = None
            raise Exception("failed to get base address")

    def try_read(self, address, size):
        if not self.handle or size <= 0:
            return None
        buffer = (ctypes.c_byte * size)()
        got = ctypes.c_size_t(0)
        NtReadVirtualMemory(self.handle, ctypes.c_void_p(address),
                            ctypes.byref(buffer), size, ctypes.byref(got))
        if got.value == 0:
            return None
        return bytes(bytearray(buffer)[:got.value])

    def image_size(self):
        header = self.try_read(self.base_address, 0x1000)
        if not header or header[:2] != b"MZ":
            return None
        try:
            pe = struct.unpack_from("<I", header, 0x3C)[0]
            if header[pe:pe + 4] != b"PE\0\0":
                return None
            return struct.unpack_from("<I", header, pe + 24 + 0x38)[0]
        except Exception:
            return None

    def read_headers(self):
        return self.try_read(self.base_address, 0x1000)

    def module_regions(self):
        size = self.image_size()
        if not size:
            return []
        out = []
        mbi = MEMORY_BASIC_INFORMATION64()
        address = self.base_address
        end_of_module = self.base_address + size
        while address < end_of_module:
            if not windll.kernel32.VirtualQueryEx(
                    self.handle, ctypes.c_void_p(address),
                    ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            region_start = int(mbi.BaseAddress)
            region_end = region_start + int(mbi.RegionSize)
            if region_end <= address:
                break
            usable = (
                mbi.State == MEM_COMMIT
                and mbi.Protect in READABLE_PROTECTIONS
                and not (mbi.Protect & PAGE_GUARD)
                and not (mbi.Protect & PAGE_NOACCESS)
            )
            if usable:
                lo = max(region_start, self.base_address)
                hi = min(region_end, end_of_module)
                if hi > lo:
                    out.append((lo, hi - lo))
            address = region_end
        return out

    def read_image(self, chunk=0x100000, page=0x1000):
        size = self.image_size()
        if not size:
            return None, 0

        out = bytearray(size)
        covered = 0
        spans = self.module_regions() or [(self.base_address, size)]

        for span_start, span_size in spans:
            offset = 0
            while offset < span_size:
                want = min(chunk, span_size - offset)
                address = span_start + offset
                data = self.try_read(address, want)
                if data:
                    dest = address - self.base_address
                    out[dest:dest + len(data)] = data
                    covered += len(data)
                else:
                    for sub in range(0, want, page):
                        sub_size = min(page, want - sub)
                        sub_data = self.try_read(address + sub, sub_size)
                        if sub_data:
                            dest = (address + sub) - self.base_address
                            out[dest:dest + len(sub_data)] = sub_data
                            covered += len(sub_data)
                offset += want

        return out, covered

    def close(self):
        if self.handle:
            windll.kernel32.CloseHandle(self.handle)
            self.handle = None


HEADER_FILENAME = "offsets.h"
DUMPER_NAME = "niggaware! (by fylux22!!!!!!)"


def get_process_image_path(pid):
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        handle = windll.kernel32.OpenProcess(0x0410, False, pid)
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buf))
        if windll.kernel32.QueryFullProcessImageNameW(handle, 0, buf, byref(size)):
            return buf.value
    finally:
        windll.kernel32.CloseHandle(handle)
    return ""


def roblox_version_from_path(image_path):
    if not image_path:
        return "unknown"
    match = re.search(r"version-[0-9a-fA-F]+", image_path, re.IGNORECASE)
    if match:
        return match.group(0)
    folder = os.path.basename(os.path.dirname(image_path))
    return folder or "unknown"


def offset_count(namespace_map):
    return sum(len(items) for items in namespace_map.values())


def _build_namespace_tree(namespace_map):
    tree = {}
    for path, items in namespace_map.items():
        node_map = tree
        for index, part in enumerate(path):
            node = node_map.setdefault(part, {"offsets": {}, "children": {}})
            if index == len(path) - 1:
                node["offsets"].update(items)
            node_map = node["children"]
    return tree


def _emit_namespace_tree(lines, tree, indent):
    pad = " " * indent
    names = sorted(tree.keys(), key=str.lower)
    for index, name in enumerate(names):
        node = tree[name]
        lines.append("%snamespace %s {" % (pad, name))
        offsets = sorted(node["offsets"].items(), key=lambda item: item[0].lower())
        if offsets:
            width = max(len(key) for key, _ in offsets)
            member_pad = " " * (indent + 5)
            for key, value in offsets:
                lines.append(
                    "%sinline constexpr uintptr_t %-*s = 0x%x;"
                    % (member_pad, width, key, value)
                )
        if node["children"]:
            _emit_namespace_tree(lines, node["children"], indent + 5)
        lines.append("%s}" % pad)
        if index != len(names) - 1:
            lines.append("")


def render_header(version, elapsed_ms, namespace_map):
    total = offset_count(namespace_map)
    lines = [
        "#pragma once",
        "/* 8====================================================D",
        "/*            %s" % DUMPER_NAME,
        "/* 8====================================================D",
        "/*  Dumped With     : %s" % DUMPER_NAME,
        "/*  Roblox Version  : %s" % version,
        "/*  Time Taken      : %d ms" % elapsed_ms,
        "/*  Total Offsets   : %d" % total,
        "/* 8====================================================D",
        "*/",
        "",
        "#include <cstdint>",
        "#include <string>",
        "",
        "namespace Offsets {",
        '    inline std::string ClientVersion = "%s";' % version,
        "",
    ]
    _emit_namespace_tree(lines, _build_namespace_tree(namespace_map), 4)
    lines.append("")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def write_header(out_path, text):
    with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


import glob

_MAX_OFFSET = 0x1000

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


def _rtti_class_name(reader, addr):
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


def _resolve_datamodel(reader, fdm_ptr_rva, fdm_off_rva):
    base = reader.base_address

    def _is_dm(addr):
        return _rtti_class_name(reader, addr) == "RBX::DataModel"

    fake_dm = read_mem_u64(reader, base + fdm_ptr_rva) if fdm_ptr_rva else 0

    if not _valid_ptr(fake_dm) or not _is_dm(fake_dm):


        found = 0
        for delta in range(0, 0x20000, 8):
            candidates = [fdm_ptr_rva + delta] if delta == 0 else \
                         [fdm_ptr_rva + delta, fdm_ptr_rva - delta]
            for rva in candidates:
                if rva <= 0 or rva + 8 > len(image_bytes):
                    continue
                cand = read_mem_u64(reader, base + rva)
                if _is_dm(cand):
                    found = rva
                    fake_dm = cand
                    break
            if found:
                break
        if not found:
            return 0, 0, 0
        fdm_ptr_rva = found
        debug_log("  [inst] FakeDataModel.Pointer relocated -> 0x%X" % found)

    dm = read_mem_u64(reader, fake_dm + fdm_off_rva) if fdm_off_rva else 0
    if _valid_ptr(dm) and _is_dm(dm):
        return dm, fake_dm, fdm_off_rva


    for off in range(0, 0x1000):
        cand = read_mem_u64(reader, fake_dm + off)
        if _is_dm(cand):
            debug_log("  [inst] RealDataModel relocated -> 0x%X" % off)
            return cand, fake_dm, off
    return 0, fake_dm, 0


def _iter_children(reader, instance_ptr, children_off, name_off,
                   name_field_off=8, limit=512):
    if not instance_ptr or children_off is None or name_off is None:
        return
    vec = read_mem_u64(reader, instance_ptr + children_off)
    if not _valid_ptr(vec):
        return
    begin = read_mem_u64(reader, vec)
    end = read_mem_u64(reader, vec + 8)
    if not _valid_ptr(begin):
        return
    if not _valid_ptr(end) or end <= begin or (end - begin) > 0x10000:
        end = begin + limit * 8
    slots = 0
    for addr in range(begin, min(end, begin + limit * 8), 8):
        ptr = read_mem_u64(reader, addr)
        if not _valid_ptr(ptr):
            continue
        np = read_mem_u64(reader, ptr + name_off)
        s = _rbx_read_string(reader, np + name_field_off) \
            if _valid_ptr(np) else None
        yield ptr, s


def dump_instance_offsets(reader, datamodel):
    out = {}

    def note(name, value):
        out[name] = value
        debug_log("  [inst] %-28s 0x%X" % (name, value))

    place_id_log, user_id_log = _get_roblox_log_ids()


    name_off = None
    name_field_off = 0
    dm_name_str = 0
    for i in range(0, 0x200):
        container = read_mem_u64(reader, datamodel + i)
        if not _valid_ptr(container):
            continue
        for j in range(0, 0x40):
            if _rbx_read_string(reader, container + j) == "Ugc":
                name_off = i
                name_field_off = j
                dm_name_str = container + j
                break
        if name_off is not None:
            break
    if name_off is None:
        debug_log("  [inst] WARN: could not find NameContainer offset (name-dependent scans skipped)")
        debug_log("  [inst] Join the dumper9000 place first - without it "
                  "the value scans cannot run")
    else:
        note("NameContainer", name_off)
        note("Name", name_field_off)


    class_desc_off = None
    for off in range(0, _MAX_OFFSET):
        cd_ptr = read_mem_u64(reader, datamodel + off)
        if not _valid_ptr(cd_ptr):
            continue
        name_ptr = read_mem_u64(reader, cd_ptr + 0x8)
        if not _valid_ptr(name_ptr):
            continue
        s = _rbx_read_string(reader, name_ptr)
        if s == "DataModel":
            class_desc_off = off
            note("ClassDescriptor", off)
            break

    if name_off is None:
        return out


    slen = _scan_field(reader, dm_name_str, 0x40, "<Q",
                       lambda v: v == len("Ugc"))
    if slen is not None:
        note("StringLength", slen)


    children_off = None
    players_ptr  = None
    runservice_ptr = None
    scriptctx_ptr  = None
    workspace_ptr  = None
    workspace_off  = None

    for off in range(0, _MAX_OFFSET):
        start_ptr = read_mem_u64(reader, datamodel + off)
        if not _valid_ptr(start_ptr):
            continue
        child_list = read_mem_u64(reader, start_ptr)
        if not _valid_ptr(child_list):
            continue
        list_end = read_mem_u64(reader, start_ptr + 8)
        if not _valid_ptr(list_end) or list_end <= child_list \
                or (list_end - child_list) > 0x10000:
            list_end = child_list + 300 * 8
        found_players = False
        slot = child_list
        seen = 0
        while slot < list_end and seen < 300:
            inst = read_mem_u64(reader, slot)
            slot += 8
            seen += 1
            if not _valid_ptr(inst):
                continue
            np = read_mem_u64(reader, inst + name_off)
            if not _valid_ptr(np):
                continue
            s = _rbx_read_string(reader, np + name_field_off)
            if s == "Players":
                found_players = True
                players_ptr = inst
            elif s == "Run Service":
                runservice_ptr = inst
            elif s == "Script Context":
                scriptctx_ptr = inst
            elif s == "Workspace":
                workspace_ptr = inst
        if found_players:
            children_off = off
            note("ChildrenStart", off)
            break


    if children_off is not None:
        vec_base = read_mem_u64(reader, datamodel + children_off)
        begin = read_mem_u64(reader, vec_base)
        end_val = read_mem_u64(reader, vec_base + 8)
        if _valid_ptr(begin) and end_val > begin:
            note("ChildrenEnd", 0x8)


    if workspace_ptr is None:

        for off in range(0, _MAX_OFFSET, 8):
            ptr = read_mem_u64(reader, datamodel + off)
            if not _valid_ptr(ptr):
                continue
            np = read_mem_u64(reader, ptr + name_off)
            if not _valid_ptr(np):
                continue
            s = _rbx_read_string(reader, np + name_field_off)
            if s == "Workspace":
                workspace_ptr = ptr
                workspace_off = off
                note("Workspace", off)
                break
    elif workspace_ptr:

        off = _scan_field(reader, datamodel, _MAX_OFFSET, "<Q",
                          lambda v: v == workspace_ptr, step=8)
        if off is not None:
            workspace_off = off
            note("Workspace", off)


    off = _scan_field(reader, datamodel + 0x500, _MAX_OFFSET - 0x500,
                      "<q", lambda v: v == 31)
    if off is not None:
        note("GameLoaded", off + 0x500)


    if place_id_log:
        off = _scan_field(reader, datamodel, _MAX_OFFSET, "<Q",
                          lambda v: v == place_id_log, step=8)
        if off is not None:
            note("PlaceId", off)


    parent_off = None
    if workspace_ptr:
        for off in range(0, _MAX_OFFSET, 8):
            p_ptr = read_mem_u64(reader, workspace_ptr + off)
            if not _valid_ptr(p_ptr):
                continue
            np = read_mem_u64(reader, p_ptr + name_off)
            if not _valid_ptr(np):
                continue
            s = _rbx_read_string(reader, np + name_field_off)
            if s == "Ugc":
                parent_off = off
                note("Parent", off)
                break


    camera_ptr = None
    if workspace_ptr:
        for off in range(0, _MAX_OFFSET, 8):
            ptr = read_mem_u64(reader, workspace_ptr + off)
            if not _valid_ptr(ptr):
                continue
            np = read_mem_u64(reader, ptr + name_off)
            if not _valid_ptr(np):
                continue
            s = _rbx_read_string(reader, np + name_field_off)
            if s == "Camera":
                camera_ptr = ptr
                note("Camera", off)
                break


    world_ptr = None
    if workspace_ptr and class_desc_off is not None:

        for off in range(0, 0x800, 8):
            ptr = read_mem_u64(reader, workspace_ptr + off)
            if not _valid_ptr(ptr):
                continue

            g = read_mem_float(reader, ptr + 0x22C)
            if g is not None and abs(g - 196.2) < 5.0:
                world_ptr = ptr
                note("WorkspaceWorldPtr", off)
                break


    if workspace_ptr:
        off = _scan_field(reader, workspace_ptr, _MAX_OFFSET, "<f",
                          lambda f: abs(f - 196.2) < 0.5, step=4)
        if off is not None:
            note("Gravity", off)


    local_player_ptr = None
    if players_ptr and children_off is not None:
        vec = read_mem_u64(reader, players_ptr + children_off)
        clist = read_mem_u64(reader, vec) if _valid_ptr(vec) else 0
        if _valid_ptr(clist):

            members = set()
            cblock = reader.try_read(clist, 48 * 8)
            if cblock:
                for i in range(0, len(cblock) - 7, 8):
                    v = struct.unpack_from("<Q", cblock, i)[0]
                    if _valid_ptr(v):
                        members.add(v)


            candidates = []
            seen = set()
            pblock = reader.try_read(players_ptr, _MAX_OFFSET)
            if pblock:
                for off in range(0, len(pblock) - 7, 8):
                    v = struct.unpack_from("<Q", pblock, off)[0]
                    if v in members and v not in seen:
                        seen.add(v)
                        candidates.append((off, v))
            local_player_off = None
            if len(candidates) == 1:
                local_player_off, local_player_ptr = candidates[0]
            elif candidates:
                ws_names = set()
                if workspace_ptr and name_off is not None \
                        and children_off is not None:
                    wvec = read_mem_u64(reader, workspace_ptr + children_off)
                    wlist = read_mem_u64(reader, wvec) if _valid_ptr(wvec) else 0
                    wb = reader.try_read(wlist, 256 * 8) if _valid_ptr(wlist) else None
                    if wb:
                        for i in range(0, len(wb) - 7, 8):
                            cptr = struct.unpack_from("<Q", wb, i)[0]
                            if not _valid_ptr(cptr):
                                continue
                            np = read_mem_u64(reader, cptr + name_off)
                            if _valid_ptr(np):
                                nm = _rbx_read_string(reader, np + name_field_off)
                                if nm:
                                    ws_names.add(nm)
                matched = []
                for off, pptr in candidates:
                    np = read_mem_u64(reader, pptr + name_off)
                    if _valid_ptr(np):
                        nm = _rbx_read_string(reader, np + name_field_off)
                        if nm and nm in ws_names:
                            matched.append((off, pptr))
                if len(matched) == 1:
                    local_player_off, local_player_ptr = matched[0]
                else:
                    local_player_off, local_player_ptr = candidates[0]
                    debug_log("  [!] Players::LocalPlayer ambiguous - %d candidates"
                          " (%s); picked 0x%X"
                          % (len(candidates),
                             ",".join("0x%X" % c[0] for c in candidates[:6]),
                             local_player_off))
            if local_player_off is not None:
                note("LocalPlayer", local_player_off)


    character_ptr = None
    my_name = None
    if local_player_ptr:
        np = read_mem_u64(reader, local_player_ptr + name_off)
        if _valid_ptr(np):
            my_name = _rbx_read_string(reader, np + name_field_off)

    if local_player_ptr and my_name:
        for off in range(0, _MAX_OFFSET, 8):
            ptr = read_mem_u64(reader, local_player_ptr + off)
            if not _valid_ptr(ptr):
                continue
            np = read_mem_u64(reader, ptr + name_off)
            if not _valid_ptr(np):
                continue
            s = _rbx_read_string(reader, np + name_field_off)
            if s == my_name:
                character_ptr = ptr
                note("Character", off)
                break


    humanoid_ptr = None
    if character_ptr and class_desc_off is not None and children_off is not None:
        cblock = reader.try_read(character_ptr, _MAX_OFFSET)
        for ptr, _ in _iter_children(reader, character_ptr, children_off,
                                     name_off, name_field_off):
            if _check_class_name(reader, ptr, class_desc_off) == "Humanoid":

                if cblock:
                    for off in range(0, len(cblock) - 7, 8):
                        if struct.unpack_from("<Q", cblock, off)[0] == ptr:
                            humanoid_ptr = ptr
                            note("Humanoid", off)
                            break
                if humanoid_ptr:
                    break


    hrp_ptr = None
    if character_ptr and class_desc_off is not None and children_off is not None:
        hblock = reader.try_read(humanoid_ptr, 0x600) \
            if humanoid_ptr else None
        for ptr, nm in _iter_children(reader, character_ptr, children_off,
                                      name_off, name_field_off):
            if nm == "HumanoidRootPart":
                if humanoid_ptr and hblock:
                    for off in range(0, len(hblock) - 7, 8):
                        if struct.unpack_from("<Q", hblock, off)[0] == ptr:
                            hrp_ptr = ptr
                            note("HumanoidRootPart", off)
                            break
                break


    if humanoid_ptr:
        hblock = reader.try_read(humanoid_ptr, _MAX_OFFSET) or b""

        def _hits(target, tol):
            found = []
            for off in range(0, len(hblock) - 3, 4):
                f = struct.unpack_from("<f", hblock, off)[0]
                if abs(f - target) < tol:
                    found.append(off)
            return found

        h = _hits(50.0, 0.001)
        if h:
            note("JumpPower", h[0])
        ws = _hits(16.0, 0.001)
        if len(ws) >= 1:
            note("WalkSpeedA", ws[0])
        if len(ws) >= 2:
            note("WalkSpeedB", ws[1])
        h = _hits(100.0, 0.001)
        if len(h) >= 1:
            note("Health", h[0])
        if len(h) >= 2:
            note("MaxHealth", h[1])
        h = _hits(7.2, 0.05)
        if h:
            note("JumpHeight", h[0])
        h = _hits(1.35, 0.05)
        if h:
            note("HipHeight", h[0])


    if camera_ptr:
        default_fov = 70.0 * (3.1415926 / 180.0)
        cblock = reader.try_read(camera_ptr, _MAX_OFFSET)
        if cblock:
            for off in range(0, len(cblock) - 3, 4):
                f = struct.unpack_from("<f", cblock, off)[0]
                if abs(f - default_fov) < 0.001:
                    note("FOV", off)
                    break


    if local_player_ptr and user_id_log:
        uid = user_id_log & 0xFFFFFFFF
        off = _scan_field(reader, local_player_ptr, _MAX_OFFSET, "<I",
                          lambda v: v == uid, step=4)
        if off is not None:
            note("UserId", off + 0x10)


    if local_player_ptr and character_ptr:
        off = _scan_field(reader, local_player_ptr, _MAX_OFFSET, "<Q",
                          lambda v: v == character_ptr, step=8)
        if off is not None:
            note("ModelInstance", off)

    return out


def _get_window_size(default=(1920, 1080)):
    try:
        hwnd = windll.user32.FindWindowA(None, b"Roblox")
        if not hwnd:
            return default
        rect = wintypes.RECT()
        if not windll.user32.GetClientRect(hwnd, byref(rect)):
            return default
        w, h = rect.right - rect.left, rect.bottom - rect.top
        if w <= 0 or h <= 0:
            return default
        return (w, h)
    except Exception:
        return default


UNCERTAIN_MIN_CANDIDATES = 8


_STRICT_UNCERTAIN = False


def set_strict_uncertain(flag):
    global _STRICT_UNCERTAIN
    _STRICT_UNCERTAIN = bool(flag)


def _report_uncertain(category, name, n_cands, n_targets, kind, off):
    if not _STRICT_UNCERTAIN:
        debug_log("  [!!] %s::%s UNCERTAIN - %d offsets matched the same "
              "%d-target %s pattern" % (category, name, n_cands, n_targets,
                                        kind))
        debug_log("  [svc] %-34s 0x%X  <-- BEST GUESS, %d candidates"
              % (category + "::" + name, off, n_cands))
        return off
    debug_log("  [!] %s::%s UNCERTAIN - %d offsets matched the same %d-target "
          "%s pattern; NOT dumped" % (category, name, n_cands, n_targets, kind))
    return None

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
        debug_log("  [!] No offset found for %s::%s" % (category, name))
        return 0

    off = cands[0] + start


    if len(cands) > UNCERTAIN_MIN_CANDIDATES:
        guess = _report_uncertain(category, name, len(cands), len(targets),
                                  kind, off)
        if guess is None:
            return 0
        store.setdefault(category, {})[name] = guess
        return guess
    if len(cands) > 1:
        debug_log("  [!] %s::%s ambiguous - %d %s offsets matched; picked 0x%X"
              % (category, name, len(cands), kind, off))
    store.setdefault(category, {})[name] = off
    debug_log("  [svc] %-34s 0x%X" % (category + "::" + name, off))
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


class InstanceTree(object):

    def __init__(self, reader, children_off, name_off, name_field_off):
        self.r = reader
        self.children_off = children_off
        self.name_off = name_off
        self.name_field_off = name_field_off
        self._names = {}

    def name(self, inst):
        if not inst or self.name_off is None:
            return None
        if inst in self._names:
            return self._names[inst]
        np = read_mem_u64(self.r, inst + self.name_off)
        s = (_rbx_read_string(self.r, np + self.name_field_off)
             if _valid_ptr(np) else None)
        self._names[inst] = s
        return s

    def children(self, inst, limit=1024):
        if not inst or self.children_off is None:
            return []
        vec = read_mem_u64(self.r, inst + self.children_off)
        if not _valid_ptr(vec):
            return []
        begin = read_mem_u64(self.r, vec)
        end = read_mem_u64(self.r, vec + 8)
        if not _valid_ptr(begin):
            return []
        if not _valid_ptr(end) or end <= begin or (end - begin) > 0x20000:
            end = begin + limit * 8
        block = self.r.try_read(begin, min(end, begin + limit * 8) - begin)
        out = []
        if not block:
            return out
        for off in range(0, len(block) - 7, 8):
            ptr = struct.unpack_from("<Q", block, off)[0]
            if _valid_ptr(ptr):
                out.append(ptr)
        return out

    def find_all(self, inst, names, limit=64):
        wanted = set(n for n in names if n)
        if not inst or self.children_off is None or not wanted:
            return []
        out = []
        for child in self.children(inst):
            if self.name(child) in wanted:
                out.append(child)
                if len(out) >= limit:
                    break
        return out

    def find(self, inst, name):
        if not name:
            return None
        hits = self.find_all(inst, (name, _RBX_CLASS_ALIASES.get(name)))
        return hits[0] if hits else None

    def child_int(self, folder, default=None):
        if not folder:
            return default
        kids = self.children(folder)
        if not kids:
            return default
        return self.name(kids[0])

    def find_deep(self, inst, name, depth=6):
        level = [inst]
        for _ in range(depth):
            nxt = []
            for cur in level:
                for child in self.children(cur):
                    if self.name(child) == name:
                        return child
                    nxt.append(child)
            level = nxt
            if not level:
                break
        return None


def dump_service_offsets(reader, datamodel, children_off, name_off,
                         name_field_off, win_size=None):
    store = {}
    skipped = []
    tree = InstanceTree(reader, children_off, name_off, name_field_off)
    if win_size is None:
        win_size = _get_window_size()

    def need(inst, label):
        if not inst:
            skipped.append(label)
        return inst

    workspace = need(tree.find(datamodel, "Workspace"), "Workspace")
    lighting = need(tree.find(datamodel, "Lighting"), "Lighting")
    players = need(tree.find(datamodel, "Players"), "Players")
    local_player = tree.children(players)[0] if players else 0
    player_name = tree.name(local_player) if local_player else None
    character = tree.find(workspace, player_name) if (workspace and player_name) else 0
    humanoid = tree.find(character, "Humanoid") if character else 0


    if lighting:
        scan_for_value(reader, store, "ClockTime", "Lighting",
                      [lighting], [-0.00897], "float", eps=0.0001)
        scan_for_value(reader, store, "Brightness", "Lighting",
                      [lighting], [2.54], "float", eps=0.01)
        scan_for_value(reader, store, "EnvironmentDiffuseScale", "Lighting",
                      [lighting], [0.872])
        scan_for_value(reader, store, "EnvironmentSpecularScale", "Lighting",
                      [lighting], [0.233])
        scan_for_value(reader, store, "FogStart", "Lighting",
                      [lighting], [722.1], "float", eps=0.1)
        scan_for_value(reader, store, "FogEnd", "Lighting",
                      [lighting], [100000.0], "float", eps=0.1)
        scan_for_value(reader, store, "FogColor", "Lighting", [lighting],
                      [(0.752941, 0.752941, 0.752941)], "color3", eps=0.01)
        scan_for_value(reader, store, "Ambient", "Lighting", [lighting],
                      [(0.541, 0.541, 0.541)], "color3", eps=0.01)
        scan_for_value(reader, store, "OutdoorAmbient", "Lighting", [lighting],
                      [(0.502, 0.502, 0.502)], "color3", eps=0.01)
        scan_for_value(reader, store, "ColorShift_Top", "Lighting", [lighting],
                      [(0.121569, 0.705882, 0.207843)], "color3", eps=0.01)
        scan_for_value(reader, store, "ColorShift_Bottom", "Lighting", [lighting],
                      [(0.070588, 0.062745, 0.027451)], "color3", eps=0.01)
        scan_for_value(reader, store, "ExposureCompensation", "Lighting",
                      [lighting], [2.13], "float", eps=0.01)
        scan_for_value(reader, store, "GeographicLatitude", "Lighting",
                      [lighting], [115.231], "float", eps=1.0)


        blk = reader.try_read(lighting, _MAX_OFFSET)
        if blk:
            for off in range(0x120, len(blk) - 11):
                r, g, b = struct.unpack_from("<fff", blk, off)
                if (0.001 < r < 0.999 and 0.001 < g < 0.999 and 0.001 < b < 0.999
                        and abs(r - 0.75) <= 0.01 and abs(g - 0.75) <= 0.01
                        and abs(b - 0.75) <= 0.01):
                    store_offset(store, "Lighting", "LightColor", off)
                    debug_log("  [svc] %-34s 0x%X" % ("Lighting::LightColor", off))
                    break


        gradient_top = 0
        found_light_dir = False
        blk = reader.try_read(lighting, _MAX_OFFSET)
        if blk:
            for off in range(0, len(blk) - 11):
                x, y, z = struct.unpack_from("<fff", blk, off)
                if (not found_light_dir and abs(x - 0.0151139) <= 0.01
                        and abs(y + 0.026178) <= 0.01 and abs(z - 0.999543) <= 0.01):
                    found_light_dir = True
                    store_offset(store, "Lighting", "LightDirection", off)
                    debug_log("  [svc] %-34s 0x%X" % ("Lighting::LightDirection", off))
                    continue
                if x == 1.0 and y == 1.0 and z == 1.0:
                    if not gradient_top:
                        gradient_top = off
                        store_offset(store, "Lighting", "GradientTop", off)
                        debug_log("  [svc] %-34s 0x%X" % ("Lighting::GradientTop", off))
                    else:
                        store_offset(store, "Lighting", "GradientBottom", off)
                        debug_log("  [svc] %-34s 0x%X" % ("Lighting::GradientBottom", off))

        if gradient_top:
            scan_for_value(reader, store, "GlobalShadows", "Lighting",
                          [lighting], [True], "bool",
                          start=max(0, gradient_top - 12 - 2))

        moon = scan_for_value(reader, store, "MoonPosition", "Lighting",
                             [lighting],
                             [(-0.0151139, 0.026178, 0.999543)], "v3")
        sun = scan_for_value(reader, store, "SunPosition", "Lighting",
                            [lighting],
                            [(0.0151139, -0.026178, 0.999543)], "v3",
                            start=max(0, moon - 12 - 2))
        store_offset(store, "Lighting", "Source", sun - 4 if sun else 0)

        lighting_sky = tree.find(lighting, "Sky")
        if lighting_sky:
            scan_for_value(reader, store, "Sky", "Lighting", [lighting],
                          [lighting_sky], "u64")

    workspace_sky = tree.find(workspace, "Sky") if workspace else 0
    if workspace_sky:
        for f, url in (("SkyboxBk", "rbxasset://textures/sky/sky512_bk.tex"),
                       ("SkyboxDn", "rbxasset://textures/sky/sky512_dn.tex"),
                       ("SkyboxFt", "rbxasset://textures/sky/sky512_ft.tex"),
                       ("SkyboxLf", "rbxasset://textures/sky/sky512_lf.tex"),
                       ("SkyboxRt", "rbxasset://textures/sky/sky512_rt.tex"),
                       ("SkyboxUp", "rbxasset://textures/sky/sky512_up.tex"),
                       ("SunTextureId", "rbxasset://sky/sun.jpg"),
                       ("MoonTextureId", "rbxasset://sky/moon.jpg")):
            scan_for_value(reader, store, f, "Sky", [workspace_sky], [url], "string")
        scan_for_value(reader, store, "SunAngularSize", "Sky", [workspace_sky],
                      [21.0], "float", eps=1.0)
        scan_for_value(reader, store, "MoonAngularSize", "Sky", [workspace_sky],
                      [11.0], "float", eps=1.0)
        scan_for_value(reader, store, "SkyboxOrientation", "Sky", [workspace_sky],
                      [(123.0, 22.0, 83.0)], "v3", eps=0.01)
        scan_for_value(reader, store, "StarCount", "Sky", [workspace_sky],
                      [3000], "int")

    if lighting:
        atmosphere = tree.find(lighting, "Atmosphere")
        if atmosphere:
            scan_for_value(reader, store, "Density", "Atmosphere",
                          [atmosphere], [0.315])
            scan_for_value(reader, store, "Offset", "Atmosphere",
                          [atmosphere], [0.243])
            scan_for_value(reader, store, "Color", "Atmosphere", [atmosphere],
                          [(0.541, 0.541, 0.541)], "color3")
            scan_for_value(reader, store, "Decay", "Atmosphere", [atmosphere],
                          [(18 / 255.0, 16 / 255.0, 7 / 255.0)], "color3")
            scan_for_value(reader, store, "Glare", "Atmosphere",
                          [atmosphere], [0.125])
            scan_for_value(reader, store, "Haze", "Atmosphere",
                          [atmosphere], [0.372])


        blooms = (tree.find_all(lighting, ("Bloom", "BloomEffect", "Bloom2",
                                           "Bloom3", "Bloom4")) + [0, 0, 0])[:4]
        if blooms[0]:
            scan_for_value(reader, store, "Intensity", "BloomEffect",
                          [blooms[0]], [0.652])
            scan_for_value(reader, store, "Size", "BloomEffect",
                          [blooms[0]], [5.123])
            scan_for_value(reader, store, "Threshold", "BloomEffect",
                          [blooms[0]], [4.231])
        enabled_off = scan_for_value(
            reader, store, "Enabled", "BloomEffect",
            [b for b in blooms if b], [True, False, False, False][:len([b for b in blooms if b])],
            "bool")

        dof = tree.find(lighting, "DepthOfField")
        if dof:
            scan_for_value(reader, store, "FocusDistance", "DepthOfFieldEffect",
                          [dof], [93.82])
            scan_for_value(reader, store, "FarIntensity", "DepthOfFieldEffect",
                          [dof], [0.259])
            scan_for_value(reader, store, "NearIntensity", "DepthOfFieldEffect",
                          [dof], [0.173])
            scan_for_value(reader, store, "InFocusRadius", "DepthOfFieldEffect",
                          [dof], [9.875])
            store_offset(store, "DepthOfFieldEffect", "Enabled", enabled_off)

        sunrays = tree.find(lighting, "SunRays")
        if sunrays:
            scan_for_value(reader, store, "Intensity", "SunRaysEffect",
                          [sunrays], [0.296])
            scan_for_value(reader, store, "Spread", "SunRaysEffect",
                          [sunrays], [0.827])
            store_offset(store, "SunRaysEffect", "Enabled", enabled_off)

        cc = tree.find(lighting, "ColorCorrection")
        if cc:
            scan_for_value(reader, store, "Brightness", "ColorCorrectionEffect",
                          [cc], [0.124])
            scan_for_value(reader, store, "Contrast", "ColorCorrectionEffect",
                          [cc], [0.132])
            scan_for_value(reader, store, "TintColor", "ColorCorrectionEffect",
                          [cc], [(126 / 255.0, 139 / 255.0, 82 / 255.0)],
                          "color3")
            store_offset(store, "ColorCorrectionEffect", "Enabled", enabled_off)


        cgs = (tree.find_all(lighting, ("ColorGrading", "ColorGradingEffect",
                                        "ColorGrading2", "ColorGrading3",
                                        "ColorGrading4")) + [0, 0, 0])[:4]
        if cgs[0]:
            keep = [c for c in cgs if c]
            scan_for_value(reader, store, "TonemapperPreset",
                          "ColorGradingEffect", keep,
                          [0, 0, 1, 1][:len(keep)], "int")
            store_offset(store, "ColorGradingEffect", "Enabled", enabled_off)

        blur = tree.find(lighting, "Blur")
        if blur:
            scan_for_value(reader, store, "Size", "BlurEffect", [blur], [32.213])
            store_offset(store, "BlurEffect", "Enabled", enabled_off)


    world = 0
    world_off = 0
    if workspace:

        ws_block = reader.try_read(workspace, _MAX_OFFSET)
        for off in range(0, len(ws_block or b"") - 7, 8):
            cand = struct.unpack_from("<Q", ws_block, off)[0]
            if not _valid_ptr(cand):
                continue
            sub = reader.try_read(cand, 0x300)
            if not sub:
                continue
            hits = _scan_block_candidates(sub, "float", 165.231, 0.001, 4)
            if hits:
                world, world_off = cand, off
                store_offset(store, "Workspace", "World", off)
                store_offset(store, "World", "Gravity", hits[0])
                debug_log("  [svc] %-34s 0x%X" % ("Workspace::World", off))
                debug_log("  [svc] %-34s 0x%X" % ("World::Gravity", hits[0]))
                break

    if world:
        scan_for_value(reader, store, "worldStepsPerSec", "World",
                      [world], [240.0], start=0x600)
        scan_for_value(reader, store, "FallenPartsDestroyHeight", "World",
                      [world], [-231.232])
        scan_for_value(reader, store, "ReadOnlyGravity", "Workspace",
                      [workspace], [165.231])


        game_time = tree.child_int(tree.find(workspace, "GameTime"))
        try:
            game_time = float(str(game_time).strip())
        except (TypeError, ValueError):
            game_time = None
        if game_time is None:
            debug_log("  [!] Workspace::GameTime folder missing - "
                  "DistributedGameTime not dumped")
        else:
            scan_for_value(reader, store, "DistributedGameTime", "Workspace",
                          [workspace], [game_time], "double", eps=2.0)


        air_off = air_den_off = 0
        for off in range(0x50, 0x250):
            air = read_mem_u64(reader, world + off)
            if not _valid_ptr(air):
                continue
            sub = reader.try_read(air, 0x100)
            if not sub:
                continue
            hits = _scan_block_candidates(sub, "float", 0.201, 0.001, 4)
            if hits:
                air_off, air_den_off = off, hits[0]
                break
        store_offset(store, "World", "AirProperties", air_off)
        store_offset(store, "AirProperties", "AirDensity", air_den_off)
        if air_off:
            debug_log("  [svc] %-34s 0x%X" % ("World::AirProperties", air_off))
            debug_log("  [svc] %-34s 0x%X" % ("AirProperties::AirDensity", air_den_off))
            air = read_mem_u64(reader, world + air_off)
            scan_for_value(reader, store, "GlobalWind", "AirProperties", [air],
                          [(154.632, 155.632, 156.632)], "v3")

    ctx = {
        "tree": tree, "datamodel": datamodel, "workspace": workspace,
        "lighting": lighting, "players": players,
        "local_player": local_player, "player_name": player_name,
        "character": character, "humanoid": humanoid,
        "world": world, "world_off": world_off, "win_size": win_size,
    }
    return store, skipped, ctx


_MATERIALS = [
    ("Asphalt", (80, 84, 84)), ("Basalt", (75, 74, 74)), ("Brick", (138, 97, 73)),
    ("Cobblestone", (134, 134, 118)), ("Concrete", (152, 152, 152)),
    ("CrackedLava", (255, 24, 67)), ("Glacier", (221, 228, 229)),
    ("Grass", (111, 126, 62)), ("Ground", (140, 130, 104)),
    ("Ice", (204, 210, 223)), ("LeafyGrass", (106, 134, 64)),
    ("Limestone", (255, 243, 192)), ("Mud", (121, 112, 98)),
    ("Pavement", (143, 144, 135)), ("Rock", (99, 100, 102)),
    ("Salt", (255, 255, 254)), ("Sand", (207, 203, 167)),
    ("Sandstone", (148, 124, 95)), ("Slate", (88, 89, 86)),
    ("Snow", (235, 253, 255)), ("WoodPlanks", (172, 148, 108)),
]


def _count_primitives(reader, array_ptr, limit=0x2000):
    block = reader.try_read(array_ptr, limit)
    if not block:
        return 0
    total = 0
    for off in range(0, len(block) - 0x10, 8):
        prim = struct.unpack_from("<Q", block, off)[0]
        if not _valid_ptr(prim):
            break
        d = reader.try_read(prim + 8, 4)
        if not d or len(d) < 4:
            break
        if struct.unpack_from("<i", d, 0)[0] == 6:
            total += 1
    return total


def dump_workspace_instances(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    world = ctx["world"]
    datamodel = ctx["datamodel"]
    if not workspace:
        return


    prim_count = tree.child_int(tree.find(workspace, "PrimCount"))
    try:
        prim_count = int(str(prim_count).strip())
    except (TypeError, ValueError):
        prim_count = None
    if prim_count and world:
        found = 0
        base_offsets = [ctx["world_off"]]
        ws_block = reader.try_read(workspace, _MAX_OFFSET)
        base_offsets += [o for o in range(0, len(ws_block or b"") - 7, 8)
                         if o not in (ctx["world_off"],)]
        for boff in base_offsets[:32]:
            holder = read_mem_u64(reader, workspace + boff)
            if not _valid_ptr(holder):
                continue
            for off in range(0x150, 0x300, 8):
                arr = read_mem_u64(reader, holder + off)
                if not _valid_ptr(arr):
                    continue
                if _count_primitives(reader, arr) == prim_count:
                    found = off
                    break
            if found:
                break
        store_offset(store, "World", "Primitives", found)
        if found:
            debug_log("  [svc] %-34s 0x%X" % ("World::Primitives", found))
        else:
            debug_log("  [!] No offset found for World::Primitives")

    all_prim = tree.child_int(tree.find(workspace, "AllPrimCount"))
    try:
        all_prim = int(str(all_prim).strip())
    except (TypeError, ValueError):
        all_prim = None
    if all_prim is not None:
        scan_for_value(reader, store, "PrimitiveCount", "DataModel",
                      [datamodel], [all_prim], "int")


    terrain = tree.find(workspace, "Terrain")
    if terrain:
        scan_for_value(reader, store, "GrassLength", "Terrain", [terrain], [0.723])
        scan_for_value(reader, store, "WaterReflectance", "Terrain",
                      [terrain], [0.652])
        scan_for_value(reader, store, "WaterTransparency", "Terrain",
                      [terrain], [0.323])
        scan_for_value(reader, store, "WaterWaveSize", "Terrain",
                      [terrain], [0.123])
        scan_for_value(reader, store, "WaterWaveSpeed", "Terrain",
                      [terrain], [35.234])
        scan_for_value(reader, store, "WaterColor", "Terrain", [terrain],
                      [(0.047, 0.329, 0.361)], "color3")


        terr_block = reader.try_read(terrain, _MAX_OFFSET)
        mat_colors_off = 0
        for off in range(0, len(terr_block or b"") - 7, 8):
            ptr = struct.unpack_from("<Q", terr_block, off)[0]
            if not _valid_ptr(ptr):
                continue
            sub = reader.try_read(ptr + 0x10, 0x40)
            if not sub:
                continue
            if _scan_block_candidates(sub, "coloru8", (80, 84, 84), 0, 1):
                mat_colors_off = off
                break
        store_offset(store, "Terrain", "MaterialColors", mat_colors_off)
        if mat_colors_off:
            debug_log("  [svc] %-34s 0x%X" % ("Terrain::MaterialColors",
                                           mat_colors_off))
            mat_colors = read_mem_u64(reader, terrain + mat_colors_off)
            for mat_name, rgb in _MATERIALS:
                scan_for_value(reader, store, mat_name, "MaterialColors",
                              [mat_colors], [rgb], "coloru8")


    sound = tree.find(workspace, "Sound")
    if sound:
        scan_for_value(reader, store, "SoundId", "Sound", [sound],
                      ["rbxassetid://skibidi"], "string")
        scan_for_value(reader, store, "RollOffMaxDistance", "Sound",
                      [sound], [2312.321])
        scan_for_value(reader, store, "RollOffMinDistance", "Sound",
                      [sound], [2423.213])
        scan_for_value(reader, store, "PlaybackSpeed", "Sound", [sound], [1.237])
        scan_for_value(reader, store, "Volume", "Sound", [sound], [0.523])
        sound_group = tree.find(workspace, "SoundGroup")
        if sound_group:
            scan_for_value(reader, store, "SoundGroup", "Sound", [sound],
                          [sound_group], "u64")
        quad = [tree.find(workspace, n)
                for n in ("Sound", "Sound2", "Sound3", "Sound4")]
        if all(quad):
            scan_for_value(reader, store, "IsPlaying", "Sound", quad,
                          [False, True, False, True], "bool")
            scan_for_value(reader, store, "Looped", "Sound", quad,
                          [False, True, True, False], "bool")


    spawns = [tree.find(workspace, n)
              for n in ("SpawnLocation", "SpawnLocation2", "SpawnLocation3")]
    if all(spawns):
        scan_for_value(reader, store, "AllowTeamChangeOnTouch", "SpawnLocation",
                      spawns, [True, True, False], "bool")
        scan_for_value(reader, store, "Enabled", "SpawnLocation", spawns,
                      [True, False, True], "bool")
        scan_for_value(reader, store, "Neutral", "SpawnLocation", spawns,
                      [False, True, False], "bool")
        scan_for_value(reader, store, "ForcefieldDuration", "SpawnLocation",
                      spawns[:2], [4345, 4350], "int")
        scan_for_value(reader, store, "TeamColor", "SpawnLocation", spawns[:2],
                      [307, 315], "int")


    sa = [tree.find(workspace, n)
          for n in ("SurfaceAppearance", "SurfaceAppearance2", "SurfaceAppearance3")]
    if all(sa):
        scan_for_value(reader, store, "AlphaMode", "SurfaceAppearance", sa,
                      [0, 2, 1], "int")
        scan_for_value(reader, store, "Color", "SurfaceAppearance", sa[:1],
                      [(45 / 255.0, 172 / 255.0, 102 / 255.0)], "color3")
        for f, aid in (("ColorMap", 73879578225090),
                       ("EmissiveMaskContent", 73879578225091),
                       ("MetalnessMap", 73879578225092),
                       ("NormalMap", 73879578225093),
                       ("RoughnessMap", 73879578225094)):
            scan_for_value(reader, store, f, "SurfaceAppearance", sa[:1],
                          ["rbxassetid://%d" % aid], "string")
        scan_for_value(reader, store, "EmissiveStrength", "SurfaceAppearance",
                      sa[:1], [3.532])
        scan_for_value(reader, store, "EmissiveTint", "SurfaceAppearance", sa[:1],
                      [(18 / 255.0, 100 / 255.0, 231 / 255.0)], "color3")


    pe = tree.find(workspace, "ParticleEmitter")
    if pe:
        for f, val in (("Brightness", 1.993), ("LightEmission", 0.872),
                       ("LightInfluence", 1.332), ("ZOffset", 832.235),
                       ("Rate", 33.884), ("Rotation", 88.243),
                       ("RotSpeed", 23.856), ("Speed", 2.123),
                       ("Drag", 0.376), ("TimeScale", 0.728),
                       ("VelocityInheritance", 0.238)):
            scan_for_value(reader, store, f, "ParticleEmitter", [pe], [val])
        scan_for_value(reader, store, "Texture", "ParticleEmitter", [pe],
                      ["rbxasset://textures/particles/sparkles_main.dds"], "string")
        scan_for_value(reader, store, "Lifetime", "ParticleEmitter", [pe],
                      [(5.32, 10.88)], "v2")
        scan_for_value(reader, store, "SpreadAngle", "ParticleEmitter", [pe],
                      [(4.233, 8.354)], "v2")
        scan_for_value(reader, store, "Acceleration", "ParticleEmitter", [pe],
                      [(90.394, 32.234, 12.857)], "v3")


    beam = tree.find(workspace, "Beam")
    att1 = tree.find(workspace, "BeamAttach1")
    att2 = tree.find(workspace, "BeamAttach2")
    if beam:
        for f, val in (("Brightness", 1.775), ("LightEmission", 0.392),
                       ("LightInfluence", 0.745), ("TextureLength", 1.625),
                       ("TextureSpeed", 0.642), ("ZOffset", 0.975),
                       ("CurveSize0", 3.324), ("CurveSize1", 7.885),
                       ("Width0", 0.328), ("Width1", 5.775)):
            scan_for_value(reader, store, f, "Beam", [beam], [val])
        scan_for_value(reader, store, "Texture", "Beam", [beam],
                      ["rbxassetid://73879578225090"], "string")
        if att1:
            scan_for_value(reader, store, "Attachment0", "Beam", [beam], [att1], "u64")
        if att2:
            scan_for_value(reader, store, "Attachment1", "Beam", [beam], [att2], "u64")


def _find_matrix_offset(reader, ptr, want, tol=0.1, limit=0x1000):
    block = reader.try_read(ptr, limit)
    if not block:
        return None
    for off in range(0, len(block) - 35):
        d = struct.unpack_from("<fffffffff", block, off)
        e = _matrix3x3_to_euler(d)
        if all(abs(e[i] - want[i]) <= tol for i in range(3)):
            return off
    return None


def dump_parts_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    if not workspace:
        return


    pos_part = tree.find(workspace, "Position")
    if not pos_part:
        debug_log("  [!] Workspace has no 'Position' part - Parts dumps "
                  "skipped (needs the dumper9000 place)")
        return
    tp_block = reader.try_read(pos_part, _MAX_OFFSET)
    prim_off = pos_off = 0
    for off in range(0, len(tp_block or b"") - 7, 8):
        prim = struct.unpack_from("<Q", tp_block, off)[0]
        if not _valid_ptr(prim):
            continue
        sub = reader.try_read(prim, 0x1000)
        if not sub:
            continue
        hits = _scan_block_candidates(sub, "v3", (255.0, 84.7, -255.0), 0.1, 4)
        if hits:
            prim_off, pos_off = off, hits[0]
            break
    store_offset(store, "BasePart", "Primitive", prim_off)
    store_offset(store, "Primitive", "Position", pos_off)
    store_offset(store, "Primitive", "Validate", 6)
    debug_log("  [svc] %-34s 0x%X" % ("BasePart::Primitive", prim_off))
    debug_log("  [svc] %-34s 0x%X" % ("Primitive::Position", pos_off))
    if not prim_off:
        return
    p1 = read_mem_u64(reader, pos_part + prim_off)

    scan_for_value(reader, store, "Owner", "Primitive", [p1], [pos_part], "u64")

    size_part = tree.find(workspace, "Size")
    rot_part = tree.find(workspace, "Rotation")
    mark_part = tree.find(workspace, "67")
    p2 = read_mem_u64(reader, size_part + prim_off) if size_part else 0
    p3 = read_mem_u64(reader, rot_part + prim_off) if rot_part else 0
    p4 = read_mem_u64(reader, mark_part + prim_off) if mark_part else 0

    if p2:
        scan_for_value(reader, store, "Size", "Primitive", [p2],
                      [(77.1, 4.2, 99.0)], "v3")
    if p3:
        rot = _find_matrix_offset(reader, p3, (-78.81, 16.93, 21.32))
        store_offset(store, "Primitive", "Rotation", rot or 0)
        debug_log("  [svc] %-34s 0x%X" % ("Primitive::Rotation", rot or 0))
    if mark_part:
        scan_for_value(reader, store, "Transparency", "BasePart",
                      [mark_part, pos_part], [0.231, 0.749])


    flags_off = 0
    if p1 and p2 and p3 and p4:
        want_collide = (True, False, True, True)
        want_anchor = (True, True, True, False)


        prim_blk = [reader.try_read(p, 0x1000) for p in (p1, p2, p3, p4)]
        for off in range(0x100, 0x1000):
            ok = True
            for blk, wc, wa in zip(prim_blk, want_collide, want_anchor):
                if not blk or off >= len(blk):
                    ok = False
                    break
                byte = blk[off]
                if bool(byte & 0x8) != wc or bool(byte & 0x2) != wa:
                    ok = False
                    break
            if ok:
                flags_off = off
                break
    store_offset(store, "Primitive", "Flags", flags_off)
    debug_log("  [svc] %-34s 0x%X" % ("Primitive::Flags", flags_off))
    store_offset(store, "PrimitiveFlags", "Anchored", 0x2)
    store_offset(store, "PrimitiveFlags", "CanCollide", 0x8)
    store_offset(store, "PrimitiveFlags", "CanTouch", 0x10)
    store_offset(store, "PrimitiveFlags", "CanQuery", 0x20)

    scan_for_value(reader, store, "Color3", "BasePart", [pos_part], [121],
                  "uint8")
    anchor_part = tree.find(workspace, "Anchored")
    p5 = read_mem_u64(reader, anchor_part + prim_off) if anchor_part else 0
    if p5 and p2 and p3 and p4:
        scan_for_value(reader, store, "Material", "Primitive",
                      [p1, p2, p3, p4], [2, 2, 2, 4], "int")
    if size_part and rot_part:
        scan_for_value(reader, store, "Shape", "BasePart",
                      [pos_part, size_part, rot_part], [1, 0, 2], "int")

    vel_part = tree.find(workspace, "Velocity")
    p6 = read_mem_u64(reader, vel_part + prim_off) if vel_part else 0
    if p6:
        scan_for_value(reader, store, "AssemblyLinearVelocity", "Primitive", [p6],
                      [(100.0, 59.2, 2.0)], "v3")
        scan_for_value(reader, store, "AssemblyAngularVelocity", "Primitive", [p6],
                      [(67.0, 67.69, 6.0)], "v3")

    mesh_part = tree.find(workspace, "MeshPart")
    if mesh_part:
        scan_for_value(reader, store, "MeshId", "MeshPart", [mesh_part],
                      ["rbxassetid://5281167063"], "string")
        scan_for_value(reader, store, "Texture", "MeshPart", [mesh_part],
                      ["rbxassetid://73879578225090"], "string")
        scan_for_value(reader, store, "MeshSize", "MeshPart", [mesh_part],
                      [(4.028, 2.956, 4.028)], "v3")

    the_parts = [tree.find(workspace, n)
                 for n in ("ThePart", "ThePart2", "ThePart3", "ThePart4")]
    if all(the_parts):
        scan_for_value(reader, store, "Massless", "BasePart", the_parts,
                      [True, False, True, True], "bool")
        scan_for_value(reader, store, "CastShadow", "BasePart", the_parts,
                      [True, False, True, False], "bool")
        scan_for_value(reader, store, "Locked", "BasePart", the_parts,
                      [False, True, False, True], "bool")
        scan_for_value(reader, store, "Reflectance", "BasePart", the_parts[:1],
                      [0.832])

    value_inst = tree.find(workspace, "Value")
    if value_inst:
        scan_for_value(reader, store, "Value", "Misc", [value_inst],
                      ["Value :3"], "string")

    model = tree.find(workspace, "Model")
    if model:
        kids = tree.children(model)
        if kids:
            scan_for_value(reader, store, "PrimaryPart", "Model", [model],
                          [kids[0]], "u64")
        scan_for_value(reader, store, "Scale", "Model", [model], [1.622])

    special_mesh = tree.find(workspace, "Mesh")
    if special_mesh:
        scan_for_value(reader, store, "Scale", "SpecialMesh", [special_mesh],
                      [(17.2, 13.0, 23.0)], "v3")
        scan_for_value(reader, store, "MeshId", "SpecialMesh", [special_mesh],
                      ["rbxassetid://5281167063"], "string")

    attachment = tree.find(workspace, "Attachment")
    if attachment:
        scan_for_value(reader, store, "Position", "Attachment", [attachment],
                      [(12.23, 24.23, 1.23)], "v3")

    weld_folder = tree.find(workspace, "Welds")
    if weld_folder:
        weld = tree.find(weld_folder, "Weld")
        weld_con = tree.find(weld_folder, "WeldConstraint")
        wp1 = tree.find(weld_folder, "Part1")
        wp2 = tree.find(weld_folder, "Part2")
        if weld and wp1 and wp2:
            scan_for_value(reader, store, "Part0", "Weld", [weld], [wp1], "u64")
            scan_for_value(reader, store, "Part1", "Weld", [weld], [wp2], "u64")
        if weld_con and wp1 and wp2:
            scan_for_value(reader, store, "Part0", "WeldConstraint", [weld_con],
                          [wp1], "u64")
            scan_for_value(reader, store, "Part1", "WeldConstraint", [weld_con],
                          [wp2], "u64")

    union2 = tree.find(workspace, "Union2")
    if union2:
        scan_for_value(reader, store, "AssetId", "UnionOperation", [union2],
                      ["https://www.roblox.com//asset/?id=83292086558510"],
                      "string")


def dump_players_offsets(reader, ctx, store):
    tree = ctx["tree"]
    players = ctx["players"]
    workspace = ctx["workspace"]
    local_player = ctx["local_player"]
    if not (players and local_player):
        return

    scan_for_value(reader, store, "LocalPlayer", "Player", [players],
                  [local_player], "u64")

    user_id_folder = tree.find(workspace, "UserID") if workspace else 0
    user_id = None
    if user_id_folder:
        try:
            user_id = int(str(tree.child_int(user_id_folder)).strip())
        except (TypeError, ValueError):
            user_id = None
    if user_id is not None:
        scan_for_value(reader, store, "UserId", "Player", [local_player],
                      [user_id], "u64")

    display_folder = tree.find(workspace, "DisplayName") if workspace else 0
    if display_folder:
        scan_for_value(reader, store, "DisplayName", "Player", [local_player],
                      [tree.child_int(display_folder) or ""], "string", start=0x100)

    scan_for_value(reader, store, "HealthDisplayDistance", "Player",
                  [local_player], [132.233])
    scan_for_value(reader, store, "NameDisplayDistance", "Player",
                  [local_player], [342.853])

    character = ctx["character"]
    if character:
        scan_for_value(reader, store, "ModelInstance", "Player", [local_player],
                      [character], "u64")

    teams = tree.find(ctx["datamodel"], "Teams")
    meow = tree.find(teams, "Meow") if teams else 0
    if meow:
        scan_for_value(reader, store, "Team", "Player", [local_player], [meow], "u64")
        scan_for_value(reader, store, "BrickColor", "Team", [meow], [1015], "int")
        scan_for_value(reader, store, "TeamColor", "Player", [local_player],
                      [1015], "int")


    locale = _scan_locale_id(reader, local_player)
    if locale:
        scan_for_value(reader, store, "LocaleId", "Player", [local_player],
                      [locale], "string")
        debug_log("  [svc]   (locale derived from Player: %r)" % locale)
    else:
        debug_log("  [!] Player::LocaleId - no 2-letter uppercase string found")

    age_folder = tree.find(workspace, "AccountAge") if workspace else 0
    age = None
    if age_folder:
        try:
            age = int(str(tree.child_int(age_folder)).strip())
        except (TypeError, ValueError):
            age = None
    if age is not None:
        scan_for_value(reader, store, "AccountAge", "Player", [local_player],
                      [age], "int")

    humanoid = ctx["humanoid"]
    if humanoid:
        scan_for_value(reader, store, "Health", "Humanoid", [humanoid], [52.382])
        scan_for_value(reader, store, "MaxHealth", "Humanoid", [humanoid], [88.817])
        walk = scan_for_value(reader, store, "Walkspeed", "Humanoid", [humanoid],
                             [18.827])
        if walk:
            scan_for_value(reader, store, "WalkspeedCheck", "Humanoid",
                          [humanoid], [18.827], start=walk + 1)
        scan_for_value(reader, store, "JumpPower", "Humanoid", [humanoid], [27.322])
        scan_for_value(reader, store, "JumpHeight", "Humanoid", [humanoid], [7.812])
        scan_for_value(reader, store, "HipHeight", "Humanoid", [humanoid], [1.998],
                      start=0x100)
        scan_for_value(reader, store, "MaxSlopeAngle", "Humanoid", [humanoid], [89.9])

    rig = tree.find(workspace, "Rig") if workspace else 0
    r_h = tree.find(workspace, "Humanoid") if workspace else 0
    rig_h = tree.find(rig, "Humanoid") if rig else 0
    rh = [tree.find(workspace, "Humanoid%d" % i) if workspace else 0
          for i in range(2, 8)]
    noob = tree.find(workspace, "Noob") if workspace else 0
    noob_h = tree.find(noob, "Humanoid") if noob else 0
    sit_npc = tree.find(workspace, "SIT") if workspace else 0
    sit_h = tree.find(sit_npc, "Humanoid") if sit_npc else 0
    sit_root = tree.find(sit_npc, "HumanoidRootPart") if sit_npc else 0
    seat = tree.find(workspace, "Seat") if workspace else 0

    if sit_h:
        if seat:
            scan_for_value(reader, store, "SeatPart", "Humanoid", [sit_h],
                          [seat], "u64")
        if sit_root:
            scan_for_value(reader, store, "HumanoidRootPart", "Humanoid", [sit_h],
                          [sit_root], "u64")

    if r_h:
        scan_for_value(reader, store, "CameraOffset", "Humanoid", [r_h],
                      [(13.232, 14.532, 0.231)], "v3")
        scan_for_value(reader, store, "HealthDisplayDistance", "Humanoid", [r_h],
                      [734.457])
        scan_for_value(reader, store, "NameDisplayDistance", "Humanoid", [r_h],
                      [342.789])
        scan_for_value(reader, store, "DisplayName", "Humanoid", [r_h], ["wow"],
                      "string")

    rh_keep = [h for h in rh[:3] if h]
    if r_h and len(rh_keep) >= 3:
        scan_for_value(reader, store, "DisplayDistanceType", "Humanoid",
                      [r_h] + rh_keep[:2], [0, 1, 2], "int")
    rh57 = [h for h in rh[3:6] if h]
    if r_h and len(rh57) >= 3:
        scan_for_value(reader, store, "HealthDisplayType", "Humanoid", rh57,
                      [0, 2, 1], "int")
        scan_for_value(reader, store, "NameOcclusion", "Humanoid", rh57,
                      [1, 0, 1], "int")


    rh4567 = [h for h in rh[2:6] if h]
    if len(rh4567) >= 4:
        scan_for_value(reader, store, "Sit", "Humanoid", rh4567,
                      [False, True, False, True], "bool")
        scan_for_value(reader, store, "PlatformStand", "Humanoid", rh4567,
                      [True, True, False, True], "bool")

    if noob_h:
        scan_for_value(reader, store, "MoveDirection", "Humanoid", [noob_h],
                      [(-0.6884002089500427, 0.43886613845825195,
                        0.5774961709976196)], "v3", eps=0.001)

    rig_triple = [h for h in (humanoid, r_h, rig_h) if h]
    if humanoid and len(rig_triple) >= 3:
        scan_for_value(reader, store, "RigType", "Humanoid", rig_triple,
                      [1, 0, 0], "int", start=0x100, end=0x200)
        jump4 = [h for h in (humanoid, r_h, rh[1], rh[2]) if h]
        if len(jump4) >= 4:
            scan_for_value(reader, store, "Jump", "Humanoid", jump4,
                          [False, False, True, False], "bool",
                          start=0x100, end=0x200)

    if rh[1]:
        scan_for_value(reader, store, "MoveToPoint", "Humanoid", [rh[1]],
                      [(8282.0, 222.243, 3.232)], "v3")

    if seat and sit_h:
        scan_for_value(reader, store, "Occupant", "Seat", [seat], [sit_h], "u64")

    vehicle_seat = tree.find(workspace, "VehicleSeat") if workspace else 0
    if vehicle_seat:
        for f, val in (("MaxSpeed", 47.321), ("SteerFloat", 0.892),
                       ("ThrottleFloat", 0.118), ("Torque", 24.234),
                       ("TurnSpeed", 2.992)):
            scan_for_value(reader, store, f, "VehicleSeat", [vehicle_seat], [val])

    stats = tree.find(ctx["datamodel"], "Stats")
    perf = tree.find(stats, "PerformanceStats") if stats else 0
    ping = tree.find(perf, "Ping") if perf else 0
    if ping:


        cands = []
        block = reader.try_read(ping, _MAX_OFFSET)
        if block:
            for off in range(0, len(block) - 3, 4):
                if 30 <= struct.unpack_from("<i", block, off)[0] <= 60:
                    cands.append(off)
        if len(cands) == 1:
            store_offset(store, "StatsItem", "Value", cands[0])
            debug_log("  [svc] %-34s 0x%X" % ("StatsItem::Value", cands[0]))
        elif len(cands) > 1:
            guess = _report_uncertain("StatsItem", "Value", len(cands), 1,
                                      "int32", cands[0])
            if guess is not None:
                store_offset(store, "StatsItem", "Value", guess)

    backpack = tree.find(local_player, "Backpack")
    tools = [tree.find(backpack, n)
             for n in ("Tool", "Tool2", "Tool3", "Tool4")] if backpack else []
    if tools and all(tools):
        scan_for_value(reader, store, "Tooltip", "Tool", tools[:1], ["meow"], "string")
        scan_for_value(reader, store, "TextureId", "Tool", tools[:1],
                      ["rbxassetid://73879578225090"], "string")
        scan_for_value(reader, store, "Grip", "Tool", tools[:1],
                      [(67.0, 69.0, 420.0)], "v3")
        scan_for_value(reader, store, "Enabled", "Tool", tools,
                      [True, False, True, False], "bool")
        scan_for_value(reader, store, "CanBeDropped", "Tool", tools,
                      [False, True, False, True], "bool")
        scan_for_value(reader, store, "ManualActivationOnly", "Tool", tools,
                      [True, False, True, True], "bool")
        scan_for_value(reader, store, "RequiresHandle", "Tool", tools,
                      [True, True, False, True], "bool")

    clothing = tree.find(workspace, "Clothing") if workspace else 0
    if clothing:
        scan_for_value(reader, store, "Template", "Clothing", [clothing],
                      ["rbxassetid://73879578225090"], "string")
        scan_for_value(reader, store, "Color3", "Clothing", [clothing],
                      [(17 / 255.0, 199 / 255.0, 255 / 255.0)], "color3")

    cmesh = [tree.find(workspace, n) if workspace else 0
             for n in ("CharacterMesh", "CharacterMesh2")]
    if cmesh[0]:
        scan_for_value(reader, store, "BaseTextureId", "CharacterMesh", cmesh[:1],
                      ["rbxassetid://3242"], "string")
        scan_for_value(reader, store, "OverlayTextureId", "CharacterMesh", cmesh[:1],
                      ["rbxassetid://2732"], "string")
        scan_for_value(reader, store, "MeshId", "CharacterMesh", cmesh[:1],
                      ["rbxassetid://5867"], "string")
    if all(cmesh):
        scan_for_value(reader, store, "BodyPart", "CharacterMesh", cmesh,
                      [3, 5], "int")


def dump_camera_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    local_player = ctx["local_player"]
    if not workspace:
        return
    cam = tree.find(workspace, "Camera")
    if cam:
        scan_for_value(reader, store, "CurrentCamera", "Workspace", [workspace],
                      [cam], "u64")
        scan_for_value(reader, store, "Position", "Camera", [cam],
                      [(0.0, 7.733, 12.074)], "v3")
        rot = _find_matrix_offset(reader, cam, (15.0, 0.0, 0.0))


        if rot is not None:
            store_offset(store, "Camera", "Rotation", rot, allow_zero=True)
            debug_log("  [svc] %-34s 0x%X" % ("Camera::Rotation", rot))
        else:
            debug_log("  [!] No offset found for Camera::Rotation")
        humanoid = ctx["humanoid"]
        if humanoid:
            scan_for_value(reader, store, "CameraSubject", "Camera", [cam],
                          [humanoid], "u64")
        scan_for_value(reader, store, "FieldOfView", "Camera", [cam], [1.3166])
        depth = 1.0 / (2.0 * _tan(1.3166 / 2.0))
        scan_for_value(reader, store, "ImagePlaneDepth", "Camera", [cam], [depth])
        scan_for_value(reader, store, "CameraType", "Camera", [cam], [5], "int",
                      start=0x100)
        w, h = ctx["win_size"]
        scan_for_value(reader, store, "Viewport", "Camera", [cam], [w], "int16")
        scan_for_value(reader, store, "ViewportSize", "Camera", [cam],
                      [(float(w), float(h))], "v2")

    if local_player:
        zoom_min = scan_for_value(reader, store, "MinZoomDistance", "Player",
                                 [local_player], [0.528])
        scan_for_value(reader, store, "MaxZoomDistance", "Player",
                      [local_player], [128.0])
        if zoom_min:
            scan_for_value(reader, store, "CameraMode", "Player", [local_player],
                          [0], "int", start=zoom_min)


def _tan(x):
    import math
    return math.tan(x)


def live_cursor_position():
    try:
        point = wintypes.POINT()
        if windll.user32.GetCursorPos(byref(point)):
            return (float(point.x), float(point.y))
    except Exception:
        return None
    return None


def dump_mouse_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    local_player = ctx["local_player"]
    mouse_service = tree.find(ctx["datamodel"], "MouseService")
    if not (mouse_service and workspace):
        return
    folder = tree.find(workspace, "MousePosition")
    pos_str = tree.child_int(folder) if folder else None
    expected_positions = []
    if pos_str and "," in pos_str:
        try:
            parts = pos_str.split(",")
            place_sample = (float(parts[0]), float(parts[1]))
            if place_sample[0] >= 100 and place_sample[1] >= 100:
                expected_positions.append(place_sample)
        except (TypeError, ValueError):
            pass
    cursor = live_cursor_position()
    if cursor and cursor[0] >= 100 and cursor[1] >= 100:
        if cursor not in expected_positions:
            expected_positions.append(cursor)
    if not expected_positions:
        warn("  [-] no usable mouse sample - move the mouse and re-run")
    for mouse_pos in expected_positions:
        for off in range(0xE0, 0x251):
            obj = read_mem_u64(reader, mouse_service + off)
            if not _valid_ptr(obj):
                continue
            sub = reader.try_read(obj, 0x104)
            if not sub:
                continue
            for j in range(0xB0, 0x101, 4):
                if j + 8 > len(sub):
                    break
                x, y = struct.unpack_from("<ff", sub, j)
                if abs(x - mouse_pos[0]) <= 1.0 and abs(y - mouse_pos[1]) <= 75.0:
                    store_offset(store, "MouseService", "InputObject", off)
                    store_offset(store, "MouseService", "InputObject2", off + 0x10)
                    store_offset(store, "MouseService", "MousePosition", j)
                    debug_log("  [svc] %-34s 0x%X" % ("MouseService::InputObject", off))
                    debug_log("  [svc] %-34s 0x%X" % ("MouseService::MousePosition", j))
                    break
            if store.get("MouseService", {}).get("MousePosition") is not None:
                break
        if store.get("MouseService", {}).get("MousePosition") is not None:
            break

    if local_player and workspace:


        lp_blk = reader.try_read(local_player + 0xB00, _MAX_OFFSET - 0xB00)
        for pm_off in range(0, len(lp_blk or b"") - 7, 8):
            pm = struct.unpack_from("<Q", lp_blk, pm_off)[0]
            if not _valid_ptr(pm):
                continue
            sub = reader.try_read(pm + 0x100, 0x154)
            if not sub:
                continue
            hit = None
            for i in range(0, len(sub) - 7, 8):
                if struct.unpack_from("<Q", sub, i)[0] == workspace:
                    hit = 0x100 + i
                    break
            if hit is None:
                continue
            real_off = 0xB00 + pm_off
            store_offset(store, "Player", "Mouse", real_off)
            store_offset(store, "PlayerMouse", "Workspace", hit)
            debug_log("  [svc] %-34s 0x%X" % ("Player::Mouse", real_off))
            debug_log("  [svc] %-34s 0x%X" % ("PlayerMouse::Workspace", hit))
            scan_for_value(reader, store, "Icon", "PlayerMouse", [pm],
                          ["meow"], "string")
            return
        debug_log("  [!] No offset found for Player::Mouse")


def dump_ui_offsets(reader, ctx, store):
    tree = ctx["tree"]
    local_player = ctx["local_player"]
    if not local_player:
        return
    player_gui = tree.find(local_player, "PlayerGui")
    if not player_gui:
        return
    freecam = tree.find(player_gui, "Freecam")
    enabled_ui = tree.find(player_gui, "Enabled")
    disabled_ui = tree.find(player_gui, "NotEnabled")
    if freecam and enabled_ui and disabled_ui:
        scan_for_value(reader, store, "ScreenGui_Enabled", "GuiObject",
                      [freecam, enabled_ui, disabled_ui],
                      [True, True, False], "bool", start=0x300)

    ui_frame = tree.find(enabled_ui, "Frame") if enabled_ui else 0
    if ui_frame:
        scan_for_value(reader, store, "Position", "GuiObject", [ui_frame],
                      [(0.144, 27, 0.122, 87)], "udim2")
        scan_for_value(reader, store, "Size", "GuiObject", [ui_frame],
                      [(0.433, 100, 0.211, 100)], "udim2")

    visible = tree.find(enabled_ui, "Visible") if enabled_ui else 0
    invisible = tree.find(enabled_ui, "NotVisible") if enabled_ui else 0
    if visible and ui_frame and invisible:
        scan_for_value(reader, store, "Visible", "GuiObject",
                      [visible, ui_frame, invisible],
                      [True, True, False], "bool", start=0x400)

    image_label = tree.find(enabled_ui, "ImageLabel") if enabled_ui else 0
    if image_label:
        scan_for_value(reader, store, "Image", "GuiObject", [image_label],
                      ["rbxassetid://73879578225090"], "string")
    text_label = tree.find(enabled_ui, "TextLabel") if enabled_ui else 0
    if text_label:
        scan_for_value(reader, store, "Text", "GuiObject", [text_label],
                      ["RbxDumper"], "string")
        scan_for_value(reader, store, "RichText", "GuiObject", [text_label],
                      ["<b>RbxDumper</b>"], "string")
        scan_for_value(reader, store, "TextColor3", "GuiObject", [text_label],
                      [(0.752941, 0.752941, 0.752941)], "color3", eps=0.01)
        scan_for_value(reader, store, "LayoutOrder", "GuiObject", [text_label],
                      [-286], "int")
        rot = scan_for_value(reader, store, "Rotation", "GuiObject", [text_label],
                            [9.72], "float", eps=0.01)
        store_offset(store, "GuiBase2D", "AbsoluteRotation", rot or 0)

    if visible:
        scan_for_value(reader, store, "BackgroundColor3", "GuiObject", [visible],
                      [(0.752941, 0.752941, 0.752941)], "color3", eps=0.01)
    if ui_frame:
        scan_for_value(reader, store, "BorderColor3", "GuiObject", [ui_frame],
                      [(0.752941, 0.752941, 0.752941)], "color3", eps=0.01)
        scan_for_value(reader, store, "ZIndex", "GuiObject", [ui_frame],
                      [67], "int")
        scan_for_value(reader, store, "BackgroundTransparency", "GuiObject",
                      [ui_frame], [0.752])


    w, h = ctx["win_size"]
    if ui_frame:
        for f, base in (("AbsoluteSize", 931.360), ("AbsolutePosition", 303.480)):
            scan_for_value(reader, store, f, "GuiBase2D", [ui_frame],
                          [base * (w / 1920.0)], "float", eps=10.0)

    text_box = tree.find(enabled_ui, "TextBox") if enabled_ui else 0
    uis = tree.find(ctx["datamodel"], "UserInputService")
    if text_box and uis:
        for off in range(0x200, 0x400):
            wis = read_mem_u64(reader, uis + off)
            if not _valid_ptr(wis):
                continue
            sub = reader.try_read(wis, 0x50)
            if not sub:
                continue
            for j in range(0x20, 0x50, 8):
                if struct.unpack_from("<Q", sub, j)[0] == text_box:
                    store_offset(store, "UserInputService", "WindowInputState", off)
                    store_offset(store, "WindowInputState", "CurrentTextBox", j)
                    store_offset(store, "WindowInputState", "CapsLock", j - 8)
                    debug_log("  [svc] %-34s 0x%X"
                          % ("UserInputService::WindowInputState", off))
                    debug_log("  [svc] %-34s 0x%X"
                          % ("WindowInputState::CurrentTextBox", j))
                    break
            if store.get("WindowInputState", {}).get("CurrentTextBox") is not None:
                break

    workspace = ctx["workspace"]
    decal = tree.find(workspace, "Decal") if workspace else 0
    if decal:
        scan_for_value(reader, store, "Decal_Texture", "Textures", [decal],
                      ["rbxassetid://73879578225090"], "string")
    texture = tree.find(workspace, "Texture") if workspace else 0
    if texture:
        scan_for_value(reader, store, "Texture_Texture", "Textures", [texture],
                      ["rbxassetid://73879578225090"], "string")


_EXPECTED_BYTECODE_LEN = 100


def dump_animation_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    if not workspace:
        return
    animation = tree.find(workspace, "Animation")
    if animation:
        scan_for_value(reader, store, "AnimationId", "Misc", [animation],
                      ["rbxassetid://121903298942078"], "string")

    value_off = store.get("Misc", {}).get("Value")
    if value_off is None:
        debug_log("  [!] Misc::Value unknown - AnimationTrack dumps skipped")
        return

    tracks = []
    for n in ("AnimationTrackHolder", "AnimationTrackHolder2",
              "AnimationTrackHolder3", "AnimationTrackHolder4"):
        holder = tree.find(workspace, n)
        tracks.append(read_mem_u64(reader, holder + value_off) if holder else 0)
    rig = tree.find(workspace, "Rig")
    rig_h = tree.find(rig, "Humanoid") if rig else 0
    animator = tree.find(rig_h, "Animator") if rig_h else 0

    if tracks[0]:
        if animation:
            scan_for_value(reader, store, "Animation", "AnimationTrack",
                          [tracks[0]], [animation], "u64")
        if animator:
            scan_for_value(reader, store, "Animator", "AnimationTrack",
                          [tracks[0]], [animator], "u64")
        speed = scan_for_value(reader, store, "Speed", "AnimationTrack",
                              [tracks[0]], [6.218])
        store_offset(store, "AnimationTrack", "TimePosition",
                 speed + 4 if speed else 0)
        quad = [t for t in tracks if t]
        if len(quad) >= 4:
            scan_for_value(reader, store, "Looped", "AnimationTrack", quad,
                          [True, False, False, True], "bool")
            scan_for_value(reader, store, "IsPlaying", "AnimationTrack", quad,
                          [True, False, False, True], "bool", start=0x200)

    if animator:
        for off in range(0x600, 0x1000):
            head = read_mem_u64(reader, animator + off)
            if not _valid_ptr(head):
                continue
            node = read_mem_u64(reader, head)
            guard = 0
            while node and node != head and guard < 4096:
                guard += 1
                track = read_mem_u64(reader, node + 0x10)
                if _valid_ptr(track) and tree.name(track) == "Animation":
                    store_offset(store, "Animator", "ActiveAnimations", off)
                    debug_log("  [svc] %-34s 0x%X"
                          % ("Animator::ActiveAnimations", off))
                    break
                node = read_mem_u64(reader, node)
            if store.get("Animator", {}).get("ActiveAnimations") is not None:
                break


def dump_scripts_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    if not workspace:
        return
    empty_hash = "d41d8cd98f00b204e9800998ecf8427e"
    specs = (
        ("LocalScript", "{704E7537-4EFC-4E9E-BB5A-60CDCA238EAD}"),
        ("ModuleScript", "{4330BBB6-38D5-43C8-B302-C2DC97068AF6}"),
        ("Script", "{7C692C7B-5ABE-400F-AA26-035C6BC2A36A}"),
    )
    for inst_name, guid in specs:
        inst = tree.find(workspace, inst_name)
        if not inst:
            continue
        scan_for_value(reader, store, "GUID", inst_name, [inst], [guid], "string")
        scan_for_value(reader, store, "Hash", inst_name, [inst], [empty_hash],
                      "string")
        bc_off = 0
        for off in range(0x100, 0x1000):
            embedded = read_mem_u64(reader, inst + off)
            if not _valid_ptr(embedded):
                continue
            size = read_mem_u64(reader, embedded + 0x28)
            if size == _EXPECTED_BYTECODE_LEN:
                bc_off = off
                break
        if bc_off:
            store_offset(store, inst_name, "ByteCode", bc_off)
            debug_log("  [svc] %-34s 0x%X" % (inst_name + "::ByteCode", bc_off))
        else:

            debug_log("  [!] %s::ByteCode not found (no %d-byte bytecode blob)"
                  % (inst_name, _EXPECTED_BYTECODE_LEN))
    store_offset(store, "ByteCode", "Pointer", 0x10)
    store_offset(store, "ByteCode", "Size", 0x28)


def dump_interactables_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    if not workspace:
        return
    prompt = tree.find(workspace, "ProximityPrompt")
    if prompt:
        scan_for_value(reader, store, "ActionText", "ProximityPrompt", [prompt],
                      ["This is action text"], "string")
        scan_for_value(reader, store, "ObjectText", "ProximityPrompt", [prompt],
                      ["This is object text"], "string")
        scan_for_value(reader, store, "HoldDuration", "ProximityPrompt", [prompt],
                      [0.282], "float", eps=0.01)
        scan_for_value(reader, store, "MaxActivationDistance", "ProximityPrompt",
                      [prompt], [10.882], "float", eps=0.01)
        scan_for_value(reader, store, "KeyCode", "ProximityPrompt", [prompt],
                      [101], "int")
        scan_for_value(reader, store, "GamepadKeyCode", "ProximityPrompt", [prompt],
                      [1000], "int")
        trio = [tree.find(workspace, n)
                for n in ("ProximityPrompt", "ProximityPrompt2", "ProximityPrompt3")]
        if all(trio):
            scan_for_value(reader, store, "Enabled", "ProximityPrompt", trio,
                          [True, False, True], "bool")
            scan_for_value(reader, store, "RequiresLineOfSight", "ProximityPrompt",
                          trio, [True, True, False], "bool")

    click = tree.find(workspace, "ClickDetector")
    if click:
        scan_for_value(reader, store, "MaxActivationDistance", "ClickDetector",
                      [click], [32.211], "float", eps=0.01)
        scan_for_value(reader, store, "MouseIcon", "ClickDetector", [click],
                      ["rbxassetid://73879578225090"], "string")

    drag = tree.find(workspace, "DragDetector")
    drag_part = tree.find(workspace, "dragdetectpart")
    if drag:
        if drag_part:
            scan_for_value(reader, store, "ReferenceInstance", "DragDetector",
                          [drag], [drag_part], "u64")
        for f, val in (("MaxActivationDistance", 743.321), ("MaxDragAngle", 120.83),
                       ("MinDragAngle", 4.842), ("MaxForce", 7452.386),
                       ("MaxTorque", 236.872), ("Responsiveness", 881.415)):
            scan_for_value(reader, store, f, "DragDetector", [drag], [val])
        scan_for_value(reader, store, "MaxDragTranslation", "DragDetector", [drag],
                      [(128.83, 129.83, 130.83)], "v3")
        scan_for_value(reader, store, "MinDragTranslation", "DragDetector", [drag],
                      [(118.83, 119.83, 110.83)], "v3")
        scan_for_value(reader, store, "ActivatedCursorIcon", "DragDetector", [drag],
                      ["rbxassetid://73879578225091"], "string")
        scan_for_value(reader, store, "CursorIcon", "DragDetector", [drag],
                      ["rbxassetid://73879578225090"], "string")


def dump_mesh_content_provider(reader, ctx, store):
    tree = ctx["tree"]
    mcp = tree.find(ctx["datamodel"], "MeshContentProvider")
    if not mcp:
        debug_log("  [!] MeshContentProvider not found")
        return
    lrucache = 0
    lru_holder = lru_field = 0
    for i in range(0, 0x300, 8):
        holder = read_mem_u64(reader, mcp + i)
        if not _valid_ptr(holder):
            continue
        sub = reader.try_read(holder, 0x100)
        if not sub:
            continue
        for j in range(0, 0x100, 8):
            cand = struct.unpack_from("<Q", sub, j)[0]
            if not _valid_ptr(cand):
                continue
            name = _rtti_class_name(reader, cand)
            if name and "MemEnforcedLRUCache" in name:
                lru_holder, lru_field, lrucache = i, j, cand
                break
        if lrucache:
            break
    if not lrucache:
        debug_log("  [!] Failed to get MeshContentProvider::LRUHolder")
        return
    store_offset(store, "MeshContentProvider", "LRUHolder", lru_holder)
    store_offset(store, "LRUHolder", "MemEnforcedLRUCache", lru_field)
    debug_log("  [svc] %-34s 0x%X" % ("MeshContentProvider::LRUHolder", lru_holder))

    head = 0
    for i in range(0x8, 0x100, 8):
        ptr = read_mem_u64(reader, lrucache + i)
        if _valid_ptr(ptr) and _valid_ptr(read_mem_u64(reader, ptr)) \
                and _valid_ptr(read_mem_u64(reader, ptr + 8)):
            head = i
            break
    if not head:
        debug_log("  [!] Failed to get MemEnforcedLRUCache::Head")
        return
    store_offset(store, "MemEnforcedLRUCache", "Head", head)

    sentinel = read_mem_u64(reader, lrucache + head)
    first = read_mem_u64(reader, sentinel)
    if not _valid_ptr(sentinel) or not _valid_ptr(first) or sentinel == first:
        debug_log("  [!] MemEnforcedLRUCache is empty")
        return

    assetid = 0
    for i in range(0, 0x100, 8):
        s = _rbx_read_string(reader, first + i)
        if s and ("rbxasset" in s or "http" in s):
            assetid = i
            break
    if not assetid:
        debug_log("  [!] Failed to get LRUNode::AssetID")
        return
    store_offset(store, "LRUNode", "Next", 0x0, allow_zero=True)
    store_offset(store, "LRUNode", "AssetID", assetid)

    node, rightleg = first, 0
    for _ in range(0x2000):
        if node == sentinel:
            break
        s = _rbx_read_string(reader, node + assetid)
        if s and "rightleg" in s:
            rightleg = node
            break
        nxt = read_mem_u64(reader, node)
        if not _valid_ptr(nxt) or nxt == node:
            break
        node = nxt
    if not rightleg:
        debug_log("  [!] Failed to find rightleg in LRUCache")
        return

    want = (-0.5, -1.0, -0.5)
    for i in range(8, 0x100, 8):
        if i == assetid:
            continue
        cached = read_mem_u64(reader, rightleg + i)
        if not _valid_ptr(cached):
            continue
        sub = reader.try_read(cached, 0x100)
        if not sub:
            continue
        for j in range(8, 0x100, 8):
            fmd = struct.unpack_from("<Q", sub, j)[0]
            if not _valid_ptr(fmd):
                continue
            blob = reader.try_read(fmd, 0x300)
            if not blob:
                continue
            hits = _scan_block_candidates(blob, "v3", want, 0.01, 4)
            if hits:
                store_offset(store, "LRUNode", "CachedItem", i)
                store_offset(store, "CachedItem", "FileMeshData", j)
                store_offset(store, "FileMeshData", "AABBMin", hits[0])
                store_offset(store, "FileMeshData", "AABBMax", hits[0] + 12)
                debug_log("  [svc] %-34s 0x%X" % ("CachedItem::FileMeshData", j))
                fmd_ptr = fmd
                break
        if "CachedItem" in store.get("LRUNode", {}):
            break
    else:
        return
    if "CachedItem" not in store.get("LRUNode", {}):
        debug_log("  [!] Failed to get LRUNode::CachedItem")
        return

    verts = faces = 0
    for i in range(0, 0x100, 8):
        a = read_mem_u64(reader, fmd_ptr + i)
        b = read_mem_u64(reader, fmd_ptr + i + 8)
        if _valid_ptr(a) and _valid_ptr(b) and (b - a) == 0x690:
            verts = i
            break
    if not verts:
        debug_log("  [!] Failed to get FileMeshData::Vertices")
        return
    for i in range(verts + 0x10, 0x100, 8):
        a = read_mem_u64(reader, fmd_ptr + i)
        b = read_mem_u64(reader, fmd_ptr + i + 8)
        if _valid_ptr(a) and _valid_ptr(b) and (b - a) == 0x210:
            faces = i
            break
    if not faces:
        debug_log("  [!] Failed to get FileMeshData::Faces")
        return
    store_offset(store, "FileMeshData", "Vertices", verts)
    store_offset(store, "FileMeshData", "VerticesEnd", verts + 8)
    store_offset(store, "FileMeshData", "Faces", faces)
    store_offset(store, "FileMeshData", "FacesEnd", faces + 8)


_RENDER_CLASSES = {
    "GeometryD3D11": (b".?AVGeometryD3D11@",),
    "DeviceD3D11Gfx": (b".?AVDeviceD3D11Gfx@", b".?AVDeviceD3D11Gfx@@"),
    "ClusterNode": (b".?AVClusterNode@",),
}


def dump_static_vtable_offsets(image, base, store):
    for namespace, prefixes in _RENDER_CLASSES.items():
        vtable = None
        for prefix in prefixes:
            vtable = _resolve_rtti_vtable(image, base, prefix)
            if vtable is not None:
                break
        if vtable is not None:
            store_offset(store, namespace, "VTableRva", vtable)
        else:
            debug_log("  %s::VTableRva not found in image" % namespace)
    return store


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


STATIC_OFFSETS = {
    ("Instance",): {
        "ClassDescriptor": 0x18,
        "Name":            0x8,
        "NameContainer":   0x70,
        "Parent":          0x68,
        "ChildrenStart":   0x78,
        "ChildrenEnd":     0x8,
        "ClassBase":       0x1b0,
        "ClassName":       0x8,
        "This":            0x8,
    },
    ("DataModel",): {
        "CreatorId":     0x178,
        "GameId":        0x180,
        "GameLoaded":    0x5d0,
        "JobId":         0x110,
        "PlaceId":       0x188,
        "PlaceVersion":  0x1a4,
        "PrimitiveCount":0x418,
        "ScriptContext": 0x440,
        "ServerIP":      0x5b8,
        "ToRenderView1": 0x1c0,
        "ToRenderView2": 0x8,
        "ToRenderView3": 0x28,
        "Workspace":     0x150,
    },
    ("Humanoid",): {
        "AutoJumpEnabled":       0x1c4,
        "AutoRotate":            0x1c5,
        "AutomaticScalingEnabled":0x1c6,
        "BreakJointsOnDeath":    0x1c7,
        "CameraOffset":          0x118,
        "DisplayDistanceType":   0x170,
        "DisplayName":           0xa8,
        "EvaluateStateMachine":  0x1c8,
        "FloorMaterial":         0x174,
        "Health":                0x180,
        "HealthDisplayDistance": 0x178,
        "HealthDisplayType":     0x17c,
        "HipHeight":             0x184,
        "HumanoidRootPart":      0x458,
        "HumanoidState":         0x8a0,
        "HumanoidStateID":       0x20,
        "IsWalking":             0xa1f,
        "Jump":                  0x1ca,
        "JumpHeight":            0x190,
        "JumpPower":             0x194,
        "MaxHealth":             0x198,
        "MaxSlopeAngle":         0x19c,
        "MoveDirection":         0x130,
        "MoveToPart":            0x108,
        "MoveToPoint":           0x154,
        "NameDisplayDistance":   0x1a0,
        "NameOcclusion":         0x1a4,
        "PlatformStand":         0x1cc,
        "RequiresNeck":          0x1cd,
        "RigType":               0x1b0,
        "SeatPart":              0xf8,
        "Sit":                   0x1cd,
        "TargetPoint":           0x13c,
        "UseJumpPower":          0x1d0,
        "WalkTimer":             0x0,
        "Walkspeed":             0x1c0,
        "WalkspeedCheck":        0x39c,
    },
    ("Player",): {
        "AccountAge":          0x34c,
        "CameraMode":          0x360,
        "DisplayName":         0x128,
        "HealthDisplayDistance":0x384,
        "LocalPlayer":         0x120,
        "LocaleId":            0x108,
        "MaxZoomDistance":     0x358,
        "MinZoomDistance":     0x35c,
        "ModelInstance":       0x288,
        "Mouse":               0x1208,
        "NameDisplayDistance": 0x394,
        "Team":                0x2c8,
        "TeamColor":           0x3a0,
        "UserId":              0xc0,
    },
    ("Camera",): {
        "CameraSubject":  0xb8,
        "CameraType":     0x128,
        "FieldOfView":    0x130,
        "ImagePlaneDepth":0x2c4,
        "Position":       0xec,
        "Rotation":       0xc8,
        "Viewport":       0x27c,
        "ViewportSize":   0x2bc,
    },
    ("Workspace",): {
        "CurrentCamera":       0x4a8,
        "DistributedGameTime": 0x4c8,
        "ReadOnlyGravity":     0x9b8,
        "World":               0x400,
    },
    ("World",): {
        "AirProperties":          0x240,
        "FallenPartsDestroyHeight":0x220,
        "Gravity":                0x22c,
        "Primitives":             0x2b0,
        "worldStepsPerSec":       0x748,
    },
    ("Primitive",): {
        "AssemblyAngularVelocity": 0xec,
        "AssemblyLinearVelocity":  0xe0,
        "Flags":                   0x1b6,
        "Material":                0x0,
        "Owner":                   0x210,
        "Position":                0xd4,
        "Rotation":                0xb0,
        "Size":                    0x1bc,
        "Validate":                0x6,
    },
    ("PrimitiveFlags",): {
        "Anchored":  0x2,
        "CanCollide":0x8,
        "CanQuery":  0x20,
        "CanTouch":  0x10,
    },
    ("BasePart",): {
        "CastShadow":  0x125,
        "Color3":      0x198,
        "Locked":      0x126,
        "Massless":    0x127,
        "Primitive":   0x178,
        "Reflectance": 0xfc,
        "Shape":       0x1a8,
        "Transparency":0x120,
    },
    ("Model",): {
        "PrimaryPart": 0x248,
        "Scale":       0x134,
    },
    ("RunService",): {
        "HeartbeatFPS":  0xc8,
        "HeartbeatTask": 0xe0,
    },
    ("RenderJob",): {
        "FakeDataModel": 0x38,
        "RealDataModel": 0x1f0,
        "RenderView":    0x1d8,
    },
    ("VisualEngine",): {
        "Dimensions":    0xb10,
        "FakeDataModel": 0xaf0,
        "RenderView":    0xc30,
        "ViewMatrix":    0x1b0,
    },
    ("TaskScheduler",): {
        "JobEnd":   0xd0,
        "JobName":  0x18,
        "JobStart": 0xc8,
        "MaxFPS":   0xb0,
    },
    ("Misc",): {
        "Adornee":    0xe0,
        "AnimationId":0xb0,
        "StringLength":0x10,
        "Value":      0xa8,
    },
    ("Script",): {
        "GUID": 0xc0,
        "Hash": 0x190,
    },
    ("LocalScript",): {
        "GUID": 0xc0,
        "Hash": 0x190,
    },
    ("ModuleScript",): {
        "GUID": 0xc0,
        "Hash": 0x350,
    },
    ("ByteCode",): {
        "Pointer": 0x10,
        "Size":    0x28,
    },
}




FAKE_DATA_MODEL_POINTER_RVA = 0x8b54980
FAKE_DATA_MODEL_OFFSET = 0x1f8

INSTANCE_NAMESPACE_ROUTES = {
    "NameContainer":   ("Instance", "NameContainer"),
    "Name":            ("Instance", "Name"),
    "ClassDescriptor": ("Instance", "ClassDescriptor"),
    "Parent":          ("Instance", "Parent"),
    "ChildrenStart":   ("Instance", "ChildrenStart"),
    "ChildrenEnd":     ("Instance", "ChildrenEnd"),
    "Workspace":       ("DataModel", "Workspace"),
    "GameLoaded":      ("DataModel", "GameLoaded"),
    "PlaceId":         ("DataModel", "PlaceId"),
    "Camera":          ("DataModel", "Camera"),
    "Gravity":         ("World", "Gravity"),
    "LocalPlayer":     ("Player", "LocalPlayer"),
    "UserId":          ("Player", "UserId"),
    "ModelInstance":   ("Player", "ModelInstance"),
    "Health":          ("Humanoid", "Health"),
    "JumpPower":       ("Humanoid", "JumpPower"),
    "MaxHealth":       ("Humanoid", "MaxHealth"),
    "JumpHeight":      ("Humanoid", "JumpHeight"),
    "HipHeight":       ("Humanoid", "HipHeight"),
    "HumanoidRootPart": ("Humanoid", "HumanoidRootPart"),
    "WalkSpeedA":      ("Humanoid", "Walkspeed"),
    "WalkSpeedB":      ("Humanoid", "WalkspeedCheck"),
    "FOV":             ("Camera", "FieldOfView"),
}

LUAU_PROTO_KEYS = {"Proto_memcat", "Proto_code", "Proto_p", "Proto_k",
                   "Proto_lineinfo", "Proto_locvars", "Proto_upvalues",
                   "Proto_debuginsn"}

LUAU_MISC_KEYS = {"Print", "ScriptContextResume", "GetProperty", "NewInstance",
                  "lua_pushstring", "lua_setfield", "Bytecode_xref"}

SERVICE_SCAN_FUNCTIONS = (
    dump_workspace_instances,
    dump_parts_offsets,
    dump_players_offsets,
    dump_camera_offsets,
    dump_mouse_offsets,
    dump_ui_offsets,
    dump_animation_offsets,
    dump_scripts_offsets,
    dump_interactables_offsets,
    dump_mesh_content_provider,
)


def find_client():
    pid = find_roblox_process()
    if not pid:
        if find_roblox_process(b"RobloxStudioBeta.exe"):
            warn("  [-] Roblox Studio is running - Studio's Play button starts "
                 "the game inside RobloxStudioBeta.exe, so there is no "
                 "standalone client to read. Publish your place, open it in a "
                 "browser on roblox.com, press Play, then run this again.")
        else:
            warn("  [-] RobloxPlayerBeta.exe isn't running - open your place's "
                 "roblox.com page in a browser, press Play, then run this "
                 "again while it is open.")
        return None
    return pid


def scan_raycaster(reader, image, sections):
    layout, _candidates = find_raycast_descriptor_by_brute_force(
        reader, image, reader.base_address, sections)
    if not layout:
        warn("  [-] could not find the Raycast descriptor - FN_OFFS or the "
             "string storage changed, or the read failed (run as admin)")
        return {}
    desc_rva = layout["desc_va"] - reader.base_address
    fn_offset = layout["fn_offset"]
    debug_log("  RaycastBoundDesc 0x%X, RaycastBoundFn 0x%X" % (desc_rva, fn_offset))
    return {("WorldRoot",): {"RaycastBoundDesc": desc_rva,
                             "RaycastBoundFn": fn_offset}}


def scan_fastcluster(image, base):
    result = resolve_fastcluster_vtable(image, base)
    if result.get("error"):
        warn("  [-] FastCluster dump failed: %s" % result["error"])
        return {}
    entity = {"VTableRva": result["vtable_rva"]}
    entity.update(FIELD_OFFSETS)
    return {
        ("FastClusterEntity",): entity,
        ("TechniqueArray",): dict(TECHNIQUE_ARRAY),
        ("MaterialLayer",): dict(MATERIAL_LAYER),
    }


def save_offsets(local_map, namespace, fields):
    local_map.setdefault(namespace, {}).update(fields)


def merge_namespaces(local_map, groups):
    for namespace, fields in groups.items():
        save_offsets(local_map, namespace, fields)


def add_static_offsets(local_map):
    for namespace, fields in STATIC_OFFSETS.items():
        save_offsets(local_map, namespace, fields)
    debug_log("  static offsets: %d across %d namespaces"
              % (offset_count(STATIC_OFFSETS), len(STATIC_OFFSETS)))


def scan_image_vtables(image, base, local_map):
    for namespace, fields in dump_static_vtable_offsets(image, base, {}).items():
        save_offsets(local_map, (namespace,), fields)


def scan_instance_tree(reader, datamodel, local_map):
    instance_offsets = dump_instance_offsets(reader, datamodel)
    if not instance_offsets:
        warn("  [-] instance scan came back empty - keep the place open and do "
             "not move the camera, then run this again")
        return {}
    if "StringLength" in instance_offsets:
        save_offsets(local_map, ("Misc",),
                     {"StringLength": instance_offsets["StringLength"]})
    for scan_key, (namespace, field) in INSTANCE_NAMESPACE_ROUTES.items():
        if scan_key in instance_offsets:
            save_offsets(local_map, (namespace,),
                         {field: instance_offsets[scan_key]})
    debug_log("  instance offsets: %d" % len(instance_offsets))
    return instance_offsets


def scan_service_values(reader, datamodel, instance_offsets, local_map):
    service_offsets, missing_instances, scan_context = dump_service_offsets(
        reader, datamodel,
        instance_offsets.get("ChildrenStart"),
        instance_offsets.get("NameContainer"),
        instance_offsets.get("Name", 0x8))
    scan_context["class_desc_off"] = instance_offsets.get("ClassDescriptor")

    for scan_fn in SERVICE_SCAN_FUNCTIONS:
        try:
            scan_fn(reader, scan_context, service_offsets)
        except Exception as scan_error:
            warn("  [-] %s: %s" % (scan_fn.__name__, scan_error))

    for namespace, fields in service_offsets.items():
        local_map.setdefault((namespace,), {}).update(fields)
    if missing_instances:
        debug_log("  instances not found: %s"
                  % ", ".join(sorted(set(missing_instances))))
    debug_log("  service offsets: %d across %d namespaces"
              % (sum(len(fields) for fields in service_offsets.values()),
                 len(service_offsets)))


def collect_luau_offsets(image, base, local_map):
    functions = {}
    structs = {}

    try:
        started = time.perf_counter()
        functions = dump_luau_offsets(image, base)
        debug_log("  luau functions: %d in %.1fs"
                  % (len(functions), time.perf_counter() - started))
    except Exception as luau_error:
        warn("  [-] luau function dump failed: %s" % luau_error)

    try:
        started = time.perf_counter()
        structs = dump_luau_global_offsets(image, base)
        debug_log("  luau structs: %d in %.1fs"
                  % (len(structs), time.perf_counter() - started))
    except Exception as luau_error:
        warn("  [-] luau struct dump failed: %s" % luau_error)

    function_fields = {name: value for name, value in functions.items()
                       if name not in LUAU_PROTO_KEYS
                       and name not in LUAU_MISC_KEYS}
    proto_fields = {name[6:]: value for name, value in functions.items()
                    if name in LUAU_PROTO_KEYS}
    misc_fields = {name: value for name, value in functions.items()
                   if name in LUAU_MISC_KEYS}
    if function_fields:
        save_offsets(local_map, ("Luau",), function_fields)
    if proto_fields:
        save_offsets(local_map, ("Luau", "Proto"), proto_fields)
    if misc_fields:
        save_offsets(local_map, ("Misc",), misc_fields)

    global_fields = {name: value for name, value in structs.items()
                     if name.startswith("g_")}
    state_fields = {name: value for name, value in structs.items()
                    if name.startswith("L_")}
    if global_fields:
        save_offsets(local_map, ("Luau", "global_State"), global_fields)
    if state_fields:
        save_offsets(local_map, ("Luau", "lua_State"), state_fields)


def main():
    started = time.perf_counter()

    pid = find_client()
    if not pid:
        return 1
    client_version = roblox_version_from_path(get_process_image_path(pid))
    debug_log("  client %s, pid %d" % (client_version, pid))

    try:
        reader = Reader(pid)
    except Exception as attach_error:
        warn("  [-] could not attach to the client: %s" % attach_error)
        return 1

    fingerprint = pe_fingerprint(reader.read_headers())
    if fingerprint:
        debug_log("  build id %s" % fingerprint["id"])

    try:
        image, _covered = reader.read_image()
        if not image:
            warn("  [-] could not read the process image - run this as admin")
            return 1

        global image_bytes, image_base, lea_xref_cache
        image_bytes = image
        image_base = reader.base_address
        lea_xref_cache = {}

        local_map = {}
        merge_namespaces(local_map,
                         scan_raycaster(reader, image, parse_sections(image)))
        merge_namespaces(local_map,
                         scan_fastcluster(image, reader.base_address))
        add_static_offsets(local_map)
        scan_image_vtables(image, reader.base_address, local_map)

        try:
            datamodel, _fake_data_model, _data_model_offset = \
                _resolve_datamodel(reader, FAKE_DATA_MODEL_POINTER_RVA,
                                   FAKE_DATA_MODEL_OFFSET)
            if not datamodel:
                warn("  [-] could not find the DataModel - FakeDataModel."
                     "Pointer is stale for this build, so only the static "
                     "offsets were written")
            else:
                instance_offsets = scan_instance_tree(reader, datamodel, local_map)
                if instance_offsets:
                    scan_service_values(reader, datamodel, instance_offsets,
                                        local_map)
        except Exception as instance_error:
            warn("  [-] instance dump failed: %s" % instance_error)

        collect_luau_offsets(image, reader.base_address, local_map)

        if not local_map:
            warn("  [-] nothing to write")
            return 1

        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                HEADER_FILENAME)
        header_text = render_header(client_version,
                                    int((time.perf_counter() - started) * 1000),
                                    local_map)
        write_header(out_path, header_text)
        print(header_text)
        return 0
    except Exception as error:
        warn("  [-] unexpected error: %s" % error)
        return 1
    finally:
        reader.close()


def disable_quick_edit():
    try:
        h_stdin = windll.kernel32.GetStdHandle(-10)
        mode = wintypes.DWORD()
        if windll.kernel32.GetConsoleMode(h_stdin, byref(mode)):
            windll.kernel32.SetConsoleMode(h_stdin, (mode.value & ~0x0040) | 0x0080)
    except Exception:
        pass


if __name__ == "__main__":
    disable_quick_edit()
    if "--verbose" in sys.argv:
        set_verbose(True)
    if "--strict" in sys.argv:
        set_strict_uncertain(True)
        warn("  [-] --strict: under-determined scans are dropped instead "
              "of best-guessed")
    try:
        code = main()
    except KeyboardInterrupt:
        warn("  [-] cancelled")
        code = 1
    except Exception as exc:
        import traceback
        warn(scrub_paths(traceback.format_exc()).rstrip())
        code = 1
    sys.exit(code)