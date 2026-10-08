import re
import struct

from ib.decode import decode_one, rip_target, call_target, scan_string_rva
from patterns.patterns import pattern_scan, _LUAC_GUIDES
from xrefs.xrefs import (find_lea_xref, find_nth_lea_xref, find_next, find_prev,
                         collect_calls, func_end)


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


    s_rva = scan_string_rva(image, '{"type":"table","cat":%d,"size":%d}')
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
            m = re.search(r'[\w+\s*+\s*0x([0-9a-f]+)\]', insn.ops, re.IGNORECASE)
            if m: return int(m.group(1), 16)
            m = re.search(r'[\w+\s*+\s*(\d+)\]', insn.ops)
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


    for key in ("lua_newstate", "luaD_Throw", "luaO_pushfstring",
                "luaL_loadsafe", "dumpgco", "lua_checkstack", "pseudo2addr",
                "luaO_NilObject", "ktable", "Print"):
        rva = _resolve_guide(image, base, key)
        if rva and key not in out:
            out[key] = rva

    return out


def dump_luau_global_offsets(image, base):
    out = {}

    def _note(name, val):
        if val is not None:
            out[name] = val

    def _parse_mem_offset(insn):
        m = re.search(r'[\w+\s*+\s*0x([0-9a-f]+)\]', insn.ops, re.IGNORECASE)
        if m: return int(m.group(1), 16)
        m = re.search(r'\[(\w+)\]', insn.ops)
        return None


    _gcstep_hint_rva = [None]

    luac_step_va, _gcstep_hint = _resolve_luac_step(image, base)
    if luac_step_va is None:
        return out
    if not (base <= luac_step_va < base + len(image)):
        return out

    luac_step_rva = luac_step_va - base


    va = luac_step_va
    push_seen = sub_seen = False
    for _ in range(100):
        ins = decode_one(image, va, base)
        if ins is None: break
        if ins.mnem == "push": push_seen = True
        elif push_seen and ins.mnem in ("arith","sub"): sub_seen = True
        elif push_seen and sub_seen and ins.mnem == "mov":
            m = re.search(r'[\w+\s*+\s*0x([0-9a-f]+)\]', ins.ops, re.IGNORECASE)
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
            m = re.search(r'[\w+\s*+\s*0x([0-9a-f]+)\]', ins.ops, re.IGNORECASE)
            if m:
                _note("g_gcstepmul", int(m.group(1), 16))

                ins2 = decode_one(image, va + ins.size, base)
                if ins2 and ins2.mnem == "mov":
                    m2 = re.search(r'[\w+\s*+\s*0x([0-9a-f]+)\]', ins2.ops, re.IGNORECASE)
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


        va = gcstep_va
        for _ in range(150):
            ins = decode_one(image, va, base)
            if ins is None: break
            if ins.mnem == "movzx":
                m = re.search(r'[\w+\s*+\s*0x([0-9a-f]+)\]', ins.ops, re.IGNORECASE)
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
                                m = re.search(r'[\w+\s*+\s*0x([0-9a-f]+)\]', r10movs[idx].ops, re.IGNORECASE)
                                if m: _note(gname, int(m.group(1), 16))
                        break
            va += ins.size

    return out
