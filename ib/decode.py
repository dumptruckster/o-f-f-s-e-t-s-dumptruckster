import re

from core.defs import read_u8, read_s8, read_u32, read_s32, read_u64

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
