import re

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
