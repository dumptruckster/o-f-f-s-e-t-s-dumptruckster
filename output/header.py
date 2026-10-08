import ctypes
import os
import re
from ctypes import wintypes, windll, byref

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


HEADER_FILENAME = "offsets.h"
