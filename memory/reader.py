import os
import struct
import ctypes
from ctypes import wintypes, windll, byref, sizeof, c_void_p, c_size_t

from core.defs import (PROCESS_VM_READ, PROCESS_QUERY_INFORMATION,
                       NtReadVirtualMemory, MEMORY_BASIC_INFORMATION64,
                       MEM_COMMIT, READABLE_PROTECTIONS, PAGE_GUARD,
                       PAGE_NOACCESS)


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


def module_ranges(reader):
    cached = getattr(reader, "_module_ranges_cache", None)
    if cached is not None:
        return cached
    out = {}
    handle = getattr(reader, "handle", None)
    if handle:
        try:
            count = 1024
            arr = (c_void_p * count)()
            needed = c_size_t()
            psapi = windll.psapi
            ok = False
            enum_ex = getattr(psapi, "EnumProcessModulesEx", None)
            if enum_ex is not None:
                try:
                    ok = bool(enum_ex(handle, arr, sizeof(arr), byref(needed),
                                      0x03))
                except Exception:
                    ok = False
            if not ok:
                ok = bool(psapi.EnumProcessModules(handle, arr, sizeof(arr),
                                                   byref(needed)))
            if ok:
                total = min(count, (needed.value + sizeof(c_void_p) - 1)
                            // sizeof(c_void_p))
                name_fn = psapi.GetModuleFileNameExW
                try:
                    name_fn.argtypes = [wintypes.HANDLE, c_void_p,
                                        wintypes.LPWSTR, wintypes.DWORD]
                    name_fn.restype = wintypes.DWORD
                except Exception:
                    pass
                name_buf = ctypes.create_unicode_buffer(32768)
                for index in range(total):
                    hmod = arr[index]
                    if not hmod:
                        continue
                    if not name_fn(handle, hmod, name_buf,
                                   len(name_buf)):
                        continue
                    base_name = os.path.basename(name_buf.value).lower()
                    head = reader.try_read(int(hmod), 0x1000)
                    size = 0
                    if head and head[:2] == b"MZ":
                        pe = struct.unpack_from("<I", head, 0x3C)[0]
                        if pe + 0x40 <= len(head) \
                                and head[pe:pe + 4] == b"PE\0\0":
                            size = struct.unpack_from("<I", head,
                                                      pe + 24 + 0x38)[0]
                    if size:
                        out[base_name] = (int(hmod), int(hmod) + size)
        except Exception:
            out = {}
    try:
        reader._module_ranges_cache = out
    except Exception:
        pass
    return out


def disable_quick_edit():
    try:
        h_stdin = windll.kernel32.GetStdHandle(-10)
        mode = wintypes.DWORD()
        if windll.kernel32.GetConsoleMode(h_stdin, byref(mode)):
            windll.kernel32.SetConsoleMode(h_stdin, (mode.value & ~0x0040) | 0x0080)
    except Exception:
        pass
