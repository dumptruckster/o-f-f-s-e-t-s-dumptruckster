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


def read_u8(buf, off):  return buf[off] if off < len(buf) else 0
def read_s8(buf, off):  v = read_u8(buf, off); return v - 256 if v >= 128 else v
def read_u32(buf, off): return struct.unpack_from("<I", buf, off)[0] if off + 4 <= len(buf) else 0
def read_s32(buf, off): return struct.unpack_from("<i", buf, off)[0] if off + 4 <= len(buf) else 0
def read_u64(buf, off): return struct.unpack_from("<Q", buf, off)[0] if off + 8 <= len(buf) else 0
