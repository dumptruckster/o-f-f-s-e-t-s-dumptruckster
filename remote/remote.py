import time

from rtti.rtti import _resolve_rtti_vtable, read_vtable_slots
from offsets.tables import save_offsets
from xrefs.xrefs import _cached_xref_map, lea_xref_cache
from ib.decode import scan_string_rva
from ib.decode import decode_one
from xrefs.xrefs import collect_calls
from pe.pe import parse_sections, is_executable


_REMOTE_VTABLE_CLASSES = (
    ("RemoteEvent", "VTableRva", b".?AVRemoteEvent@RBX@@"),
    ("BaseRemoteEvent", "BaseVTableRva", b".?AVBaseRemoteEvent@RBX@@"),
    ("Instance", "InstanceVTableRva", b".?AVInstance@RBX@@"),
    ("DescribedBaseRemoteEvent", "DescribedVTableRva",
     b".?AVDescribed<class RBX::BaseRemoteEvent"),
)

_REMOTE_FIRE_MESSAGES = (
    ("FireServer", "FireServer can only be called from the client"),
    ("FireClient", "FireClient can only be called from the server"),
    ("FireAllClients", "FireAllClients can only be called from the server"),
    ("InvokeServer", "InvokeServer can only be called from the client"),
    ("InvokeClient", "InvokeClient can only be called from the server"),
)

_REMOTE_BOUNDARIES = {0xCC: 1, 0x90: 1, 0xC3: 1, 0xC2: 3, 0xCB: 3}
_REMOTE_RETRY_DELAY = 2


def _functions_for_message(image, base, message):
    string_rva = scan_string_rva(image, message)
    if string_rva is None:
        return []
    xrefs = _cached_xref_map(image)
    entries = []
    for site in xrefs.get(string_rva, []):
        entry = _function_entry_for(image, base, site)
        if entry not in entries:
            entries.append(entry)
    return entries


def _function_entry_for(image, base, site_rva, window=0x3000):
    at = site_rva
    while at > site_rva - window:
        step = _REMOTE_BOUNDARIES.get(read_u8_from_image(image, at))
        if step is None:
            at -= 1
            continue
        if _decode_reaches(image, base, at + step, site_rva):
            return at + step
        at -= 1
    return site_rva


def _decode_reaches(image, base, start, stop):
    at = start
    while at < stop:
        insn = decode_one(image, base + at, base)
        if insn is None:
            return False
        at += insn.size
    return at == stop


def read_u8_from_image(image, pos):
    if pos < 0 or pos >= len(image):
        return 0
    return image[pos]


def _first_call_target(image, base, sections, entry_rva, window=0x80):
    start = base + entry_rva
    for _site, target in collect_calls(image, base, start, start + window):
        if target != entry_rva and is_executable(base + target, base, sections):
            return target
    return None


def _remote_fire(image, base, sections, local_map):
    fire = {}
    locked = []
    for label, message in _REMOTE_FIRE_MESSAGES:
        entries = _functions_for_message(image, base, message)
        if not entries:
            locked.append(label)
            continue
        fire[label] = entries[0]
        if len(entries) > 1:
            fire[label + "B"] = entries[1]
        prep = _first_call_target(image, base, sections, entries[0])
        if prep is not None:
            fire[label + "Prep"] = prep
    if fire:
        save_offsets(local_map, ("RemoteEvent", "Fire"), fire)
    return locked


def retry_remote_fire(reader, local_map):
    time.sleep(_REMOTE_RETRY_DELAY)
    image, _covered = reader.read_image()
    if not image:
        return []
    lea_xref_cache.clear()
    return _remote_fire(image, reader.base_address,
                        parse_sections(image), local_map)


def scan_remote_events(image, base, local_map):
    sections = parse_sections(image)
    tables = {}
    for label, _field, prefix in _REMOTE_VTABLE_CLASSES:
        tables[label] = _resolve_rtti_vtable(image, base, prefix)

    slots = {label: read_vtable_slots(image, base, sections, table_rva)
             for label, table_rva in tables.items()}
    remote_slots = slots.get("RemoteEvent") or {}
    base_slots = slots.get("BaseRemoteEvent") or {}
    instance_slots = slots.get("Instance") or {}

    fields = {}
    for label, field, _prefix in _REMOTE_VTABLE_CLASSES:
        if tables.get(label) is not None:
            fields[field] = tables[label]
    if remote_slots:
        fields["VTableSlots"] = len(remote_slots)

    hooked = [slot for slot in sorted(remote_slots)
              if remote_slots[slot] != base_slots.get(slot)
              and remote_slots[slot] != instance_slots.get(slot)]
    owned = [slot for slot in hooked if slot]
    if hooked:
        fields["HookSlotCount"] = len(hooked)
    if owned:
        fields["SignalFireSlot"] = owned[0]
        fields["SignalFire"] = remote_slots[owned[0]]

    if fields:
        save_offsets(local_map, ("RemoteEvent",), fields)
    return _remote_fire(image, base, sections, local_map)
