from ib.decode import decode_one, rip_target, scan_string_rva
from xrefs.xrefs import _cached_xref_map
from offsets.tables import ATTRIBUTE_LAYOUT, ATTRIBUTES_MAP


def _storage_type_ids(image, base):
    string_rva = scan_string_rva(image, "AttributeStorageComponent")
    if string_rva is None:
        return None, None
    for site in _cached_xref_map(image).get(string_rva, []):
        at = base + site
        for _ in range(24):
            insn = decode_one(image, at, base)
            if insn is None:
                break
            if insn.mnem == "mov" and insn.ops.startswith("[rip"):
                target = rip_target(insn, base)
                if target is not None:
                    return target + 0xc, target + 0x14
            at += insn.size
    return None, None


def dump_attribute_offsets(image, base, store):
    fields = dict(ATTRIBUTE_LAYOUT)
    type_rva, type_rva_new = _storage_type_ids(image, base)
    if type_rva is not None:
        fields["TypeIdRva"] = type_rva
        fields["TypeIdRvaNew"] = type_rva_new
    store.setdefault("Attribute", {}).update(fields)
    store.setdefault("AttributesMap", {}).update(ATTRIBUTES_MAP)
    return store
