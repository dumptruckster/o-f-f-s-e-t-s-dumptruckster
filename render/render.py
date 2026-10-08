from rtti.rtti import (_resolve_rtti_vtable, resolve_rtti_vtables,
                       resolve_fastcluster_vtable,
                       find_raycast_descriptor_by_brute_force)
from offsets.tables import (FIELD_OFFSETS, TECHNIQUE_ARRAY, MATERIAL_LAYER,
                            FASTCLUSTER_BINDING)
from instances.scanvalue import store_offset
from ib.decode import decode_one, scan_string_rva
from xrefs.xrefs import _cached_xref_map
from remote.remote import _REMOTE_BOUNDARIES

_RENDER_CLASSES = {
    "GeometryD3D11": (b".?AVGeometryD3D11@",),
    "DeviceD3D11Gfx": (b".?AVDeviceD3D11Gfx@", b".?AVDeviceD3D11Gfx@@"),
    "FastCluster": (b".?AVFastCluster@Graphics@RBX@@",),
    "FastClusterBinding": (b".?AVFastClusterBinding@Graphics@RBX@@",),
    "ClusterNode": (b".?AVClusterNode@",),
    "RenderView": (b".?AVRenderView@Graphics@RBX@@",),
    "ViewBase": (b".?AVViewBase@RBX@@",),
    "ShaderManager": (b".?AVShaderManager@Graphics@RBX@@",),
    "TextureManager2": (b".?AVTextureManager2@Graphics@RBX@@",),
}

_SKY_SHADER_MESSAGES = (
    ("DrawCubeCallA", "DrawCubeCallB", "AdvSkyVS"),
    ("DrawSkyPixel", "DrawSkyPixelB", "AdvSkyFS"),
    ("DrawSkyEnv", "DrawSkyEnvB", "AdvSkyEnvFS"),
    ("DrawSun", "DrawSunB", "AdvSunFS"),
    ("DrawStars", "DrawStarsB", "AdvStarsFS"),
    ("SkyThread", "SkyThreadB", "AdvSkyThread"),
    ("CubeTextures", "CubeTexturesB", "textures/sky/sky512_dn.tex"),
    ("SkyGroup", "SkyGroupB", "RenderAdvSkyGroup"),
)

def dump_device_d3d11_offsets(image, base, store):
    vtable = None
    for prefix in (b".?AVDeviceD3D11@@", b".?AVDeviceD3D11@"):
        vtable = _resolve_rtti_vtable(image, base, prefix)
        if vtable is not None:
            break
    if vtable is None:
        return store
    store_offset(store, "DeviceD3D11", "VTableRva", vtable)
    return store


def dump_static_vtable_offsets(image, base, store):
    for namespace, prefixes in _RENDER_CLASSES.items():
        vtables = []
        for prefix in prefixes:
            vtables = resolve_rtti_vtables(image, base, prefix)
            if vtables:
                break
        if not vtables:
            continue
        store_offset(store, namespace, "VTableRva", vtables[0])
        if namespace == "FastCluster" and len(vtables) > 1:
            store_offset(store, namespace, "VTableRvaSub", vtables[1])
    if "FastClusterBinding" in store:
        store_offset(store, "FastClusterBinding", "Owner",
                     FASTCLUSTER_BINDING["Owner"])
    dump_device_d3d11_offsets(image, base, store)
    return store


def dump_sky_shader_offsets(image, base, store):
    for name_a, name_b, message in _SKY_SHADER_MESSAGES:
        entries = _functions_for_message(image, base, message)
        if not entries:
            continue
        store_offset(store, "Sky", name_a, entries[0])
        if len(entries) > 1:
            store_offset(store, "Sky", name_b, entries[1])
    return store


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


def scan_raycaster(reader, image, sections):
    layout, _candidates = find_raycast_descriptor_by_brute_force(
        reader, image, reader.base_address, sections)
    if not layout:
        return {}
    desc_rva = layout["desc_va"] - reader.base_address
    fn_offset = layout["fn_offset"]
    return {("WorldRoot",): {"RaycastBoundDesc": desc_rva,
                             "RaycastBoundFn": fn_offset}}


def scan_fastcluster(image, base):
    result = resolve_fastcluster_vtable(image, base)
    if result.get("error"):
        return {}
    entity = {"VTableRva": result["vtable_rva"]}
    entity.update(FIELD_OFFSETS)
    return {
        ("FastClusterEntity",): entity,
        ("TechniqueArray",): dict(TECHNIQUE_ARRAY),
        ("MaterialLayer",): dict(MATERIAL_LAYER),
    }



