import os
import re
import struct
import sys
import time

from core.defs import read_u8, read_s32, read_u32, read_u64
from ib.decode import decode_one, rip_target, call_target, scan_string_rva
from xrefs.xrefs import (func_end, find_next, find_prev, collect_calls,
                         lea_xref_cache, _cached_xref_map, find_lea_xref,
                         find_nth_lea_xref, _build_lea_xref_map)
from patterns.patterns import pattern_scan, _LUAC_GUIDES
from guides.guides import (_scan_call_sites_to, _looks_like_string,
                          dump_luau_offsets, dump_luau_global_offsets,
                          _resolve_luac_step, _legacy_gcstep,
                          _func_start_before, _all_rip_targets, _resolve_guide)
from pe.pe import parse_sections
from rtti.rtti import (_resolve_rtti_vtable, find_type_descriptors,
                       find_complete_object_locators, find_vtables,
                       read_mangled_name, find_raycast_descriptor_by_brute_force,
                       _find_descriptor_from_string_positions,
                       resolve_fastcluster_vtable, _rtti_demangle, _rtti_class_name,
                       read_vtable_slots)
from memory.reader import Reader, find_roblox_process, get_module_base, disable_quick_edit
from memory.utils import (read_mem_u64, read_mem_float, _rbx_read_string,
                          _check_class_name, _get_roblox_log_ids, _valid_ptr,
                          _scan_field, _scan_locale_id)
from instances.scanvalue import (_SCAN_FMT, _SCAN_ALIGN, _scan_value_matches,
                                 _scan_block_candidates, _string_candidates,
                                 _value_at_matches, scan_for_value, store_offset,
                                 _matrix3x3_to_euler, _asin, _atan2, _tan,
                                 _RBX_CLASS_ALIASES, UNCERTAIN_MIN_CANDIDATES,
                                 _STRICT_UNCERTAIN, set_strict_uncertain,
                                 _report_uncertain)
from instances.instances import (InstanceTree, dump_instance_offsets,
                                _iter_children, _get_window_size)
from instances.services import (dump_service_offsets, dump_workspace_instances,
                                dump_parts_offsets, dump_players_offsets,
                                dump_camera_offsets, dump_mouse_offsets,
                                dump_ui_offsets, dump_animation_offsets,
                                dump_scripts_offsets, dump_interactables_offsets,
                                dump_mesh_content_provider)
from render.render import (dump_static_vtable_offsets, dump_sky_shader_offsets,
                          _RENDER_CLASSES, _SKY_SHADER_MESSAGES, scan_raycaster,
                          scan_fastcluster)
from attribute.attribute import dump_attribute_offsets
from reflection.reflection import dump_reflection_offsets
from output.header import (render_header, write_header, DUMPER_NAME,
                          get_process_image_path, roblox_version_from_path,
                          offset_count, HEADER_FILENAME)
from offsets.tables import (STATIC_OFFSETS, FIELD_OFFSETS, TECHNIQUE_ARRAY,
                            MATERIAL_LAYER, TARGET, FN_OFFS, TYPE_PREFIX,
                            COL_TYPE_DESCRIPTOR_RVA, COL_CLASS_DESCRIPTOR_RVA,
                            TYPE_DESCRIPTOR_NAME_OFFSET, fmt_hex, fmt_cstr,
                            find_all, _MAX_OFFSET, INSTANCE_NAMESPACE_ROUTES,
                            LUAU_PROTO_KEYS, LUAU_MISC_KEYS,
                            SERVICE_SCAN_FUNCTIONS_NAMES,
                            FAKE_DATA_MODEL_POINTER_RVA, FAKE_DATA_MODEL_OFFSET)
from remote.remote import (_decode_reaches, _function_entry_for,
                          _functions_for_message, _first_call_target,
                          _remote_fire, retry_remote_fire, scan_remote_events,
                          _REMOTE_VTABLE_CLASSES, _REMOTE_FIRE_MESSAGES,
                          _REMOTE_BOUNDARIES, _REMOTE_RETRY_DELAY)
from core.live import dump_live_offsets, resolve_datamodel_from_jobs, _find_global_rva

image_bytes = b""
image_base = 0


def _resolve_datamodel(reader, fdm_ptr_rva, fdm_off_rva):
    base = reader.base_address
    import rtti.rtti as _rtti
    _rtti.image_bytes = image_bytes
    _rtti.image_base = image_base

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

    dm = read_mem_u64(reader, fake_dm + fdm_off_rva) if fdm_off_rva else 0
    if _valid_ptr(dm) and _is_dm(dm):
        return dm, fake_dm, fdm_off_rva

    for off in range(0, 0x1000):
        cand = read_mem_u64(reader, fake_dm + off)
        if _is_dm(cand):
            return cand, fake_dm, off
    return 0, fake_dm, 0


def scan_image_vtables(image, base, local_map):
    for namespace, fields in dump_static_vtable_offsets(image, base, {}).items():
        save_offsets(local_map, (namespace,), fields)
    for namespace, fields in dump_sky_shader_offsets(image, base, {}).items():
        save_offsets(local_map, (namespace,), fields)
    for namespace, fields in dump_attribute_offsets(image, base, {}).items():
        save_offsets(local_map, (namespace,), fields)


def scan_instance_tree(reader, datamodel, local_map):
    instance_offsets = dump_instance_offsets(reader, datamodel)
    if not instance_offsets:
        return {}
    if "StringLength" in instance_offsets:
        save_offsets(local_map, ("Misc",),
                     {"StringLength": instance_offsets["StringLength"]})
    for scan_key, (namespace, field) in INSTANCE_NAMESPACE_ROUTES.items():
        if scan_key in instance_offsets:
            save_offsets(local_map, (namespace,),
                         {field: instance_offsets[scan_key]})
    return instance_offsets


def scan_service_values(reader, datamodel, instance_offsets, local_map):
    service_offsets, missing_instances, scan_context = dump_service_offsets(
        reader, datamodel,
        instance_offsets.get("ChildrenStart"),
        instance_offsets.get("NameContainer"),
        instance_offsets.get("Name", 0x8))

    scan_context["class_desc_off"] = instance_offsets.get("ClassDescriptor")

    _svc_funcs = {
        "dump_workspace_instances": dump_workspace_instances,
        "dump_parts_offsets": dump_parts_offsets,
        "dump_players_offsets": dump_players_offsets,
        "dump_camera_offsets": dump_camera_offsets,
        "dump_mouse_offsets": dump_mouse_offsets,
        "dump_ui_offsets": dump_ui_offsets,
        "dump_animation_offsets": dump_animation_offsets,
        "dump_scripts_offsets": dump_scripts_offsets,
        "dump_interactables_offsets": dump_interactables_offsets,
        "dump_mesh_content_provider": dump_mesh_content_provider,
    }
    for scan_fn_name in SERVICE_SCAN_FUNCTIONS_NAMES:
        scan_fn = _svc_funcs.get(scan_fn_name)
        if scan_fn:
            try:
                scan_fn(reader, scan_context, service_offsets)
            except Exception:
                pass

    for namespace, fields in service_offsets.items():
        local_map.setdefault((namespace,), {}).update(fields)


def collect_luau_offsets(image, base, local_map):
    functions = {}
    structs = {}

    try:
        functions = dump_luau_offsets(image, base)
    except Exception:
        pass

    try:
        structs = dump_luau_global_offsets(image, base)
    except Exception:
        pass

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


def merge_namespaces(local_map, groups):
    for namespace, fields in groups.items():
        save_offsets(local_map, namespace, fields)


def add_static_offsets(local_map):
    for namespace, fields in STATIC_OFFSETS.items():
        save_offsets(local_map, namespace, fields)


def save_offsets(local_map, namespace, fields):
    local_map.setdefault(namespace, {}).update(fields)


def pe_fingerprint(image):
    import hashlib
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


def find_client():
    pid = find_roblox_process()
    if not pid:
        return None
    return pid


def _log_ids():
    return _get_roblox_log_ids()


import instances.instances as _instances_mod

_instances_mod._get_roblox_log_ids = _log_ids


def main():
    started = time.perf_counter()

    pid = find_client()
    if not pid:
        return 1
    client_version = roblox_version_from_path(get_process_image_path(pid))

    try:
        reader = Reader(pid)
    except Exception:
        return 1

    try:
        image, _covered = reader.read_image()
        if not image:
            return 1

        global image_bytes, image_base
        image_bytes = image
        image_base = reader.base_address
        lea_xref_cache.clear()

        import offsets.tables as _tables
        import rtti.rtti as _rtti
        _tables.image_bytes = image
        _tables.image_base = reader.base_address
        _rtti.image_bytes = image
        _rtti.image_base = reader.base_address

        local_map = {}
        merge_namespaces(local_map,
                         scan_raycaster(reader, image, parse_sections(image)))
        merge_namespaces(local_map,
                         scan_fastcluster(image, reader.base_address))
        add_static_offsets(local_map)
        scan_image_vtables(image, reader.base_address, local_map)
        try:
            dump_reflection_offsets(reader, image, reader.base_address, local_map)
        except Exception:
            pass
        locked = scan_remote_events(image, reader.base_address, local_map)

        datamodel = 0
        _fake_data_model = 0
        _data_model_offset = 0
        instance_offsets = {}
        try:
            datamodel, _fake_data_model, _data_model_offset = \
                _resolve_datamodel(reader, FAKE_DATA_MODEL_POINTER_RVA,
                                   FAKE_DATA_MODEL_OFFSET)
        except Exception:
            datamodel = 0
        if not datamodel:
            try:
                datamodel, _fake_data_model, _data_model_offset, _fdm_rva = \
                    resolve_datamodel_from_jobs(reader, image,
                                                reader.base_address)
            except Exception:
                datamodel = 0
        try:
            if datamodel:
                instance_offsets = scan_instance_tree(reader, datamodel, local_map)
                if instance_offsets:
                    scan_service_values(reader, datamodel, instance_offsets,
                                        local_map)
        except Exception:
            pass
        if datamodel and _fake_data_model:
            fdm_fields = {}
            if _data_model_offset:
                fdm_fields["RealDataModel"] = _data_model_offset
            fdm_ptr = _find_global_rva(image, _fake_data_model)
            if fdm_ptr:
                fdm_fields["Pointer"] = fdm_ptr
            if fdm_fields:
                save_offsets(local_map, ("FakeDataModel",), fdm_fields)

        try:
            dump_live_offsets(reader, image, reader.base_address, datamodel,
                              _fake_data_model, instance_offsets, local_map)
        except Exception:
            pass

        collect_luau_offsets(image, reader.base_address, local_map)

        if locked:
            retry_remote_fire(reader, local_map)

        if not local_map:
            return 1

        out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                HEADER_FILENAME)
        header_text = render_header(client_version,
                                    int((time.perf_counter() - started) * 1000),
                                    local_map)
        write_header(out_path, header_text)
        print(header_text)
        return 0
    except Exception:
        return 1
    finally:
        reader.close()


if __name__ == "__main__":
    disable_quick_edit()
    if "--strict" in sys.argv:
        set_strict_uncertain(True)
    try:
        code = main()
    except KeyboardInterrupt:
        code = 1
    except Exception:
        code = 1
    sys.exit(code)
