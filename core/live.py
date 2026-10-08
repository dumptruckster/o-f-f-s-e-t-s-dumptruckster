import os
import re
import struct

from memory.utils import (read_mem_u64, _valid_ptr, _rbx_read_string,
                          _get_roblox_log_ids, _check_class_name)
from memory.reader import module_ranges
from ib.decode import decode_one, rip_target, scan_string_rva
from xrefs.xrefs import _cached_xref_map
from rtti.rtti import _rtti_class_name, _resolve_rtti_vtable
from pe.pe import parse_sections
from instances.instances import InstanceTree, _get_window_size
from instances.scanvalue import store_offset
from remote.remote import _functions_for_message
from render.render import _SKY_SHADER_MESSAGES


_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_IP_RE = re.compile(
    r"^((25[0-5]|2[0-4]\d|1\d\d|\d\d|\d)\.){3}"
    r"(25[0-5]|2[0-4]\d|1\d\d|\d\d|\d)\|\d{1,5}$")
_JOB_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_ ]{3,}$")


def framerate_cap():
    path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Roblox",
                        "GlobalBasicSettings_13.xml")
    try:
        text = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return 144.0
    match = re.search(r'name="FramerateCap">\s*(\d+)</int>', text)
    return float(match.group(1)) if match else 144.0


def find_scheduler(reader, image, base):
    string_rva = scan_string_rva(image, "Default job arbiter must always be valid")
    if string_rva is None:
        return 0
    for site in _cached_xref_map(image).get(string_rva, []):
        at = base + site
        for _ in range(80):
            at -= 1
            insn = decode_one(image, at, base)
            if insn is None or at + insn.size > base + site:
                continue
            if insn.mnem == "mov" and "[" in insn.ops and "rip" in insn.ops:
                target = rip_target(insn, base)
                if target and _valid_ptr(read_mem_u64(reader, base + target)):
                    return target
    return 0


def _scan_jobs(reader, sched):
    for off in range(0x50, 0x250, 8):
        begin = read_mem_u64(reader, sched + off)
        if not _valid_ptr(begin):
            continue
        block = reader.try_read(begin, 0x1000)
        if not block or len(block) < 8:
            continue
        first = struct.unpack_from("<Q", block, 0)[0]
        if not _valid_ptr(first):
            continue
        name_off = 0
        render_job = 0
        heartbeat_job = 0
        for rr in range(0x10, 0x30):
            sample = _rbx_read_string(reader, first + rr)
            if not (sample and _JOB_NAME_RE.match(sample)):
                continue
            found_render = 0
            found_heartbeat = 0
            for pos in range(0, len(block) - 7, 0x10):
                job = struct.unpack_from("<Q", block, pos)[0]
                if not _valid_ptr(job):
                    break
                name = _rbx_read_string(reader, job + rr)
                if name == "RenderJob":
                    found_render = job
                elif name == "Heartbeat":
                    found_heartbeat = job
            if found_render:
                name_off = rr
                render_job = found_render
                heartbeat_job = found_heartbeat
                break
        if not render_job:
            continue
        end_ptr = read_mem_u64(reader, sched + off + 8)
        end_off = 0
        if _valid_ptr(end_ptr) and begin < end_ptr <= begin + 0x4000:
            end_off = off + 8
        return ({"JobStart": off, "JobEnd": end_off, "JobName": name_off},
                render_job, heartbeat_job)
    return {}, 0, 0


def _scan_max_fps(reader, sched, cap):
    block = reader.try_read(sched, 0x400)
    if not block:
        return 0
    tolerance = max(1.0, cap * 0.05)
    for off in range(0, len(block) - 7, 8):
        value = struct.unpack_from("<d", block, off)[0]
        if 0 < value < 1.0 and abs(1.0 / value - cap) <= tolerance:
            return off
    return 0


def _scan_render_job(reader, render_job, datamodel, fake_data_model, store):
    block = reader.try_read(render_job, 0x400)
    if not block:
        return 0
    render_view = 0
    for off in range(0, len(block) - 7, 8):
        ptr = struct.unpack_from("<Q", block, off)[0]
        if not _valid_ptr(ptr):
            continue
        kind = _rtti_class_name(reader, ptr) or ""
        if "RenderView" in kind:
            render_view = ptr
            store_offset(store, ("RenderJob",), "RenderView", off)
            break
    if not render_view or not datamodel:
        return render_view
    for lo, hi in ((0x20, 0x100), (0, len(block))):
        for off1 in range(lo, hi - 7, 8):
            holder = struct.unpack_from("<Q", block, off1)[0]
            if not _valid_ptr(holder):
                continue
            kind = _rtti_class_name(reader, holder) or ""
            if "DataModel" not in kind:
                continue
            for off2 in range(0x100, 0x300, 8):
                if read_mem_u64(reader, holder + off2) == datamodel:
                    store_offset(store, ("RenderJob",), "FakeDataModel", off1)
                    store_offset(store, ("RenderJob",), "RealDataModel", off2)
                    return render_view
    return render_view


def _scan_to_render_view(reader, datamodel, render_view, store):
    block = reader.try_read(datamodel + 0x100, 0x150)
    if not block:
        return
    for i in range(0, len(block) - 7, 8):
        first = struct.unpack_from("<Q", block, i)[0]
        if not _valid_ptr(first):
            continue
        for k in range(0, 0x40, 8):
            second = read_mem_u64(reader, first + k)
            if not _valid_ptr(second):
                continue
            inner = reader.try_read(second, 0x50)
            if not inner:
                continue
            for j in range(8, min(len(inner) - 7, 0x50), 8):
                if struct.unpack_from("<Q", inner, j)[0] == render_view:
                    store_offset(store, ("DataModel",), "ToRenderView1", 0x100 + i)
                    store_offset(store, ("DataModel",), "ToRenderView2", k)
                    store_offset(store, ("DataModel",), "ToRenderView3", j)
                    return


def _find_global_rva(image, value):
    if not value:
        return 0
    needle = struct.pack("<Q", value)
    for section in parse_sections(image).values():
        if not (section["characteristics"] & 0x80000000):
            continue
        start = max(0, section["start"])
        end = min(section["end"], len(image))
        if end <= start:
            continue
        pos = image.find(needle, start, end)
        if pos != -1:
            return pos
    return 0


def _vtable_slots(reader, vt, span):
    lo, hi = span
    slots = 0
    while slots < 0x400 and lo <= read_mem_u64(reader, vt + slots * 8) < hi:
        slots += 1
    return slots


def _scan_device_d3d11(reader, dev, store):
    block = reader.try_read(dev, 0x400)
    if not block:
        return
    modules = module_ranges(reader)
    d3d = modules.get("d3d11.dll")
    dxgi = modules.get("dxgi.dll")
    ctxobj_off = None
    ctxobj = 0
    for off in range(0, len(block) - 7, 8):
        ptr = struct.unpack_from("<Q", block, off)[0]
        if _valid_ptr(ptr) and "ContextD3D11" in (_rtti_class_name(reader, ptr) or ""):
            ctxobj_off = off
            ctxobj = ptr
            break
    if ctxobj_off is None:
        return
    linked = set()
    holder = reader.try_read(ctxobj, 0x200)
    if holder:
        for off in range(8, len(holder) - 7, 8):
            ptr = struct.unpack_from("<Q", holder, off)[0]
            if _valid_ptr(ptr) and ptr != dev and ptr != ctxobj:
                linked.add(ptr)
    swap = None
    context = None
    devices = []
    for off in range(0, len(block) - 7, 8):
        if off == ctxobj_off:
            continue
        ptr = struct.unpack_from("<Q", block, off)[0]
        if not _valid_ptr(ptr) or ptr == dev:
            continue
        vt = read_mem_u64(reader, ptr)
        if not _valid_ptr(vt):
            continue
        if dxgi and dxgi[0] <= vt < dxgi[1]:
            if swap is None:
                swap = off
            continue
        if d3d and d3d[0] <= vt < d3d[1]:
            devices.append((off, vt))
        if context is None and ptr in linked:
            context = off
    device = None
    if devices:
        device = max(devices, key=lambda item: _vtable_slots(reader, item[1], d3d))[0]
    store_offset(store, ("DeviceD3D11",), "SwapChainPtr", swap)
    store_offset(store, ("DeviceD3D11",), "DevicePtr", device)
    if context is not None:
        store_offset(store, ("DeviceD3D11",), "ContextPtr", context)
        store_offset(store, ("DeviceD3D11",), "Context", context)
    store_offset(store, ("DeviceD3D11",), "ContextObj", ctxobj_off)


def _scan_render_view(reader, image, base, render_view, store):
    block = reader.try_read(render_view, 0x400)
    if not block:
        return 0
    visual_engine = 0
    for off in range(0, len(block) - 7, 8):
        ptr = struct.unpack_from("<Q", block, off)[0]
        if not _valid_ptr(ptr):
            continue
        kind = _rtti_class_name(reader, ptr) or ""
        if kind == "RBX::Graphics::DeviceD3D11":
            store_offset(store, ("RenderView",), "DeviceD3D11", off)
            try:
                _scan_device_d3d11(reader, ptr, store)
            except Exception:
                pass
        elif kind == "RBX::Graphics::VisualEngine":
            visual_engine = ptr
            store_offset(store, ("RenderView",), "VisualEngine", off)
    _scan_render_view_flags(image, base, block, store)
    return visual_engine


def _flag_writes(image, hi):
    hits = {}
    for section in parse_sections(image).values():
        if not (section["characteristics"] & 0x20000000):
            continue
        start = max(0, section["start"])
        end = min(section["end"], len(image))
        for opcode in (0xC6, 0xC7):
            needle = bytes((opcode,))
            site = image.find(needle, start, end)
            while site != -1:
                _record_write(image, site, opcode, hi, hits)
                site = image.find(needle, site + 1, end)
    return hits


def _record_write(image, site, opcode, hi, hits):
    if site + 7 >= len(image):
        return
    modrm = image[site + 1]
    if modrm >> 3 & 7:
        return
    mode = modrm >> 6
    if mode not in (1, 2):
        return
    disp_pos = site + 2 + (1 if modrm & 7 == 4 else 0)
    if mode == 1:
        if disp_pos + 2 > len(image):
            return
        disp = struct.unpack_from("<b", image, disp_pos)[0]
        imm_pos = disp_pos + 1
    else:
        if disp_pos + 5 > len(image):
            return
        disp = struct.unpack_from("<i", image, disp_pos)[0]
        imm_pos = disp_pos + 4
    if disp < 0 or disp >= hi:
        return
    if opcode == 0xC6:
        if imm_pos >= len(image):
            return
        imm = image[imm_pos]
        if imm != 0 and imm != 1:
            return
        key = "s1" if imm else "s0"
    else:
        if imm_pos + 4 > len(image):
            return
        key = "m32i"
    hits.setdefault(disp, {"s1": [], "s0": [], "m32i": []})[key].append(site)


def _sky_ranges(image, base):
    ranges = []
    for entry in _SKY_SHADER_MESSAGES:
        for site in _functions_for_message(image, base, entry[2]):
            ranges.append((site, site + 0x4000))
    return ranges


def _vtable_methods(image, base):
    vtable = _resolve_rtti_vtable(image, base, b".?AVRenderView@Graphics@RBX@@")
    if vtable is None:
        return []
    starts = []
    raw = image[vtable:vtable + 8 * 200]
    for off in range(0, len(raw) - 7, 8):
        value = struct.unpack_from("<Q", raw, off)[0]
        fn = value - base if value >= base else value
        if 0 < fn < len(image):
            starts.append(fn)
    starts = sorted(set(starts))
    bounds = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else start + 0x4000
        bounds.append((start, end))
    return bounds


def _method_owner(site, bounds):
    for idx, (lo, hi) in enumerate(bounds):
        if lo <= site < hi:
            return idx
    return None


def _scan_render_view_flags(image, base, block, store):
    hits = _flag_writes(image, 0x400)
    candidates = [disp for disp in sorted(hits)
                  if 0x100 <= disp < len(block) and block[disp] == 1]
    sky_ranges = _sky_ranges(image, base)
    sky_valid = 0
    for disp in candidates:
        inside = False
        for site in hits[disp]["m32i"]:
            for lo, hi in sky_ranges:
                if lo <= site < hi:
                    inside = True
                    break
            if inside:
                break
        if inside:
            sky_valid = disp
            break
    methods = _vtable_methods(image, base)
    lighting_valid = 0
    for disp in candidates:
        if disp == sky_valid:
            continue
        rec = hits[disp]
        owners = set(_method_owner(site, methods) for site in rec["s1"])
        if len(owners) != 1:
            continue
        owner = owners.pop()
        if owner is None:
            continue
        if any(_method_owner(site, methods) == owner for site in rec["s0"]):
            lighting_valid = disp
            break
    store_offset(store, ("RenderView",), "SkyValid", sky_valid)
    store_offset(store, ("RenderView",), "LightingValid", lighting_valid)


def _valid_view_matrix(values):
    for value in values:
        if value != value or value in (float("inf"), float("-inf")):
            return False
    if abs(values[11] - 0.1) > 0.01:
        return False
    if abs(values[14] + 1.0) < 0.01 and abs(values[15]) < 0.01:
        return False
    return 10.0 < abs(values[15]) < 10000.0


def _scan_visual_engine(reader, visual_engine, fake_data_model, render_view, store):
    block = reader.try_read(visual_engine, 0x1000)
    if not block:
        return
    width, height = _get_window_size()
    for off in range(0, len(block) - 7, 4):
        fw, fh = struct.unpack_from("<ff", block, off)
        if abs(fw - width) < 2 and abs(fh - height) < 2:
            store_offset(store, ("VisualEngine",), "Dimensions", off)
            break
    for off in range(0, len(block) - 63, 4):
        matrix = struct.unpack_from("<16f", block, off)
        if _valid_view_matrix(matrix):
            store_offset(store, ("VisualEngine",), "ViewMatrix", off)
            break
    fake_off = 0
    view_off = 0
    for off in range(0, len(block) - 7, 8):
        ptr = struct.unpack_from("<Q", block, off)[0]
        if not fake_off and fake_data_model and ptr == fake_data_model:
            fake_off = off
        if not view_off and render_view and ptr == render_view:
            view_off = off
        if fake_off and view_off:
            break
    store_offset(store, ("VisualEngine",), "FakeDataModel", fake_off)
    store_offset(store, ("VisualEngine",), "RenderView", view_off)


def _scan_datamodel(reader, datamodel, tree, store):
    block = reader.try_read(datamodel, 0x8000)
    if not block:
        return
    for off in range(0, len(block) - 23):
        size = struct.unpack_from("<Q", block, off + 16)[0]
        if size != 36:
            continue
        text = _rbx_read_string(reader, datamodel + off)
        if text and _GUID_RE.match(text):
            store_offset(store, ("DataModel",), "JobId", off)
            break
    for off in range(0, len(block) - 23):
        size = struct.unpack_from("<Q", block, off + 16)[0]
        if not 9 <= size <= 22:
            continue
        text = _rbx_read_string(reader, datamodel + off)
        if text and _IP_RE.match(text):
            store_offset(store, ("DataModel",), "ServerIP", off)
            break
    place_id, _user_id = _get_roblox_log_ids()
    if place_id:
        for off in range(0, len(block) - 7, 8):
            if struct.unpack_from("<Q", block, off)[0] != place_id:
                continue
            store_offset(store, ("DataModel",), "PlaceId", off)
            if off >= 16:
                creator = struct.unpack_from("<Q", block, off - 16)[0]
                game = struct.unpack_from("<Q", block, off - 8)[0]
                if 0 < creator < 0x4000000000000 and 0 < game < 0x4000000000000:
                    store_offset(store, ("DataModel",), "CreatorId", off - 16)
                    store_offset(store, ("DataModel",), "GameId", off - 8)
            break
    if not tree:
        return
    children_off = tree.children_off
    script_context = tree.find(datamodel, "Script Context")
    if script_context and children_off is not None:
        vec = read_mem_u64(reader, datamodel + children_off)
        if _valid_ptr(vec):
            begin = read_mem_u64(reader, vec)
            end = read_mem_u64(reader, vec + 8)
            if _valid_ptr(begin) and end > begin:
                listed = reader.try_read(begin, min(end - begin, 0x8000))
                if listed:
                    for off in range(0, len(listed) - 7, 8):
                        if struct.unpack_from("<Q", listed, off)[0] == script_context:
                            store_offset(store, ("DataModel",), "ScriptContext", off)
                            break
    workspace = tree.find(datamodel, "Workspace")
    if workspace:
        folder = tree.find(workspace, "PlaceVersion")
        if folder:
            kids = tree.children(folder)
            text = tree.name(kids[0]) if kids else None
            if text and text.isdigit():
                want = int(text)
                for off in range(0, len(block) - 3):
                    if struct.unpack_from("<i", block, off)[0] == want:
                        store_offset(store, ("DataModel",), "PlaceVersion", off)
                        break


def _scan_runservice(reader, datamodel, tree, heartbeat_job, cap, store):
    if not tree:
        return
    service = tree.find(datamodel, "Run Service")
    if not service:
        return
    if heartbeat_job:
        for off in range(0, 0x400, 8):
            if read_mem_u64(reader, service + off) == heartbeat_job:
                store_offset(store, ("RunService",), "HeartbeatTask", off)
                break
        block = reader.try_read(heartbeat_job, 0x200)
        if block:
            tolerance = max(30.0, cap * 0.05)
            for off in range(0x60, len(block) - 7, 8):
                value = struct.unpack_from("<d", block, off)[0]
                if 0 < value < 1.0 and abs(1.0 / value - cap) <= tolerance:
                    store_offset(store, ("RunService",), "HeartbeatFPS", off)
                    break


def _class_descriptor_offset(reader, inst):
    block = reader.try_read(inst, 0x100)
    if not block:
        return None
    for off in range(0, len(block) - 7, 8):
        cd = struct.unpack_from("<Q", block, off)[0]
        if not _valid_ptr(cd):
            continue
        name_ptr = read_mem_u64(reader, cd + 0x8)
        if not _valid_ptr(name_ptr):
            continue
        if _rbx_read_string(reader, name_ptr) == "DataModel":
            return off
    return None


_SERVICE_CLASS_NAMES = {
    "Workspace", "Players", "Lighting", "RunService", "SoundService",
    "ReplicatedStorage", "ServerScriptService", "ServerStorage",
    "StarterGui", "StarterPack", "StarterPlayer", "Teams",
    "CollectionService", "InsertService", "Chat", "Debris",
    "MaterialService", "ScriptContext", "UserInputService", "Terrain",
}


def _looks_like_datamodel(reader, inst):
    if not _valid_ptr(inst):
        return False
    cd_off = _class_descriptor_offset(reader, inst)
    if cd_off is None:
        return False
    for off in range(0, 0x200, 8):
        vec = read_mem_u64(reader, inst + off)
        if not _valid_ptr(vec):
            continue
        begin = read_mem_u64(reader, vec)
        end = read_mem_u64(reader, vec + 8)
        if not _valid_ptr(begin) or end <= begin or (end - begin) > 0x10000:
            continue
        listed = reader.try_read(begin, min(end - begin, 0x400))
        if not listed:
            continue
        for slot in range(0, len(listed) - 7, 8):
            child = struct.unpack_from("<Q", listed, slot)[0]
            if not _valid_ptr(child):
                continue
            cls = _check_class_name(reader, child, cd_off)
            if cls in _SERVICE_CLASS_NAMES:
                return True
    return False


def resolve_datamodel_from_jobs(reader, image, base):
    try:
        sched_rva = find_scheduler(reader, image, base)
        if not sched_rva:
            return 0, 0, 0, 0
        sched = read_mem_u64(reader, base + sched_rva)
        if not _valid_ptr(sched):
            return 0, 0, 0, 0
        _jobs, render_job, _heartbeat = _scan_jobs(reader, sched)
        if not render_job:
            return 0, 0, 0, 0
        block = reader.try_read(render_job, 0x400)
        if not block:
            return 0, 0, 0, 0
        holder_fallback = 0
        for off in range(0, len(block) - 7, 8):
            holder = struct.unpack_from("<Q", block, off)[0]
            if not _valid_ptr(holder):
                continue
            kind = _rtti_class_name(reader, holder) or ""
            if "DataModel" not in kind:
                continue
            if not holder_fallback and kind == "RBX::DataModel" \
                    and _looks_like_datamodel(reader, holder):
                holder_fallback = holder
            inner = reader.try_read(holder, 0x800)
            if not inner:
                continue
            for off2 in range(0, len(inner) - 7, 8):
                real = struct.unpack_from("<Q", inner, off2)[0]
                if not _valid_ptr(real) or real == holder:
                    continue
                if _rtti_class_name(reader, real) != "RBX::DataModel":
                    continue
                if not _looks_like_datamodel(reader, real):
                    continue
                return real, holder, off2, _find_global_rva(image, holder)
        if holder_fallback:
            return holder_fallback, 0, 0, 0
    except Exception:
        pass
    return 0, 0, 0, 0


def dump_live_offsets(reader, image, base, datamodel, fake_data_model,
                      instance_offsets, store):
    cap = framerate_cap()
    sched_rva = find_scheduler(reader, image, base)
    render_job = 0
    heartbeat_job = 0
    if sched_rva:
        store_offset(store, ("TaskScheduler",), "Pointer", sched_rva)
        sched = read_mem_u64(reader, base + sched_rva)
        if _valid_ptr(sched):
            jobs, render_job, heartbeat_job = _scan_jobs(reader, sched)
            for name, value in jobs.items():
                store_offset(store, ("TaskScheduler",), name, value)
            store_offset(store, ("TaskScheduler",), "MaxFPS",
                         _scan_max_fps(reader, sched, cap))
    render_view = 0
    if render_job:
        render_view = _scan_render_job(reader, render_job, datamodel,
                                       fake_data_model, store)
    if render_view and datamodel:
        _scan_to_render_view(reader, datamodel, render_view, store)
    visual_engine = 0
    if render_view:
        visual_engine = _scan_render_view(reader, image, base, render_view, store)
    if visual_engine:
        store_offset(store, ("VisualEngine",), "Pointer",
                     _find_global_rva(image, visual_engine))
        _scan_visual_engine(reader, visual_engine, fake_data_model,
                            render_view, store)
    if datamodel:
        tree = None
        children_off = instance_offsets.get("ChildrenStart")
        name_off = instance_offsets.get("NameContainer")
        if children_off is not None and name_off is not None:
            tree = InstanceTree(reader, children_off, name_off,
                                instance_offsets.get("Name", 0x8))
        _scan_datamodel(reader, datamodel, tree, store)
        _scan_runservice(reader, datamodel, tree, heartbeat_job, cap, store)
