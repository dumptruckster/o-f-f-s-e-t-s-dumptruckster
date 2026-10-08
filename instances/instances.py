import struct
from ctypes import windll, wintypes, byref

from memory.utils import (read_mem_u64, read_mem_float, _rbx_read_string,
                          _valid_ptr, _check_class_name, _get_roblox_log_ids,
                          _scan_field)
from offsets.tables import _MAX_OFFSET
from instances.scanvalue import _RBX_CLASS_ALIASES


class InstanceTree(object):

    def __init__(self, reader, children_off, name_off, name_field_off):
        self.r = reader
        self.children_off = children_off
        self.name_off = name_off
        self.name_field_off = name_field_off
        self._names = {}

    def name(self, inst):
        if not inst or self.name_off is None:
            return None
        if inst in self._names:
            return self._names[inst]
        np = read_mem_u64(self.r, inst + self.name_off)
        s = (_rbx_read_string(self.r, np + self.name_field_off)
             if _valid_ptr(np) else None)
        self._names[inst] = s
        return s

    def children(self, inst, limit=1024):
        if not inst or self.children_off is None:
            return []
        vec = read_mem_u64(self.r, inst + self.children_off)
        if not _valid_ptr(vec):
            return []
        begin = read_mem_u64(self.r, vec)
        end = read_mem_u64(self.r, vec + 8)
        if not _valid_ptr(begin):
            return []
        if not _valid_ptr(end) or end <= begin or (end - begin) > 0x20000:
            end = begin + limit * 8
        block = self.r.try_read(begin, min(end, begin + limit * 8) - begin)
        out = []
        if not block:
            return out
        for off in range(0, len(block) - 7, 8):
            ptr = struct.unpack_from("<Q", block, off)[0]
            if _valid_ptr(ptr):
                out.append(ptr)
        return out

    def find_all(self, inst, names, limit=64):
        wanted = set(n for n in names if n)
        if not inst or self.children_off is None or not wanted:
            return []
        out = []
        for child in self.children(inst):
            if self.name(child) in wanted:
                out.append(child)
                if len(out) >= limit:
                    break
        return out

    def find(self, inst, name):
        if not name:
            return None
        hits = self.find_all(inst, (name, _RBX_CLASS_ALIASES.get(name)))
        return hits[0] if hits else None

    def child_int(self, folder, default=None):
        if not folder:
            return default
        kids = self.children(folder)
        if not kids:
            return default
        return self.name(kids[0])

    def find_deep(self, inst, name, depth=6):
        level = [inst]
        for _ in range(depth):
            nxt = []
            for cur in level:
                for child in self.children(cur):
                    if self.name(child) == name:
                        return child
                    nxt.append(child)
            level = nxt
            if not level:
                break
        return None


_SERVICE_CLASS_NAMES = {
    "Workspace", "WorldRoot", "Players", "Lighting", "RunService",
    "SoundService", "ReplicatedStorage", "ServerScriptService",
    "ServerStorage", "StarterGui", "StarterPack", "StarterPlayer",
    "Teams", "CollectionService", "InsertService", "Chat", "Debris",
    "MaterialService", "ScriptContext", "UserInputService", "Terrain",
    "BasePartService", "NetworkClient",
}

_SERVICE_INSTANCE_NAMES = {
    "Workspace", "Players", "Lighting", "Run Service", "ReplicatedStorage",
    "ServerScriptService", "ServerStorage", "StarterGui", "StarterPack",
    "StarterPlayer", "SoundService", "Teams", "Chat", "Debris",
    "InsertService", "CollectionService", "MaterialService",
    "UserInputService", "Script Context", "Terrain", "AudioService",
    "MessagingService", "RunService", "PathfindingService",
}


def _name_like(text):
    if not text or len(text) > 64:
        return False
    if not all(32 <= ord(c) < 127 for c in text):
        return False
    if not any(c.isalpha() for c in text):
        return False
    if len(text) == 36 and text.count("-") == 4:
        return False
    return True


def _probe_children(reader, inst, children_off, class_desc_off, limit=64):
    vec = read_mem_u64(reader, inst + children_off)
    if not _valid_ptr(vec):
        return []
    begin = read_mem_u64(reader, vec)
    end = read_mem_u64(reader, vec + 8)
    if not _valid_ptr(begin):
        return []
    if not _valid_ptr(end) or end <= begin or (end - begin) > 0x10000:
        end = begin + limit * 8
    block = reader.try_read(begin, min(end, begin + limit * 8) - begin)
    if not block:
        return []
    out = []
    for slot in range(0, len(block) - 7, 8):
        ptr = struct.unpack_from("<Q", block, slot)[0]
        if _valid_ptr(ptr):
            out.append(ptr)
    return out


def _service_children_vector(reader, inst, class_desc_off):
    if class_desc_off is None:
        return None, []
    for off in range(0, _MAX_OFFSET, 8):
        vec = read_mem_u64(reader, inst + off)
        if not _valid_ptr(vec):
            continue
        children = _probe_children(reader, inst, off, class_desc_off)
        if len(children) < 2:
            continue
        hits = 0
        for child in children:
            cls = _check_class_name(reader, child, class_desc_off)
            if cls in _SERVICE_CLASS_NAMES:
                hits += 1
                if hits >= 2:
                    return off, children
    return None, []


def _bootstrap_instance_name(reader, inst, children, class_desc_off):
    candidates = []
    for i in range(0, 0x200, 8):
        container = read_mem_u64(reader, inst + i)
        if not _valid_ptr(container):
            continue
        for j in range(0, 0x40):
            text = _rbx_read_string(reader, container + j)
            if _name_like(text):
                candidates.append((i, j, text, container + j))
                break
        if len(candidates) >= 24:
            break
    best = (None, None, None, None, 0)
    for i, j, text, struct in candidates:
        score = 0
        for child in children[:64]:
            np = read_mem_u64(reader, child + i)
            if not _valid_ptr(np):
                continue
            child_name = _rbx_read_string(reader, np + j)
            if child_name in _SERVICE_INSTANCE_NAMES:
                score += 1
                if score >= 2:
                    break
        if score > best[4]:
            best = (i, j, text, struct, score)
        if best[4] >= 2:
            break
    if best[4] >= 2:
        return best[0], best[1], best[2], best[3]
    return None, None, None, None


def dump_instance_offsets(reader, datamodel):
    out = {}

    def note(name, value):
        out[name] = value

    place_id_log, user_id_log = _get_roblox_log_ids()


    name_off = None
    name_field_off = 0
    dm_name_str = 0
    dm_name = None
    for i in range(0, 0x200):
        container = read_mem_u64(reader, datamodel + i)
        if not _valid_ptr(container):
            continue
        for j in range(0, 0x40):
            if _rbx_read_string(reader, container + j) == "Ugc":
                name_off = i
                name_field_off = j
                dm_name_str = container + j
                dm_name = "Ugc"
                break
        if name_off is not None:
            break
    if name_off is not None:
        note("NameContainer", name_off)
        note("Name", name_field_off)


    class_desc_off = None
    for off in range(0, _MAX_OFFSET):
        cd_ptr = read_mem_u64(reader, datamodel + off)
        if not _valid_ptr(cd_ptr):
            continue
        name_ptr = read_mem_u64(reader, cd_ptr + 0x8)
        if not _valid_ptr(name_ptr):
            continue
        s = _rbx_read_string(reader, name_ptr)
        if s == "DataModel":
            class_desc_off = off
            note("ClassDescriptor", off)
            break

    if name_off is None:
        try:
            children_off_probe, children_probe = _service_children_vector(
                reader, datamodel, class_desc_off)
            if children_probe:
                b_i, b_j, b_text, b_struct = _bootstrap_instance_name(
                    reader, datamodel, children_probe, class_desc_off)
                if b_i is not None:
                    name_off = b_i
                    name_field_off = b_j
                    dm_name = b_text
                    dm_name_str = b_struct
                    note("NameContainer", name_off)
                    note("Name", name_field_off)
        except Exception:
            pass
    if name_off is None:
        return out


    slen = _scan_field(reader, dm_name_str, 0x40, "<Q",
                       lambda v: v == len(dm_name))
    if slen is not None:
        note("StringLength", slen)


    children_off = None
    players_ptr  = None
    runservice_ptr = None
    scriptctx_ptr  = None
    workspace_ptr  = None
    workspace_off  = None

    for off in range(0, _MAX_OFFSET):
        start_ptr = read_mem_u64(reader, datamodel + off)
        if not _valid_ptr(start_ptr):
            continue
        child_list = read_mem_u64(reader, start_ptr)
        if not _valid_ptr(child_list):
            continue
        list_end = read_mem_u64(reader, start_ptr + 8)
        if not _valid_ptr(list_end) or list_end <= child_list \
                or (list_end - child_list) > 0x10000:
            list_end = child_list + 300 * 8
        found_players = False
        slot = child_list
        seen = 0
        while slot < list_end and seen < 300:
            inst = read_mem_u64(reader, slot)
            slot += 8
            seen += 1
            if not _valid_ptr(inst):
                continue
            np = read_mem_u64(reader, inst + name_off)
            if not _valid_ptr(np):
                continue
            s = _rbx_read_string(reader, np + name_field_off)
            if s == "Players":
                found_players = True
                players_ptr = inst
            elif s == "Run Service":
                runservice_ptr = inst
            elif s == "Script Context":
                scriptctx_ptr = inst
            elif s == "Workspace":
                workspace_ptr = inst
        if found_players:
            children_off = off
            note("ChildrenStart", off)
            break


    if children_off is not None:
        vec_base = read_mem_u64(reader, datamodel + children_off)
        begin = read_mem_u64(reader, vec_base)
        end_val = read_mem_u64(reader, vec_base + 8)
        if _valid_ptr(begin) and end_val > begin:
            note("ChildrenEnd", 0x8)


    if workspace_ptr is None:

        for off in range(0, _MAX_OFFSET, 8):
            ptr = read_mem_u64(reader, datamodel + off)
            if not _valid_ptr(ptr):
                continue
            np = read_mem_u64(reader, ptr + name_off)
            if not _valid_ptr(np):
                continue
            s = _rbx_read_string(reader, np + name_field_off)
            if s == "Workspace":
                workspace_ptr = ptr
                workspace_off = off
                note("Workspace", off)
                break
    elif workspace_ptr:

        off = _scan_field(reader, datamodel, _MAX_OFFSET, "<Q",
                          lambda v: v == workspace_ptr, step=8)
        if off is not None:
            workspace_off = off
            note("Workspace", off)


    off = _scan_field(reader, datamodel + 0x500, _MAX_OFFSET - 0x500,
                      "<q", lambda v: v == 31)
    if off is not None:
        note("GameLoaded", off + 0x500)


    if place_id_log:
        off = _scan_field(reader, datamodel, _MAX_OFFSET, "<Q",
                          lambda v: v == place_id_log, step=8)
        if off is not None:
            note("PlaceId", off)


    parent_off = None
    if workspace_ptr:
        for off in range(0, _MAX_OFFSET, 8):
            p_ptr = read_mem_u64(reader, workspace_ptr + off)
            if not _valid_ptr(p_ptr):
                continue
            np = read_mem_u64(reader, p_ptr + name_off)
            if not _valid_ptr(np):
                continue
            s = _rbx_read_string(reader, np + name_field_off)
            if s == dm_name or p_ptr == datamodel:
                parent_off = off
                note("Parent", off)
                break


    camera_ptr = None
    if workspace_ptr:
        for off in range(0, _MAX_OFFSET, 8):
            ptr = read_mem_u64(reader, workspace_ptr + off)
            if not _valid_ptr(ptr):
                continue
            np = read_mem_u64(reader, ptr + name_off)
            if not _valid_ptr(np):
                continue
            s = _rbx_read_string(reader, np + name_field_off)
            if s == "Camera":
                camera_ptr = ptr
                note("Camera", off)
                break


    world_ptr = None
    if workspace_ptr and class_desc_off is not None:

        for off in range(0, 0x800, 8):
            ptr = read_mem_u64(reader, workspace_ptr + off)
            if not _valid_ptr(ptr):
                continue

            g = read_mem_float(reader, ptr + 0x22C)
            if g is not None and abs(g - 196.2) < 5.0:
                world_ptr = ptr
                note("WorkspaceWorldPtr", off)
                break


    if workspace_ptr:
        off = _scan_field(reader, workspace_ptr, _MAX_OFFSET, "<f",
                          lambda f: abs(f - 196.2) < 0.5, step=4)
        if off is not None:
            note("Gravity", off)


    local_player_ptr = None
    if players_ptr and children_off is not None:
        vec = read_mem_u64(reader, players_ptr + children_off)
        clist = read_mem_u64(reader, vec) if _valid_ptr(vec) else 0
        if _valid_ptr(clist):

            members = set()
            cblock = reader.try_read(clist, 48 * 8)

            if cblock:
                for i in range(0, len(cblock) - 7, 8):
                    v = struct.unpack_from("<Q", cblock, i)[0]
                    if _valid_ptr(v):
                        members.add(v)


            candidates = []
            seen = set()
            pblock = reader.try_read(players_ptr, _MAX_OFFSET)
            if pblock:
                for off in range(0, len(pblock) - 7, 8):
                    v = struct.unpack_from("<Q", pblock, off)[0]
                    if v in members and v not in seen:
                        seen.add(v)
                        candidates.append((off, v))
            local_player_off = None
            if len(candidates) == 1:
                local_player_off, local_player_ptr = candidates[0]
            elif candidates:
                ws_names = set()
                if workspace_ptr and name_off is not None \
                        and children_off is not None:
                    wvec = read_mem_u64(reader, workspace_ptr + children_off)
                    wlist = read_mem_u64(reader, wvec) if _valid_ptr(wvec) else 0
                    wb = reader.try_read(wlist, 256 * 8) if _valid_ptr(wlist) else None
                    if wb:
                        for i in range(0, len(wb) - 7, 8):
                            cptr = struct.unpack_from("<Q", wb, i)[0]
                            if not _valid_ptr(cptr):
                                continue
                            np = read_mem_u64(reader, cptr + name_off)
                            if _valid_ptr(np):
                                nm = _rbx_read_string(reader, np + name_field_off)
                                if nm:
                                    ws_names.add(nm)
                matched = []
                for off, pptr in candidates:
                    np = read_mem_u64(reader, pptr + name_off)
                    if _valid_ptr(np):
                        nm = _rbx_read_string(reader, np + name_field_off)
                        if nm and nm in ws_names:
                            matched.append((off, pptr))
                if len(matched) == 1:
                    local_player_off, local_player_ptr = matched[0]
                else:
                    local_player_off, local_player_ptr = candidates[0]
            if local_player_off is not None:
                note("LocalPlayer", local_player_off)


    character_ptr = None
    my_name = None
    if local_player_ptr:
        np = read_mem_u64(reader, local_player_ptr + name_off)
        if _valid_ptr(np):
            my_name = _rbx_read_string(reader, np + name_field_off)

    if local_player_ptr and my_name:
        for off in range(0, _MAX_OFFSET, 8):
            ptr = read_mem_u64(reader, local_player_ptr + off)
            if not _valid_ptr(ptr):
                continue
            np = read_mem_u64(reader, ptr + name_off)
            if not _valid_ptr(np):
                continue
            s = _rbx_read_string(reader, np + name_field_off)
            if s == my_name:
                character_ptr = ptr
                note("Character", off)
                break


    humanoid_ptr = None
    if character_ptr and class_desc_off is not None and children_off is not None:
        cblock = reader.try_read(character_ptr, _MAX_OFFSET)
        for ptr, _ in _iter_children(reader, character_ptr, children_off,
                                     name_off, name_field_off):
            if _check_class_name(reader, ptr, class_desc_off) == "Humanoid":

                if cblock:
                    for off in range(0, len(cblock) - 7, 8):
                        if struct.unpack_from("<Q", cblock, off)[0] == ptr:
                            humanoid_ptr = ptr
                            note("Humanoid", off)
                            break
                if humanoid_ptr:
                    break


    hrp_ptr = None
    if character_ptr and class_desc_off is not None and children_off is not None:
        hblock = reader.try_read(humanoid_ptr, 0x600) \
            if humanoid_ptr else None
        for ptr, nm in _iter_children(reader, character_ptr, children_off,
                                      name_off, name_field_off):
            if nm == "HumanoidRootPart":
                if humanoid_ptr and hblock:
                    for off in range(0, len(hblock) - 7, 8):
                        if struct.unpack_from("<Q", hblock, off)[0] == ptr:
                            hrp_ptr = ptr
                            note("HumanoidRootPart", off)
                            break
                break


    if humanoid_ptr:
        hblock = reader.try_read(humanoid_ptr, _MAX_OFFSET) or b""

        def _hits(target, tol):
            found = []
            for off in range(0, len(hblock) - 3, 4):
                f = struct.unpack_from("<f", hblock, off)[0]
                if abs(f - target) < tol:
                    found.append(off)
            return found

        h = _hits(50.0, 0.001)
        if h:
            note("JumpPower", h[0])
        ws = _hits(16.0, 0.001)
        if len(ws) >= 1:
            note("WalkSpeedA", ws[0])
        if len(ws) >= 2:
            note("WalkSpeedB", ws[1])
        h = _hits(100.0, 0.001)
        if len(h) >= 1:
            note("Health", h[0])
        if len(h) >= 2:
            note("MaxHealth", h[1])
        h = _hits(7.2, 0.05)
        if h:
            note("JumpHeight", h[0])
        h = _hits(1.35, 0.05)
        if h:
            note("HipHeight", h[0])


    if camera_ptr:
        default_fov = 70.0 * (3.1415926 / 180.0)
        cblock = reader.try_read(camera_ptr, _MAX_OFFSET)
        if cblock:
            for off in range(0, len(cblock) - 3, 4):
                f = struct.unpack_from("<f", cblock, off)[0]
                if abs(f - default_fov) < 0.001:
                    note("FOV", off)
                    break


    if local_player_ptr and user_id_log:
        uid = user_id_log & 0xFFFFFFFF
        off = _scan_field(reader, local_player_ptr, _MAX_OFFSET, "<I",
                          lambda v: v == uid, step=4)
        if off is not None:
            note("UserId", off + 0x10)


    if local_player_ptr and character_ptr:
        off = _scan_field(reader, local_player_ptr, _MAX_OFFSET, "<Q",
                          lambda v: v == character_ptr, step=8)
        if off is not None:
            note("ModelInstance", off)

    return out


def _iter_children(reader, instance_ptr, children_off, name_off,
                   name_field_off=8, limit=512):
    if not instance_ptr or children_off is None or name_off is None:
        return
    vec = read_mem_u64(reader, instance_ptr + children_off)
    if not _valid_ptr(vec):
        return
    begin = read_mem_u64(reader, vec)
    end = read_mem_u64(reader, vec + 8)
    if not _valid_ptr(begin):
        return
    if not _valid_ptr(end) or end <= begin or (end - begin) > 0x10000:
        end = begin + limit * 8
    slots = 0
    for addr in range(begin, min(end, begin + limit * 8), 8):
        ptr = read_mem_u64(reader, addr)
        if not _valid_ptr(ptr):
            continue
        np = read_mem_u64(reader, ptr + name_off)
        s = _rbx_read_string(reader, np + name_field_off) \
            if _valid_ptr(np) else None
        yield ptr, s


def _get_window_size(default=(1920, 1080)):
    try:
        hwnd = windll.user32.FindWindowA(None, b"Roblox")
        if not hwnd:
            return default
        rect = wintypes.RECT()
        if not windll.user32.GetClientRect(hwnd, byref(rect)):
            return default
        w, h = rect.right - rect.left, rect.bottom - rect.top
        if w <= 0 or h <= 0:
            return default
        return (w, h)
    except Exception:
        return default
