import struct

from memory.utils import (read_mem_u64, _rbx_read_string, _valid_ptr,
                          _scan_locale_id)
from instances.scanvalue import (_scan_block_candidates, scan_for_value,
                                 store_offset, _matrix3x3_to_euler,
                                 _report_uncertain)
from instances.instances import InstanceTree, _get_window_size
from offsets.tables import _MAX_OFFSET
from rtti.rtti import _rtti_class_name

_MATERIALS = [
    ("Asphalt", (80, 84, 84)), ("Basalt", (75, 74, 74)), ("Brick", (138, 97, 73)),
    ("Cobblestone", (134, 134, 118)), ("Concrete", (152, 152, 152)),
    ("CrackedLava", (255, 24, 67)), ("Glacier", (221, 228, 229)),
    ("Grass", (111, 126, 62)), ("Ground", (140, 130, 104)),
    ("Ice", (204, 210, 223)), ("LeafyGrass", (106, 134, 64)),
    ("Limestone", (255, 243, 192)), ("Mud", (121, 112, 98)),
    ("Pavement", (143, 144, 135)), ("Rock", (99, 100, 102)),
    ("Salt", (255, 255, 254)), ("Sand", (207, 203, 167)),
    ("Sandstone", (148, 124, 95)), ("Slate", (88, 89, 86)),
    ("Snow", (235, 253, 255)), ("WoodPlanks", (172, 148, 108)),
]


def _count_primitives(reader, array_ptr, limit=0x2000):
    block = reader.try_read(array_ptr, limit)
    if not block:
        return 0
    total = 0
    for off in range(0, len(block) - 0x10, 8):
        prim = struct.unpack_from("<Q", block, off)[0]
        if not _valid_ptr(prim):
            break
        d = reader.try_read(prim + 8, 4)
        if not d or len(d) < 4:
            break
        if struct.unpack_from("<i", d, 0)[0] == 6:
            total += 1
    return total


def _find_matrix_offset(reader, ptr, want, tol=0.1, limit=0x1000):
    block = reader.try_read(ptr, limit)
    if not block:
        return None
    for off in range(0, len(block) - 35):
        d = struct.unpack_from("<fffffffff", block, off)
        e = _matrix3x3_to_euler(d)
        if all(abs(e[i] - want[i]) <= tol for i in range(3)):
            return off
    return None


def dump_service_offsets(reader, datamodel, children_off, name_off,
                         name_field_off, win_size=None):
    store = {}
    skipped = []
    tree = InstanceTree(reader, children_off, name_off, name_field_off)

    if win_size is None:
        win_size = _get_window_size()

    def need(inst, label):
        if not inst:
            skipped.append(label)
        return inst

    workspace = need(tree.find(datamodel, "Workspace"), "Workspace")
    lighting = need(tree.find(datamodel, "Lighting"), "Lighting")
    players = need(tree.find(datamodel, "Players"), "Players")
    local_player = tree.children(players)[0] if players else 0
    player_name = tree.name(local_player) if local_player else None
    character = tree.find(workspace, player_name) if (workspace and player_name) else 0
    humanoid = tree.find(character, "Humanoid") if character else 0

    if lighting:
        if not scan_for_value(reader, store, "ClockTime", "Lighting",
                              [lighting], [-0.00897], "float", eps=0.0001):
            scan_for_value(reader, store, "ClockTime", "Lighting",
                          [lighting], [14.0], "float", eps=0.001)
        scan_for_value(reader, store, "Brightness", "Lighting",
                      [lighting], [2.54], "float", eps=0.01)
        scan_for_value(reader, store, "EnvironmentDiffuseScale", "Lighting",
                      [lighting], [0.872])
        scan_for_value(reader, store, "EnvironmentSpecularScale", "Lighting",
                      [lighting], [0.233])
        scan_for_value(reader, store, "FogStart", "Lighting",
                      [lighting], [722.1], "float", eps=0.1)
        scan_for_value(reader, store, "FogEnd", "Lighting",
                      [lighting], [100000.0], "float", eps=0.1)
        scan_for_value(reader, store, "FogColor", "Lighting", [lighting],
                      [(0.752941, 0.752941, 0.752941)], "color3", eps=0.01)
        scan_for_value(reader, store, "Ambient", "Lighting", [lighting],
                      [(0.541, 0.541, 0.541)], "color3", eps=0.01)
        scan_for_value(reader, store, "OutdoorAmbient", "Lighting", [lighting],
                      [(0.502, 0.502, 0.502)], "color3", eps=0.01)
        scan_for_value(reader, store, "ColorShift_Top", "Lighting", [lighting],
                      [(0.121569, 0.705882, 0.207843)], "color3", eps=0.01)
        scan_for_value(reader, store, "ColorShift_Bottom", "Lighting", [lighting],
                      [(0.070588, 0.062745, 0.027451)], "color3", eps=0.01)
        scan_for_value(reader, store, "ExposureCompensation", "Lighting",
                      [lighting], [2.13], "float", eps=0.01)
        scan_for_value(reader, store, "GeographicLatitude", "Lighting",
                      [lighting], [115.231], "float", eps=1.0)

        blk = reader.try_read(lighting, _MAX_OFFSET)
        if blk:
            for off in range(0x120, len(blk) - 11):
                r, g, b = struct.unpack_from("<fff", blk, off)
                if (0.001 < r < 0.999 and 0.001 < g < 0.999 and 0.001 < b < 0.999
                        and abs(r - 0.75) <= 0.01 and abs(g - 0.75) <= 0.01
                        and abs(b - 0.75) <= 0.01):
                    store_offset(store, "Lighting", "LightColor", off)
                    break

        gradient_top = 0
        found_light_dir = False
        blk = reader.try_read(lighting, _MAX_OFFSET)
        if blk:
            for off in range(0, len(blk) - 11):
                x, y, z = struct.unpack_from("<fff", blk, off)
                if (not found_light_dir and abs(x - 0.0151139) <= 0.01
                        and abs(y + 0.026178) <= 0.01 and abs(z - 0.999543) <= 0.01):
                    found_light_dir = True
                    store_offset(store, "Lighting", "LightDirection", off)
                    continue
                if x == 1.0 and y == 1.0 and z == 1.0:
                    if not gradient_top:
                        gradient_top = off
                        store_offset(store, "Lighting", "GradientTop", off)
                    else:
                        store_offset(store, "Lighting", "GradientBottom", off)

        if gradient_top:
            scan_for_value(reader, store, "GlobalShadows", "Lighting",
                          [lighting], [True], "bool",
                          start=max(0, gradient_top - 12 - 2))

        moon = scan_for_value(reader, store, "MoonPosition", "Lighting",
                             [lighting],
                             [(-0.0151139, 0.026178, 0.999543)], "v3")
        sun = scan_for_value(reader, store, "SunPosition", "Lighting",
                            [lighting],
                            [(0.0151139, -0.026178, 0.999543)], "v3",
                            start=max(0, moon - 12 - 2))
        store_offset(store, "Lighting", "Source", sun - 4 if sun else 0)

        lighting_sky = tree.find(lighting, "Sky")
        if lighting_sky:
            scan_for_value(reader, store, "Sky", "Lighting", [lighting],
                          [lighting_sky], "u64")

    workspace_sky = tree.find(workspace, "Sky") if workspace else 0
    if workspace_sky:
        for f, url in (("SkyboxBk", "rbxasset://textures/sky/sky512_bk.tex"),
                       ("SkyboxDn", "rbxasset://textures/sky/sky512_dn.tex"),
                       ("SkyboxFt", "rbxasset://textures/sky/sky512_ft.tex"),
                       ("SkyboxLf", "rbxasset://textures/sky/sky512_lf.tex"),
                       ("SkyboxRt", "rbxasset://textures/sky/sky512_rt.tex"),
                       ("SkyboxUp", "rbxasset://textures/sky/sky512_up.tex"),
                       ("SunTextureId", "rbxasset://sky/sun.jpg"),
                       ("MoonTextureId", "rbxasset://sky/moon.jpg")):
            scan_for_value(reader, store, f, "Sky", [workspace_sky], [url], "string")
        scan_for_value(reader, store, "SunAngularSize", "Sky", [workspace_sky],
                      [21.0], "float", eps=1.0)
        scan_for_value(reader, store, "MoonAngularSize", "Sky", [workspace_sky],
                      [11.0], "float", eps=1.0)
        scan_for_value(reader, store, "SkyboxOrientation", "Sky", [workspace_sky],
                      [(123.0, 22.0, 83.0)], "v3", eps=0.01)
        scan_for_value(reader, store, "StarCount", "Sky", [workspace_sky],
                      [3000], "int")

    if lighting:
        atmosphere = tree.find(lighting, "Atmosphere")
        if atmosphere:
            scan_for_value(reader, store, "Density", "Atmosphere",
                          [atmosphere], [0.315])
            scan_for_value(reader, store, "Offset", "Atmosphere",
                          [atmosphere], [0.243])
            scan_for_value(reader, store, "Color", "Atmosphere", [atmosphere],
                          [(0.541, 0.541, 0.541)], "color3")
            scan_for_value(reader, store, "Decay", "Atmosphere", [atmosphere],
                          [(18 / 255.0, 16 / 255.0, 7 / 255.0)], "color3")
            scan_for_value(reader, store, "Glare", "Atmosphere",
                          [atmosphere], [0.125])
            scan_for_value(reader, store, "Haze", "Atmosphere",
                          [atmosphere], [0.372])

        blooms = (tree.find_all(lighting, ("Bloom", "BloomEffect", "Bloom2",
                                           "Bloom3", "Bloom4")) + [0, 0, 0])[:4]
        if blooms[0]:
            scan_for_value(reader, store, "Intensity", "BloomEffect",
                          [blooms[0]], [0.652])
            scan_for_value(reader, store, "Size", "BloomEffect",
                          [blooms[0]], [5.123])
            scan_for_value(reader, store, "Threshold", "BloomEffect",
                          [blooms[0]], [4.231])
        enabled_off = scan_for_value(
            reader, store, "Enabled", "BloomEffect",
            [b for b in blooms if b], [True, False, False, False][:len([b for b in blooms if b])],
            "bool")

        dof = tree.find(lighting, "DepthOfField")
        if dof:
            scan_for_value(reader, store, "FocusDistance", "DepthOfFieldEffect",
                          [dof], [93.82])
            scan_for_value(reader, store, "FarIntensity", "DepthOfFieldEffect",
                          [dof], [0.259])
            scan_for_value(reader, store, "NearIntensity", "DepthOfFieldEffect",
                          [dof], [0.173])
            scan_for_value(reader, store, "InFocusRadius", "DepthOfFieldEffect",
                          [dof], [9.875])
            store_offset(store, "DepthOfFieldEffect", "Enabled", enabled_off)

        sunrays = tree.find(lighting, "SunRays")
        if sunrays:
            scan_for_value(reader, store, "Intensity", "SunRaysEffect",
                          [sunrays], [0.296])
            scan_for_value(reader, store, "Spread", "SunRaysEffect",
                          [sunrays], [0.827])
            store_offset(store, "SunRaysEffect", "Enabled", enabled_off)

        cc = tree.find(lighting, "ColorCorrection")
        if cc:
            scan_for_value(reader, store, "Brightness", "ColorCorrectionEffect",
                          [cc], [0.124])
            scan_for_value(reader, store, "Contrast", "ColorCorrectionEffect",
                          [cc], [0.132])
            scan_for_value(reader, store, "TintColor", "ColorCorrectionEffect",
                          [cc], [(126 / 255.0, 139 / 255.0, 82 / 255.0)],
                          "color3")
            store_offset(store, "ColorCorrectionEffect", "Enabled", enabled_off)

        cgs = (tree.find_all(lighting, ("ColorGrading", "ColorGradingEffect",
                                        "ColorGrading2", "ColorGrading3",
                                        "ColorGrading4")) + [0, 0, 0])[:4]
        if cgs[0]:
            keep = [c for c in cgs if c]
            scan_for_value(reader, store, "TonemapperPreset",
                          "ColorGradingEffect", keep,
                          [0, 0, 1, 1][:len(keep)], "int")
            store_offset(store, "ColorGradingEffect", "Enabled", enabled_off)

        blur = tree.find(lighting, "Blur")
        if blur:
            scan_for_value(reader, store, "Size", "BlurEffect", [blur], [32.213])
            store_offset(store, "BlurEffect", "Enabled", enabled_off)

    world = 0
    world_off = 0
    if workspace:
        ws_block = reader.try_read(workspace, _MAX_OFFSET)
        for off in range(0, len(ws_block or b"") - 7, 8):
            cand = struct.unpack_from("<Q", ws_block, off)[0]
            if not _valid_ptr(cand):
                continue
            sub = reader.try_read(cand, 0x300)
            if not sub:
                continue
            hits = _scan_block_candidates(sub, "float", 165.231, 0.001, 4)
            if hits:
                world, world_off = cand, off
                store_offset(store, "Workspace", "World", off)
                store_offset(store, "World", "Gravity", hits[0])
                break

    if world:
        scan_for_value(reader, store, "worldStepsPerSec", "World",
                      [world], [240.0], start=0x600)
        scan_for_value(reader, store, "FallenPartsDestroyHeight", "World",
                      [world], [-231.232])
        scan_for_value(reader, store, "ReadOnlyGravity", "Workspace",
                      [workspace], [165.231])

        game_time = tree.child_int(tree.find(workspace, "GameTime"))
        try:
            game_time = float(str(game_time).strip())
        except (TypeError, ValueError):
            game_time = None
        if game_time is not None:
            scan_for_value(reader, store, "DistributedGameTime", "Workspace",
                          [workspace], [game_time], "double", eps=2.0)

        air_off = air_den_off = 0
        for off in range(0x50, 0x250):
            air = read_mem_u64(reader, world + off)
            if not _valid_ptr(air):
                continue
            sub = reader.try_read(air, 0x100)
            if not sub:
                continue
            hits = _scan_block_candidates(sub, "float", 0.201, 0.001, 4)
            if hits:
                air_off, air_den_off = off, hits[0]
                break
        store_offset(store, "World", "AirProperties", air_off)
        store_offset(store, "AirProperties", "AirDensity", air_den_off)
        if air_off:
            air = read_mem_u64(reader, world + air_off)
            scan_for_value(reader, store, "GlobalWind", "AirProperties", [air],
                          [(154.632, 155.632, 156.632)], "v3")

    ctx = {
        "tree": tree, "datamodel": datamodel, "workspace": workspace,
        "lighting": lighting, "players": players,
        "local_player": local_player, "player_name": player_name,
        "character": character, "humanoid": humanoid,
        "world": world, "world_off": world_off, "win_size": win_size,
    }
    return store, skipped, ctx


def dump_workspace_instances(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    world = ctx["world"]
    datamodel = ctx["datamodel"]
    if not workspace:
        return

    prim_count = tree.child_int(tree.find(workspace, "PrimCount"))
    try:
        prim_count = int(str(prim_count).strip())
    except (TypeError, ValueError):
        prim_count = None
    if prim_count and world:
        found = 0
        base_offsets = [ctx["world_off"]]
        ws_block = reader.try_read(workspace, _MAX_OFFSET)
        base_offsets += [o for o in range(0, len(ws_block or b"") - 7, 8)
                         if o not in (ctx["world_off"],)]
        for boff in base_offsets[:32]:
            holder = read_mem_u64(reader, workspace + boff)
            if not _valid_ptr(holder):
                continue
            for off in range(0x150, 0x300, 8):
                arr = read_mem_u64(reader, holder + off)
                if not _valid_ptr(arr):
                    continue
                if _count_primitives(reader, arr) == prim_count:
                    found = off
                    break
            if found:
                break
        store_offset(store, "World", "Primitives", found)

    all_prim = tree.child_int(tree.find(workspace, "AllPrimCount"))
    try:
        all_prim = int(str(all_prim).strip())
    except (TypeError, ValueError):
        all_prim = None
    if all_prim is not None:
        scan_for_value(reader, store, "PrimitiveCount", "DataModel",
                      [datamodel], [all_prim], "int")

    terrain = tree.find(workspace, "Terrain")
    if terrain:
        scan_for_value(reader, store, "GrassLength", "Terrain", [terrain], [0.723])
        scan_for_value(reader, store, "WaterReflectance", "Terrain",
                      [terrain], [0.652])
        scan_for_value(reader, store, "WaterTransparency", "Terrain",
                      [terrain], [0.323])
        scan_for_value(reader, store, "WaterWaveSize", "Terrain",
                      [terrain], [0.123])
        scan_for_value(reader, store, "WaterWaveSpeed", "Terrain",
                      [terrain], [35.234])
        scan_for_value(reader, store, "WaterColor", "Terrain", [terrain],
                      [(0.047, 0.329, 0.361)], "color3")

        terr_block = reader.try_read(terrain, _MAX_OFFSET)
        mat_colors_off = 0
        for off in range(0, len(terr_block or b"") - 7, 8):
            ptr = struct.unpack_from("<Q", terr_block, off)[0]
            if not _valid_ptr(ptr):
                continue
            sub = reader.try_read(ptr + 0x10, 0x40)
            if not sub:
                continue
            if _scan_block_candidates(sub, "coloru8", (80, 84, 84), 0, 1):
                mat_colors_off = off
                break
        store_offset(store, "Terrain", "MaterialColors", mat_colors_off)
        if mat_colors_off:
            mat_colors = read_mem_u64(reader, terrain + mat_colors_off)
            for mat_name, rgb in _MATERIALS:
                scan_for_value(reader, store, mat_name, "MaterialColors",
                              [mat_colors], [rgb], "coloru8")

    sound = tree.find(workspace, "Sound")
    if sound:
        scan_for_value(reader, store, "SoundId", "Sound", [sound],
                      ["rbxassetid://skibidi"], "string")
        scan_for_value(reader, store, "RollOffMaxDistance", "Sound",
                      [sound], [2312.321])
        scan_for_value(reader, store, "RollOffMinDistance", "Sound",
                      [sound], [2423.213])
        scan_for_value(reader, store, "PlaybackSpeed", "Sound", [sound], [1.237])
        scan_for_value(reader, store, "Volume", "Sound", [sound], [0.523])
        sound_group = tree.find(workspace, "SoundGroup")
        if sound_group:
            scan_for_value(reader, store, "SoundGroup", "Sound", [sound],
                          [sound_group], "u64")
        quad = [tree.find(workspace, n)
                for n in ("Sound", "Sound2", "Sound3", "Sound4")]
        if all(quad):
            scan_for_value(reader, store, "IsPlaying", "Sound", quad,
                          [False, True, False, True], "bool")
            scan_for_value(reader, store, "Looped", "Sound", quad,
                          [False, True, True, False], "bool")

    spawns = [tree.find(workspace, n)
              for n in ("SpawnLocation", "SpawnLocation2", "SpawnLocation3")]
    if all(spawns):
        scan_for_value(reader, store, "AllowTeamChangeOnTouch", "SpawnLocation",
                      spawns, [True, True, False], "bool")
        scan_for_value(reader, store, "Enabled", "SpawnLocation", spawns,
                      [True, False, True], "bool")
        scan_for_value(reader, store, "Neutral", "SpawnLocation", spawns,
                      [False, True, False], "bool")
        scan_for_value(reader, store, "ForcefieldDuration", "SpawnLocation",
                      spawns[:2], [4345, 4350], "int")
        scan_for_value(reader, store, "TeamColor", "SpawnLocation", spawns[:2],
                      [307, 315], "int")

    sa = [tree.find(workspace, n)
          for n in ("SurfaceAppearance", "SurfaceAppearance2", "SurfaceAppearance3")]
    if all(sa):
        scan_for_value(reader, store, "AlphaMode", "SurfaceAppearance", sa,
                      [0, 2, 1], "int")
        scan_for_value(reader, store, "Color", "SurfaceAppearance", sa[:1],
                      [(45 / 255.0, 172 / 255.0, 102 / 255.0)], "color3")
        for f, aid in (("ColorMap", 73879578225090),
                       ("EmissiveMaskContent", 73879578225091),
                       ("MetalnessMap", 73879578225092),
                       ("NormalMap", 73879578225093),
                       ("RoughnessMap", 73879578225094)):
            scan_for_value(reader, store, f, "SurfaceAppearance", sa[:1],
                          ["rbxassetid://%d" % aid], "string")
        scan_for_value(reader, store, "EmissiveStrength", "SurfaceAppearance",
                      sa[:1], [3.532])
        scan_for_value(reader, store, "EmissiveTint", "SurfaceAppearance", sa[:1],
                      [(18 / 255.0, 100 / 255.0, 231 / 255.0)], "color3")

    pe = tree.find(workspace, "ParticleEmitter")
    if pe:
        for f, val in (("Brightness", 1.993), ("LightEmission", 0.872),
                       ("LightInfluence", 1.332), ("ZOffset", 832.235),
                       ("Rate", 33.884), ("Rotation", 88.243),
                       ("RotSpeed", 23.856), ("Speed", 2.123),
                       ("Drag", 0.376), ("TimeScale", 0.728),
                       ("VelocityInheritance", 0.238)):
            scan_for_value(reader, store, f, "ParticleEmitter", [pe], [val])
        scan_for_value(reader, store, "Texture", "ParticleEmitter", [pe],
                      ["rbxasset://textures/particles/sparkles_main.dds"], "string")
        scan_for_value(reader, store, "Lifetime", "ParticleEmitter", [pe],
                      [(5.32, 10.88)], "v2")
        scan_for_value(reader, store, "SpreadAngle", "ParticleEmitter", [pe],
                      [(4.233, 8.354)], "v2")
        scan_for_value(reader, store, "Acceleration", "ParticleEmitter", [pe],
                      [(90.394, 32.234, 12.857)], "v3")

    beam = tree.find(workspace, "Beam")
    att1 = tree.find(workspace, "BeamAttach1")
    att2 = tree.find(workspace, "BeamAttach2")
    if beam:
        for f, val in (("Brightness", 1.775), ("LightEmission", 0.392),
                       ("LightInfluence", 0.745), ("TextureLength", 1.625),
                       ("TextureSpeed", 0.642), ("ZOffset", 0.975),
                       ("CurveSize0", 3.324), ("CurveSize1", 7.885),
                       ("Width0", 0.328), ("Width1", 5.775)):
            scan_for_value(reader, store, f, "Beam", [beam], [val])
        scan_for_value(reader, store, "Texture", "Beam", [beam],
                      ["rbxassetid://73879578225090"], "string")
        if att1:
            scan_for_value(reader, store, "Attachment0", "Beam", [beam], [att1], "u64")
        if att2:
            scan_for_value(reader, store, "Attachment1", "Beam", [beam], [att2], "u64")


def dump_parts_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    if not workspace:
        return

    pos_part = tree.find(workspace, "Position")
    if not pos_part:
        return
    tp_block = reader.try_read(pos_part, _MAX_OFFSET)
    prim_off = pos_off = 0
    for off in range(0, len(tp_block or b"") - 7, 8):
        prim = struct.unpack_from("<Q", tp_block, off)[0]
        if not _valid_ptr(prim):
            continue
        sub = reader.try_read(prim, 0x1000)
        if not sub:
            continue
        hits = _scan_block_candidates(sub, "v3", (255.0, 84.7, -255.0), 0.1, 4)
        if hits:
            prim_off, pos_off = off, hits[0]
            break
    store_offset(store, "BasePart", "Primitive", prim_off)
    store_offset(store, "Primitive", "Position", pos_off)
    store_offset(store, "Primitive", "Validate", 6)
    if not prim_off:
        return
    p1 = read_mem_u64(reader, pos_part + prim_off)

    scan_for_value(reader, store, "Owner", "Primitive", [p1], [pos_part], "u64")

    size_part = tree.find(workspace, "Size")
    rot_part = tree.find(workspace, "Rotation")
    mark_part = tree.find(workspace, "67")
    p2 = read_mem_u64(reader, size_part + prim_off) if size_part else 0
    p3 = read_mem_u64(reader, rot_part + prim_off) if rot_part else 0
    p4 = read_mem_u64(reader, mark_part + prim_off) if mark_part else 0

    if p2:
        scan_for_value(reader, store, "Size", "Primitive", [p2],
                      [(77.1, 4.2, 99.0)], "v3")
    if p3:
        rot = _find_matrix_offset(reader, p3, (-78.81, 16.93, 21.32))
        store_offset(store, "Primitive", "Rotation", rot or 0)
    if mark_part:
        scan_for_value(reader, store, "Transparency", "BasePart",
                      [mark_part, pos_part], [0.231, 0.749])

    flags_off = 0
    if p1 and p2 and p3 and p4:
        want_collide = (True, False, True, True)
        want_anchor = (True, True, True, False)

        prim_blk = [reader.try_read(p, 0x1000) for p in (p1, p2, p3, p4)]
        for off in range(0x100, 0x1000):
            ok = True
            for blk, wc, wa in zip(prim_blk, want_collide, want_anchor):
                if not blk or off >= len(blk):
                    ok = False
                    break
                byte = blk[off]
                if bool(byte & 0x8) != wc or bool(byte & 0x2) != wa:
                    ok = False
                    break
            if ok:
                flags_off = off
                break
    store_offset(store, "Primitive", "Flags", flags_off)
    store_offset(store, "PrimitiveFlags", "Anchored", 0x2)
    store_offset(store, "PrimitiveFlags", "CanCollide", 0x8)
    store_offset(store, "PrimitiveFlags", "CanTouch", 0x10)
    store_offset(store, "PrimitiveFlags", "CanQuery", 0x20)

    scan_for_value(reader, store, "Color3", "BasePart", [pos_part], [121],
                  "uint8")
    anchor_part = tree.find(workspace, "Anchored")
    p5 = read_mem_u64(reader, anchor_part + prim_off) if anchor_part else 0
    if p5 and p2 and p3 and p4:
        scan_for_value(reader, store, "Material", "Primitive",
                      [p1, p2, p3, p4], [2, 2, 2, 4], "int")
    if size_part and rot_part:
        scan_for_value(reader, store, "Shape", "BasePart",
                      [pos_part, size_part, rot_part], [1, 0, 2], "int")

    vel_part = tree.find(workspace, "Velocity")
    p6 = read_mem_u64(reader, vel_part + prim_off) if vel_part else 0
    if p6:
        scan_for_value(reader, store, "AssemblyLinearVelocity", "Primitive", [p6],
                      [(100.0, 59.2, 2.0)], "v3")
        scan_for_value(reader, store, "AssemblyAngularVelocity", "Primitive", [p6],
                      [(67.0, 67.69, 6.0)], "v3")

    mesh_part = tree.find(workspace, "MeshPart")
    if mesh_part:
        scan_for_value(reader, store, "MeshId", "MeshPart", [mesh_part],
                      ["rbxassetid://5281167063"], "string")
        scan_for_value(reader, store, "Texture", "MeshPart", [mesh_part],
                      ["rbxassetid://73879578225090"], "string")
        scan_for_value(reader, store, "MeshSize", "MeshPart", [mesh_part],
                      [(4.028, 2.956, 4.028)], "v3")

    the_parts = [tree.find(workspace, n)
                 for n in ("ThePart", "ThePart2", "ThePart3", "ThePart4")]
    if all(the_parts):
        scan_for_value(reader, store, "Massless", "BasePart", the_parts,
                      [True, False, True, True], "bool")
        scan_for_value(reader, store, "CastShadow", "BasePart", the_parts,
                      [True, False, True, False], "bool")
        scan_for_value(reader, store, "Locked", "BasePart", the_parts,
                      [False, True, False, True], "bool")
        scan_for_value(reader, store, "Reflectance", "BasePart", the_parts[:1],
                      [0.832])

    value_inst = tree.find(workspace, "Value")
    if value_inst:
        scan_for_value(reader, store, "Value", "Misc", [value_inst],
                      ["Value :3"], "string")

    model = tree.find(workspace, "Model")
    if model:
        kids = tree.children(model)
        if kids:
            scan_for_value(reader, store, "PrimaryPart", "Model", [model],
                          [kids[0]], "u64")
        scan_for_value(reader, store, "Scale", "Model", [model], [1.622])

    special_mesh = tree.find(workspace, "Mesh")
    if special_mesh:
        scan_for_value(reader, store, "Scale", "SpecialMesh", [special_mesh],
                      [(17.2, 13.0, 23.0)], "v3")
        scan_for_value(reader, store, "MeshId", "SpecialMesh", [special_mesh],
                      ["rbxassetid://5281167063"], "string")

    attachment = tree.find(workspace, "Attachment")
    if attachment:
        scan_for_value(reader, store, "Position", "Attachment", [attachment],
                      [(12.23, 24.23, 1.23)], "v3")

    weld_folder = tree.find(workspace, "Welds")
    if weld_folder:
        weld = tree.find(weld_folder, "Weld")
        weld_con = tree.find(weld_folder, "WeldConstraint")
        wp1 = tree.find(weld_folder, "Part1")
        wp2 = tree.find(weld_folder, "Part2")
        if weld and wp1 and wp2:
            scan_for_value(reader, store, "Part0", "Weld", [weld], [wp1], "u64")
            scan_for_value(reader, store, "Part1", "Weld", [weld], [wp2], "u64")
        if weld_con and wp1 and wp2:
            scan_for_value(reader, store, "Part0", "WeldConstraint", [weld_con],
                          [wp1], "u64")
            scan_for_value(reader, store, "Part1", "WeldConstraint", [weld_con],
                          [wp2], "u64")

    union2 = tree.find(workspace, "Union2")
    if union2:
        scan_for_value(reader, store, "AssetId", "UnionOperation", [union2],
                      ["https://www.roblox.com//asset/?id=83292086558510"],
                      "string")


def dump_players_offsets(reader, ctx, store):
    tree = ctx["tree"]
    players = ctx["players"]
    workspace = ctx["workspace"]
    local_player = ctx["local_player"]
    if not (players and local_player):
        return

    scan_for_value(reader, store, "LocalPlayer", "Player", [players],
                  [local_player], "u64")

    user_id_folder = tree.find(workspace, "UserID") if workspace else 0
    user_id = None
    if user_id_folder:
        try:
            user_id = int(str(tree.child_int(user_id_folder)).strip())
        except (TypeError, ValueError):
            user_id = None
    if user_id is not None:
        scan_for_value(reader, store, "UserId", "Player", [local_player],
                      [user_id], "u64")

    display_folder = tree.find(workspace, "DisplayName") if workspace else 0
    if display_folder:
        scan_for_value(reader, store, "DisplayName", "Player", [local_player],
                      [tree.child_int(display_folder) or ""], "string", start=0x100)

    scan_for_value(reader, store, "HealthDisplayDistance", "Player",
                  [local_player], [132.233])
    scan_for_value(reader, store, "NameDisplayDistance", "Player",
                  [local_player], [342.853])

    character = ctx["character"]
    if character:
        scan_for_value(reader, store, "ModelInstance", "Player", [local_player],
                      [character], "u64")

    teams = tree.find(ctx["datamodel"], "Teams")
    meow = tree.find(teams, "Meow") if teams else 0
    if meow:
        scan_for_value(reader, store, "Team", "Player", [local_player], [meow], "u64")
        scan_for_value(reader, store, "BrickColor", "Team", [meow], [1015], "int")
        scan_for_value(reader, store, "TeamColor", "Player", [local_player],
                      [1015], "int")

    locale = _scan_locale_id(reader, local_player)
    if locale:
        scan_for_value(reader, store, "LocaleId", "Player", [local_player],
                      [locale], "string")

    age_folder = tree.find(workspace, "AccountAge") if workspace else 0
    age = None
    if age_folder:
        try:
            age = int(str(tree.child_int(age_folder)).strip())
        except (TypeError, ValueError):
            age = None
    if age is not None:
        scan_for_value(reader, store, "AccountAge", "Player", [local_player],
                      [age], "int")

    humanoid = ctx["humanoid"]
    if humanoid:
        scan_for_value(reader, store, "Health", "Humanoid", [humanoid], [52.382])
        scan_for_value(reader, store, "MaxHealth", "Humanoid", [humanoid], [88.817])
        walk = scan_for_value(reader, store, "Walkspeed", "Humanoid", [humanoid],
                             [18.827])
        if walk:
            scan_for_value(reader, store, "WalkspeedCheck", "Humanoid",
                          [humanoid], [18.827], start=walk + 1)
        scan_for_value(reader, store, "JumpPower", "Humanoid", [humanoid], [27.322])
        scan_for_value(reader, store, "JumpHeight", "Humanoid", [humanoid], [7.812])
        scan_for_value(reader, store, "HipHeight", "Humanoid", [humanoid], [1.998],
                      start=0x100)
        scan_for_value(reader, store, "MaxSlopeAngle", "Humanoid", [humanoid], [89.9])

    rig = tree.find(workspace, "Rig") if workspace else 0
    r_h = tree.find(workspace, "Humanoid") if workspace else 0
    rig_h = tree.find(rig, "Humanoid") if rig else 0
    rh = [tree.find(workspace, "Humanoid%d" % i) if workspace else 0
          for i in range(2, 8)]
    noob = tree.find(workspace, "Noob") if workspace else 0
    noob_h = tree.find(noob, "Humanoid") if noob else 0
    sit_npc = tree.find(workspace, "SIT") if workspace else 0
    sit_h = tree.find(sit_npc, "Humanoid") if sit_npc else 0
    sit_root = tree.find(sit_npc, "HumanoidRootPart") if sit_npc else 0
    seat = tree.find(workspace, "Seat") if workspace else 0

    if sit_h:
        if seat:
            scan_for_value(reader, store, "SeatPart", "Humanoid", [sit_h],
                          [seat], "u64")
        if sit_root:
            scan_for_value(reader, store, "HumanoidRootPart", "Humanoid", [sit_h],
                          [sit_root], "u64")

    if r_h:
        scan_for_value(reader, store, "CameraOffset", "Humanoid", [r_h],
                      [(13.232, 14.532, 0.231)], "v3")
        scan_for_value(reader, store, "HealthDisplayDistance", "Humanoid", [r_h],
                      [734.457])
        scan_for_value(reader, store, "NameDisplayDistance", "Humanoid", [r_h],
                      [342.789])
        scan_for_value(reader, store, "DisplayName", "Humanoid", [r_h], ["wow"],
                      "string")

    wt_targets = [h for h in (r_h, rig_h) if h]
    if wt_targets:
        wt_expected = [8.0] * len(wt_targets)
        if not scan_for_value(reader, store, "WalkTimer", "Humanoid",
                              wt_targets, wt_expected, "double",
                              start=0x3f0, end=0x3f8):
            scan_for_value(reader, store, "WalkTimer", "Humanoid",
                           wt_targets, wt_expected, "double",
                           start=0x3e0, end=0x400)

    rh_keep = [h for h in rh[:3] if h]
    if r_h and len(rh_keep) >= 3:
        scan_for_value(reader, store, "DisplayDistanceType", "Humanoid",
                      [r_h] + rh_keep[:2], [0, 1, 2], "int")
    rh57 = [h for h in rh[3:6] if h]
    if r_h and len(rh57) >= 3:
        scan_for_value(reader, store, "HealthDisplayType", "Humanoid", rh57,
                      [0, 2, 1], "int")
        scan_for_value(reader, store, "NameOcclusion", "Humanoid", rh57,
                      [1, 0, 1], "int")

    rh4567 = [h for h in rh[2:6] if h]
    if len(rh4567) >= 4:
        scan_for_value(reader, store, "Sit", "Humanoid", rh4567,
                      [False, True, False, True], "bool")
        scan_for_value(reader, store, "PlatformStand", "Humanoid", rh4567,
                      [True, True, False, True], "bool")

    if noob_h:
        scan_for_value(reader, store, "MoveDirection", "Humanoid", [noob_h],
                      [(-0.6884002089500427, 0.43886613845825195,
                        0.5774961709976196)], "v3", eps=0.001)

    rig_triple = [h for h in (humanoid, r_h, rig_h) if h]
    if humanoid and len(rig_triple) >= 3:
        scan_for_value(reader, store, "RigType", "Humanoid", rig_triple,
                      [1, 0, 0], "int", start=0x100, end=0x200)
        jump4 = [h for h in (humanoid, r_h, rh[1], rh[2]) if h]
        if len(jump4) >= 4:
            scan_for_value(reader, store, "Jump", "Humanoid", jump4,
                          [False, False, True, False], "bool",
                          start=0x100, end=0x200)

    if rh[1]:
        scan_for_value(reader, store, "MoveToPoint", "Humanoid", [rh[1]],
                      [(8282.0, 222.243, 3.232)], "v3")

    if seat and sit_h:
        scan_for_value(reader, store, "Occupant", "Seat", [seat], [sit_h], "u64")

    vehicle_seat = tree.find(workspace, "VehicleSeat") if workspace else 0
    if vehicle_seat:
        for f, val in (("MaxSpeed", 47.321), ("SteerFloat", 0.892),
                       ("ThrottleFloat", 0.118), ("Torque", 24.234),
                       ("TurnSpeed", 2.992)):
            scan_for_value(reader, store, f, "VehicleSeat", [vehicle_seat], [val])

    stats = tree.find(ctx["datamodel"], "Stats")
    perf = tree.find(stats, "PerformanceStats") if stats else 0
    ping = tree.find(perf, "Ping") if perf else 0
    if ping:
        cands = []
        block = reader.try_read(ping, _MAX_OFFSET)
        if block:
            for off in range(0, len(block) - 3, 4):
                if 30 <= struct.unpack_from("<i", block, off)[0] <= 60:
                    cands.append(off)
        if len(cands) == 1:
            store_offset(store, "StatsItem", "Value", cands[0])
        elif len(cands) > 1:
            guess = _report_uncertain(cands[0])
            if guess is not None:
                store_offset(store, "StatsItem", "Value", guess)

    backpack = tree.find(local_player, "Backpack")
    tools = [tree.find(backpack, n)
             for n in ("Tool", "Tool2", "Tool3", "Tool4")] if backpack else []
    if tools and all(tools):
        scan_for_value(reader, store, "Tooltip", "Tool", tools[:1], ["meow"], "string")
        scan_for_value(reader, store, "TextureId", "Tool", tools[:1],
                      ["rbxassetid://73879578225090"], "string")
        scan_for_value(reader, store, "Grip", "Tool", tools[:1],
                      [(67.0, 69.0, 420.0)], "v3")
        scan_for_value(reader, store, "Enabled", "Tool", tools,
                      [True, False, True, False], "bool")
        scan_for_value(reader, store, "CanBeDropped", "Tool", tools,
                      [False, True, False, True], "bool")
        scan_for_value(reader, store, "ManualActivationOnly", "Tool", tools,
                      [True, False, True, True], "bool")
        scan_for_value(reader, store, "RequiresHandle", "Tool", tools,
                      [True, True, False, True], "bool")

    clothing = tree.find(workspace, "Clothing") if workspace else 0
    if clothing:
        scan_for_value(reader, store, "Template", "Clothing", [clothing],
                      ["rbxassetid://73879578225090"], "string")
        scan_for_value(reader, store, "Color3", "Clothing", [clothing],
                      [(17 / 255.0, 199 / 255.0, 255 / 255.0)], "color3")

    cmesh = [tree.find(workspace, n) if workspace else 0
             for n in ("CharacterMesh", "CharacterMesh2")]
    if cmesh[0]:
        scan_for_value(reader, store, "BaseTextureId", "CharacterMesh", cmesh[:1],
                      ["rbxassetid://3242"], "string")
        scan_for_value(reader, store, "OverlayTextureId", "CharacterMesh", cmesh[:1],
                      ["rbxassetid://2732"], "string")
        scan_for_value(reader, store, "MeshId", "CharacterMesh", cmesh[:1],
                      ["rbxassetid://5867"], "string")
    if all(cmesh):
        scan_for_value(reader, store, "BodyPart", "CharacterMesh", cmesh,
                      [3, 5], "int")


def dump_camera_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    local_player = ctx["local_player"]
    if not workspace:
        return
    cam = tree.find(workspace, "Camera")
    if cam:
        scan_for_value(reader, store, "CurrentCamera", "Workspace", [workspace],
                      [cam], "u64")
        scan_for_value(reader, store, "Position", "Camera", [cam],
                      [(0.0, 7.733, 12.074)], "v3")
        rot = _find_matrix_offset(reader, cam, (15.0, 0.0, 0.0))

        if rot is not None:
            store_offset(store, "Camera", "Rotation", rot, allow_zero=True)
        humanoid = ctx["humanoid"]
        if humanoid:
            scan_for_value(reader, store, "CameraSubject", "Camera", [cam],
                          [humanoid], "u64")
        scan_for_value(reader, store, "FieldOfView", "Camera", [cam], [1.3166])
        depth = 1.0 / (2.0 * _tan(1.3166 / 2.0))
        scan_for_value(reader, store, "ImagePlaneDepth", "Camera", [cam], [depth])
        scan_for_value(reader, store, "CameraType", "Camera", [cam], [5], "int",
                      start=0x100)
        w, h = ctx["win_size"]
        scan_for_value(reader, store, "Viewport", "Camera", [cam], [w], "int16")
        scan_for_value(reader, store, "ViewportSize", "Camera", [cam],
                      [(float(w), float(h))], "v2")

    if local_player:
        zoom_min = scan_for_value(reader, store, "MinZoomDistance", "Player",
                                 [local_player], [0.528])
        scan_for_value(reader, store, "MaxZoomDistance", "Player",
                      [local_player], [128.0])
        if zoom_min:
            scan_for_value(reader, store, "CameraMode", "Player", [local_player],
                          [0], "int", start=zoom_min)


def _tan(x):
    import math
    return math.tan(x)


def live_cursor_position():
    try:
        from ctypes import wintypes, windll, byref
        point = wintypes.POINT()
        if windll.user32.GetCursorPos(byref(point)):
            return (float(point.x), float(point.y))
    except Exception:
        return None
    return None


def dump_mouse_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    local_player = ctx["local_player"]
    mouse_service = tree.find(ctx["datamodel"], "MouseService")
    if not (mouse_service and workspace):
        return
    folder = tree.find(workspace, "MousePosition")
    pos_str = tree.child_int(folder) if folder else None
    expected_positions = []
    if pos_str and "," in pos_str:
        try:
            parts = pos_str.split(",")
            place_sample = (float(parts[0]), float(parts[1]))
            if place_sample[0] >= 100 and place_sample[1] >= 100:
                expected_positions.append(place_sample)
        except (TypeError, ValueError):
            pass
    cursor = live_cursor_position()
    if cursor and cursor[0] >= 100 and cursor[1] >= 100:
        if cursor not in expected_positions:
            expected_positions.append(cursor)
    for mouse_pos in expected_positions:
        for off in range(0xE0, 0x251):
            obj = read_mem_u64(reader, mouse_service + off)
            if not _valid_ptr(obj):
                continue
            sub = reader.try_read(obj, 0x104)
            if not sub:
                continue
            for j in range(0xB0, 0x101, 4):
                if j + 8 > len(sub):
                    break
                x, y = struct.unpack_from("<ff", sub, j)
                if abs(x - mouse_pos[0]) <= 1.0 and abs(y - mouse_pos[1]) <= 75.0:
                    store_offset(store, "MouseService", "InputObject", off)
                    store_offset(store, "MouseService", "InputObject2", off + 0x10)
                    store_offset(store, "MouseService", "MousePosition", j)
                    break
            if store.get("MouseService", {}).get("MousePosition") is not None:
                break
        if store.get("MouseService", {}).get("MousePosition") is not None:
            break

    if local_player and workspace:
        lp_blk = reader.try_read(local_player + 0xB00, _MAX_OFFSET - 0xB00)
        for pm_off in range(0, len(lp_blk or b"") - 7, 8):
            pm = struct.unpack_from("<Q", lp_blk, pm_off)[0]
            if not _valid_ptr(pm):
                continue
            sub = reader.try_read(pm + 0x100, 0x154)
            if not sub:
                continue
            hit = None
            for i in range(0, len(sub) - 7, 8):
                if struct.unpack_from("<Q", sub, i)[0] == workspace:
                    hit = 0x100 + i
                    break
            if hit is None:
                continue
            real_off = 0xB00 + pm_off
            store_offset(store, "Player", "Mouse", real_off)
            store_offset(store, "PlayerMouse", "Workspace", hit)
            scan_for_value(reader, store, "Icon", "PlayerMouse", [pm],
                          ["meow"], "string")
            return


def dump_ui_offsets(reader, ctx, store):
    tree = ctx["tree"]
    local_player = ctx["local_player"]
    if not local_player:
        return
    player_gui = tree.find(local_player, "PlayerGui")
    if not player_gui:
        return
    freecam = tree.find(player_gui, "Freecam")
    enabled_ui = tree.find(player_gui, "Enabled")
    disabled_ui = tree.find(player_gui, "NotEnabled")
    gui_targets = [t for t in (freecam, enabled_ui, disabled_ui) if t]
    if len(gui_targets) >= 2:
        gui_expected = [True, True, False] if freecam else [True, False]
        scan_for_value(reader, store, "ScreenGui_Enabled", "GuiObject",
                      gui_targets, gui_expected, "bool", start=0x300)

    ui_frame = tree.find(enabled_ui, "Frame") if enabled_ui else 0
    if ui_frame:
        scan_for_value(reader, store, "Position", "GuiObject", [ui_frame],
                      [(0.144, 27, 0.122, 87)], "udim2")
        scan_for_value(reader, store, "Size", "GuiObject", [ui_frame],
                      [(0.433, 100, 0.211, 100)], "udim2")

    visible = tree.find(enabled_ui, "Visible") if enabled_ui else 0
    invisible = tree.find(enabled_ui, "NotVisible") if enabled_ui else 0
    if visible and ui_frame and invisible:
        scan_for_value(reader, store, "Visible", "GuiObject",
                      [visible, ui_frame, invisible],
                      [True, True, False], "bool", start=0x400)

    image_label = tree.find(enabled_ui, "ImageLabel") if enabled_ui else 0
    if image_label:
        scan_for_value(reader, store, "Image", "GuiObject", [image_label],
                      ["rbxassetid://73879578225090"], "string")
    text_label = tree.find(enabled_ui, "TextLabel") if enabled_ui else 0
    text_box = tree.find(enabled_ui, "TextBox") if enabled_ui else 0
    if text_label:
        rich_markup = "<b>RbxDumper</b>"
        text_off = scan_for_value(reader, store, "Text", "GuiObject",
                                  [text_label], [rich_markup], "string")
        if not text_off:
            text_off = scan_for_value(reader, store, "Text", "GuiObject",
                                      [text_label], ["RbxDumper"], "string")
        if text_off:
            store_offset(store, "TextLabel", "Text", text_off)
        content_off = scan_for_value(reader, store, "ContentText",
                                     "TextLabel", [text_label],
                                     ["RbxDumper"], "string")
        if not content_off:
            content_off = scan_for_value(reader, store, "ContentText",
                                         "TextLabel", [text_label],
                                         [rich_markup], "string")
        localized_off = scan_for_value(reader, store, "LocalizedText",
                                       "TextLabel", [text_label],
                                       [rich_markup], "string")
        if not localized_off:
            localized_off = scan_for_value(reader, store, "LocalizedText",
                                           "TextLabel", [text_label],
                                           ["RbxDumper"], "string")
        scan_for_value(reader, store, "TextSize", "TextLabel",
                      [text_label], [14.0], "float", eps=0.001)
        scan_for_value(reader, store, "MaxVisibleGraphemes", "TextLabel",
                      [text_label], [-1], "int")
        if text_box:
            scan_for_value(reader, store, "RichText", "TextLabel",
                          [text_label, text_box], [True, False], "bool",
                          start=0x300)
        scan_for_value(reader, store, "RichText", "GuiObject", [text_label],
                      [rich_markup], "string")
        color_off = scan_for_value(reader, store, "TextColor3", "GuiObject",
                                   [text_label],
                                   [(0.752941, 0.752941, 0.752941)], "color3",
                                   eps=0.01)
        if color_off:
            store_offset(store, "TextLabel", "TextColor3", color_off)
        scan_for_value(reader, store, "LayoutOrder", "GuiObject", [text_label],
                      [-286], "int")
        rot = scan_for_value(reader, store, "Rotation", "GuiObject", [text_label],
                            [9.72], "float", eps=0.01)
        store_offset(store, "GuiBase2D", "AbsoluteRotation", rot or 0)

    if visible:
        scan_for_value(reader, store, "BackgroundColor3", "GuiObject", [visible],
                      [(0.752941, 0.752941, 0.752941)], "color3", eps=0.01)
    if ui_frame:
        scan_for_value(reader, store, "BorderColor3", "GuiObject", [ui_frame],
                      [(0.752941, 0.752941, 0.752941)], "color3", eps=0.01)
        scan_for_value(reader, store, "ZIndex", "GuiObject", [ui_frame],
                      [67], "int")
        scan_for_value(reader, store, "BackgroundTransparency", "GuiObject",
                      [ui_frame], [0.752])

    w, h = ctx["win_size"]
    if ui_frame:
        for f, base in (("AbsoluteSize", 931.360), ("AbsolutePosition", 303.480)):
            scan_for_value(reader, store, f, "GuiBase2D", [ui_frame],
                          [base * (w / 1920.0)], "float", eps=10.0)

    text_box = tree.find(enabled_ui, "TextBox") if enabled_ui else 0
    uis = tree.find(ctx["datamodel"], "UserInputService")
    if text_box and uis:
        for off in range(0x200, 0x400):
            wis = read_mem_u64(reader, uis + off)
            if not _valid_ptr(wis):
                continue
            sub = reader.try_read(wis, 0x50)
            if not sub:
                continue
            for j in range(0x20, 0x50, 8):
                if struct.unpack_from("<Q", sub, j)[0] == text_box:
                    store_offset(store, "UserInputService", "WindowInputState", off)
                    store_offset(store, "WindowInputState", "CurrentTextBox", j)
                    store_offset(store, "WindowInputState", "CapsLock", j - 8)
                    break
            if store.get("WindowInputState", {}).get("CurrentTextBox") is not None:
                break

    workspace = ctx["workspace"]
    decal = tree.find(workspace, "Decal") if workspace else 0
    if decal:
        scan_for_value(reader, store, "Decal_Texture", "Textures", [decal],
                      ["rbxassetid://73879578225090"], "string")
    texture = tree.find(workspace, "Texture") if workspace else 0
    if texture:
        scan_for_value(reader, store, "Texture_Texture", "Textures", [texture],
                      ["rbxassetid://73879578225090"], "string")


_EXPECTED_BYTECODE_LEN = 100


def dump_animation_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    if not workspace:
        return
    animation = tree.find(workspace, "Animation")
    if animation:
        scan_for_value(reader, store, "AnimationId", "Misc", [animation],
                      ["rbxassetid://121903298942078"], "string")

    value_off = store.get("Misc", {}).get("Value")
    if value_off is None:
        return

    tracks = []
    for n in ("AnimationTrackHolder", "AnimationTrackHolder2",
              "AnimationTrackHolder3", "AnimationTrackHolder4"):
        holder = tree.find(workspace, n)
        tracks.append(read_mem_u64(reader, holder + value_off) if holder else 0)
    rig = tree.find(workspace, "Rig")
    rig_h = tree.find(rig, "Humanoid") if rig else 0
    animator = tree.find(rig_h, "Animator") if rig_h else 0

    if tracks[0]:
        if animation:
            scan_for_value(reader, store, "Animation", "AnimationTrack",
                          [tracks[0]], [animation], "u64")
        if animator:
            scan_for_value(reader, store, "Animator", "AnimationTrack",
                          [tracks[0]], [animator], "u64")
        speed = scan_for_value(reader, store, "Speed", "AnimationTrack",
                              [tracks[0]], [6.218])
        store_offset(store, "AnimationTrack", "TimePosition",
                 speed + 4 if speed else 0)
        quad = [t for t in tracks if t]
        if len(quad) >= 4:
            scan_for_value(reader, store, "Looped", "AnimationTrack", quad,
                          [True, False, False, True], "bool", start=0x200)

    if animator:
        for off in range(0x600, 0x1000):
            head = read_mem_u64(reader, animator + off)
            if not _valid_ptr(head):
                continue
            node = read_mem_u64(reader, head)
            guard = 0
            while node and node != head and guard < 4096:
                guard += 1
                track = read_mem_u64(reader, node + 0x10)
                if _valid_ptr(track) and tree.name(track) == "Animation":
                    store_offset(store, "Animator", "ActiveAnimations", off)
                    break
                node = read_mem_u64(reader, node)
            if store.get("Animator", {}).get("ActiveAnimations") is not None:
                break


def _is_bytecode(reader, base):
    ptr = read_mem_u64(reader, base + 0x10)
    size = read_mem_u64(reader, base + 0x28)
    if not _valid_ptr(ptr) or size == 0 or size > 0x200000:
        return False
    if size == _EXPECTED_BYTECODE_LEN:
        return True
    head = reader.try_read(ptr, 1)
    return bool(head) and head[0] == 6


def dump_scripts_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    if not workspace:
        return
    empty_hash = "d41d8cd98f00b204e9800998ecf8427e"
    specs = (
        ("LocalScript", "{704E7537-4EFC-4E9E-BB5A-60CDCA238EAD}"),
        ("ModuleScript", "{4330BBB6-38D5-43C8-B302-C2DC97068AF6}"),
        ("Script", "{7C692C7B-5ABE-400F-AA26-035C6BC2A36A}"),
    )
    for inst_name, guid in specs:
        inst = tree.find(workspace, inst_name)
        if not inst:
            continue
        scan_for_value(reader, store, "GUID", inst_name, [inst], [guid], "string")
        scan_for_value(reader, store, "Hash", inst_name, [inst], [empty_hash],
                      "string")
        bc_off = 0
        for off in range(0x100, 0x1000, 8):
            embedded = read_mem_u64(reader, inst + off)
            if _valid_ptr(embedded) and _is_bytecode(reader, embedded):
                bc_off = off
                break
            if _is_bytecode(reader, inst + off):
                bc_off = off
                break
        if bc_off:
            store_offset(store, inst_name, "Bytecode", bc_off)

    store_offset(store, "ByteCode", "Pointer", 0x10)
    store_offset(store, "ByteCode", "Size", 0x28)


def dump_interactables_offsets(reader, ctx, store):
    tree = ctx["tree"]
    workspace = ctx["workspace"]
    if not workspace:
        return
    prompt = tree.find(workspace, "ProximityPrompt")
    if prompt:
        scan_for_value(reader, store, "ActionText", "ProximityPrompt", [prompt],
                      ["This is action text"], "string")
        scan_for_value(reader, store, "ObjectText", "ProximityPrompt", [prompt],
                      ["This is object text"], "string")
        scan_for_value(reader, store, "HoldDuration", "ProximityPrompt", [prompt],
                      [0.282], "float", eps=0.01)
        scan_for_value(reader, store, "MaxActivationDistance", "ProximityPrompt",
                      [prompt], [10.882], "float", eps=0.01)
        scan_for_value(reader, store, "KeyCode", "ProximityPrompt", [prompt],
                      [101], "int")
        scan_for_value(reader, store, "GamepadKeyCode", "ProximityPrompt", [prompt],
                      [1000], "int")
        trio = [tree.find(workspace, n)
                for n in ("ProximityPrompt", "ProximityPrompt2", "ProximityPrompt3")]
        if all(trio):
            scan_for_value(reader, store, "Enabled", "ProximityPrompt", trio,
                          [True, False, True], "bool")
            scan_for_value(reader, store, "RequiresLineOfSight", "ProximityPrompt",
                          trio, [True, True, False], "bool")

    click = tree.find(workspace, "ClickDetector")
    if click:
        scan_for_value(reader, store, "MaxActivationDistance", "ClickDetector",
                      [click], [32.211], "float", eps=0.01)
        scan_for_value(reader, store, "MouseIcon", "ClickDetector", [click],
                      ["rbxassetid://73879578225090"], "string")

    drag = tree.find(workspace, "DragDetector")
    drag_part = tree.find(workspace, "dragdetectpart")
    if drag:
        if drag_part:
            scan_for_value(reader, store, "ReferenceInstance", "DragDetector",
                          [drag], [drag_part], "u64")
        for f, val in (("MaxActivationDistance", 743.321), ("MaxDragAngle", 120.83),
                       ("MinDragAngle", 4.842), ("MaxForce", 7452.386),
                       ("MaxTorque", 236.872), ("Responsiveness", 881.415)):
            scan_for_value(reader, store, f, "DragDetector", [drag], [val])
        scan_for_value(reader, store, "MaxDragTranslation", "DragDetector", [drag],
                      [(128.83, 129.83, 130.83)], "v3")
        scan_for_value(reader, store, "MinDragTranslation", "DragDetector", [drag],
                      [(118.83, 119.83, 110.83)], "v3")
        scan_for_value(reader, store, "ActivatedCursorIcon", "DragDetector", [drag],
                      ["rbxassetid://73879578225091"], "string")
        scan_for_value(reader, store, "CursorIcon", "DragDetector", [drag],
                      ["rbxassetid://73879578225090"], "string")


def dump_mesh_content_provider(reader, ctx, store):
    tree = ctx["tree"]
    mcp = tree.find(ctx["datamodel"], "MeshContentProvider")
    if not mcp:
        return
    lrucache = 0
    lru_holder = lru_field = 0
    for i in range(0, 0x300, 8):
        holder = read_mem_u64(reader, mcp + i)
        if not _valid_ptr(holder):
            continue
        sub = reader.try_read(holder, 0x100)
        if not sub:
            continue
        for j in range(0, 0x100, 8):
            cand = struct.unpack_from("<Q", sub, j)[0]
            if not _valid_ptr(cand):
                continue
            name = _rtti_class_name(reader, cand)
            if name and "MemEnforcedLRUCache" in name:
                lru_holder, lru_field, lrucache = i, j, cand
                break
        if lrucache:
            break
    if not lrucache:
        return
    store_offset(store, "MeshContentProvider", "LRUHolder", lru_holder)
    store_offset(store, "LRUHolder", "MemEnforcedLRUCache", lru_field)

    head = 0
    for i in range(0x8, 0x100, 8):
        ptr = read_mem_u64(reader, lrucache + i)
        if _valid_ptr(ptr) and _valid_ptr(read_mem_u64(reader, ptr)) \
                and _valid_ptr(read_mem_u64(reader, ptr + 8)):
            head = i
            break
    if not head:
        return
    store_offset(store, "MemEnforcedLRUCache", "Head", head)

    sentinel = read_mem_u64(reader, lrucache + head)
    first = read_mem_u64(reader, sentinel)
    if not _valid_ptr(sentinel) or not _valid_ptr(first) or sentinel == first:
        return

    assetid = 0
    for i in range(0, 0x100, 8):
        s = _rbx_read_string(reader, first + i)
        if s and ("rbxasset" in s or "http" in s):
            assetid = i
            break
    if not assetid:
        return
    store_offset(store, "LRUNode", "Next", 0x0, allow_zero=True)
    store_offset(store, "LRUNode", "AssetID", assetid)

    node, rightleg = first, 0
    for _ in range(0x2000):
        if node == sentinel:
            break
        s = _rbx_read_string(reader, node + assetid)
        if s and "rightleg" in s:
            rightleg = node
            break
        nxt = read_mem_u64(reader, node)
        if not _valid_ptr(nxt) or nxt == node:
            break
        node = nxt
    if not rightleg:
        return

    want = (-0.5, -1.0, -0.5)
    for i in range(8, 0x100, 8):
        if i == assetid:
            continue
        cached = read_mem_u64(reader, rightleg + i)
        if not _valid_ptr(cached):
            continue
        sub = reader.try_read(cached, 0x100)
        if not sub:
            continue
        for j in range(8, 0x100, 8):
            fmd = struct.unpack_from("<Q", sub, j)[0]
            if not _valid_ptr(fmd):
                continue
            blob = reader.try_read(fmd, 0x300)
            if not blob:
                continue
            hits = _scan_block_candidates(blob, "v3", want, 0.01, 4)
            if hits:
                store_offset(store, "LRUNode", "CachedItem", i)
                store_offset(store, "CachedItem", "FileMeshData", j)
                store_offset(store, "FileMeshData", "AABBMin", hits[0])
                store_offset(store, "FileMeshData", "AABBMax", hits[0] + 12)
                fmd_ptr = fmd
                break
        if "CachedItem" in store.get("LRUNode", {}):
            break
    else:
        return
    if "CachedItem" not in store.get("LRUNode", {}):
        return

    verts = faces = 0
    for i in range(0, 0x100, 8):
        a = read_mem_u64(reader, fmd_ptr + i)
        b = read_mem_u64(reader, fmd_ptr + i + 8)
        if _valid_ptr(a) and _valid_ptr(b) and (b - a) == 0x690:
            verts = i
            break
    if not verts:
        return
    for i in range(verts + 0x10, 0x100, 8):
        a = read_mem_u64(reader, fmd_ptr + i)
        b = read_mem_u64(reader, fmd_ptr + i + 8)
        if _valid_ptr(a) and _valid_ptr(b) and (b - a) == 0x210:
            faces = i
            break
    if not faces:
        return
    store_offset(store, "FileMeshData", "Vertices", verts)
    store_offset(store, "FileMeshData", "VerticesEnd", verts + 8)
    store_offset(store, "FileMeshData", "Faces", faces)
    store_offset(store, "FileMeshData", "FacesEnd", faces + 8)
    store_offset(store, "MeshData", "VertexStart", verts)
    store_offset(store, "MeshData", "VertexEnd", verts + 8)
    store_offset(store, "MeshData", "FaceStart", faces)
    store_offset(store, "MeshData", "FaceEnd", faces + 8)
