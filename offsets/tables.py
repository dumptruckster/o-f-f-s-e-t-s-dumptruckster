import struct

TARGET = "Raycast"
FN_OFFS = (0x80, 0x78, 0x88, 0x70, 0x90, 0x68, 0x98)


FIELD_OFFSETS = {
    "ContextPtr": 0x08,
    "RenderQueueId": 0x10,
    "AlphaByte": 0x14,
    "MaterialPtr": 0x20,
    "DecalMaterialPtr": 0x48,
    "TechniqueArrayPtr": 0x70,
    "PrimitiveIndexArrayPtr": 0x80,
    "BBoxMinX": 0x98,
    "BBoxMinY": 0x9C,
    "BBoxMinZ": 0xA0,
    "BBoxMaxX": 0xA4,
    "BBoxMaxY": 0xA8,
    "BBoxMaxZ": 0xAC,
}
FASTCLUSTER_BINDING = {"Owner": 0x60}

ATTRIBUTE_LAYOUT = {
    "Key":   0x0,
    "Size":  0x58,
    "Value": 0x8,
}

ATTRIBUTES_MAP = {
    "Attributes": 0x10,
    "Length":     0x0,
}

TECHNIQUE_ARRAY = {"BeginOffset": 0x00, "EndOffset": 0x08, "EntryStride": 136}
MATERIAL_LAYER = {
    "Stride": 136,
    "FillModeByte": 0x11,
    "MatFlags": 0x18,
    "Param": 0x1C,
    "Flags2": 0x20,
    "ColorData": 0x24,
}

TYPE_PREFIX = b".?AVFastClusterEntity@"
COL_TYPE_DESCRIPTOR_RVA = 0x0C
COL_CLASS_DESCRIPTOR_RVA = 0x10
TYPE_DESCRIPTOR_NAME_OFFSET = 0x10

image_bytes = b""
image_base = 0


def fmt_hex(ea):
    offset = ea - image_base
    if 0 <= offset <= len(image_bytes) - 8:
        return struct.unpack_from("<Q", image_bytes, offset)[0]
    return 0


def fmt_cstr(ea, n=96):
    if not ea:
        return ""
    offset = ea - image_base
    if 0 <= offset < len(image_bytes):
        limit = min(n, len(image_bytes) - offset)
        chunk = image_bytes[offset : offset + limit]
        zero_idx = chunk.find(b"\x00")
        if zero_idx != -1:
            chunk = chunk[:zero_idx]
        if all(32 <= c < 127 for c in chunk):
            try:
                return chunk.decode('ascii')
            except Exception:
                pass
    return ""


def find_all(haystack, needle, start=0, end=None):
    if end is None:
        end = len(haystack)
    pos = haystack.find(needle, start, end)
    while pos != -1:
        yield pos
        pos = haystack.find(needle, pos + 1, end)


_MAX_OFFSET = 0x1000


STATIC_OFFSETS = {
    ("Instance",): {
        "AttributeContainer": 0x40,
        "AttributeList":      0x10,
        "AttributeToNext":    0x58,
        "AttributeToValue":   0x18,
        "ClassDescriptor":    0x18,
        "Name":               0x8,
        "NameContainer":      0x70,
        "Parent":             0x68,
        "ChildrenStart":      0x78,
        "ChildrenEnd":        0x8,
        "ClassBase":          0x1b0,
        "ClassName":          0x8,
        "This":               0x8,
    },
    ("DataModel",): {
        "CreatorId":     0x178,
        "GameId":        0x180,
        "GameLoaded":    0x5d0,
        "JobId":         0x110,
        "PlaceId":       0x188,
        "PlaceVersion":  0x1a4,
        "PrimitiveCount":0x418,
        "ScriptContext": 0x440,
        "ServerIP":      0x5b8,
        "ToRenderView1": 0x1c0,
        "ToRenderView2": 0x8,
        "ToRenderView3": 0x28,
        "Workspace":     0x150,
    },
    ("Humanoid",): {
        "AutoJumpEnabled":       0x1c4,
        "AutoRotate":            0x1c5,
        "AutomaticScalingEnabled":0x1c6,
        "BreakJointsOnDeath":    0x1c7,
        "CameraOffset":          0x118,
        "DisplayDistanceType":   0x170,
        "DisplayName":           0xa8,
        "EvaluateStateMachine":  0x1c8,
        "FloorMaterial":         0x174,
        "Health":                0x180,
        "HealthDisplayDistance": 0x178,
        "HealthDisplayType":     0x17c,
        "HipHeight":             0x184,
        "HumanoidRootPart":      0x458,
        "HumanoidState":         0x8a0,
        "HumanoidStateID":       0x20,
        "IsWalking":             0xa1f,
        "Jump":                  0x1ca,
        "JumpHeight":            0x190,
        "JumpPower":             0x194,
        "MaxHealth":             0x198,
        "MaxSlopeAngle":         0x19c,
        "MoveDirection":         0x130,
        "MoveToPart":            0x108,
        "MoveToPoint":           0x154,
        "NameDisplayDistance":   0x1a0,
        "NameOcclusion":         0x1a4,
        "PlatformStand":         0x1cc,
        "RequiresNeck":          0x1cd,
        "RigType":               0x1b0,
        "SeatPart":              0xf8,
        "Sit":                   0x1cd,
        "TargetPoint":           0x13c,
        "UseJumpPower":          0x1d0,
        "WalkTimer":             0x0,
        "Walkspeed":             0x1c0,
        "WalkspeedCheck":        0x39c,
    },
    ("Player",): {
        "AccountAge":          0x34c,
        "CameraMode":          0x360,
        "DisplayName":         0x128,
        "HealthDisplayDistance":0x384,
        "LocalPlayer":         0x120,
        "LocaleId":            0x108,
        "MaxZoomDistance":     0x358,
        "MinZoomDistance":     0x35c,
        "ModelInstance":       0x288,
        "Mouse":               0x1208,
        "NameDisplayDistance": 0x394,
        "Team":                0x2c8,
        "TeamColor":           0x3a0,
        "UserId":              0xc0,
    },
    ("Camera",): {
        "CameraSubject":  0xb8,
        "CameraType":     0x128,
        "FieldOfView":    0x130,
        "ImagePlaneDepth":0x2c4,
        "Position":       0xec,
        "Rotation":       0xc8,
        "Viewport":       0x27c,
        "ViewportSize":   0x2bc,
    },
    ("Workspace",): {
        "CurrentCamera":       0x4a8,
        "DistributedGameTime": 0x4c8,
        "ReadOnlyGravity":     0x9b8,
        "World":               0x400,
    },
    ("World",): {
        "AirProperties":          0x240,
        "FallenPartsDestroyHeight":0x220,
        "Gravity":                0x22c,
        "Primitives":             0x2b0,
        "worldStepsPerSec":       0x748,
    },
    ("Primitive",): {
        "AssemblyAngularVelocity": 0xec,
        "AssemblyLinearVelocity":  0xe0,
        "Flags":                   0x1b6,
        "Material":                0x0,
        "Owner":                   0x210,
        "Position":                0xd4,
        "Rotation":                0xb0,
        "Size":                    0x1bc,
        "Validate":                0x6,
    },
    ("PrimitiveFlags",): {
        "Anchored":  0x2,
        "CanCollide":0x8,
        "CanQuery":  0x20,
        "CanTouch":  0x10,
    },
    ("BasePart",): {
        "CastShadow":  0x125,
        "ClusterNode": 0xe0,
        "Color3":      0x198,
        "Locked":      0x126,
        "Massless":    0x127,
        "Primitive":   0x178,
        "Reflectance": 0xfc,
        "Shape":       0x1a8,
        "Transparency":0x120,
    },
    ("Model",): {
        "PrimaryPart": 0x248,
        "Scale":       0x134,
    },
    ("RunService",): {
        "HeartbeatFPS":  0xc8,
        "HeartbeatTask": 0xe0,
    },
    ("RenderJob",): {
        "FakeDataModel": 0x38,
        "RealDataModel": 0x1f0,
        "RenderView":    0x1d8,
    },
    ("RenderView",): {
        "DeviceD3D11":   0x8,
        "LightingValid": 0x278,
        "SkyValid":      0x2dc,
        "VisualEngine":  0x18,
    },
    ("VisualEngine",): {
        "Dimensions":    0xb10,
        "FakeDataModel": 0xaf0,
        "RenderView":    0xc30,
        "ViewMatrix":    0x1b0,
    },
    ("TaskScheduler",): {
        "JobEnd":   0xd0,
        "JobName":  0x18,
        "JobStart": 0xc8,
        "MaxFPS":   0xb0,
    },
    ("Misc",): {
        "Adornee":    0xe0,
        "AnimationId":0xb0,
        "StringLength":0x10,
        "Value":      0xa8,
    },
    ("Script",): {
        "GUID": 0xc0,
        "Hash": 0x190,
    },
    ("LocalScript",): {
        "GUID": 0xc0,
        "Hash": 0x190,
    },
    ("ModuleScript",): {
        "Bytecode": 0x138,
        "GUID":     0xc0,
        "Hash":     0x350,
    },
    ("ByteCode",): {
        "Pointer": 0x10,
        "Size":    0x28,
    },
    ("FakeDataModel",): {
        "Pointer":       0x8bcfd50,
        "RealDataModel": 0x1f0,
    },
    ("FFlag",): {
        "RenderFastClusterOcclusionCulling": 0x862bc90,
    },
    ("GuiObject",): {
        "Position": 0x500,
        "Size":     0x520,
    },
    ("Reflection",): {
        "CreatorTable": 0x8b63c68,
        "EntryValue":   0x8,
        "NameTable":    0x50,
        "TableEmpty":   0x20,
        "TableEnd":     0x8,
        "TableStart":   0x0,
        "TableStride":  0x10,
    },
}


INSTANCE_NAMESPACE_ROUTES = {
    "NameContainer":   ("Instance", "NameContainer"),
    "Name":            ("Instance", "Name"),
    "ClassDescriptor": ("Instance", "ClassDescriptor"),
    "Parent":          ("Instance", "Parent"),
    "ChildrenStart":   ("Instance", "ChildrenStart"),
    "ChildrenEnd":     ("Instance", "ChildrenEnd"),
    "Workspace":       ("DataModel", "Workspace"),
    "GameLoaded":      ("DataModel", "GameLoaded"),
    "PlaceId":         ("DataModel", "PlaceId"),
    "Camera":          ("DataModel", "Camera"),
    "Gravity":         ("World", "Gravity"),
    "LocalPlayer":     ("Player", "LocalPlayer"),
    "UserId":          ("Player", "UserId"),
    "ModelInstance":   ("Player", "ModelInstance"),
    "Health":          ("Humanoid", "Health"),
    "JumpPower":       ("Humanoid", "JumpPower"),
    "MaxHealth":       ("Humanoid", "MaxHealth"),
    "JumpHeight":      ("Humanoid", "JumpHeight"),
    "HipHeight":       ("Humanoid", "HipHeight"),
    "HumanoidRootPart": ("Humanoid", "HumanoidRootPart"),
    "WalkSpeedA":      ("Humanoid", "Walkspeed"),
    "WalkSpeedB":      ("Humanoid", "WalkspeedCheck"),
    "FOV":             ("Camera", "FieldOfView"),
}

LUAU_PROTO_KEYS = {"Proto_memcat", "Proto_code", "Proto_p", "Proto_k",
                   "Proto_lineinfo", "Proto_locvars", "Proto_upvalues",
                   "Proto_debuginsn"}

LUAU_MISC_KEYS = {"Print", "ScriptContextResume", "GetProperty", "NewInstance",
                  "lua_pushstring", "lua_setfield", "Bytecode_xref"}

SERVICE_SCAN_FUNCTIONS_NAMES = (
    "dump_workspace_instances",
    "dump_parts_offsets",
    "dump_players_offsets",
    "dump_camera_offsets",
    "dump_mouse_offsets",
    "dump_ui_offsets",
    "dump_animation_offsets",
    "dump_scripts_offsets",
    "dump_interactables_offsets",
    "dump_mesh_content_provider",
)


def save_offsets(local_map, namespace, fields):
    local_map.setdefault(namespace, {}).update(fields)


FAKE_DATA_MODEL_POINTER_RVA = 0x8bcfd50
FAKE_DATA_MODEL_OFFSET = 0x1f8
