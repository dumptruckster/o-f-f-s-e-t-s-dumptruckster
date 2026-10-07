#pragma once
/* 8====================================================D
/*            niggaware! (by fylux22!!!!!!)
/* 8====================================================D
/*  Dumped With     : niggaware! (by fylux22!!!!!!)
/*  Roblox Version  : version-cec3ad5889b447cf
/*  Time Taken      : 43618 ms
/*  Total Offsets   : 196
/* 8====================================================D
*/

#include <cstdint>
#include <string>

namespace Offsets {
    inline std::string ClientVersion = "version-cec3ad5889b447cf";

    namespace BasePart {
         inline constexpr uintptr_t CastShadow   = 0x125;
         inline constexpr uintptr_t Color3       = 0x198;
         inline constexpr uintptr_t Locked       = 0x126;
         inline constexpr uintptr_t Massless     = 0x127;
         inline constexpr uintptr_t Primitive    = 0x178;
         inline constexpr uintptr_t Reflectance  = 0xfc;
         inline constexpr uintptr_t Shape        = 0x1a8;
         inline constexpr uintptr_t Transparency = 0x120;
    }

    namespace ByteCode {
         inline constexpr uintptr_t Pointer = 0x10;
         inline constexpr uintptr_t Size    = 0x28;
    }

    namespace Camera {
         inline constexpr uintptr_t CameraSubject   = 0xb8;
         inline constexpr uintptr_t CameraType      = 0x128;
         inline constexpr uintptr_t FieldOfView     = 0x130;
         inline constexpr uintptr_t ImagePlaneDepth = 0x2c4;
         inline constexpr uintptr_t Position        = 0xec;
         inline constexpr uintptr_t Rotation        = 0xc8;
         inline constexpr uintptr_t Viewport        = 0x27c;
         inline constexpr uintptr_t ViewportSize    = 0x2bc;
    }

    namespace DataModel {
         inline constexpr uintptr_t CreatorId      = 0x178;
         inline constexpr uintptr_t GameId         = 0x180;
         inline constexpr uintptr_t GameLoaded     = 0x5d0;
         inline constexpr uintptr_t JobId          = 0x110;
         inline constexpr uintptr_t PlaceId        = 0x188;
         inline constexpr uintptr_t PlaceVersion   = 0x1a4;
         inline constexpr uintptr_t PrimitiveCount = 0x418;
         inline constexpr uintptr_t ScriptContext  = 0x440;
         inline constexpr uintptr_t ServerIP       = 0x5b8;
         inline constexpr uintptr_t ToRenderView1  = 0x1c0;
         inline constexpr uintptr_t ToRenderView2  = 0x8;
         inline constexpr uintptr_t ToRenderView3  = 0x28;
         inline constexpr uintptr_t Workspace      = 0x150;
    }

    namespace DeviceD3D11 {
         inline constexpr uintptr_t VTableRva = 0x6d03498;
    }

    namespace FastClusterEntity {
         inline constexpr uintptr_t AlphaByte              = 0x14;
         inline constexpr uintptr_t BBoxMaxX               = 0xa4;
         inline constexpr uintptr_t BBoxMaxY               = 0xa8;
         inline constexpr uintptr_t BBoxMaxZ               = 0xac;
         inline constexpr uintptr_t BBoxMinX               = 0x98;
         inline constexpr uintptr_t BBoxMinY               = 0x9c;
         inline constexpr uintptr_t BBoxMinZ               = 0xa0;
         inline constexpr uintptr_t ContextPtr             = 0x8;
         inline constexpr uintptr_t DecalMaterialPtr       = 0x48;
         inline constexpr uintptr_t MaterialPtr            = 0x20;
         inline constexpr uintptr_t PrimitiveIndexArrayPtr = 0x80;
         inline constexpr uintptr_t RenderQueueId          = 0x10;
         inline constexpr uintptr_t TechniqueArrayPtr      = 0x70;
         inline constexpr uintptr_t VTableRva              = 0x6d70ce8;
    }

    namespace GeometryD3D11 {
         inline constexpr uintptr_t VTableRva = 0x6d03990;
    }

    namespace Humanoid {
         inline constexpr uintptr_t AutoJumpEnabled         = 0x1c4;
         inline constexpr uintptr_t AutomaticScalingEnabled = 0x1c6;
         inline constexpr uintptr_t AutoRotate              = 0x1c5;
         inline constexpr uintptr_t BreakJointsOnDeath      = 0x1c7;
         inline constexpr uintptr_t CameraOffset            = 0x118;
         inline constexpr uintptr_t DisplayDistanceType     = 0x170;
         inline constexpr uintptr_t DisplayName             = 0xa8;
         inline constexpr uintptr_t EvaluateStateMachine    = 0x1c8;
         inline constexpr uintptr_t FloorMaterial           = 0x174;
         inline constexpr uintptr_t Health                  = 0x180;
         inline constexpr uintptr_t HealthDisplayDistance   = 0x178;
         inline constexpr uintptr_t HealthDisplayType       = 0x17c;
         inline constexpr uintptr_t HipHeight               = 0x184;
         inline constexpr uintptr_t HumanoidRootPart        = 0x458;
         inline constexpr uintptr_t HumanoidState           = 0x8a0;
         inline constexpr uintptr_t HumanoidStateID         = 0x20;
         inline constexpr uintptr_t IsWalking               = 0xa1f;
         inline constexpr uintptr_t Jump                    = 0x1ca;
         inline constexpr uintptr_t JumpHeight              = 0x190;
         inline constexpr uintptr_t JumpPower               = 0x194;
         inline constexpr uintptr_t MaxHealth               = 0x198;
         inline constexpr uintptr_t MaxSlopeAngle           = 0x19c;
         inline constexpr uintptr_t MoveDirection           = 0x130;
         inline constexpr uintptr_t MoveToPart              = 0x108;
         inline constexpr uintptr_t MoveToPoint             = 0x154;
         inline constexpr uintptr_t NameDisplayDistance     = 0x1a0;
         inline constexpr uintptr_t NameOcclusion           = 0x1a4;
         inline constexpr uintptr_t PlatformStand           = 0x1cc;
         inline constexpr uintptr_t RequiresNeck            = 0x1cd;
         inline constexpr uintptr_t RigType                 = 0x1b0;
         inline constexpr uintptr_t SeatPart                = 0xf8;
         inline constexpr uintptr_t Sit                     = 0x1cd;
         inline constexpr uintptr_t TargetPoint             = 0x13c;
         inline constexpr uintptr_t UseJumpPower            = 0x1d0;
         inline constexpr uintptr_t Walkspeed               = 0x1c0;
         inline constexpr uintptr_t WalkspeedCheck          = 0x39c;
         inline constexpr uintptr_t WalkTimer               = 0x0;
    }

    namespace Instance {
         inline constexpr uintptr_t ChildrenEnd     = 0x8;
         inline constexpr uintptr_t ChildrenStart   = 0x78;
         inline constexpr uintptr_t ClassBase       = 0x1b0;
         inline constexpr uintptr_t ClassDescriptor = 0x18;
         inline constexpr uintptr_t ClassName       = 0x8;
         inline constexpr uintptr_t Name            = 0x8;
         inline constexpr uintptr_t NameContainer   = 0x70;
         inline constexpr uintptr_t Parent          = 0x68;
         inline constexpr uintptr_t This            = 0x8;
    }

    namespace LocalScript {
         inline constexpr uintptr_t GUID = 0xc0;
         inline constexpr uintptr_t Hash = 0x190;
    }

    namespace MaterialLayer {
         inline constexpr uintptr_t ColorData    = 0x24;
         inline constexpr uintptr_t FillModeByte = 0x11;
         inline constexpr uintptr_t Flags2       = 0x20;
         inline constexpr uintptr_t MatFlags     = 0x18;
         inline constexpr uintptr_t Param        = 0x1c;
         inline constexpr uintptr_t Stride       = 0x88;
    }

    namespace Misc {
         inline constexpr uintptr_t Adornee      = 0xe0;
         inline constexpr uintptr_t AnimationId  = 0xb0;
         inline constexpr uintptr_t StringLength = 0x10;
         inline constexpr uintptr_t Value        = 0xa8;
    }

    namespace Model {
         inline constexpr uintptr_t PrimaryPart = 0x248;
         inline constexpr uintptr_t Scale       = 0x134;
    }

    namespace ModuleScript {
         inline constexpr uintptr_t GUID = 0xc0;
         inline constexpr uintptr_t Hash = 0x350;
    }

    namespace Player {
         inline constexpr uintptr_t AccountAge            = 0x34c;
         inline constexpr uintptr_t CameraMode            = 0x360;
         inline constexpr uintptr_t DisplayName           = 0x128;
         inline constexpr uintptr_t HealthDisplayDistance = 0x384;
         inline constexpr uintptr_t LocaleId              = 0x108;
         inline constexpr uintptr_t LocalPlayer           = 0x120;
         inline constexpr uintptr_t MaxZoomDistance       = 0x358;
         inline constexpr uintptr_t MinZoomDistance       = 0x35c;
         inline constexpr uintptr_t ModelInstance         = 0x288;
         inline constexpr uintptr_t Mouse                 = 0x1208;
         inline constexpr uintptr_t NameDisplayDistance   = 0x394;
         inline constexpr uintptr_t Team                  = 0x2c8;
         inline constexpr uintptr_t TeamColor             = 0x3a0;
         inline constexpr uintptr_t UserId                = 0xc0;
    }

    namespace Primitive {
         inline constexpr uintptr_t AssemblyAngularVelocity = 0xec;
         inline constexpr uintptr_t AssemblyLinearVelocity  = 0xe0;
         inline constexpr uintptr_t Flags                   = 0x1b6;
         inline constexpr uintptr_t Material                = 0x0;
         inline constexpr uintptr_t Owner                   = 0x210;
         inline constexpr uintptr_t Position                = 0xd4;
         inline constexpr uintptr_t Rotation                = 0xb0;
         inline constexpr uintptr_t Size                    = 0x1bc;
         inline constexpr uintptr_t Validate                = 0x6;
    }

    namespace PrimitiveFlags {
         inline constexpr uintptr_t Anchored   = 0x2;
         inline constexpr uintptr_t CanCollide = 0x8;
         inline constexpr uintptr_t CanQuery   = 0x20;
         inline constexpr uintptr_t CanTouch   = 0x10;
    }

    namespace RemoteEvent {
         inline constexpr uintptr_t BaseVTableRva     = 0x6d60a08;
         inline constexpr uintptr_t HookSlotCount     = 0x7;
         inline constexpr uintptr_t InstanceVTableRva = 0x6cebaa0;
         inline constexpr uintptr_t SignalFire        = 0x3521790;
         inline constexpr uintptr_t SignalFireSlot    = 0x2;
         inline constexpr uintptr_t VTableRva         = 0x6d66648;
         inline constexpr uintptr_t VTableSlots       = 0x4f;
         namespace Fire {
              inline constexpr uintptr_t FireAllClients     = 0x3449c8a;
              inline constexpr uintptr_t FireAllClientsB    = 0x344a28a;
              inline constexpr uintptr_t FireAllClientsPrep = 0x1270;
              inline constexpr uintptr_t FireClient         = 0x3449a81;
              inline constexpr uintptr_t FireClientB        = 0x344a081;
              inline constexpr uintptr_t FireClientPrep     = 0x7053e0;
              inline constexpr uintptr_t FireServer         = 0x344984c;
              inline constexpr uintptr_t FireServerB        = 0x3449e4c;
              inline constexpr uintptr_t FireServerPrep     = 0x7053e0;
         }
    }

    namespace RenderJob {
         inline constexpr uintptr_t FakeDataModel = 0x38;
         inline constexpr uintptr_t RealDataModel = 0x1f0;
         inline constexpr uintptr_t RenderView    = 0x1e0;
    }

    namespace RenderView {
         inline constexpr uintptr_t DeviceD3D11   = 0x8;
         inline constexpr uintptr_t LightingValid = 0x278;
         inline constexpr uintptr_t SkyValid      = 0x2dc;
         inline constexpr uintptr_t VisualEngine  = 0x18;
         inline constexpr uintptr_t VTableRva     = 0x6d6c5a8;
    }

    namespace RunService {
         inline constexpr uintptr_t HeartbeatFPS  = 0xc8;
         inline constexpr uintptr_t HeartbeatTask = 0xe0;
    }

    namespace Script {
         inline constexpr uintptr_t GUID = 0xc0;
         inline constexpr uintptr_t Hash = 0x190;
    }

    namespace ShaderManager {
         inline constexpr uintptr_t VTableRva = 0x6d6e3f8;
    }

    namespace Sky {
         inline constexpr uintptr_t CubeTextures  = 0x2df74c2;
         inline constexpr uintptr_t DrawCubeCallA = 0x3748299;
         inline constexpr uintptr_t DrawCubeCallB = 0x3748350;
         inline constexpr uintptr_t DrawSkyEnv    = 0x3748299;
         inline constexpr uintptr_t DrawSkyPixel  = 0x3748350;
         inline constexpr uintptr_t DrawStars     = 0x37497c0;
         inline constexpr uintptr_t DrawSun       = 0x3748ef4;
    }

    namespace TaskScheduler {
         inline constexpr uintptr_t JobEnd   = 0xd0;
         inline constexpr uintptr_t JobName  = 0x18;
         inline constexpr uintptr_t JobStart = 0xc8;
         inline constexpr uintptr_t MaxFPS   = 0xb0;
    }

    namespace TechniqueArray {
         inline constexpr uintptr_t BeginOffset = 0x0;
         inline constexpr uintptr_t EndOffset   = 0x8;
         inline constexpr uintptr_t EntryStride = 0x88;
    }

    namespace TextureManager2 {
         inline constexpr uintptr_t VTableRva = 0x6d6d4b0;
    }

    namespace ViewBase {
         inline constexpr uintptr_t VTableRva = 0x6d6c840;
    }

    namespace VisualEngine {
         inline constexpr uintptr_t Dimensions    = 0xb10;
         inline constexpr uintptr_t FakeDataModel = 0xaf0;
         inline constexpr uintptr_t RenderView    = 0xc30;
         inline constexpr uintptr_t ViewMatrix    = 0x1b0;
    }

    namespace Workspace {
         inline constexpr uintptr_t CurrentCamera       = 0x4a8;
         inline constexpr uintptr_t DistributedGameTime = 0x4c8;
         inline constexpr uintptr_t ReadOnlyGravity     = 0x9b8;
         inline constexpr uintptr_t World               = 0x400;
    }

    namespace World {
         inline constexpr uintptr_t AirProperties            = 0x240;
         inline constexpr uintptr_t FallenPartsDestroyHeight = 0x220;
         inline constexpr uintptr_t Gravity                  = 0x22c;
         inline constexpr uintptr_t Primitives               = 0x2b0;
         inline constexpr uintptr_t worldStepsPerSec         = 0x748;
    }

    namespace WorldRoot {
         inline constexpr uintptr_t RaycastBoundDesc = 0x8364bb0;
         inline constexpr uintptr_t RaycastBoundFn   = 0x90;
    }

}
