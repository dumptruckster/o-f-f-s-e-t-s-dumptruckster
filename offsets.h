#pragma once
/* 8====================================================D
/*            fylux22
/* 8====================================================D
/*  Dumped With     : fylux22
/*  Roblox Version  : version-7a0c6d10fcb34a2c
/*  Time Taken      : 69356 ms
/*  Total Offsets   : 558
/* 8====================================================D
*/

#include <cstdint>
#include <string>

namespace Offsets {
    inline std::string ClientVersion = "version-7a0c6d10fcb34a2c";

    namespace AirProperties {
         inline constexpr uintptr_t AirDensity = 0x18;
         inline constexpr uintptr_t GlobalWind = 0x3c;
    }

    namespace Atmosphere {
         inline constexpr uintptr_t Color   = 0xa8;
         inline constexpr uintptr_t Decay   = 0xb4;
         inline constexpr uintptr_t Density = 0xc0;
         inline constexpr uintptr_t Glare   = 0xc4;
         inline constexpr uintptr_t Haze    = 0xc8;
         inline constexpr uintptr_t Offset  = 0xcc;
    }

    namespace Attribute {
         inline constexpr uintptr_t TypeIdRva    = 0x8cb18ac;
         inline constexpr uintptr_t TypeIdRvaNew = 0x8cb18b4;
    }

    namespace BasePart {
         inline constexpr uintptr_t CastShadow   = 0x128;
         inline constexpr uintptr_t Color3       = 0x1ac;
         inline constexpr uintptr_t Locked       = 0x129;
         inline constexpr uintptr_t Massless     = 0x70;
         inline constexpr uintptr_t Primitive    = 0x188;
         inline constexpr uintptr_t Reflectance  = 0xfc;
         inline constexpr uintptr_t Shape        = 0x1a8;
         inline constexpr uintptr_t Transparency = 0x120;
    }

    namespace Beam {
         inline constexpr uintptr_t Attachment0    = 0x150;
         inline constexpr uintptr_t Attachment1    = 0x160;
         inline constexpr uintptr_t Brightness     = 0x170;
         inline constexpr uintptr_t CurveSize0     = 0x174;
         inline constexpr uintptr_t CurveSize1     = 0x178;
         inline constexpr uintptr_t LightEmission  = 0x17c;
         inline constexpr uintptr_t LightInfluence = 0x180;
         inline constexpr uintptr_t Texture        = 0x130;
         inline constexpr uintptr_t TextureLength  = 0x18c;
         inline constexpr uintptr_t TextureSpeed   = 0x194;
         inline constexpr uintptr_t Width0         = 0x198;
         inline constexpr uintptr_t Width1         = 0x19c;
         inline constexpr uintptr_t ZOffset        = 0x1a0;
    }

    namespace BloomEffect {
         inline constexpr uintptr_t Enabled   = 0xa0;
         inline constexpr uintptr_t Intensity = 0xa8;
         inline constexpr uintptr_t Size      = 0xac;
         inline constexpr uintptr_t Threshold = 0xb0;
    }

    namespace BlurEffect {
         inline constexpr uintptr_t Enabled = 0xa0;
         inline constexpr uintptr_t Size    = 0xa8;
    }

    namespace ByteCode {
         inline constexpr uintptr_t Pointer = 0x10;
         inline constexpr uintptr_t Size    = 0x28;
    }

    namespace CachedItem {
         inline constexpr uintptr_t FileMeshData = 0x28;
    }

    namespace Camera {
         inline constexpr uintptr_t CameraSubject   = 0xb8;
         inline constexpr uintptr_t CameraType      = 0x128;
         inline constexpr uintptr_t FieldOfView     = 0x130;
         inline constexpr uintptr_t ImagePlaneDepth = 0x2d4;
         inline constexpr uintptr_t Position        = 0xec;
         inline constexpr uintptr_t Rotation        = 0xc8;
         inline constexpr uintptr_t Viewport        = 0x28c;
         inline constexpr uintptr_t ViewportSize    = 0x2cc;
    }

    namespace CharacterMesh {
         inline constexpr uintptr_t BaseTextureId    = 0xb8;
         inline constexpr uintptr_t BodyPart         = 0x138;
         inline constexpr uintptr_t MeshId           = 0xe8;
         inline constexpr uintptr_t OverlayTextureId = 0x118;
    }

    namespace ClickDetector {
         inline constexpr uintptr_t MaxActivationDistance = 0xd8;
         inline constexpr uintptr_t MouseIcon             = 0xb8;
    }

    namespace Clothing {
         inline constexpr uintptr_t Color3   = 0x110;
         inline constexpr uintptr_t Template = 0xf0;
    }

    namespace ColorCorrectionEffect {
         inline constexpr uintptr_t Brightness = 0xb4;
         inline constexpr uintptr_t Contrast   = 0xb8;
         inline constexpr uintptr_t Enabled    = 0xa0;
         inline constexpr uintptr_t TintColor  = 0xa8;
    }

    namespace ColorGradingEffect {
         inline constexpr uintptr_t Enabled          = 0xa0;
         inline constexpr uintptr_t TonemapperPreset = 0xa8;
    }

    namespace DataModel {
         inline constexpr uintptr_t Camera         = 0x4a8;
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

    namespace DepthOfFieldEffect {
         inline constexpr uintptr_t Enabled       = 0xa0;
         inline constexpr uintptr_t FarIntensity  = 0xa8;
         inline constexpr uintptr_t FocusDistance = 0xac;
         inline constexpr uintptr_t InFocusRadius = 0xb0;
         inline constexpr uintptr_t NearIntensity = 0xb4;
    }

    namespace DeviceD3D11 {
         inline constexpr uintptr_t Context      = 0x180;
         inline constexpr uintptr_t ContextObj   = 0x1b0;
         inline constexpr uintptr_t ContextPtr   = 0x180;
         inline constexpr uintptr_t DevicePtr    = 0x178;
         inline constexpr uintptr_t SwapChainPtr = 0x80;
         inline constexpr uintptr_t VTableRva    = 0x6ebe108;
    }

    namespace DragDetector {
         inline constexpr uintptr_t ActivatedCursorIcon   = 0x1b0;
         inline constexpr uintptr_t CursorIcon            = 0xb8;
         inline constexpr uintptr_t MaxActivationDistance = 0xd8;
         inline constexpr uintptr_t MaxDragAngle          = 0x298;
         inline constexpr uintptr_t MaxDragTranslation    = 0x25c;
         inline constexpr uintptr_t MaxForce              = 0x29c;
         inline constexpr uintptr_t MaxTorque             = 0x2a0;
         inline constexpr uintptr_t MinDragAngle          = 0x2a4;
         inline constexpr uintptr_t MinDragTranslation    = 0x268;
         inline constexpr uintptr_t ReferenceInstance     = 0x1e0;
         inline constexpr uintptr_t Responsiveness        = 0x2b0;
    }

    namespace FakeDataModel {
         inline constexpr uintptr_t RealDataModel = 0x1f0;
    }

    namespace FastCluster {
         inline constexpr uintptr_t VTableRva    = 0x6f288a8;
         inline constexpr uintptr_t VTableRvaSub = 0x6f288c8;
    }

    namespace FastClusterBinding {
         inline constexpr uintptr_t VTableRva = 0x6f2a018;
    }

    namespace FastClusterEntity {
         inline constexpr uintptr_t ContextPtr        = 0x8;
         inline constexpr uintptr_t TechniqueArrayPtr = 0x70;
         inline constexpr uintptr_t VTableRva         = 0x6f2a0f0;
    }

    namespace FFlag {
         inline constexpr uintptr_t RenderFastClusterOcclusionCulling = 0x8886310;
    }

    namespace FileMeshData {
         inline constexpr uintptr_t AABBMax = 0x18c;
         inline constexpr uintptr_t AABBMin = 0x180;
    }

    namespace FLog {
         inline constexpr uintptr_t BooleanType = 0x6fc42d8;
    }

    namespace GeometryD3D11 {
         inline constexpr uintptr_t VTableRva = 0x6ebe5e8;
    }

    namespace GuiBase2D {
         inline constexpr uintptr_t AbsolutePosition = 0xfc;
         inline constexpr uintptr_t AbsoluteRotation = 0xd8;
         inline constexpr uintptr_t AbsoluteSize     = 0x104;
    }

    namespace GuiObject {
         inline constexpr uintptr_t BackgroundColor3       = 0x530;
         inline constexpr uintptr_t BackgroundTransparency = 0x53c;
         inline constexpr uintptr_t BorderColor3           = 0x53c;
         inline constexpr uintptr_t Image                  = 0x9a8;
         inline constexpr uintptr_t LayoutOrder            = 0x56c;
         inline constexpr uintptr_t RichText               = 0xba0;
         inline constexpr uintptr_t Rotation               = 0xd8;
         inline constexpr uintptr_t ScreenGui_Enabled      = 0x310;
         inline constexpr uintptr_t Text                   = 0xba0;
         inline constexpr uintptr_t TextColor3             = 0xeb8;
         inline constexpr uintptr_t Visible                = 0x59d;
         inline constexpr uintptr_t ZIndex                 = 0x594;
    }

    namespace Humanoid {
         inline constexpr uintptr_t CameraOffset          = 0x118;
         inline constexpr uintptr_t DisplayDistanceType   = 0x17c;
         inline constexpr uintptr_t DisplayName           = 0xa8;
         inline constexpr uintptr_t Health                = 0x18c;
         inline constexpr uintptr_t HealthDisplayDistance = 0x184;
         inline constexpr uintptr_t HealthDisplayType     = 0x188;
         inline constexpr uintptr_t HipHeight             = 0x190;
         inline constexpr uintptr_t HumanoidRootPart      = 0x468;
         inline constexpr uintptr_t Jump                  = 0x17c;
         inline constexpr uintptr_t JumpHeight            = 0x19c;
         inline constexpr uintptr_t JumpPower             = 0x1a0;
         inline constexpr uintptr_t MaxHealth             = 0x1a4;
         inline constexpr uintptr_t MaxSlopeAngle         = 0x1a8;
         inline constexpr uintptr_t MoveDirection         = 0x13c;
         inline constexpr uintptr_t NameDisplayDistance   = 0x1ac;
         inline constexpr uintptr_t NameOcclusion         = 0x1b0;
         inline constexpr uintptr_t PlatformStand         = 0x1b0;
         inline constexpr uintptr_t RigType               = 0x1bc;
         inline constexpr uintptr_t SeatPart              = 0xf8;
         inline constexpr uintptr_t Sit                   = 0x1da;
         inline constexpr uintptr_t Walkspeed             = 0x1cc;
    }

    namespace Instance {
         inline constexpr uintptr_t ChildrenEnd     = 0x8;
         inline constexpr uintptr_t ChildrenStart   = 0x78;
         inline constexpr uintptr_t ClassDescriptor = 0x18;
         inline constexpr uintptr_t ClassName       = 0x8;
         inline constexpr uintptr_t Name            = 0x8;
         inline constexpr uintptr_t NameContainer   = 0x70;
         inline constexpr uintptr_t Parent          = 0x68;
         inline constexpr uintptr_t This            = 0x8;
         namespace Function {
              inline constexpr uintptr_t GetAttribute = 0xd581a0;
              inline constexpr uintptr_t Index        = 0x412a0b0;
              inline constexpr uintptr_t New          = 0x42c92e1;
         }
    }

    namespace Lighting {
         inline constexpr uintptr_t Ambient                  = 0xc0;
         inline constexpr uintptr_t Brightness               = 0x108;
         inline constexpr uintptr_t ClockTime                = 0xb8;
         inline constexpr uintptr_t ColorShift_Bottom        = 0xd8;
         inline constexpr uintptr_t ColorShift_Top           = 0xcc;
         inline constexpr uintptr_t EnvironmentDiffuseScale  = 0x10c;
         inline constexpr uintptr_t EnvironmentSpecularScale = 0x110;
         inline constexpr uintptr_t ExposureCompensation     = 0x114;
         inline constexpr uintptr_t FogColor                 = 0xe4;
         inline constexpr uintptr_t FogEnd                   = 0x11c;
         inline constexpr uintptr_t FogStart                 = 0x120;
         inline constexpr uintptr_t GeographicLatitude       = 0x124;
         inline constexpr uintptr_t GlobalShadows            = 0x134;
         inline constexpr uintptr_t GradientBottom           = 0x180;
         inline constexpr uintptr_t GradientTop              = 0x140;
         inline constexpr uintptr_t LightColor               = 0x14c;
         inline constexpr uintptr_t LightDirection           = 0x158;
         inline constexpr uintptr_t MoonPosition             = 0x174;
         inline constexpr uintptr_t OutdoorAmbient           = 0xf0;
         inline constexpr uintptr_t Sky                      = 0x1b8;
    }

    namespace LocalScript {
         inline constexpr uintptr_t GUID = 0xc0;
         inline constexpr uintptr_t Hash = 0x190;
    }

    namespace LRUHolder {
         inline constexpr uintptr_t MemEnforcedLRUCache = 0x20;
    }

    namespace LRUNode {
         inline constexpr uintptr_t AssetID    = 0x10;
         inline constexpr uintptr_t CachedItem = 0x38;
         inline constexpr uintptr_t Next       = 0x0;
    }

    namespace Luau {
         inline constexpr uintptr_t GetGlobalState   = 0x41ab690;
         inline constexpr uintptr_t lua_checkstack   = 0x350c710;
         inline constexpr uintptr_t lua_error        = 0x261bea0;
         inline constexpr uintptr_t lua_newstate     = 0x261f920;
         inline constexpr uintptr_t lua_pushfstring  = 0x26195d0;
         inline constexpr uintptr_t luaC_step        = 0x2642b60;
         inline constexpr uintptr_t luaD_Throw       = 0x262c620;
         inline constexpr uintptr_t luaF_freeproto   = 0x2657c20;
         inline constexpr uintptr_t luaO_pushfstring = 0x26195d0;
         inline constexpr uintptr_t LuaVMLoad        = 0xa41a00;
         inline constexpr uintptr_t pseudo2addr      = 0x2617fe0;
         inline constexpr uintptr_t PushInstance     = 0x491b7f0;
         namespace Base {
              inline constexpr uintptr_t assert       = 0x26814b0;
              inline constexpr uintptr_t error        = 0x2679f90;
              inline constexpr uintptr_t gcinfo       = 0x267fdf0;
              inline constexpr uintptr_t getfenv      = 0x267b540;
              inline constexpr uintptr_t getmetatable = 0x267a9d0;
              inline constexpr uintptr_t newproxy     = 0x26823d0;
              inline constexpr uintptr_t next         = 0x2680a00;
              inline constexpr uintptr_t print        = 0x2679b30;
              inline constexpr uintptr_t rawequal     = 0x267b830;
              inline constexpr uintptr_t rawget       = 0x267b940;
              inline constexpr uintptr_t rawlen       = 0x267fd50;
              inline constexpr uintptr_t rawset       = 0x267c7b0;
              inline constexpr uintptr_t select       = 0x2681560;
              inline constexpr uintptr_t setfenv      = 0x267b600;
              inline constexpr uintptr_t setmetatable = 0x267ab60;
              inline constexpr uintptr_t tonumber     = 0x2679c00;
              inline constexpr uintptr_t tostring     = 0x2682370;
              inline constexpr uintptr_t type         = 0x267fe10;
              inline constexpr uintptr_t typeof       = 0x2680410;
         }

         namespace bit32 {
              inline constexpr uintptr_t add        = 0x58e35e0;
              inline constexpr uintptr_t arshift    = 0x58e4bb0;
              inline constexpr uintptr_t band       = 0x58e3ea0;
              inline constexpr uintptr_t bnot       = 0x58e40a0;
              inline constexpr uintptr_t bor        = 0x58e3fa0;
              inline constexpr uintptr_t bswap      = 0x58e53b0;
              inline constexpr uintptr_t btest      = 0x58e51e0;
              inline constexpr uintptr_t bxor       = 0x58e40f0;
              inline constexpr uintptr_t clamp      = 0x58e5100;
              inline constexpr uintptr_t countlz    = 0x58e5340;
              inline constexpr uintptr_t countrz    = 0x58e52e0;
              inline constexpr uintptr_t create     = 0x58e3140;
              inline constexpr uintptr_t div        = 0x58e3760;
              inline constexpr uintptr_t extract    = 0x58e4db0;
              inline constexpr uintptr_t fromstring = 0x58e3250;
              inline constexpr uintptr_t ge         = 0x58e4740;
              inline constexpr uintptr_t gt         = 0x58e4630;
              inline constexpr uintptr_t idiv       = 0x58e3840;
              inline constexpr uintptr_t le         = 0x58e4300;
              inline constexpr uintptr_t lrotate    = 0x58e4c90;
              inline constexpr uintptr_t lshift     = 0x58e4a70;
              inline constexpr uintptr_t lt         = 0x58e41f0;
              inline constexpr uintptr_t max        = 0x58e3d60;
              inline constexpr uintptr_t min        = 0x58e3c20;
              inline constexpr uintptr_t mod        = 0x58e39f0;
              inline constexpr uintptr_t mul        = 0x58e36e0;
              inline constexpr uintptr_t neg        = 0x58e3590;
              inline constexpr uintptr_t rem        = 0x58e3930;
              inline constexpr uintptr_t replace    = 0x58e4f30;
              inline constexpr uintptr_t rrotate    = 0x58e4d20;
              inline constexpr uintptr_t rshift     = 0x58e4b10;
              inline constexpr uintptr_t sub        = 0x58e3660;
              inline constexpr uintptr_t tonumber   = 0x58e34e0;
              inline constexpr uintptr_t udiv       = 0x58e3ae0;
              inline constexpr uintptr_t uge        = 0x58e4960;
              inline constexpr uintptr_t ugt        = 0x58e4850;
              inline constexpr uintptr_t ule        = 0x58e4520;
              inline constexpr uintptr_t ult        = 0x58e4410;
              inline constexpr uintptr_t urem       = 0x58e3b80;
         }

         namespace buffer {
              inline constexpr uintptr_t copy         = 0x58fe3f0;
              inline constexpr uintptr_t create       = 0x58fd070;
              inline constexpr uintptr_t fill         = 0x58fe6e0;
              inline constexpr uintptr_t fromstring   = 0x58fd120;
              inline constexpr uintptr_t len          = 0x58fe340;
              inline constexpr uintptr_t readbits     = 0x58fe930;
              inline constexpr uintptr_t readf32      = 0x58ff6f0;
              inline constexpr uintptr_t readf64      = 0x58ff860;
              inline constexpr uintptr_t readi16      = 0x58ff170;
              inline constexpr uintptr_t readi32      = 0x58ff430;
              inline constexpr uintptr_t readi8       = 0x58feeb0;
              inline constexpr uintptr_t readinteger  = 0x58fd770;
              inline constexpr uintptr_t readstring   = 0x58fd9c0;
              inline constexpr uintptr_t readu16      = 0x58ff2d0;
              inline constexpr uintptr_t readu32      = 0x58ff590;
              inline constexpr uintptr_t readu8       = 0x58ff010;
              inline constexpr uintptr_t tostring     = 0x58fd1f0;
              inline constexpr uintptr_t writebits    = 0x58feb70;
              inline constexpr uintptr_t writef32     = 0x58ffe40;
              inline constexpr uintptr_t writef64     = 0x58fffd0;
              inline constexpr uintptr_t writei16     = 0x58ffb40;
              inline constexpr uintptr_t writei32     = 0x58ffcc0;
              inline constexpr uintptr_t writei8      = 0x58ff9c0;
              inline constexpr uintptr_t writeinteger = 0x58fd880;
              inline constexpr uintptr_t writestring  = 0x58fe0a0;
              inline constexpr uintptr_t writeu16     = 0x58ffb40;
              inline constexpr uintptr_t writeu32     = 0x58ffcc0;
              inline constexpr uintptr_t writeu8      = 0x58ff9c0;
         }

         namespace Coroutine {
              inline constexpr uintptr_t CoroutineCreate      = 0x5903580;
              inline constexpr uintptr_t CoroutineIsYieldable = 0x5903e80;
              inline constexpr uintptr_t CoroutineRunning     = 0x5903e10;
              inline constexpr uintptr_t CoroutineStatus      = 0x5901b10;
              inline constexpr uintptr_t CoroutineWrap        = 0x5903b40;
              inline constexpr uintptr_t CoroutineYield       = 0x5903db0;
         }

         namespace global_State {
              inline constexpr uintptr_t g_gcstepmul = 0x30;
         }

         namespace lua_State {
              inline constexpr uintptr_t L_global_offset = 0x50;
         }

         namespace Proto {
              inline constexpr uintptr_t code      = 0x28;
              inline constexpr uintptr_t debuginsn = 0x30;
              inline constexpr uintptr_t k         = 0x20;
              inline constexpr uintptr_t lineinfo  = 0x70;
              inline constexpr uintptr_t memcat    = 0x1;
              inline constexpr uintptr_t p         = 0x18;
         }

         namespace string {
              inline constexpr uintptr_t byte     = 0x58eb580;
              inline constexpr uintptr_t char     = 0x58eb810;
              inline constexpr uintptr_t find     = 0x58ed440;
              inline constexpr uintptr_t format   = 0x58ef7d0;
              inline constexpr uintptr_t gmatch   = 0x58ed830;
              inline constexpr uintptr_t gsub     = 0x58eee00;
              inline constexpr uintptr_t len      = 0x58ea090;
              inline constexpr uintptr_t lower    = 0x58eacf0;
              inline constexpr uintptr_t match    = 0x58ed450;
              inline constexpr uintptr_t pack     = 0x58f2f40;
              inline constexpr uintptr_t packsize = 0x58f38a0;
              inline constexpr uintptr_t rep      = 0x58eaf90;
              inline constexpr uintptr_t reverse  = 0x58eaba0;
              inline constexpr uintptr_t split    = 0x58efe00;
              inline constexpr uintptr_t sub      = 0x58ea140;
              inline constexpr uintptr_t unpack   = 0x58f3c10;
              inline constexpr uintptr_t upper    = 0x58eae40;
         }

         namespace table {
              inline constexpr uintptr_t clear    = 0x2692740;
              inline constexpr uintptr_t clone    = 0x26929e0;
              inline constexpr uintptr_t concat   = 0x268f540;
              inline constexpr uintptr_t create   = 0x26918b0;
              inline constexpr uintptr_t find     = 0x2692080;
              inline constexpr uintptr_t foreach  = 0x268a4e0;
              inline constexpr uintptr_t foreachi = 0x2689780;
              inline constexpr uintptr_t freeze   = 0x2692790;
              inline constexpr uintptr_t getn     = 0x268b900;
              inline constexpr uintptr_t insert   = 0x268cae0;
              inline constexpr uintptr_t isfrozen = 0x2692910;
              inline constexpr uintptr_t maxn     = 0x268b640;
              inline constexpr uintptr_t move     = 0x268d050;
              inline constexpr uintptr_t pack     = 0x268f860;
              inline constexpr uintptr_t remove   = 0x268cce0;
              inline constexpr uintptr_t sort     = 0x2691730;
              inline constexpr uintptr_t unpack   = 0x26900b0;
         }

         namespace utf8 {
              inline constexpr uintptr_t char      = 0x58e63d0;
              inline constexpr uintptr_t codepoint = 0x58e6030;
              inline constexpr uintptr_t codes     = 0x58e70b0;
              inline constexpr uintptr_t len       = 0x58e5d50;
              inline constexpr uintptr_t offset    = 0x58e6b60;
         }
    }

    namespace MaterialColors {
         inline constexpr uintptr_t Asphalt     = 0x30;
         inline constexpr uintptr_t Basalt      = 0x27;
         inline constexpr uintptr_t Brick       = 0xf;
         inline constexpr uintptr_t Cobblestone = 0x33;
         inline constexpr uintptr_t Concrete    = 0xc;
         inline constexpr uintptr_t CrackedLava = 0x2d;
         inline constexpr uintptr_t Glacier     = 0x1b;
         inline constexpr uintptr_t Grass       = 0x6;
         inline constexpr uintptr_t Ground      = 0x2a;
         inline constexpr uintptr_t Ice         = 0x36;
         inline constexpr uintptr_t LeafyGrass  = 0x39;
         inline constexpr uintptr_t Limestone   = 0x3f;
         inline constexpr uintptr_t Mud         = 0x24;
         inline constexpr uintptr_t Pavement    = 0x42;
         inline constexpr uintptr_t Rock        = 0x18;
         inline constexpr uintptr_t Salt        = 0x3c;
         inline constexpr uintptr_t Sand        = 0x12;
         inline constexpr uintptr_t Sandstone   = 0x21;
         inline constexpr uintptr_t Slate       = 0x9;
         inline constexpr uintptr_t Snow        = 0x1e;
         inline constexpr uintptr_t WoodPlanks  = 0x15;
    }

    namespace MemEnforcedLRUCache {
         inline constexpr uintptr_t Head = 0x8;
    }

    namespace MeshContentProvider {
         inline constexpr uintptr_t LRUHolder = 0xc8;
    }

    namespace MeshPart {
         inline constexpr uintptr_t MeshId   = 0x300;
         inline constexpr uintptr_t MeshSize = 0x218;
         inline constexpr uintptr_t Texture  = 0x330;
    }

    namespace Misc {
         inline constexpr uintptr_t AnimationId  = 0xb0;
         inline constexpr uintptr_t GetProperty  = 0x49ddd53;
         inline constexpr uintptr_t Print        = 0x1ce4150;
         inline constexpr uintptr_t StringLength = 0x10;
    }

    namespace Model {
         inline constexpr uintptr_t PrimaryPart = 0x248;
         inline constexpr uintptr_t Scale       = 0x134;
    }

    namespace ModuleScript {
         inline constexpr uintptr_t GUID = 0xc0;
         inline constexpr uintptr_t Hash = 0xa50;
    }

    namespace MouseService {
         inline constexpr uintptr_t InputObject   = 0xe0;
         inline constexpr uintptr_t InputObject2  = 0xf0;
         inline constexpr uintptr_t MousePosition = 0xc4;
    }

    namespace ParticleEmitter {
         inline constexpr uintptr_t Acceleration        = 0x1d0;
         inline constexpr uintptr_t Brightness          = 0x20c;
         inline constexpr uintptr_t Drag                = 0x210;
         inline constexpr uintptr_t Lifetime            = 0x1e4;
         inline constexpr uintptr_t LightEmission       = 0x228;
         inline constexpr uintptr_t LightInfluence      = 0x22c;
         inline constexpr uintptr_t Rate                = 0x238;
         inline constexpr uintptr_t Rotation            = 0x1f4;
         inline constexpr uintptr_t RotSpeed            = 0x1ec;
         inline constexpr uintptr_t Speed               = 0x1fc;
         inline constexpr uintptr_t SpreadAngle         = 0x204;
         inline constexpr uintptr_t Texture             = 0x1b0;
         inline constexpr uintptr_t TimeScale           = 0x24c;
         inline constexpr uintptr_t VelocityInheritance = 0x250;
         inline constexpr uintptr_t ZOffset             = 0x254;
    }

    namespace Player {
         inline constexpr uintptr_t AccountAge            = 0x35c;
         inline constexpr uintptr_t CameraMode            = 0x370;
         inline constexpr uintptr_t DisplayName           = 0x128;
         inline constexpr uintptr_t HealthDisplayDistance = 0x394;
         inline constexpr uintptr_t LocaleId              = 0x108;
         inline constexpr uintptr_t MaxZoomDistance       = 0x368;
         inline constexpr uintptr_t MinZoomDistance       = 0x36c;
         inline constexpr uintptr_t ModelInstance         = 0x298;
         inline constexpr uintptr_t NameDisplayDistance   = 0x3a4;
         inline constexpr uintptr_t Team                  = 0x2d8;
         inline constexpr uintptr_t TeamColor             = 0x3b0;
         inline constexpr uintptr_t UserId                = 0xc0;
    }

    namespace Primitive {
         inline constexpr uintptr_t Owner    = 0x10;
         inline constexpr uintptr_t Position = 0xac;
         inline constexpr uintptr_t Rotation = 0x88;
         inline constexpr uintptr_t Validate = 0x6;
    }

    namespace PrimitiveFlags {
         inline constexpr uintptr_t Anchored   = 0x2;
         inline constexpr uintptr_t CanCollide = 0x8;
         inline constexpr uintptr_t CanQuery   = 0x20;
         inline constexpr uintptr_t CanTouch   = 0x10;
    }

    namespace Property {
         inline constexpr uintptr_t GetPropertyData = 0x7c5d5f;
    }

    namespace ProximityPrompt {
         inline constexpr uintptr_t ActionText            = 0xa0;
         inline constexpr uintptr_t Enabled               = 0x126;
         inline constexpr uintptr_t GamepadKeyCode        = 0x10c;
         inline constexpr uintptr_t HoldDuration          = 0x110;
         inline constexpr uintptr_t KeyCode               = 0x114;
         inline constexpr uintptr_t MaxActivationDistance = 0x118;
         inline constexpr uintptr_t ObjectText            = 0xc0;
         inline constexpr uintptr_t RequiresLineOfSight   = 0x127;
    }

    namespace RakNet {
         inline constexpr uintptr_t ConvertItemEnumToString = 0x4818858;
         inline constexpr uintptr_t Encrypt                 = 0x288384c;
         inline constexpr uintptr_t PeerReceive             = 0x28519b0;
         inline constexpr uintptr_t ProcessNetworkPacket    = 0x28667a0;
         inline constexpr uintptr_t ReportNetworkError      = 0x3587c20;
         inline constexpr uintptr_t Send                    = 0x285a3d0;
         inline constexpr uintptr_t UpdateLoop              = 0x157d720;
         inline constexpr uintptr_t VirtualTable            = 0x6ebec40;
    }

    namespace Reflection {
         inline constexpr uintptr_t NameRegistry = 0x84f9bc0;
         inline constexpr uintptr_t NameTable    = 0x48;
         inline constexpr uintptr_t TableEnd     = 0x8;
         inline constexpr uintptr_t TableStart   = 0x0;
         inline constexpr uintptr_t TableStride  = 0x10;
    }

    namespace RenderJob {
         inline constexpr uintptr_t FakeDataModel = 0x38;
         inline constexpr uintptr_t RealDataModel = 0x1f0;
         inline constexpr uintptr_t RenderView    = 0x1e0;
    }

    namespace RenderView {
         inline constexpr uintptr_t DeviceD3D11   = 0x8;
         inline constexpr uintptr_t LightingValid = 0x33c;
         inline constexpr uintptr_t SkyValid      = 0x2dc;
         inline constexpr uintptr_t VisualEngine  = 0x18;
         inline constexpr uintptr_t VTableRva     = 0x6f25be0;
    }

    namespace RunService {
         inline constexpr uintptr_t HeartbeatTask = 0xe0;
    }

    namespace Script {
         inline constexpr uintptr_t GUID = 0xc0;
         inline constexpr uintptr_t Hash = 0x190;
    }

    namespace Seat {
         inline constexpr uintptr_t Occupant = 0x208;
    }

    namespace ShaderManager {
         inline constexpr uintptr_t VTableRva = 0x6f27708;
    }

    namespace Sky {
         inline constexpr uintptr_t CubeTextures      = 0x374bcf0;
         inline constexpr uintptr_t DrawCubeCallA     = 0x374fe89;
         inline constexpr uintptr_t DrawCubeCallB     = 0x374ff49;
         inline constexpr uintptr_t DrawSkyEnv        = 0x374fe89;
         inline constexpr uintptr_t DrawSkyPixel      = 0x374ff49;
         inline constexpr uintptr_t DrawStars         = 0x37512ff;
         inline constexpr uintptr_t DrawSun           = 0x3750a74;
         inline constexpr uintptr_t MoonAngularSize   = 0x234;
         inline constexpr uintptr_t MoonTextureId     = 0xb8;
         inline constexpr uintptr_t SkyboxBk          = 0xe8;
         inline constexpr uintptr_t SkyboxDn          = 0x118;
         inline constexpr uintptr_t SkyboxFt          = 0x148;
         inline constexpr uintptr_t SkyboxLf          = 0x178;
         inline constexpr uintptr_t SkyboxOrientation = 0x228;
         inline constexpr uintptr_t SkyboxRt          = 0x1a8;
         inline constexpr uintptr_t SkyboxUp          = 0x1d8;
         inline constexpr uintptr_t SkyGroup          = 0x374afea;
         inline constexpr uintptr_t StarCount         = 0x238;
         inline constexpr uintptr_t SunAngularSize    = 0x22c;
         inline constexpr uintptr_t SunTextureId      = 0x208;
    }

    namespace Sound {
         inline constexpr uintptr_t IsPlaying          = 0xb8;
         inline constexpr uintptr_t Looped             = 0x12d;
         inline constexpr uintptr_t PlaybackSpeed      = 0x10c;
         inline constexpr uintptr_t RollOffMaxDistance = 0x110;
         inline constexpr uintptr_t RollOffMinDistance = 0x114;
         inline constexpr uintptr_t SoundGroup         = 0xd8;
         inline constexpr uintptr_t SoundId            = 0xb8;
         inline constexpr uintptr_t Volume             = 0x120;
    }

    namespace SpawnLocation {
         inline constexpr uintptr_t AllowTeamChangeOnTouch = 0x38;
         inline constexpr uintptr_t Enabled                = 0x1e1;
         inline constexpr uintptr_t ForcefieldDuration     = 0x1d8;
         inline constexpr uintptr_t Neutral                = 0x9e;
         inline constexpr uintptr_t TeamColor              = 0x1dc;
    }

    namespace SpecialMesh {
         inline constexpr uintptr_t MeshId = 0xe8;
         inline constexpr uintptr_t Scale  = 0xb4;
    }

    namespace StatsItem {
         inline constexpr uintptr_t Value = 0x190;
    }

    namespace SunRaysEffect {
         inline constexpr uintptr_t Enabled   = 0xa0;
         inline constexpr uintptr_t Intensity = 0xa8;
         inline constexpr uintptr_t Spread    = 0xac;
    }

    namespace SurfaceAppearance {
         inline constexpr uintptr_t AlphaMode           = 0x1e0;
         inline constexpr uintptr_t Color               = 0x1c8;
         inline constexpr uintptr_t ColorMap            = 0xb8;
         inline constexpr uintptr_t EmissiveMaskContent = 0xe8;
         inline constexpr uintptr_t EmissiveStrength    = 0x1e4;
         inline constexpr uintptr_t EmissiveTint        = 0x1d4;
         inline constexpr uintptr_t MetalnessMap        = 0x118;
         inline constexpr uintptr_t NormalMap           = 0x148;
         inline constexpr uintptr_t RoughnessMap        = 0x178;
    }

    namespace Task {
         inline constexpr uintptr_t TaskDefer  = 0x82ca60;
         inline constexpr uintptr_t TaskDelay  = 0x4322fb0;
         inline constexpr uintptr_t TaskDesync = 0x4321bde;
         inline constexpr uintptr_t TaskSpawn  = 0x4322c10;
         inline constexpr uintptr_t TaskSync   = 0x432176b;
         inline constexpr uintptr_t TaskWait   = 0x4323435;
    }

    namespace TaskScheduler {
         inline constexpr uintptr_t JobEnd    = 0xd0;
         inline constexpr uintptr_t JobName   = 0x18;
         inline constexpr uintptr_t JobStart  = 0xc8;
         inline constexpr uintptr_t MaxFPS    = 0xb0;
         inline constexpr uintptr_t Pointer   = 0x8d6f048;
         inline constexpr uintptr_t TargetFPS = 0x85da990;
    }

    namespace Team {
         inline constexpr uintptr_t BrickColor = 0xa8;
    }

    namespace TechniqueArray {
         inline constexpr uintptr_t BeginOffset = 0x0;
         inline constexpr uintptr_t EndOffset   = 0x8;
         inline constexpr uintptr_t EntryStride = 0x88;
    }

    namespace Terrain {
         inline constexpr uintptr_t GrassLength       = 0x1e0;
         inline constexpr uintptr_t MaterialColors    = 0x4a8;
         inline constexpr uintptr_t WaterColor        = 0x1d0;
         inline constexpr uintptr_t WaterReflectance  = 0x1e8;
         inline constexpr uintptr_t WaterTransparency = 0x1ec;
         inline constexpr uintptr_t WaterWaveSize     = 0x1f0;
         inline constexpr uintptr_t WaterWaveSpeed    = 0x1f4;
    }

    namespace TextLabel {
         inline constexpr uintptr_t ContentText         = 0xe08;
         inline constexpr uintptr_t LocalizedText       = 0xba0;
         inline constexpr uintptr_t MaxVisibleGraphemes = 0xa8;
         inline constexpr uintptr_t RichText            = 0x56c;
         inline constexpr uintptr_t Text                = 0xba0;
         inline constexpr uintptr_t TextColor3          = 0xeb8;
         inline constexpr uintptr_t TextSize            = 0xd74;
    }

    namespace TextureManager2 {
         inline constexpr uintptr_t VTableRva = 0x6f26aa0;
    }

    namespace Textures {
         inline constexpr uintptr_t Decal_Texture   = 0x1d0;
         inline constexpr uintptr_t Texture_Texture = 0x1d0;
    }

    namespace Tool {
         inline constexpr uintptr_t CanBeDropped         = 0x4a8;
         inline constexpr uintptr_t Enabled              = 0x1c8;
         inline constexpr uintptr_t Grip                 = 0x49c;
         inline constexpr uintptr_t ManualActivationOnly = 0x4aa;
         inline constexpr uintptr_t RequiresHandle       = 0x10;
         inline constexpr uintptr_t TextureId            = 0x350;
         inline constexpr uintptr_t Tooltip              = 0x458;
    }

    namespace UnionOperation {
         inline constexpr uintptr_t AssetId = 0x300;
    }

    namespace UserInputService {
         inline constexpr uintptr_t WindowInputState = 0x2b0;
    }

    namespace VehicleSeat {
         inline constexpr uintptr_t MaxSpeed      = 0x218;
         inline constexpr uintptr_t SteerFloat    = 0x21c;
         inline constexpr uintptr_t ThrottleFloat = 0x220;
         inline constexpr uintptr_t Torque        = 0x224;
         inline constexpr uintptr_t TurnSpeed     = 0x228;
    }

    namespace ViewBase {
         inline constexpr uintptr_t VTableRva = 0x6f25e30;
    }

    namespace VisualEngine {
         inline constexpr uintptr_t Dimensions = 0xb10;
         inline constexpr uintptr_t Pointer    = 0x884a0b0;
         inline constexpr uintptr_t RenderView = 0xc38;
         inline constexpr uintptr_t ViewMatrix = 0x1b0;
    }

    namespace Weld {
         inline constexpr uintptr_t Part0 = 0x108;
         inline constexpr uintptr_t Part1 = 0x118;
    }

    namespace WeldConstraint {
         inline constexpr uintptr_t Part0 = 0xa8;
         inline constexpr uintptr_t Part1 = 0xb8;
    }

    namespace WindowInputState {
         inline constexpr uintptr_t CapsLock       = 0x40;
         inline constexpr uintptr_t CurrentTextBox = 0x48;
    }

    namespace Workspace {
         inline constexpr uintptr_t CurrentCamera       = 0x4a8;
         inline constexpr uintptr_t DistributedGameTime = 0x4c8;
         inline constexpr uintptr_t ReadOnlyGravity     = 0x9c8;
         inline constexpr uintptr_t World               = 0x400;
    }

    namespace World {
         inline constexpr uintptr_t AirProperties            = 0x238;
         inline constexpr uintptr_t FallenPartsDestroyHeight = 0x214;
         inline constexpr uintptr_t Gravity                  = 0x220;
         inline constexpr uintptr_t Primitives               = 0x2c8;
         inline constexpr uintptr_t worldStepsPerSec         = 0x880;
    }

    namespace WorldRoot {
         inline constexpr uintptr_t RaycastBoundDesc = 0x8555420;
         inline constexpr uintptr_t RaycastBoundFn   = 0x90;
    }

}
