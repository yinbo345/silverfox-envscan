// compute.cpp — GPU 加速内容扫描引擎：三档自适应 + 「特征地图」显存常驻
//
// 实测依据（本机 NVIDIA MX250 / i5-8265U，见 C:\temp\mem_probe.cpp / map_probe.cpp）：
//   显存内拷贝        23.59 GB/s（单向）   ← 比 DDR 快 6.3 倍
//   DDR memcpy 8 线程  3.72 GB/s（单向）
//   PCIe 上行（整块）  1.72 GB/s           ← 「把数据丢给 GPU」的硬天花板
//   PCIe 上行（64KB 分块）0.10 GB/s        ← 分块逐次上传是灾难，必须整批
//   PCIe 下行          2.52 GB/s
//   GPU 线性匹配 32 模式      51 MB/s
//   GPU 地图式 AC 自动机    1534 MB/s      ← 30 倍
//   CPU 单线程地图式          199 MB/s（原线性 4 MB/s，50 倍）
//   CPU 4 线程地图式          470 MB/s
//
// 结论：显存的优势只有让【不常变的大数据】常驻才拿得到 —— 那就是规则库编译出的地图
//       （35 条家族串 → 389 状态 → 0.38 MB）。文件数据只过一趟 PCIe 就能算完。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <dxgi1_3.h>
#include <d3d11.h>
#include <d3dcompiler.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "compute.h"
#include "common.h"
#include "matcher.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3dcompiler.lib")

namespace compute {

// ---------------------------------------------------------------------------
//  注册表开关（HKLM\SOFTWARE\SilverFoxGuard\gpu_scan，默认 0=关）
// ---------------------------------------------------------------------------
bool IsGpuEnabled() {
    HKEY hk;
    DWORD v = 0, sz = sizeof(v);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sf::CFG_ROOT, 0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "gpu_scan", nullptr, nullptr, (LPBYTE)&v, &sz) != ERROR_SUCCESS) v = 0;
        RegCloseKey(hk);
    }
    return v == 1;
}
bool SetGpuEnabled(bool on) {
    HKEY hk;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, sf::CFG_ROOT, 0, nullptr, 0, KEY_WRITE | KEY_WOW64_64KEY,
                        nullptr, &hk, nullptr) != ERROR_SUCCESS) return false;
    DWORD v = on ? 1 : 0;
    LONG r = RegSetValueExA(hk, "gpu_scan", 0, REG_DWORD, (LPBYTE)&v, sizeof(v));
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

const char* TierName(Tier t) {
    switch (t) {
        case Tier::Map:     return "地图常驻(map)";
        case Tier::Basic:   return "常规批量(basic)";
        default:            return "纯CPU(cpu)";
    }
}

// ---------------------------------------------------------------------------
//  HLSL 内核 A：常规线性匹配（档1 用；保留原实现）
// ---------------------------------------------------------------------------
static const char* kKernelLinear = R"CS(
StructuredBuffer<uint> gIn     : register(t0);
StructuredBuffer<uint> gRange  : register(t1);
RWStructuredBuffer<uint> gOut  : register(u0);
cbuffer Cb : register(b0) { uint gFileCount; uint gPad0; uint gPad1; uint gPad2; }

uint GetByte(uint p) { return (gIn[p >> 2] >> ((p & 3u) * 8u)) & 255u; }

bool MatchAt(uint base, uint len) {
    if (len >= 5 && GetByte(base+0)==83 && GetByte(base+1)==70 && GetByte(base+2)==117 && GetByte(base+3)==99 && GetByte(base+4)==107) return true;
    if (len >= 8 && GetByte(base+0)==113 && GetByte(base+1)==81 && GetByte(base+2)==57 && GetByte(base+3)==57 && GetByte(base+4)==54 && GetByte(base+5)==53 && GetByte(base+6)==52 && GetByte(base+7)==53) return true;
    if (len >= 5 && GetByte(base+0)==87 && GetByte(base+1)==105 && GetByte(base+2)==110 && GetByte(base+3)==48 && GetByte(base+4)==115) return true;
    if (len >= 5 && GetByte(base+0)==71 && GetByte(base+1)==104 && GetByte(base+2)==48 && GetByte(base+3)==115 && GetByte(base+4)==116) return true;
    if (len >= 5 && GetByte(base+0)==119 && GetByte(base+1)==105 && GetByte(base+2)==110 && GetByte(base+3)==111 && GetByte(base+4)==115) return true;
    return false;
}

[numthreads(256, 1, 1)]
void CSMain(uint3 tid : SV_DispatchThreadID) {
    uint fileIdx = tid.x / 256;
    uint lane    = tid.x % 256;
    if (fileIdx >= gFileCount) return;
    uint ofs  = gRange[fileIdx * 2 + 0];
    uint len  = gRange[fileIdx * 2 + 1];
    if (len == 0) return;
    uint part = (len + 255) / 256;
    uint beg  = lane * part;
    uint end  = min((lane + 1) * part, len);
    for (uint pos = beg; pos < end; ++pos) {
        if (MatchAt(ofs + pos, len - pos)) { InterlockedOr(gOut[fileIdx], 1u); break; }
    }
}
)CS";

// ---------------------------------------------------------------------------
//  HLSL 内核 B：地图式匹配（档2 用）—— 每字节在状态图上走一步
//  gTable[state * 256 + byte] = nextState；gTerm[state] != 0 表示命中。
//  段尾多扫 (gMaxLen-1) 字节，避免跨段边界的模式被漏掉。
// ---------------------------------------------------------------------------
static const char* kKernelMap = R"CS(
StructuredBuffer<uint> gIn    : register(t0);
StructuredBuffer<uint> gRange : register(t1);
StructuredBuffer<uint> gTable : register(t2);
StructuredBuffer<uint> gTerm  : register(t3);
RWStructuredBuffer<uint> gOut : register(u0);
cbuffer Cb : register(b0) { uint gFileCount; uint gMaxLen; uint gPad0; uint gPad1; }

uint GetByte(uint p) { return (gIn[p >> 2] >> ((p & 3u) * 8u)) & 255u; }

[numthreads(256, 1, 1)]
void CSMain(uint3 tid : SV_DispatchThreadID) {
    uint fileIdx = tid.x / 256;
    uint lane    = tid.x % 256;
    if (fileIdx >= gFileCount) return;
    uint ofs = gRange[fileIdx * 2 + 0];
    uint len = gRange[fileIdx * 2 + 1];
    if (len == 0) return;
    uint part = (len + 255) / 256;
    uint beg  = lane * part;
    uint end  = min((lane + 1) * part, len);
    uint end2 = min(end + (gMaxLen > 0u ? gMaxLen - 1u : 0u), len);
    uint st = 0;
    for (uint pos = beg; pos < end2; ++pos) {
        st = gTable[st * 256u + GetByte(ofs + pos)];
        if (gTerm[st]) { InterlockedOr(gOut[fileIdx], 1u); return; }
    }
}
)CS";

// 每文件读前缀字节数：C2 握手/RC4 密钥都位于 PE 头部区，64KB 覆盖足够
static constexpr uint32_t kProbeBytes = 65536;
// 单批上限（输入缓冲 16MB）—— 档2（PCIe 宽裕）用满批
static constexpr size_t   kBatchMaxFiles = 16u * 1024 * 1024 / kProbeBytes;
// 档1（PCIe 一般 / 显存紧张）：单批 4MB，显存占用降为 1/4
static constexpr size_t   kBatchMaxFilesSlim = 4u * 1024 * 1024 / kProbeBytes;

// ---------------------------------------------------------------------------
//  ⚠️ GPU 崩溃熔断（2026-09-18 新增）
//
//  实测真因：NVIDIA 用户态驱动 nvwgf2umx.dll v32.0.15.8266 在 compute dispatch
//  路径上存在**确定性崩溃**（0xC0000005 @ 偏移 0xeead00），跨两个构建签名完全一致。
//  该崩溃可能发生在驱动的延迟提交/工作线程里，SEH 抓不住 → std::terminate()
//  → 进程静默死亡（WIN32_EXIT_CODE: 0，日志"干净地断掉"）→ SCM 按 sc failure
//  策略 60 秒后重启 → 启动自检又跑到同一处 → 又崩，形成无限循环。
//
//  同时实测确认 GPU 路径**无收益**：同一机器三轮探测 ratio = 1.08 / 0.75 / 0.38
//  剧烈抖动，CPU 实测 463/716/1424 MB/s 而 GPU e2e 稳定在 ~500 MB/s。
//
//  所以策略不是"修好 GPU"，而是【让它失败得可控】：
//    · 连续 kGpuFailThreshold 次失败 → 永久熔断（本进程内不再尝试 GPU）
//    · 熔断是进程级静态量，服务重启会重置 —— 但如果崩溃真的发生，进程本来就死了，
//      重启后重试一次也是合理的（区别于"每轮都重试"的旧行为）
// ---------------------------------------------------------------------------
static std::atomic<int>  g_gpuFailStreak{ 0 };
static std::atomic<bool> g_gpuTripped{ false };      // true = 已熔断
static const int         kGpuFailThreshold = 2;      // 连续失败 2 次即熔断

static void GpuMarkFailure(const char* why);
// GpuTripped 是 compute.h 导出的公开接口（service.cpp 的 gpuprog 要读），
// 定义处**不能加 static**，否则只有内部链接、服务侧链接不到（LNK2019）。
bool GpuTripped();

// ---------------------------------------------------------------------------
//  D3D11 引擎（惰性初始化 + 互斥保护；线程安全）
// ---------------------------------------------------------------------------
struct GpuDevice {
    ID3D11Device*        dev = nullptr;
    ID3D11DeviceContext* ctx = nullptr;
    ID3D11ComputeShader* csLinear = nullptr;    // 档1
    ID3D11ComputeShader* csMap    = nullptr;    // 档2

    // 批量扫描缓冲（两档共用）
    ID3D11Buffer* inBuf = nullptr;
    ID3D11Buffer* rangeBuf = nullptr;
    ID3D11Buffer* outBuf = nullptr;
    ID3D11Buffer* staging = nullptr;
    ID3D11Buffer* cbuf = nullptr;
    ID3D11ShaderResourceView* inSRV = nullptr;
    ID3D11ShaderResourceView* rangeSRV = nullptr;
    ID3D11UnorderedAccessView* outUAV = nullptr;
    size_t   inCapBytes = 0;
    uint32_t maxFiles = 0;

    // 「地图」—— 常驻显存的 AC 状态转移表
    ID3D11Buffer* mapTableBuf = nullptr;
    ID3D11Buffer* mapTermBuf = nullptr;
    ID3D11ShaderResourceView* mapTableSRV = nullptr;
    ID3D11ShaderResourceView* mapTermSRV = nullptr;
    uint32_t mapStates = 0;
    uint32_t mapMaxLen = 0;
    bool     mapLoaded = false;

    std::string gpuName;
    uint64_t    vramMB = 0;

    // adapter=nullptr 用系统默认；否则显式指定适配器。
    // 多显卡机器上必须显式选：服务进程（Session 0）常常拿到核显而不是独显。
    bool Init(IDXGIAdapter1* adapter = nullptr) {
        HRESULT hr;
        if (adapter) {
            // 显式传适配器时驱动类型必须是 D3D_DRIVER_TYPE_UNKNOWN（MSDN 规定）
            hr = D3D11CreateDevice(adapter, D3D_DRIVER_TYPE_UNKNOWN, nullptr, 0,
                                   nullptr, 0, D3D11_SDK_VERSION, &dev, nullptr, &ctx);
        } else {
            hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                                   nullptr, 0, D3D11_SDK_VERSION, &dev, nullptr, &ctx);
        }
        if (FAILED(hr)) {
            // 不回退 WARP：WARP 是 CPU 软件光栅化器，做字节匹配比直接走多线程 CPU 更慢，
            // 在无独显/驱动异常的低配机上「用 WARP 假装 GPU 加速」只会白吃 CPU。
            sf::LogDbg("[gpu] no hardware d3d11 device -> use CPU path (WARP skipped)");
            return false;
        }
        // 适配器信息（显存大小用于档位判定）
        IDXGIDevice* dxd = nullptr;
        if (SUCCEEDED(dev->QueryInterface(__uuidof(IDXGIDevice), (void**)&dxd)) && dxd) {
            IDXGIAdapter* ad = nullptr;
            if (SUCCEEDED(dxd->GetAdapter(&ad)) && ad) {
                DXGI_ADAPTER_DESC d{};
                ad->GetDesc(&d);
                char mb[256] = { 0 };
                WideCharToMultiByte(CP_UTF8, 0, d.Description, -1, mb, sizeof(mb) - 1, nullptr, nullptr);
                gpuName = mb;
                vramMB = (uint64_t)(d.DedicatedVideoMemory >> 20);
                ad->Release();
            }
            dxd->Release();
        }
        if (!Compile(kKernelLinear, &csLinear)) return false;
        if (!Compile(kKernelMap, &csMap)) return false;
        sf::LogDbg("[gpu] engine ready: " + gpuName + " vram=" + std::to_string(vramMB) + "MB");
        return true;
    }

    bool Compile(const char* src, ID3D11ComputeShader** out) {
        ID3DBlob* blob = nullptr; ID3DBlob* err = nullptr;
        HRESULT hr = D3DCompile(src, strlen(src), nullptr, nullptr, nullptr, "CSMain", "cs_5_0", 0, 0, &blob, &err);
        if (FAILED(hr)) {
            sf::LogDbg("[gpu] kernel compile failed");
            if (err) { sf::LogDbg("[gpu] " + std::string((const char*)err->GetBufferPointer(), err->GetBufferSize())); err->Release(); }
            return false;
        }
        hr = dev->CreateComputeShader(blob->GetBufferPointer(), blob->GetBufferSize(), nullptr, out);
        blob->Release();
        if (FAILED(hr)) { sf::LogDbg("[gpu] create shader failed"); return false; }
        return true;
    }

    bool EnsureCapacity(uint32_t fileCount) {
        size_t need = (size_t)fileCount * kProbeBytes;
        if (need > 16u * 1024 * 1024) fileCount = (uint32_t)kBatchMaxFiles;
        if (inBuf && (size_t)fileCount * kProbeBytes <= inCapBytes && maxFiles >= fileCount) return true;
        if (inBuf) CleanupBulk();      // 仅当已有旧缓冲（容量不足/参数变化）才释放重建
        inCapBytes = 0; maxFiles = 0;
        D3D11_BUFFER_DESC bd{};
        bd.ByteWidth = (UINT)((size_t)fileCount * kProbeBytes);
        bd.Usage = D3D11_USAGE_DEFAULT;
        bd.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        bd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
        bd.StructureByteStride = 4;
        bd.CPUAccessFlags = 0;
        if (FAILED(dev->CreateBuffer(&bd, nullptr, &inBuf))) { sf::LogDbg("[gpu] create inBuf fail"); CleanupBulk(); return false; }
        D3D11_SHADER_RESOURCE_VIEW_DESC srv{};
        srv.Format = DXGI_FORMAT_UNKNOWN;
        srv.ViewDimension = D3D11_SRV_DIMENSION_BUFFER;
        srv.Buffer.NumElements = (UINT)(((size_t)fileCount * kProbeBytes) / 4);
        if (FAILED(dev->CreateShaderResourceView(inBuf, &srv, &inSRV))) { sf::LogDbg("[gpu] create inSRV fail"); CleanupBulk(); return false; }
        bd.ByteWidth = fileCount * 2 * 4; bd.StructureByteStride = 4;
        bd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
        bd.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        if (FAILED(dev->CreateBuffer(&bd, nullptr, &rangeBuf))) { sf::LogDbg("[gpu] create rangeBuf fail"); CleanupBulk(); return false; }
        srv.Format = DXGI_FORMAT_UNKNOWN;
        srv.Buffer.NumElements = fileCount * 2;
        if (FAILED(dev->CreateShaderResourceView(rangeBuf, &srv, &rangeSRV))) { sf::LogDbg("[gpu] create rangeSRV fail"); CleanupBulk(); return false; }
        bd.ByteWidth = fileCount * 4; bd.BindFlags = D3D11_BIND_UNORDERED_ACCESS;
        bd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
        bd.StructureByteStride = 4;
        if (FAILED(dev->CreateBuffer(&bd, nullptr, &outBuf))) { sf::LogDbg("[gpu] create outBuf fail"); CleanupBulk(); return false; }
        D3D11_UNORDERED_ACCESS_VIEW_DESC uav{};
        uav.Format = DXGI_FORMAT_UNKNOWN;
        uav.ViewDimension = D3D11_UAV_DIMENSION_BUFFER;
        uav.Buffer.NumElements = fileCount;
        if (FAILED(dev->CreateUnorderedAccessView(outBuf, &uav, &outUAV))) { sf::LogDbg("[gpu] create outUAV fail"); CleanupBulk(); return false; }
        bd.ByteWidth = fileCount * 4; bd.Usage = D3D11_USAGE_STAGING; bd.BindFlags = 0;
        bd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        bd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
        bd.StructureByteStride = 4;
        if (FAILED(dev->CreateBuffer(&bd, nullptr, &staging))) { sf::LogDbg("[gpu] create staging fail"); CleanupBulk(); return false; }
        bd.ByteWidth = 16; bd.Usage = D3D11_USAGE_DEFAULT; bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        bd.CPUAccessFlags = 0;
        bd.MiscFlags = 0; bd.StructureByteStride = 0;
        if (FAILED(dev->CreateBuffer(&bd, nullptr, &cbuf))) { sf::LogDbg("[gpu] create cbuf fail"); CleanupBulk(); return false; }
        inCapBytes = (size_t)fileCount * kProbeBytes;
        maxFiles = fileCount;
        return true;
    }

    // ---- 地图上传：把 AC 状态转移表放进显存常驻 ----
    bool UploadMap(const sf::AcMatcher& ac) {
        UnloadMapBuffers();
        if (ac.empty()) { sf::LogDbg("[gpu] map upload skipped: empty pattern set"); return false; }
        D3D11_BUFFER_DESC bd{};
        bd.Usage = D3D11_USAGE_DEFAULT;
        bd.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        bd.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_STRUCTURED;
        bd.StructureByteStride = 4;
        bd.ByteWidth = (UINT)ac.table().size() * 4;
        if (bd.ByteWidth == 0) return false;
        if (FAILED(dev->CreateBuffer(&bd, nullptr, &mapTableBuf))) { sf::LogDbg("[gpu] create mapTable fail"); return false; }
        D3D11_SHADER_RESOURCE_VIEW_DESC srv{};
        srv.Format = DXGI_FORMAT_UNKNOWN;
        srv.ViewDimension = D3D11_SRV_DIMENSION_BUFFER;
        srv.Buffer.NumElements = (UINT)ac.table().size();
        if (FAILED(dev->CreateShaderResourceView(mapTableBuf, &srv, &mapTableSRV))) { sf::LogDbg("[gpu] create mapTableSRV fail"); return false; }
        bd.ByteWidth = (UINT)ac.term().size() * 4;
        if (FAILED(dev->CreateBuffer(&bd, nullptr, &mapTermBuf))) { sf::LogDbg("[gpu] create mapTerm fail"); return false; }
        srv.Buffer.NumElements = (UINT)ac.term().size();
        if (FAILED(dev->CreateShaderResourceView(mapTermBuf, &srv, &mapTermSRV))) { sf::LogDbg("[gpu] create mapTermSRV fail"); return false; }
        ctx->UpdateSubresource(mapTableBuf, 0, nullptr, ac.table().data(), 0, 0);
        ctx->UpdateSubresource(mapTermBuf, 0, nullptr, ac.term().data(), 0, 0);
        mapStates = (uint32_t)ac.stateCount();
        mapMaxLen = (uint32_t)ac.longestPattern();
        mapLoaded = true;
        return true;
    }

    void UnloadMapBuffers() {
        if (mapTableSRV) { mapTableSRV->Release(); mapTableSRV = nullptr; }
        if (mapTermSRV)  { mapTermSRV->Release();  mapTermSRV = nullptr; }
        if (mapTableBuf) { mapTableBuf->Release(); mapTableBuf = nullptr; }
        if (mapTermBuf)  { mapTermBuf->Release();  mapTermBuf = nullptr; }
        mapStates = 0; mapMaxLen = 0; mapLoaded = false;
    }

    // 纯 C 函数：绑定 + dispatch + copy + map 读回（成员指针以参数传入）。
    // 函数体内无 C++ 对象（全部 COM/裸指针 + memcpy），才允许用 __try 捕获
    // 个别驱动/虚拟化环境的 compute 崩溃（0xC0000005），保证服务进程不倒下。
    // 返回：0=成功 1=GPU 执行崩溃（调用方回退 CPU） 2=读回失败
    static int GpuRunCore(ID3D11DeviceContext* ctx, ID3D11ComputeShader* cs,
                          ID3D11Buffer* cbuf, ID3D11ShaderResourceView** srvs, UINT nSrv,
                          ID3D11UnorderedAccessView* outUAV,
                          ID3D11Buffer* staging, ID3D11Buffer* outBuf,
                          UINT n, const UINT* cb, UINT* outBits) {
        __try {
            ctx->UpdateSubresource(cbuf, 0, nullptr, cb, 0, 0);
            ctx->CSSetShader(cs, nullptr, 0);
            ctx->CSSetConstantBuffers(0, 1, &cbuf);
            ctx->CSSetShaderResources(0, nSrv, srvs);
            ID3D11UnorderedAccessView* uavs[1] = { outUAV };
            ctx->CSSetUnorderedAccessViews(0, 1, uavs, nullptr);
            ctx->Dispatch(n, 1, 1);
            ctx->Flush();
            ctx->CSSetShader(nullptr, nullptr, 0);
            // 解绑 UAV 必须传「全 NULL 的指针数组」；传 NULL 数组指针 + 计数 1 会让 D3D11 运行时
            // 解引用空指针（0xC0000005），被本函数的 __try 捕获返回 1 → 上层误判「dispatch 崩溃」
            // 并丢弃整批 GPU 结果回退 CPU。这是「GPU 一次都没真正跑过」的唯一真因。
            ID3D11UnorderedAccessView* nullUAVs[1] = { nullptr };
            ctx->CSSetUnorderedAccessViews(0, 1, nullUAVs, nullptr);
            ctx->CopyResource(staging, outBuf);
            D3D11_MAPPED_SUBRESOURCE map{};
            if (!SUCCEEDED(ctx->Map(staging, 0, D3D11_MAP_READ, 0, &map)) || !map.pData) return 2;
            memcpy(outBits, map.pData, (size_t)n * 4);
            ctx->Unmap(staging, 0);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return 1;   // compute 执行崩溃 → 调用方回退 CPU
        }
        return 0;
    }

    // 读文件前缀进 UINT 池
    void LoadPool(const std::vector<std::string>& paths, uint32_t n,
                  std::vector<UINT>& pool, std::vector<UINT>& ranges) {
        const size_t perUints = kProbeBytes / 4;
        std::vector<BYTE> bytes(kProbeBytes);
        pool.assign((size_t)n * perUints, 0);
        ranges.assign((size_t)n * 2, 0);
        for (uint32_t i = 0; i < n; ++i) {
            DWORD got = 0;
            HANDLE hf = CreateFileA(paths[i].c_str(), GENERIC_READ, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (hf == INVALID_HANDLE_VALUE) {
                ranges[i * 2 + 0] = i * (UINT)kProbeBytes; ranges[i * 2 + 1] = 0;
                continue;
            }
            ReadFile(hf, bytes.data(), kProbeBytes, &got, nullptr);
            CloseHandle(hf);
            memset(bytes.data() + got, 0, kProbeBytes - got);
            memcpy(pool.data() + (size_t)i * perUints, bytes.data(), kProbeBytes);
            ranges[i * 2 + 0] = i * (UINT)kProbeBytes;
            ranges[i * 2 + 1] = got;
        }
    }

    // useMap=true 走地图内核（档2），false 走线性内核（档1）
    bool RunBatch(const std::vector<std::string>& paths, std::vector<bool>& hits, bool useMap) {
        hits.assign(paths.size(), false);
        if (paths.empty()) return true;
        uint32_t n = (uint32_t)paths.size();
        if (!EnsureCapacity(n)) { sf::LogDbg("[gpu] capacity fail n=" + std::to_string(n)); return false; }
        std::vector<UINT> pool, ranges, zeroOut(n, 0);
        LoadPool(paths, n, pool, ranges);
        // 整批一次上传（实测：整块 Map/DEFAULT 上传 1.72 GB/s，而 64KB 分块仅 0.10 GB/s）
        ctx->UpdateSubresource(inBuf, 0, nullptr, pool.data(), 0, 0);
        ctx->UpdateSubresource(rangeBuf, 0, nullptr, ranges.data(), 0, 0);
        ctx->UpdateSubresource(outBuf, 0, nullptr, zeroOut.data(), 0, 0);

        std::vector<UINT> bits(n, 0);
        int rc = 0;
        if (useMap && mapLoaded) {
            UINT cb[4] = { n, mapMaxLen, 0, 0 };
            ID3D11ShaderResourceView* srvs[4] = { inSRV, rangeSRV, mapTableSRV, mapTermSRV };
            rc = GpuRunCore(ctx, csMap, cbuf, srvs, 4, outUAV, staging, outBuf, n, cb, bits.data());
        } else {
            UINT cb[4] = { n, 0, 0, 0 };
            ID3D11ShaderResourceView* srvs[2] = { inSRV, rangeSRV };
            rc = GpuRunCore(ctx, csLinear, cbuf, srvs, 2, outUAV, staging, outBuf, n, cb, bits.data());
        }
        if (rc == 1) { GpuMarkFailure("dispatch crashed"); return false; }
        if (rc == 2) { GpuMarkFailure("readback failed");    return false; }
        // 成功一轮：清空失败计数（偶发抖动不该累积到熔断）
        g_gpuFailStreak.store(0, std::memory_order_release);
        for (uint32_t i = 0; i < n; ++i) hits[i] = (bits[i] != 0);
        return true;
    }

    // 地图自检：造一段含 '+sfuck' 的数据跑一遍，确认地图正确可用
    bool SelfTestMap() {
        std::vector<std::string> tmppaths;   // 不用真实文件，直接塞数据
        if (!EnsureCapacity(1)) return false;
        const size_t perUints = kProbeBytes / 4;
        std::vector<UINT> pool((size_t)1 * perUints, 0);
        std::vector<UINT> ranges(2), zeroOut(1, 0), bits(1, 0);
        std::vector<BYTE> buf(kProbeBytes, 0x41);
        memcpy(buf.data() + 1024, "sfuck", 5);
        memcpy(pool.data(), buf.data(), kProbeBytes);
        ranges[0] = 0; ranges[1] = kProbeBytes;
        ctx->UpdateSubresource(inBuf, 0, nullptr, pool.data(), 0, 0);
        ctx->UpdateSubresource(rangeBuf, 0, nullptr, ranges.data(), 0, 0);
        ctx->UpdateSubresource(outBuf, 0, nullptr, zeroOut.data(), 0, 0);
        UINT cb[4] = { 1, mapMaxLen, 0, 0 };
        ID3D11ShaderResourceView* srvs[4] = { inSRV, rangeSRV, mapTableSRV, mapTermSRV };
        int rc = GpuRunCore(ctx, csMap, cbuf, srvs, 4, outUAV, staging, outBuf, 1, cb, bits.data());
        if (rc != 0) { sf::LogDbg("[gpu] map selftest: dispatch rc=" + std::to_string(rc)); return false; }
        bool ok = (bits[0] != 0);
        sf::LogDbg(std::string("[gpu] map selftest: ") + (ok ? "OK" : "MISS(地图可能不完整)"));
        return ok;
    }

    // 用内存池跑若干轮「上传 + dispatch + 读回」，返回平均耗时（ms）。
    // 适配器评分用它 —— 端到端吞吐才是真正决定「值不值得用这块卡」的数字。
    double RunPoolOnce(const std::vector<UINT>& pool, const std::vector<UINT>& ranges,
                       uint32_t n, bool useMap, int rounds) {
        if (!EnsureCapacity(n)) return -1;
        std::vector<UINT> zeroOut(n, 0), bits(n, 0);
        UINT cb[4] = { n, mapMaxLen, 0, 0 };
        const bool map = (useMap && mapLoaded);
        ID3D11ShaderResourceView* srvs[4] = { inSRV, rangeSRV, mapTableSRV, mapTermSRV };
        ID3D11ComputeShader* sh = map ? csMap : csLinear;
        UINT nSrv = map ? 4u : 2u;
        // 预热一轮
        ctx->UpdateSubresource(inBuf, 0, nullptr, pool.data(), 0, 0);
        ctx->UpdateSubresource(rangeBuf, 0, nullptr, ranges.data(), 0, 0);
        ctx->UpdateSubresource(outBuf, 0, nullptr, zeroOut.data(), 0, 0);
        if (GpuRunCore(ctx, sh, cbuf, srvs, nSrv, outUAV, staging, outBuf, n, cb, bits.data()) != 0) return -1;
        // 取【最快一轮】：系统负载只会让测量变慢不会变快，取最小值最接近真实能力，
        // 否则 CPU 基线会随后台活动上下漂 20%+，导致档位在阈值边缘来回摆。
        double bestMs = -1;
        for (int r = 0; r < rounds; ++r) {
            auto t0 = std::chrono::steady_clock::now();
            ctx->UpdateSubresource(inBuf, 0, nullptr, pool.data(), 0, 0);
            ctx->UpdateSubresource(rangeBuf, 0, nullptr, ranges.data(), 0, 0);
            ctx->UpdateSubresource(outBuf, 0, nullptr, zeroOut.data(), 0, 0);
            if (GpuRunCore(ctx, sh, cbuf, srvs, nSrv, outUAV, staging, outBuf, n, cb, bits.data()) != 0) return -1;
            auto t1 = std::chrono::steady_clock::now();
            double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
            if (bestMs < 0 || ms < bestMs) bestMs = ms;
        }
        return bestMs;
    }

    void CleanupBulk() {
        if (inSRV)    { inSRV->Release();    inSRV = nullptr; }
        if (rangeSRV) { rangeSRV->Release(); rangeSRV = nullptr; }
        if (outUAV)   { outUAV->Release();   outUAV = nullptr; }
        if (inBuf)    { inBuf->Release();    inBuf = nullptr; }
        if (rangeBuf) { rangeBuf->Release(); rangeBuf = nullptr; }
        if (outBuf)   { outBuf->Release();   outBuf = nullptr; }
        if (staging)  { staging->Release();  staging = nullptr; }
        if (cbuf)     { cbuf->Release();     cbuf = nullptr; }
        inCapBytes = 0; maxFiles = 0;
    }

    void Cleanup() {
        UnloadMapBuffers();
        CleanupBulk();
        if (ctx) ctx->ClearState();
        if (csLinear) { csLinear->Release(); csLinear = nullptr; }
        if (csMap)    { csMap->Release();    csMap = nullptr; }
        if (ctx)      { ctx->Release();      ctx = nullptr; }
        if (dev)      { dev->Release();      dev = nullptr; }
        gpuName.clear(); vramMB = 0;
    }
    ~GpuDevice() { Cleanup(); }
};

static void GpuMarkFailure(const char* why) {
    int n = g_gpuFailStreak.fetch_add(1, std::memory_order_acq_rel) + 1;
    sf::LogDbg(std::string("[gpu] failure #") + std::to_string(n) + " (" + why + ")");
    if (n >= kGpuFailThreshold) {
        g_gpuTripped.store(true, std::memory_order_release);
        sf::LogDbg("[gpu] === 熔断：连续失败达阈值，本进程内永久停用 GPU 加速，全走 CPU ===");
    }
}
bool GpuTripped() { return g_gpuTripped.load(std::memory_order_acquire); }

static GpuDevice g_dev;
static std::mutex g_devMtx;
static std::atomic<bool> g_everTried{ false };
static std::atomic<bool> g_ok{ false };
// 探测选定的适配器索引：-1 = 系统默认；>=0 = 显式指定（多显卡机器上必须显式，
// 否则服务进程（Session 0）常拿到核显而不是独显）
static std::atomic<int> g_useAdapter{ -1 };


static bool EnsureDevice() {
    if (g_everTried.load(std::memory_order_acquire)) return g_ok.load(std::memory_order_acquire);
    std::lock_guard<std::mutex> lk(g_devMtx);
    if (g_everTried.load(std::memory_order_acquire)) return g_ok.load(std::memory_order_acquire);
    bool ok = false;
    int idx = g_useAdapter.load(std::memory_order_acquire);
    if (idx >= 0) {
        IDXGIFactory1* fac = nullptr;
        if (SUCCEEDED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&fac)) && fac) {
            IDXGIAdapter1* ad = nullptr;
            if (fac->EnumAdapters1((UINT)idx, &ad) != DXGI_ERROR_NOT_FOUND && ad) {
                ok = g_dev.Init(ad);
                ad->Release();
            }
            fac->Release();
        }
        if (!ok) sf::LogDbg("[gpu] 指定适配器 #" + std::to_string(idx) + " 创建失败，回退系统默认");
    }
    if (!ok) ok = g_dev.Init(nullptr);
    g_ok.store(ok, std::memory_order_release);
    g_everTried.store(true, std::memory_order_release);
    return ok;
}

// ---------------------------------------------------------------------------
//  地图状态（供 UI 轮询显示进度）
// ---------------------------------------------------------------------------
static MapInfo g_mapInfo;
static std::mutex g_mapMtx;
static std::atomic<bool> g_mapLoading{ false };

static void SetMapProgress(int pct, const std::string& stage) {
    std::lock_guard<std::mutex> lk(g_mapMtx);
    g_mapInfo.pct = pct;
    g_mapInfo.stage = stage;
}

MapInfo GetMapInfo() {
    std::lock_guard<std::mutex> lk(g_mapMtx);
    return g_mapInfo;
}

// ---------------------------------------------------------------------------
//  GPU 性能探测：开扫前跑一次，决定走哪一档
// ---------------------------------------------------------------------------
using ProgressFn = std::function<void(int, const std::string&)>;

static double NowMs(std::chrono::steady_clock::time_point a, std::chrono::steady_clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}
static double ToGBs(size_t bytes, double ms) { return ms <= 0 ? 0 : (double)bytes / (ms / 1000.0) / 1e9; }

// 显存内拷贝带宽（单向）
static double BenchVram(GpuDevice& d, size_t bytes) {
    D3D11_BUFFER_DESC bd{};
    bd.ByteWidth = (UINT)bytes; bd.Usage = D3D11_USAGE_DEFAULT; bd.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    ID3D11Buffer *src = nullptr, *dst = nullptr;
    if (FAILED(d.dev->CreateBuffer(&bd, nullptr, &src))) return 0;
    if (FAILED(d.dev->CreateBuffer(&bd, nullptr, &dst))) { src->Release(); return 0; }
    D3D11_QUERY_DESC qd{}; qd.Query = D3D11_QUERY_EVENT;
    ID3D11Query* q = nullptr;
    if (FAILED(d.dev->CreateQuery(&qd, &q))) { src->Release(); dst->Release(); return 0; }
    const int rounds = 10;
    for (int i = 0; i < 2; ++i) d.ctx->CopyResource(dst, src);
    d.ctx->End(q); while (d.ctx->GetData(q, nullptr, 0, 0) == S_FALSE) Sleep(0);
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < rounds; ++i) d.ctx->CopyResource(dst, src);
    d.ctx->End(q); while (d.ctx->GetData(q, nullptr, 0, 0) == S_FALSE) Sleep(0);
    auto t1 = std::chrono::steady_clock::now();
    double ms = NowMs(t0, t1) / rounds;
    q->Release(); src->Release(); dst->Release();
    return ToGBs(bytes * 2, ms) / 2.0;   // 单向
}

// PCIe 上行：主机 → 显存（整块 Map WRITE_DISCARD 是最快形态）
static double BenchH2D(GpuDevice& d, size_t bytes, std::vector<BYTE>& host) {
    D3D11_BUFFER_DESC bd{};
    bd.ByteWidth = (UINT)bytes; bd.Usage = D3D11_USAGE_DYNAMIC;
    bd.BindFlags = D3D11_BIND_SHADER_RESOURCE; bd.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
    ID3D11Buffer* dyn = nullptr;
    if (FAILED(d.dev->CreateBuffer(&bd, nullptr, &dyn))) return 0;
    const int rounds = 5;
    auto once = [&]() {
        D3D11_MAPPED_SUBRESOURCE m{};
        if (SUCCEEDED(d.ctx->Map(dyn, 0, D3D11_MAP_WRITE_DISCARD, 0, &m))) {
            memcpy(m.pData, host.data(), bytes);
            d.ctx->Unmap(dyn, 0);
        }
    };
    once();
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < rounds; ++i) once();
    auto t1 = std::chrono::steady_clock::now();
    double ms = NowMs(t0, t1) / rounds;
    dyn->Release();
    return ToGBs(bytes, ms);
}

// PCIe 下行：显存 → 主机（staging + Map READ，必须真读一遍）
static double BenchD2H(GpuDevice& d, size_t bytes) {
    D3D11_BUFFER_DESC bd{};
    bd.ByteWidth = (UINT)bytes; bd.Usage = D3D11_USAGE_DEFAULT;
    ID3D11Buffer* src = nullptr;
    if (FAILED(d.dev->CreateBuffer(&bd, nullptr, &src))) return 0;
    bd.Usage = D3D11_USAGE_STAGING; bd.BindFlags = 0; bd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    ID3D11Buffer* stg = nullptr;
    if (FAILED(d.dev->CreateBuffer(&bd, nullptr, &stg))) { src->Release(); return 0; }
    const int rounds = 5;
    volatile size_t sink = 0;
    auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < rounds; ++i) {
        d.ctx->CopyResource(stg, src);
        D3D11_MAPPED_SUBRESOURCE m{};
        if (FAILED(d.ctx->Map(stg, 0, D3D11_MAP_READ, 0, &m))) break;
        const BYTE* p = (const BYTE*)m.pData;
        size_t s = 0;
        for (size_t k = 0; k < bytes; k += 4096) s += p[k];
        sink += s;
        d.ctx->Unmap(stg, 0);
    }
    auto t1 = std::chrono::steady_clock::now();
    double ms = NowMs(t0, t1) / rounds;
    if (sink == 0xDEADBEEF) printf("");
    src->Release(); stg->Release();
    return ToGBs(bytes, ms);
}

// ---------------------------------------------------------------------------
//  适配器评分：为每块候选适配器创建临时设备实测，选最快的那个
//
//  为什么不能按「显存大小」一刀切：Intel 近几代核显（UHD / Iris Xe / Arc 140V…）
//  专用显存上报值只有 128MB 甚至 0，主力是共享内存 —— 但算力可以接近入门独显
//  （Arc 140V 级别对标 RTX 3050 的算力区间）。显存容量只决定「放不放得下工作集」
//  （地图 0.38MB + 缓冲 4~32MB），真正该比的是【实测吞吐】。
// ---------------------------------------------------------------------------
struct AdapterScore {
    int         index = -1;
    std::string name;
    uint64_t    vramMB = 0;
    uint64_t    sharedMB = 0;
    bool        integrated = false;   // 核显：专用显存很小、主要靠共享内存
    double      vramGBs = 0;
    double      xferGBs = 0;
    double      e2eMBs = 0;           // 端到端吞吐（上传+计算+读回）—— 决策数字
    bool        ok = false;
};

// 高熵测试数据（模拟真实二进制）：必须这么做 —— 若用 0x41 之类的单一字节填充，
// AC 状态机会一直停在根状态附近几乎不做转移，CPU 会跑出虚高的吞吐（实测差 3 倍以上），
// 导致「GPU 不如 CPU」的误判。末尾埋一个命中串，保证两边都「扫满」才命中，工作量对等。
static void FillHighEntropy(std::vector<BYTE>& buf, uint32_t seed) {
    uint32_t s = seed ? seed : 0x12345678u;
    for (size_t i = 0; i < buf.size(); ++i) {
        s = s * 1664525u + 1013904223u;
        buf[i] = (BYTE)(s >> 24);
    }
    if (buf.size() >= 8) memcpy(buf.data() + buf.size() - 8, "gh0st", 5);
}

static bool ScoreAdapter(UINT index, IDXGIAdapter1* ad, AdapterScore& sc,
                         const ProgressFn& cb, int pctBase, int pctSpan, int nth, int total) {
    DXGI_ADAPTER_DESC1 d{};
    ad->GetDesc1(&d);
    char nm[256] = { 0 };
    WideCharToMultiByte(CP_UTF8, 0, d.Description, -1, nm, 255, nullptr, nullptr);
    sc.index = (int)index;
    sc.name = nm;
    sc.vramMB = d.DedicatedVideoMemory >> 20;
    sc.sharedMB = d.SharedSystemMemory >> 20;
    // 核显判定：专用显存很小，且共享内存远大于它（Intel/AMD 核显都是这样上报的）
    sc.integrated = (sc.vramMB < 512 && sc.sharedMB > sc.vramMB);

    if (cb && total > 0) {
        char stage[160];
        snprintf(stage, sizeof(stage), "实测显卡 %d/%d：%s", nth + 1, total, sc.name.c_str());
        cb(pctBase + pctSpan * nth / total, stage);
    }

    GpuDevice tmp;
    if (!tmp.Init(ad)) {
        sf::LogDbg("[gpu] adapter #" + std::to_string(index) + " '" + sc.name + "' 设备创建失败，跳过");
        return false;
    }
    sc.vramGBs = BenchVram(tmp, 32ull << 20);
    std::vector<BYTE> host(8ull << 20, 0x5A);
    sc.xferGBs = BenchH2D(tmp, host.size(), host);

    sf::AcMatcher ac;
    ac.Build(sf::LoadFamilyPatterns());
    if (ac.empty() || !tmp.UploadMap(ac)) { tmp.Cleanup(); return false; }

    // 4MB 测试数据（64 文件 × 64KB），内含一个命中串用于顺带校验正确性
    const uint32_t nf = 64;
    const size_t perUints = kProbeBytes / 4;
    std::vector<UINT> pool((size_t)nf * perUints, 0), ranges(nf * 2, 0);
    {
        std::vector<BYTE> bytes(kProbeBytes);
        FillHighEntropy(bytes, 0x9E3779B9u);
        for (uint32_t i = 0; i < nf; ++i) {
            memcpy(pool.data() + (size_t)i * perUints, bytes.data(), kProbeBytes);
            ranges[i * 2] = i * (UINT)kProbeBytes;
            ranges[i * 2 + 1] = kProbeBytes;
        }
    }
    double ms = tmp.RunPoolOnce(pool, ranges, nf, true, 8);
    tmp.Cleanup();
    if (ms <= 0) return false;
    sc.e2eMBs = (double)nf * kProbeBytes / 1048576.0 * 1000.0 / ms;
    sc.ok = true;
    sf::LogDbg("[gpu] adapter #" + std::to_string(index) + " '" + sc.name + "'" +
               (sc.integrated ? "[核显]" : "[独显]") +
               " vram=" + std::to_string(sc.vramMB) + "MB shared=" + std::to_string(sc.sharedMB) + "MB" +
               " vramBW=" + std::to_string((int)sc.vramGBs) + "GB/s" +
               " xfer=" + std::to_string((int)(sc.xferGBs * 1000)) + "MB/s" +
               " e2e=" + std::to_string((int)sc.e2eMBs) + "MB/s");
    return true;
}

// 本机 CPU 基线：4 线程 AC 自动机扫描 16MB（与 GPU 端到端同口径，用于比较）
static double MeasureCpuBaselineMBs() {
    sf::AcMatcher ac;
    ac.Build(sf::LoadFamilyPatterns());
    if (ac.empty()) return 0;
    const size_t total = 16ull << 20;
    std::vector<BYTE> buf(total);
    FillHighEntropy(buf, 0x85EBCA6Bu);
    // 每个 1MB 块末尾各埋一个命中（与 GPU 侧「每文件末尾命中」同口径，两边都扫满）
    for (size_t off = 0; off + (1 << 20) <= total; off += (1 << 20))
        memcpy(buf.data() + off + (1 << 20) - 8, "gh0st", 5);
    const int threads = 4;
    const int rounds = 5;
    std::atomic<size_t> sink{ 0 };
    size_t chunk = total / threads;
    double bestMs = -1;
    for (int r = 0; r < rounds; ++r) {
        auto t0 = std::chrono::steady_clock::now();
        std::vector<std::thread> ts;
        for (int t = 0; t < threads; ++t) {
            size_t b = (size_t)t * chunk;
            size_t e = (t == threads - 1) ? total : (b + chunk);
            ts.emplace_back([&, b, e]() {
                size_t h = 0;
                for (size_t off = b; off < e; off += (1 << 20)) {
                    size_t len = std::min<size_t>(1 << 20, e - off);
                    if (ac.Scan(buf.data() + off, len) >= 0) ++h;
                }
                sink += h;
            });
        }
        for (auto& th : ts) th.join();
        auto t1 = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        if (bestMs < 0 || ms < bestMs) bestMs = ms;   // 取最快一轮
    }
    (void)sink;
    if (bestMs <= 0) return 0;
    return (double)total / 1048576.0 * 1000.0 / bestMs;
}

static Caps ProbeGpuInternal(const ProgressFn& cb) {
    Caps c;
    auto step = [&](int pct, const char* s) { if (cb) cb(pct, s); };

    step(3, "枚举显卡适配器");
    IDXGIFactory1* fac = nullptr;
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&fac)) || !fac) {
        c.reason = "DXGI 工厂创建失败";
        step(100, "完成");
        return c;
    }
    // 收集硬件适配器：跳过软件适配器（Microsoft Basic Render Driver），按 LUID 去重
    struct Cand { IDXGIAdapter1* ad; UINT index; };
    std::vector<Cand> cands;
    std::vector<std::string> seenNames;
    for (UINT i = 0;; ++i) {
        IDXGIAdapter1* ad = nullptr;
        if (fac->EnumAdapters1(i, &ad) == DXGI_ERROR_NOT_FOUND || !ad) break;
        DXGI_ADAPTER_DESC1 d{};
        ad->GetDesc1(&d);
        if (d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) { ad->Release(); continue; }
        // 同一块 GPU 常被重复枚举（每个输出一个实例；Intel 核显实测枚举出 3 次），
        // 按型号名去重，免得同一块卡被反复基准测试（每次要几百毫秒）。
        char nm[256] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, d.Description, -1, nm, 255, nullptr, nullptr);
        bool dup = false;
        for (const auto& n : seenNames) if (n == nm) { dup = true; break; }
        if (dup) { ad->Release(); continue; }
        seenNames.push_back(nm);
        cands.push_back({ ad, i });
    }
    if (cands.empty()) {
        fac->Release();
        c.reason = "未发现硬件 GPU 适配器（系统只有软件渲染设备）";
        step(100, "完成");
        return c;
    }
    c.adaptersScanned = (int)cands.size();

    // 逐块实测评分，取端到端吞吐最高者
    AdapterScore best;
    for (int k = 0; k < (int)cands.size(); ++k) {
        AdapterScore sc;
        if (ScoreAdapter(cands[k].index, cands[k].ad, sc, cb, 8, 62, k, (int)cands.size()) && sc.ok) {
            if (!best.ok || sc.e2eMBs > best.e2eMBs) best = sc;
        }
    }
    for (auto& cd : cands) cd.ad->Release();
    fac->Release();

    if (!best.ok) {
        c.reason = "所有硬件适配器的基准测试均失败";
        step(100, "完成");
        return c;
    }

    step(74, "测量 CPU 基准");
    c.cpuMBs = MeasureCpuBaselineMBs();

    c.hardware       = true;
    c.name           = best.name;
    c.adapterIndex   = best.index;
    c.integrated     = best.integrated;
    c.vramMB         = best.vramMB;
    c.sharedMB       = best.sharedMB;
    c.vramGBs        = best.vramGBs;
    c.h2dGBs         = best.xferGBs;
    c.d2hGBs         = 0;   // 核显/独显口径不同，不再单独作为判据
    c.e2eMBs         = best.e2eMBs;
    // 可用预算：独显看专用显存；核显专用很小，用共享内存折算（工作集约 200MB 足够）
    c.usableMB = best.integrated
        ? (best.vramMB + std::min<uint64_t>(best.sharedMB / 4, 2048))
        : best.vramMB;
    c.ratio = (c.cpuMBs > 0) ? (c.e2eMBs / c.cpuMBs) : 0;

    step(88, "判定加速档位");
    // 判据以【实测吞吐】为准，不看显存容量：
    //   Intel 近几代核显显存是共享的，但算力可对标入门独显，按容量一刀切会把它们全拒掉。
    char rbuf[32]; snprintf(rbuf, sizeof(rbuf), "%.2f", c.ratio);
    if (c.usableMB < 128) {
        c.tier = Tier::CpuOnly;
        c.reason = "可用显存不足 128MB，放不下工作集";
    } else if (c.ratio < 0.50) {
        // GPU 吞吐不足 CPU 一半 → 用它明显拖慢，直接走 CPU。
        // 阈值定在 0.5 而不是 1.0：移动显卡（功耗墙/热墙）实测波动可达 ±40%，
        // 且 GPU 扫描不占 CPU 线程，达到 CPU 一半吞吐时用它仍有「省 CPU」的价值。
        c.tier = Tier::CpuOnly;
        c.reason = "实测吞吐 " + std::to_string((int)c.e2eMBs) + " MB/s 不足 CPU " +
                   std::to_string((int)c.cpuMBs) + " MB/s 的一半";
    } else if (c.ratio < 1.5) {
        c.tier = Tier::Basic;
        c.reason = "实测吞吐 " + std::to_string((int)c.e2eMBs) + " MB/s ≈ CPU " +
                   std::to_string((int)c.cpuMBs) + " MB/s（可用，主要是省 CPU）";
    } else {
        c.tier = Tier::Map;
        c.reason = "实测吞吐 " + std::to_string((int)c.e2eMBs) + " MB/s，为 CPU 的 " +
                   std::string(rbuf) + " 倍 → 地图常驻显存";
    }
    sf::LogDbg("[gpu] probe: 选中 #" + std::to_string(c.adapterIndex) + " '" + c.name + "'" +
               (c.integrated ? "（核显/共享内存）" : "（独显）") +
               " 共扫描 " + std::to_string(c.adaptersScanned) + " 块卡" +
               " vram=" + std::to_string(c.vramMB) + "MB shared=" + std::to_string(c.sharedMB) + "MB" +
               " vramBW=" + std::to_string((int)c.vramGBs) + "GB/s" +
               " xfer=" + std::to_string((int)(c.h2dGBs * 1000)) + "MB/s" +
               " e2e=" + std::to_string((int)c.e2eMBs) + "MB/s" +
               " cpu=" + std::to_string((int)c.cpuMBs) + "MB/s" +
               " ratio=" + std::string(rbuf) +
               " -> " + TierName(c.tier) + " (" + c.reason + ")");
    step(100, "完成");
    return c;
}

static std::mutex g_capsMtx;
static Caps       g_cachedCaps;
static bool       g_capsDone = false;

Caps ProbeGpu(bool force) {
    std::lock_guard<std::mutex> lk(g_capsMtx);
    if (g_capsDone && !force) return g_cachedCaps;
    g_cachedCaps = ProbeGpuInternal(nullptr);
    g_capsDone = true;
    return g_cachedCaps;
}

// 带进度回调的探测（供「载入地图」流程用）：结果同样写进缓存，
// 否则扫描时的 ProbeGpu 会再跑一遍完整基准（多花 1 秒 + 可能得出不同档位）。
static Caps ProbeGpuWithProgress(const ProgressFn& cb) {
    std::lock_guard<std::mutex> lk(g_capsMtx);
    g_cachedCaps = ProbeGpuInternal(cb);
    g_capsDone = true;
    return g_cachedCaps;
}

// ---------------------------------------------------------------------------
//  地图加载 / 释放
// ---------------------------------------------------------------------------
void LoadMapAsync() {
    bool expect = false;
    if (!g_mapLoading.compare_exchange_strong(expect, true)) return;   // 已在加载
    // 开关判断由调用方负责（service.cpp 的 gpu 命令只在 on=1 时调用本函数）

    {
        std::lock_guard<std::mutex> lk(g_mapMtx);
        g_mapInfo.loading = true;
        g_mapInfo.loaded = false;
        g_mapInfo.pct = 0;
        g_mapInfo.stage = "准备";
        g_mapInfo.error.clear();
    }

    std::thread([]() {
        auto fail = [](const std::string& err) {
            std::lock_guard<std::mutex> lk(g_mapMtx);
            g_mapInfo.loading = false;
            g_mapInfo.loaded = false;
            g_mapInfo.error = err;
        };
        // 1) 探测 GPU 性能并定档（0 → 70%）—— 结果写进缓存，扫描时不再重复基准测试
        Caps caps = ProbeGpuWithProgress([](int pct, const std::string& s) {
            SetMapProgress(pct * 70 / 100, s);
        });
        {
            std::lock_guard<std::mutex> lk(g_mapMtx);
            g_mapInfo.tier       = (int)caps.tier;
            g_mapInfo.gpu        = caps.name;
            g_mapInfo.integrated = caps.integrated;
            g_mapInfo.e2eMBs     = (int)caps.e2eMBs;
            g_mapInfo.cpuMBs     = (int)caps.cpuMBs;
            g_mapInfo.ratioPct   = (int)(caps.ratio * 100);
        }
        if (caps.tier == Tier::CpuOnly) { fail(caps.reason); g_mapLoading.store(false); return; }

        // 探测已对每块硬件卡实测比较过 —— 这里锁定选中的卡，并按它重建 D3D11 设备
        // （不这么做的话，服务进程会继续用「系统默认适配器」＝常常是核显）。
        g_useAdapter.store(caps.adapterIndex, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(g_devMtx);
            g_dev.Cleanup();
        }
        g_ok.store(false, std::memory_order_release);
        g_everTried.store(false, std::memory_order_release);
        if (!EnsureDevice()) { fail("按选中显卡创建 D3D11 设备失败"); g_mapLoading.store(false); return; }

        // 2) 构建特征地图（70 → 85%）
        SetMapProgress(72, "读取规则库");
        std::vector<std::string> pats = sf::LoadFamilyPatterns();
        SetMapProgress(76, "构建特征地图");
        sf::AcMatcher ac;
        ac.Build(pats);
        if (ac.empty()) { fail("规则库为空，无法构建地图"); g_mapLoading.store(false); return; }
        {
            std::lock_guard<std::mutex> lk(g_mapMtx);
            g_mapInfo.patterns = ac.patternCount();
            g_mapInfo.states = ac.stateCount();
            g_mapInfo.bytes = ac.tableBytes() + ac.term().size() * 4;
        }
        SetMapProgress(80, "编译地图内核");

        // 3) 上传地图到显存（85 → 95%）
        SetMapProgress(86, "上传地图到显存");
        bool up = false;
        {
            std::lock_guard<std::mutex> lk(g_devMtx);
            up = g_dev.UploadMap(ac);
        }
        if (!up) { fail("地图上传显存失败"); g_mapLoading.store(false); return; }

        // 4) 自检（95 → 100%）
        SetMapProgress(96, "校验地图");
        bool ok = false;
        {
            std::lock_guard<std::mutex> lk(g_devMtx);
            ok = g_dev.SelfTestMap();
        }
        if (!ok) {
            std::lock_guard<std::mutex> lk(g_devMtx);
            g_dev.UnloadMapBuffers();
            fail("地图自检未通过");
            g_mapLoading.store(false);
            return;
        }

        {
            std::lock_guard<std::mutex> lk(g_mapMtx);
            g_mapInfo.loading = false;
            g_mapInfo.loaded = true;
            g_mapInfo.pct = 100;
            g_mapInfo.stage = "就绪";
            g_mapInfo.error.clear();
        }
        sf::LogDbg("[gpu] map loaded: patterns=" + std::to_string(ac.patternCount()) +
                   " states=" + std::to_string(ac.stateCount()) +
                   " bytes=" + std::to_string(ac.tableBytes() + ac.term().size() * 4) +
                   " tier=" + TierName(caps.tier));
        g_mapLoading.store(false);
    }).detach();
}

void UnloadMap() {
    {
        std::lock_guard<std::mutex> lk(g_devMtx);
        // 彻底释放：连设备一起销毁，全部显存立即归还（关闭加速后不占一点显存）
        g_dev.Cleanup();
        g_ok.store(false, std::memory_order_release);
        g_everTried.store(false, std::memory_order_release);
    }
    std::lock_guard<std::mutex> lk(g_mapMtx);
    g_mapInfo = MapInfo{};
    g_mapInfo.stage = "已释放";
    sf::LogDbg("[gpu] map unloaded, all GPU memory released");
}

// ---------------------------------------------------------------------------
//  扫描入口
// ---------------------------------------------------------------------------
bool GpuFamilyProbe(const std::vector<std::string>& paths, std::vector<bool>& hits) {
    hits.assign(paths.size(), false);
    if (paths.empty()) return true;

    // 熔断后本进程不再碰 GPU —— 避免在必崩的驱动上反复触发（旧行为会导致
    // 每轮扫描都撞一次崩溃 → 进程死 → SCM 重启 → 再撞，即用户看到的循环）。
    if (GpuTripped()) return false;

    Caps caps = ProbeGpu(false);
    if (caps.tier == Tier::CpuOnly) return false;      // 档0：交给 CPU 多线程路径
    if (!EnsureDevice()) { GpuMarkFailure("device create failed"); return false; }

    bool useMap = false;
    {
        std::lock_guard<std::mutex> lk(g_devMtx);
        useMap = g_dev.mapLoaded;                       // 地图未就绪时先用线性内核顶着
    }
    // 档1 用小批量（4MB）以压低显存占用；档2 用满批（16MB）跑满 PCIe
    const size_t batchMax = (caps.tier == Tier::Map) ? kBatchMaxFiles : kBatchMaxFilesSlim;

    std::lock_guard<std::mutex> lk(g_devMtx);
    for (size_t base = 0; base < paths.size(); base += batchMax) {
        size_t cnt = std::min(batchMax, paths.size() - base);
        std::vector<std::string> batch(paths.begin() + base, paths.begin() + base + cnt);
        std::vector<bool> bh;
        if (!g_dev.RunBatch(batch, bh, useMap)) {
            // 中途失败：本批已算出的结果作废，交回 CPU 重算（保证检出集与 GPU 路径一致）。
            hits.assign(paths.size(), false);
            return false;
        }
        for (size_t k = 0; k < bh.size(); ++k) hits[base + k] = bh[k];
    }
    return true;
}

}  // namespace compute
