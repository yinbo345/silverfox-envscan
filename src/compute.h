// compute.h — GPU 加速内容扫描引擎：三档自适应 + 「特征地图」显存常驻
//
// 设计（基于本机 MX250 实测数据）：
//   · 显存内部带宽 23.6 GB/s，而 DDR 只有 3.7 GB/s —— 显存确实快 6 倍；
//     但数据要过 PCIe：上行仅 1.72 GB/s（整块）/ 0.10 GB/s（64KB 分块），比直接
//     在内存里算还慢。所以「把数据丢给 GPU 算」有硬天花板，必须让【不变的东西】
//     常驻显存 —— 那就是规则库编译出的「地图」。
//
//   地图 = Aho-Corasick 自动机的确定性状态转移表（35 条家族串 → 389 状态 → 0.38 MB）。
//   扫描时每读一个字节就在图上走一步（O(1)/字节），GPU 每个线程各走一段。
//   实测：GPU 地图式 1534 MB/s vs GPU 线性 51 MB/s（30 倍）；CPU 侧同样用这张表，
//        单线程 199 MB/s、4 线程 470 MB/s（对比原线性实现的 4 MB/s，50 倍）。
//
// 三档：
//   档 0 CpuOnly：GPU 不可用/太弱（无硬件设备、PCIe 过窄）→ 全走 CPU（多线程 AC）
//   档 1 Basic  ：GPU 可用但 PCIe 一般 → 常规批量上传 + 线性内核
//   档 2 Map    ：GPU 良好 → 地图常驻显存 + AC 寻路（开扫前先探测一次再定档）
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace compute {

// ---------- 注册表开关 ----------
bool IsGpuEnabled();
bool SetGpuEnabled(bool on);

// GPU 崩溃熔断状态：true = 本进程内已因连续执行失败（驱动崩溃）永久停用 GPU。
// 触发后所有扫描走 CPU 路径，不再触碰 D3D11 —— 这是"驱动必崩"环境下的自保开关，
// 避免陷入「扫描 → 崩溃 → SCM 重启 → 又扫描 → 又崩」的无限循环。
bool GpuTripped();

// ---------- 三档 ----------
enum class Tier {
    CpuOnly = 0,   // 档0：不用 GPU
    Basic   = 1,   // 档1：常规批量丢给 GPU
    Map     = 2,   // 档2：地图常驻显存 + 寻路
};

struct Caps {
    Tier        tier      = Tier::CpuOnly;
    bool        hardware  = false;   // 是否真硬件 GPU（软件适配器视为不可用）
    bool        integrated = false;  // 核显：专用显存很小、主要靠共享内存（不是劣汰理由）
    std::string name;                // 选中适配器名
    int         adapterIndex = -1;   // 选中的 DXGI 适配器索引
    int         adaptersScanned = 0; // 扫描过的硬件适配器数
    uint64_t    vramMB    = 0;       // 专用显存
    uint64_t    sharedMB  = 0;       // 共享内存
    uint64_t    usableMB  = 0;       // 可用预算（专用 + 共享折算，用于「放得下工作集」判断）
    double      vramGBs   = 0;       // 显存内拷贝带宽（单向）
    double      h2dGBs    = 0;       // 上行（独显=PCIe；核显=内存拷贝）
    double      d2hGBs    = 0;       // 下行
    double      kernelMBs = 0;       // 地图内核纯计算吞吐（不含传输）
    double      e2eMBs    = 0;       // 端到端吞吐（上传+计算+读回）
    double      cpuMBs    = 0;       // 本机 CPU 基线（4 线程 AC 自动机）
    double      ratio     = 0;       // e2e / cpu —— 定档真正依据
    std::string reason;              // 判定原因（写日志用）
};

// 开扫前探测：枚举全部硬件适配器 → 各跑一遍基准 → 选最快 → 与 CPU 基线比较定档。
// 结果缓存；force=true 强制重测。
Caps ProbeGpu(bool force = false);
const char* TierName(Tier t);

// ---------- 「特征地图」显存生命周期 ----------
struct MapInfo {
    bool        loaded   = false;   // 地图是否已常驻显存
    bool        loading  = false;   // 是否正在加载
    int         pct      = 0;       // 加载进度 0..100
    std::string stage;              // 当前阶段文案（用于进度条）
    std::string error;              // 失败原因（非空 = 失败）
    int         patterns = 0;       // 地图上的模式条数
    int         states   = 0;       // AC 状态数
    size_t      bytes    = 0;       // 地图占用显存字节数
    int         tier     = 0;       // 探测出的档位
    std::string gpu;                // 选中的适配器名
    bool        integrated = false; // 是否核显（共享内存）
    int         e2eMBs   = 0;       // 实测端到端吞吐（MB/s）
    int         cpuMBs   = 0;       // 本机 CPU 基线（MB/s）
    int         ratioPct = 0;       // e2e / cpu（百分数）
};

// 异步把地图加载进显存（内部线程分阶段推进进度；可在 UI 轮询 GetMapInfo）
void LoadMapAsync();
// 关闭加速：释放显存中的地图与全部 GPU 资源
void UnloadMap();
// 查询地图/加载状态
MapInfo GetMapInfo();

// ---------- 扫描入口 ----------
// 批量家族特征串探测：
//   paths 待查文件列表（每个文件读取前缀 64KB）
//   hits  长度与 paths 相同的输出（true = 命中家族特征串）
// 返回 true 表示已由 GPU 完成；false 表示应回退 CPU（档0，或 GPU 执行失败）。
bool GpuFamilyProbe(const std::vector<std::string>& paths, std::vector<bool>& hits);

}  // namespace compute
