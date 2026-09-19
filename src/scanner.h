#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <chrono>

// 单条发现
struct Finding {
    std::string category;  // 进程 / 注册表 / 计划任务 / 网络 / 文件 / Defender / WMI
    std::string severity;  // 高 / 中 / 低
    std::string title;     // 简短标题
    std::string detail;    // 详细说明
    std::string ioc;       // 命中的 IOC 原文
    // 关联文件的绝对路径（仅供「一键清除」精确定位；非文件类发现为空）。
    // 注意：不要从 detail 里反解路径——detail 是给人看的中文描述，格式随时会变。
    std::string path;
    int weight = 0;        // 风险权重（由评分引擎按证据强度赋值，见 WeightOf）
};

// 一次完整扫描的结果
struct ScanResult {
    std::string timestamp;  // 本地时间串
    // 两态：normal（环境正常）/ infected（环境异常，即疑似中银狐）
    std::string status;
    int score = 0;          // 风险分：按证据强度赋权累计（高=60/中=30/低=10 基线 + 上下文微调）
    bool hardProof = false; // 是否命中铁证（已知 C2 活跃连接 / 已知银狐进程 / 银狐标记文件）
    std::string engine;     // 引擎版本
    std::vector<Finding> findings;
    std::string error;      // 扫描过程致命错误（若有）
};

// 全局最新结果（被 HTTP 线程与扫描线程共享）
extern ScanResult g_result;
extern std::mutex g_resultMutex;

// 执行一次全量扫描并写入 g_result
void RunFullScan();

// 快速清除预扫：只扫进程+文件（清除目标的全部来源），秒级返回
// ⚠️ 会做磁盘遍历（递归 Desktop/Downloads/Temp 等落点）——**只允许「清除前预扫」调用**。
//    定时器请用 RunGuardTick()。
void RunQuickScan();

// 轻量巡检（定时器专用）：进程 + 注入 + 注册表 + 服务 + 计划任务。
// 纯内存 / 注册表读取，**零磁盘遍历**，秒级完成。结果合并进 g_result
// （保留上一轮全盘扫出的「文件」类 finding，不被冲掉）。
void RunGuardTick();

// 初始化 COM 等（main 启动时调用一次）
void ScannerInit();
void ScannerCleanup();

// P3 主动防御：单文件快速启发式判定（供 WMI 进程创建监听调用）。
// 与全盘文件扫描共享同一套启发式（随机名/落地位置/家族串/PE 静态/签名），
// 返回：0=正常或豁免；1=中危旁证；2=高危（随机名+可疑位置+PE 异常或盘根或家族特征串）。
int QuickProbeExecutable(const std::string& path);

// 大小写不敏感子串查找（ASCII）
bool ci_contains(const std::string& hay, const std::string& needle);
bool ci_ends_with(const std::string& str, const std::string& suffix);
std::string to_lower(const std::string& s);
