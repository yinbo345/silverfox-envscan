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
    bool hardProof = false; // 是否命中铁证（已知 C2 活跃连接 / 已知银狐进程 / 银狐标记文件 / 自身完整性失败）
    std::string engine;     // 引擎版本
    bool selfCheck = true;  // 程序自身完整性校验是否通过（自保）
    std::vector<Finding> findings;
    std::string error;      // 扫描过程致命错误（若有）
};

// 全局最新结果（被 HTTP 线程与扫描线程共享）
extern ScanResult g_result;
extern std::mutex g_resultMutex;

// 执行一次全量扫描并写入 g_result
void RunFullScan();

// 快速清除预扫：只扫进程+文件（清除目标的全部来源），秒级返回
void RunQuickScan();

// 初始化 COM 等（main 启动时调用一次）
void ScannerInit();
void ScannerCleanup();

// 大小写不敏感子串查找（ASCII）
bool ci_contains(const std::string& hay, const std::string& needle);
bool ci_ends_with(const std::string& str, const std::string& suffix);
std::string to_lower(const std::string& s);
