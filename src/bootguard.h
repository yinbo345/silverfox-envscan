// ===========================================================================
//  bootguard.h — MBR 引导扇区防护（基线 + 5 秒级监视 + 自动拦截 + 可撤销恢复）
// ---------------------------------------------------------------------------
//  为什么需要：bootkit（引导型后门）改写磁盘引导代码后，先于 Windows 启动，
//  杀软极难清。银狐链条里「落地 → 自启」之后还可能走这一步建立终极持久化。
//  纯用户态能做的不是"拦住写盘那一瞬间"（那需要 minifilter），而是：
//    ① 基线：记住干净的扇区 0；
//    ② 监视：5 秒级轮询比对引导代码区（512B 读，开销近零）；
//    ③ 自动拦截：发现被改且近 10 分钟有行为规则标记过的可疑进程
//       → 终止该进程 + 隔离被改副本 + 基线写回（正经杀软的"自动处理"模式）；
//    ④ 可撤销：被隔离的副本留存取证，用户一键"撤销拦截"可写回（防误伤
//       用户亲手运行的磁盘/引导工具）。
//  无归因的变更（如磁盘分区工具合法改引导）不自动恢复，弹卡询问用户。
// ---------------------------------------------------------------------------
#pragma once
#include <string>

namespace boot {

// 单次校验结果
struct CheckResult {
    int status = 0;        // 0=一致 1=引导代码区被改(高危) 2=仅磁盘元数据变(已自动重立基线) 3=读盘失败/无基线
    std::string reason;    // 哈希/说明（进日志与告警卡）
};

// 一次引导扇区告警（服务层注册回调：写 findings + 右下角弹卡）
struct BootAlert {
    CheckResult cr;
    std::string procPath;           // 归因的可疑进程（可为空 = 被动告警）
    int         pid = 0;
    bool        autoHandled = false;   // true=已自动终止+恢复（撤销=写回隔离副本）
    bool        terminated = false;    // 自动终止是否成功
    std::string undoToken;          // 隔离副本 id（8 位 hex，autoHandled 时非空）
};

bool Init();                       // 基线加载/首建（服务启动时一次；成功才值得 StartWatch）
void SetStopEvent(void* ev);       // 透传服务停止事件 HANDLE（头文件不拖 windows.h）
void SetAlertCallback(void (*fn)(const BootAlert&));   // 告警回调（服务层：findings + 弹窗）
void StartWatch();                 // 启动 5 秒级监视线程（边沿触发回调，服务退出时自动结束）

// 行为引擎登记"刚被标记的可疑进程"（10 分钟归因窗）。
// 三个实时事件源（进程行为 / 落地捕获 / 自启动项）命中高危时都要调，
// 这样 MBR 一旦在可疑活动窗口期内被改，就能把变更归因到具体进程。
void NoteSuspicion(int pid, const std::string& path);

CheckResult CheckNow();            // 单次校验（快扫节奏兜底：监视线程意外退出后仍有人盯）
bool Restore();                    // 基线写回扇区 0（被动卡「恢复引导」按钮）
bool Accept();                     // 信任当前 MBR → 重立基线（被动卡「信任此变更」按钮）
bool UndoIntercept(const std::string& hexId);   // 撤销自动拦截：写回隔离副本并重立基线

// 管道 bootstatus 响应（弹窗卡归因回填 + GUI 展示）：
// {"baseline":true,"changed":false,"bootSha":"…","lastAlert":{...}}
std::string StatusJson();

}  // namespace boot
