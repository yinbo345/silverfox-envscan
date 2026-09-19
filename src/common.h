// common.h — 银狐主防程序共享基础模块
// 被 service（守护/服务）与 nmhost（原生消息宿主）两个可执行文件共用。
#pragma once
#include <string>

// 扫描结果结构定义（被 BuildResultJson 使用）
#include "scanner.h"

namespace sf {

// ---- 常量 ----
extern const wchar_t* SVC_NAME;        // Windows 服务名
extern const wchar_t* SVC_DISPLAY;     // 服务显示名
extern const wchar_t* PIPE_NAME;       // 命名管道 \\.\pipe\SilverFoxGuard
extern const char*    NM_HOST_NAME;    // Native Messaging 宿主名 com.silverfox.guard

// ---- 路径 ----
std::string GetExePath();              // 当前模块完整路径（ANSI）
std::string DirName(const std::string& path);
std::string BaseName(const std::string& path);
bool FileExists(const std::string& path);

// ---- 哈希 ----
std::string Sha256File(const std::string& path);
std::string Sha256Bytes(const void* data, size_t len);

// ---- JSON ----
std::string JsonEscape(const std::string& s);     // 转义 \ " 等
std::string JsonString(const std::string& s);     // 带引号、已转义的 JSON 字符串
// 极简字段提取：从 {"key":"value"} 中取出 key 对应的字符串值
std::string JsonGetString(const std::string& json, const std::string& key);
// 取出 key 对应的【数字】值（BuildResultJson 输出裸数字，故不能对 JsonGetString 的结果用 atoi）
int JsonGetInt(const std::string& json, const std::string& key);
// 把扫描结果序列化为 JSON（供管道 / 原生消息传输）
std::string BuildResultJson(const ScanResult& r);

// ---- 命名管道帧（4 字节小端长度前缀 + 负载）----
bool WriteFramed(HANDLE h, const std::string& msg);
bool ReadFramed(HANDLE h, std::string& out);

// ---- 系统通知 ----
// 环境异常时向交互式桌面用户发送系统消息（服务位于 Session 0，需跨会话推送）。
// 内部按状态切换去重：仅当状态较上次变化时弹一次，避免反复刷屏。
//   status = "infected"  → 高危告警（疑似中银狐）
//   status = "warning"   → 风险预警（存在可疑迹象）
//   status = "normal"    → 仅在由异常恢复时弹一次「已恢复正常」
//
// 后三个参数供「勒索回滚」场景使用（普通扫描告警留空即可）：
//   risk       = "high"    → 引擎已自动处置，卡片渲染「撤销我的处理」
//                "suspect" → 仅拦截未动手，卡片渲染「还原文件」询问按钮
//   undoToken  = 撤销凭据；非空时卡片会把 token 回传给服务调用 rollbackundo
//   rolledBack = 本次是否真的发生过覆盖写（false 则不显示撤销入口）
void NotifyAnomaly(const std::string& status, int score,
                   const std::string& risk = std::string(),
                   const std::string& undoToken = std::string(),
                   bool rolledBack = false);

// 调试日志（写 C:\ProgramData\SilverFoxGuard\guard.log，VM 也可访问）。
// 用于回捞弹窗 / 扫描链路在真实环境中的执行证据。
void LogDbg(const std::string& msg);

// 纯 C 版日志：签名只有 POD 参数，供 __except 块内使用。
// MSVC 不允许在 __try 所在函数里展开 C++ 对象（C2712），而 LogDbg 的
// std::string 参数会在调用点构造临时对象 —— 所以 SEH 处理块里必须用这个。
void LogDbgC(const char* msg);

// 在用户桌面会话渲染右下角 WebView2 通知（由服务跨会话拉起 --toast 模式调用）。
// 自带固定版本 WebView2 运行时（exe 同级 WebView2Runtime 目录），不依赖系统 Edge。
// 后三个参数为勒索回滚场景附加：risk（"high"/"suspect"）、undoToken、rolledBack。
int RunToast(const std::string& status, int score,
             const std::string& risk = std::string(),
             const std::string& undoToken = std::string(),
             bool rolledBack = false);

// 预热模式：在扫描进行期间提前创建 WebView2 环境（省去扫描完成后弹窗的冷启动 5~8 秒）。
// 预热完成后轮询结果文件，读到「正常」则静默退出不留进程；读到「异常」则原地渲染对应状态并显示。
int RunPrewarm();
int RunScanProgress();
int RunProbeToast(const std::wstring& fileW);   // 右键自定义查杀：连服务管道判定并渲染右下角卡片

// ---- Native Messaging 宿主注册表 ----
// 写清单 JSON 文件，返回其路径
bool WriteNmManifest(const std::string& hostExePath,
                     const std::string& extIdChrome,
                     const std::string& extIdEdge,
                     std::string& outManifestPath);
// 在 Chrome + Edge 的 NativeMessagingHosts 下写入指向清单的注册表项
bool RegisterNmHost(const std::string& manifestPath,
                    const std::string& extIdChrome,
                    const std::string& extIdEdge);
bool UnregisterNmHost();

// 记录 / 读取已配置的本机扩展 ID（供双击重装复用，避免丢失 allowed_origins）
bool SaveExtIds(const std::string& chrome, const std::string& edge);
bool ReadSavedExtIds(std::string& outChrome, std::string& outEdge);

// 受保护的配置根键（HKLM\SOFTWARE\SilverFoxGuard，安装时以管理员写入）
extern const char* CFG_ROOT;

}  // namespace sf
