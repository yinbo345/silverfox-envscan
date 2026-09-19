// service.cpp — 银狐主防服务：SCM 控制 / 守护循环 / 命名管道 / 安装
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <sddl.h>
#include <shlobj.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <wbemidl.h>
#include <unordered_map>
#include <map>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

#include "scanner.h"
#include "common.h"
#include "cleaner.h"
#include "compute.h"
#include "probe.h"
#include "rollback.h"
#include "service.h"
#include "behavior.h"   // 实时防护判定核心：JudgeProcess / MakeEntityOfPid / ProcEntity
#include "bootguard.h"  // MBR 引导扇区防护（基线 + 5 秒级监视 + 自动拦截 + 可撤销）

#pragma comment(lib, "advapi32.lib")

namespace sf {

SERVICE_STATUS        g_svcStatus{};
SERVICE_STATUS_HANDLE g_svcHandle = NULL;
HANDLE                g_stopEvent = NULL;
std::atomic<bool>     g_stop{false};

static void WmiProcessWatch();   // 定义见 GuardThread 之前（WMI 实时进程创建监听）
static void RegRunWatch();       // 注册表自启动项实时监控（第二个实时防护事件源）
static void LandedAlertWatch();  // 落地捕获消费线程（第三个实时防护事件源，2026-09-19）

// ---------------------------------------------------------------------------
//  ⚠️ 线程级异常兜底（2026-09-18 新增，架构级加固）
//
//  旧架构的致命缺失：ServiceMain 起三个线程后直接 WaitForSingleObject(INFINITE)，
//  **假设只要服务没被停止，进程就永远活着**。但 C++ 异常（std::bad_alloc /
//  越界 / 第三方 COM 抛出的异常）从任何一个工作线程逃逸出去，CRT 会直接调
//  std::terminate() → 进程静默死亡，日志"干净地断掉"、WIN32_EXIT_CODE 为 0，
//  服务管理器只会按 sc failure 策略把它拉起来 —— 用户看到的是"莫名其妙重启"。
//
//  这里给每个工作线程套两层兜底：
//    ① __try/__except 兜住 SEH（访问违例、除零等硬件级异常）；
//    ② try/catch(...) 兜住 C++ 异常（bad_alloc、第三方 COM 抛出的等）。
//
//  ⚠️ MSVC 限制：同一个函数里不能既用 __try 又想展开 C++ 对象（C2712/C2713）。
//  所以必须拆成两个函数：外层只做 SEH（函数体内无任何需要析构的对象），
//  内层做 C++ 异常捕获。两层各自独立，互不干扰。
// ---------------------------------------------------------------------------
// 内层：捕获 C++ 异常（此函数体内禁止出现 __try）
static void ThreadBodyCxx(const char* name, void(*fn)()) {
    try {
        fn();
    } catch (const std::exception& e) {
        LogDbg(std::string("[fatal] 线程 ") + name + " 抛出 C++ 异常: " + e.what() + "（已捕获，服务继续运行）");
    } catch (...) {
        LogDbg(std::string("[fatal] 线程 ") + name + " 抛出未知 C++ 异常（已捕获，服务继续运行）");
    }
}

// 外层：捕获 SEH。注意本函数内**不得声明任何需要析构的对象**，
// 否则 MSVC 报 C2712「无法在需要对象展开的函数中使用 __try」。
static void RunThreadGuard(const char* name, void(*fn)()) {
    DWORD sehCode = 0;
    char buf[160];   // 栈上定长缓冲：POD，不触发对象展开
    __try {
        ThreadBodyCxx(name, fn);
    } __except (sehCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        // 这里只能用 LogDbgC（纯 C）—— LogDbg 的 std::string 参数会在调用点
        // 构造临时对象，直接触发 C2712。
        snprintf(buf, sizeof(buf),
                 "[fatal] 线程 %s 触发结构化异常 0x%08X（已捕获，服务继续运行）",
                 name, (unsigned)sehCode);
        LogDbgC(buf);
    }
    // 注：此处不再无条件打印"已退出"——pipe/wmi 线程正常退出也会走到这里，
    // 只有真的异常退出才需要告警，上面两条日志已经覆盖。
}

// 普通清除（cmd=clean）后仍失败的目标清单，供「高级清除（cmd=clean_adv）」阶段消费
static std::vector<std::string> g_failedTargets;
static std::mutex               g_failedMtx;

// rescan 去重：全盘扫描 ~20 秒，用户连点「立即检查」会连发多个 rescan。
// exchange=true 表示已有全盘在跑，后到的 rescan 直接回缓存结果，不再排队重扫。
static std::atomic<bool> g_rescanBusy{ false };

void RequestStop() { g_stop.store(true); if (g_stopEvent) SetEvent(g_stopEvent); }
bool IsStopRequested() { return g_stop.load(); }

// ---------------------------------------------------------------------------
//  清除历史（NDJSON 追加写）：扩展端「清除记录」卡片的数据源。
//  每行一条 JSON 记录；读取时取最后 50 行，避免无限增长。
// ---------------------------------------------------------------------------
static std::wstring HistoryPathW() {
    wchar_t p[MAX_PATH] = { 0 };
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\clean_history.ndjson";
}

static std::string NowStr() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::ostringstream os;
    os << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return os.str();
}

// 每次清除（普通 / 高级）完成后追加一条记录
static void AppendCleanHistory(const char* mode, const CleanReport& rep) {
    std::string line = "{\"time\":\"" + NowStr() + "\",\"mode\":\"" + mode + "\"";
    line += ",\"requested\":" + std::to_string(rep.requested);
    line += ",\"deleted\":"   + std::to_string(rep.deleted);
    line += ",\"deferred\":"  + std::to_string(rep.deferred);
    line += ",\"failed\":"    + std::to_string(rep.failed);
    line += ",\"killed\":"    + std::to_string(rep.killed);
    line += ",\"extraDlls\":" + std::to_string(rep.extraDlls);
    line += ",\"items\":[";
    for (size_t i = 0; i < rep.items.size(); ++i) {
        if (i) line += ",";
        line += "{\"path\":" + JsonString(rep.items[i].path);
        line += ",\"action\":" + JsonString(rep.items[i].action);
        line += ",\"reason\":" + JsonString(rep.items[i].reason) + "}";
    }
    line += "]}\n";
    HANDLE h = CreateFileW(HistoryPathW().c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, line.data(), (DWORD)line.size(), &w, nullptr);
    CloseHandle(h);
}

// 供 cmd=history：读 NDJSON 最后 50 行，拼成扩展可直接渲染的响应帧
static std::string BuildHistoryJson() {
    std::vector<std::string> lines;
    std::ifstream f(HistoryPathW());
    if (f) {
        std::string ln;
        while (std::getline(f, ln)) {
            if (!ln.empty()) lines.push_back(ln);
            if (lines.size() > 200) lines.erase(lines.begin());   // 防超大文件读爆内存
        }
    }
    size_t start = lines.size() > 50 ? lines.size() - 50 : 0;
    std::string s = "{\"type\":\"clean_history\",\"records\":[";
    for (size_t i = start; i < lines.size(); ++i) {
        if (i > start) s += ",";
        s += lines[i];
    }
    s += "]}";
    return s;
}

// ---------------------------------------------------------------------------
//  服务控制处理
// ---------------------------------------------------------------------------
static DWORD WINAPI HandlerEx(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    switch (ctrl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_svcStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_svcHandle, &g_svcStatus);
            RequestStop();
            break;
        case SERVICE_CONTROL_INTERROGATE:
        default: break;
    }
    SetServiceStatus(g_svcHandle, &g_svcStatus);
    return NO_ERROR;
}

// ---------------------------------------------------------------------------
//  正经杀软模式的统一处置/撤销层（2026-09-19，银泊指示）
// ---------------------------------------------------------------------------
//  撤销 token 统一 10 位 hex：前 2 位是类型码，后 8 位是事件 id ——
//  NotifyAnomaly 对 undoToken 做 [0-9a-f] 白名单过滤（命令行是外部可写边界），
//  所以类型码必须编码进 hex 而不是用 "boot:" 这类带冒号前缀。
//    10xxxxxx = 引导扇区（撤销 = 写回隔离副本）   → boot::UndoIntercept
//    20xxxxxx = 自启动项（撤销 = 写回注册表原值）
//    30xxxxxx = 落地隔离（撤销 = 把文件移回原位）
//    其余     = 勒索回滚（撤销 = 反向回滚）        → rb::UndoLastRollback
struct UndoRec {
    int kind = 0;               // 2=自启动项 3=落地隔离
    std::string a, b, c, d;     // kind=2: hive|keypath|valueName|data  kind=3: 隔离路径|原路径
};
static std::mutex g_undoMtx;
static std::map<std::string, UndoRec> g_undoMap;   // id(hex) → 记录

static std::string NewUndoId() {
    char b[16];
    snprintf(b, sizeof(b), "%08x", (unsigned)(GetTickCount() & 0xFFFFFFFE) | 1);
    return b;
}

// 右下角自动拦截卡的数据源：toast 卡 JS 加载时经管道取 lastalert 回填
// 「某某程序正在干嘛」的归因文本（卡片 HTML 是静态的，进程名不能走命令行 —— 注入面）。
static std::mutex g_lastAlertMtx;
static std::string g_lastAlertJson = "{}";
static void SetLastAlertInfo(const std::string& title, const std::string& sub,
                             const std::string& proc) {
    std::string js = "{\"title\":" + sf::JsonString(title);
    js += ",\"sub\":"  + sf::JsonString(sub);
    js += ",\"proc\":" + sf::JsonString(proc) + "}";
    std::lock_guard<std::mutex> lk(g_lastAlertMtx);
    g_lastAlertJson = js;
}
static std::string LastAlertJson() {
    std::lock_guard<std::mutex> lk(g_lastAlertMtx);
    return g_lastAlertJson;
}

// 落地载荷自动隔离：移入 ProgramData 隔离目录（可撤销）。返回撤销 id（失败返回空）。
static std::string QuarantineLanded(const std::string& path) {
    std::wstring dir;
    {
        wchar_t p[MAX_PATH] = {0};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
            dir = std::wstring(p) + L"\\SilverFoxGuard\\quarantine";
        else dir = L"C:\\ProgramData\\SilverFoxGuard\\quarantine";
    }
    CreateDirectoryW(dir.c_str(), nullptr);
    std::string id = NewUndoId();
    // 同名碰撞：id 带时间与自增位，冲突时简单放弃（概率可忽略）
    std::wstring dst = dir + L"\\l_" + std::wstring(id.begin(), id.end()) + L".qtn";
    int needed = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    std::wstring wsrc(needed > 0 ? needed - 1 : 0, L'\0');
    if (needed > 1) MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wsrc[0], needed);
    if (!MoveFileW(wsrc.c_str(), dst.c_str())) return "";
    std::lock_guard<std::mutex> lk(g_undoMtx);
    if (g_undoMap.size() > 64) g_undoMap.clear();
    UndoRec r; r.kind = 3; r.a = std::string(dst.begin(), dst.end()); r.b = path;
    g_undoMap[id] = r;
    return id;
}

// 可疑自启动项自动移除：删除注册表值（原值记录在案，可撤销写回）。返回撤销 id。
static std::string RemoveAutorunValue(const std::string& loc) {
    // loc 格式（RegRunWatch collect 产出）："HKLM|path|valueName" / "HKCU|..." / "HKU|sid\path|name"
    size_t p1 = loc.find('|');
    size_t p2 = loc.rfind('|');
    if (p1 == std::string::npos || p2 == std::string::npos || p2 <= p1) return "";
    std::string hive = loc.substr(0, p1);
    std::string keyp = loc.substr(p1 + 1, p2 - p1 - 1);
    std::string name = loc.substr(p2 + 1);
    HKEY root = (hive == "HKLM") ? HKEY_LOCAL_MACHINE
              : (hive == "HKCU") ? HKEY_CURRENT_USER : HKEY_USERS;
    // 先读原值（撤销要用）
    char data[8192] = {0}; DWORD ds = sizeof(data) - 1, type = 0;
    std::string orig;
    {
        HKEY hk;
        if (RegOpenKeyExA(root, keyp.c_str(), 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hk, name.c_str(), nullptr, &type, (LPBYTE)data, &ds) == ERROR_SUCCESS)
                orig = std::string(data, ds ? ds - 1 : 0);
            RegCloseKey(hk);
        }
    }
    HKEY hk;
    if (RegOpenKeyExA(root, keyp.c_str(), 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return "";
    LSTATUS st = RegDeleteValueA(hk, name.c_str());
    RegCloseKey(hk);
    if (st != ERROR_SUCCESS) return "";
    std::string id = NewUndoId();
    std::lock_guard<std::mutex> lk(g_undoMtx);
    if (g_undoMap.size() > 64) g_undoMap.clear();
    UndoRec r; r.kind = 2; r.a = hive; r.b = keyp; r.c = name; r.d = orig;
    g_undoMap[id] = r;
    return id;
}

// 统一撤销入口：rollbackundo 管道命令按 token 前缀分发到这里/回滚引擎。
// 返回 report JSON（与 BuildUndoResultHtml 的解析格式对齐）。
static std::string UniversalUndo(const std::string& token) {
    if (token.size() == 10) {
        std::string kind = token.substr(0, 2);
        std::string id   = token.substr(2);
        if (kind == "10") {
            bool ok = boot::UndoIntercept(id);
            if (ok) LogDbg("[undo] 引导扇区拦截已撤销（token=" + token + "）");
            return std::string("{\"ok\":") + (ok ? "true" : "false") +
                   ",\"restored\":0,\"failed\":0,\"reason\":\"" +
                   (ok ? "引导记录已写回隔离副本，并重立基线。"
                       : "撤销失败：隔离副本不存在或写入被拒。") + "\"}";
        }
        if (kind == "20") {
            std::lock_guard<std::mutex> lk(g_undoMtx);
            auto it = g_undoMap.find(id);
            if (it == g_undoMap.end())
                return std::string("{\"ok\":false,\"restored\":0,\"failed\":0,\"reason\":\"记录已失效（服务重启后撤销窗口失效）。\"}");
            const UndoRec& r = it->second;
            HKEY root = (r.a == "HKLM") ? HKEY_LOCAL_MACHINE
                      : (r.a == "HKCU") ? HKEY_CURRENT_USER : HKEY_USERS;
            HKEY hk;
            bool ok = false;
            if (RegOpenKeyExA(root, r.b.c_str(), 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
                ok = RegSetValueExA(hk, r.c.c_str(), 0, REG_SZ, (const BYTE*)r.d.c_str(),
                                    (DWORD)(r.d.size() + 1)) == ERROR_SUCCESS;
                RegCloseKey(hk);
            }
            if (ok) g_undoMap.erase(it);
            if (ok) LogDbg("[undo] 自启动项已撤销移除：" + r.a + "|" + r.b + "|" + r.c);
            return std::string("{\"ok\":") + (ok ? "true" : "false") +
                   ",\"restored\":0,\"failed\":0,\"reason\":\"" +
                   (ok ? "自启动项已写回注册表。"
                       : "写回注册表失败（权限不足或键已失效）。") + "\"}";
        }
        if (kind == "30") {
            std::lock_guard<std::mutex> lk(g_undoMtx);
            auto it = g_undoMap.find(id);
            if (it == g_undoMap.end())
                return std::string("{\"ok\":false,\"restored\":0,\"failed\":0,\"reason\":\"隔离记录已失效。\"}");
            const UndoRec& r = it->second;
            int w1 = MultiByteToWideChar(CP_UTF8, 0, r.a.c_str(), -1, nullptr, 0);
            std::wstring wsrc(w1 > 0 ? w1 - 1 : 0, L'\0');
            if (w1 > 1) MultiByteToWideChar(CP_UTF8, 0, r.a.c_str(), -1, &wsrc[0], w1);
            int w2 = MultiByteToWideChar(CP_UTF8, 0, r.b.c_str(), -1, nullptr, 0);
            std::wstring wdst(w2 > 0 ? w2 - 1 : 0, L'\0');
            if (w2 > 1) MultiByteToWideChar(CP_UTF8, 0, r.b.c_str(), -1, &wdst[0], w2);
            bool ok = MoveFileW(wsrc.c_str(), wdst.c_str()) != FALSE;
            if (ok) g_undoMap.erase(it);
            if (ok) LogDbg("[undo] 落地隔离已撤销，文件已移回原位：" + r.b);
            return std::string("{\"ok\":") + (ok ? "true" : "false") +
                   ",\"restored\":0,\"failed\":0,\"reason\":\"" +
                   (ok ? "文件已移回原位。"
                       : "移回失败：目标位置被占用或文件已失。") + "\"}";
        }
    }
    return rb::UndoLastRollback(token);
}

// ---------------------------------------------------------------------------
//  MBR 告警回调（bootguard 监视线程内执行）：写 findings + 右下角弹专用卡。
//  弹卡去重：自动拦截卡弹一次就够（引导已恢复，用户可不理会）；被动告警
//  （无归因，等用户决定）30 分钟未处理重提一次，避免"弹一次就石沉大海"。
// ---------------------------------------------------------------------------
static std::mutex g_bootAlertMtx;
static bool       g_bootActive = false;
static ULONGLONG  g_bootLastTick = 0;

static void OnBootAlert(const boot::BootAlert& al) {
    {
        std::lock_guard<std::mutex> lk(g_bootAlertMtx);
        if (g_bootActive) {
            if (al.autoHandled) return;                                   // 自动拦截不重复弹
            if (GetTickCount64() - g_bootLastTick < 30ull * 60 * 1000) return;
        }
        g_bootActive = true;
        g_bootLastTick = GetTickCount64();
    }
    std::string procName = al.procPath.empty() ? "" : sf::BaseName(al.procPath);
    std::string title, sub;
    if (al.autoHandled) {
        title = "已自动拦截 · 引导扇区修改";
        sub   = "「" + (procName.empty() ? "可疑程序" : procName) +
                "」正在修改系统引导扇区（MBR），已自动终止该进程" +
                (al.terminated ? "" : "（进程可能已退出）") +
                "并用基线恢复引导记录。若这是你亲手运行的磁盘/引导工具，可点「撤销拦截」还原。";
    } else {
        title = "引导扇区被修改";
        sub   = "检测到系统引导代码区（MBR）与安装基线不一致。若你近期没有安装系统或引导管理工具，"
                "这可能是 bootkit 正在建立开机持久化，建议「恢复引导」；磁盘工具的合法改动请选「信任此变更」。";
    }
    if (!al.cr.reason.empty()) sub += "\n" + al.cr.reason;
    SetLastAlertInfo(title, sub, procName);
    {
        std::lock_guard<std::mutex> lk(g_resultMutex);
        g_result.findings.push_back({"引导防护", "高", title, sub + "\n" + al.procPath,
                                     procName, al.procPath});
        g_result.status = "infected";
        if (g_result.score < 200) g_result.score = 200;
        g_result.timestamp = NowStr();
    }
    // token 前缀 "10"（hex），NotifyAnomaly 的 [0-9a-f] 过滤可原样放行
    sf::NotifyAnomaly("infected", 200, "mbr",
                      al.autoHandled ? ("10" + al.undoToken) : std::string(),
                      al.autoHandled);
}

// 快扫节奏的 MBR 兜底校验：监视线程意外退出或错过边沿时，
// 仍保证"最多 3 分钟必有人看一次引导扇区"。
static void BootScanTick() {
    boot::CheckResult cr = boot::CheckNow();
    if (cr.status != 1) return;
    boot::BootAlert a;
    a.cr = cr;
    OnBootAlert(a);   // 被动告警路径（无归因，弹询问卡）
}

static void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_svcStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_svcStatus.dwCurrentState     = SERVICE_START_PENDING;
    g_svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_svcStatus.dwWin32ExitCode    = 0;
    g_svcStatus.dwServiceSpecificExitCode = 0;
    g_svcStatus.dwCheckPoint = 0;
    g_svcStatus.dwWaitHint   = 3000;

    g_stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_svcHandle = RegisterServiceCtrlHandlerExW(SVC_NAME, HandlerEx, NULL);
    if (!g_svcHandle) { if (g_stopEvent) CloseHandle(g_stopEvent); return; }

    g_svcStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_svcHandle, &g_svcStatus);

    // 三个工作线程全部经 RunThreadGuard 包裹：任何异常/结构化异常都就地吞掉并记日志，
    // 绝不允许从线程逃逸出去把服务进程带走（旧架构的致命缺失，见 RunThreadGuard 注释）。
    std::thread guard([] { RunThreadGuard("guard", GuardThread); });
    std::thread pipe([] { RunThreadGuard("pipe", PipeServerThread); });
    std::thread wmi([] { RunThreadGuard("wmi", WmiProcessWatch); });
    std::thread regrun([] { RunThreadGuard("regrun", RegRunWatch); });
    // 落地捕获消费线程：把回滚引擎的"落盘初筛结果"接到进程判定链上
    // （银狐链条「下载→落盘→自启」的**第二步**就被捕获，早于进程创建事件）
    std::thread landed([] { RunThreadGuard("landed", LandedAlertWatch); });

    // ---- MBR 引导扇区防护（2026-09-19 新增，银泊指示"要像正经杀软一样"）----
    // 基线加载/首建 → 注册告警回调 → 启动 5 秒级监视线程。
    // 监视线程发现引导代码区被改且近 10 分钟有可疑进程活动 → 自动终止 + 恢复引导 +
    // 弹卡（可撤销）；无归因 → 弹卡询问（恢复引导 / 信任此变更）。
    boot::SetStopEvent(g_stopEvent);
    boot::SetAlertCallback(&OnBootAlert);
    if (boot::Init()) boot::StartWatch();

    // ---- 勒索回滚引擎（对齐卡巴 System Watcher 的写前快照 + 回滚）----
    // 与扫描线程并行独立运行：扫描是"事后体检"（分钟级），回滚是"实时拦截"
    // （毫秒级），两者的时间尺度差三个数量级，必须分线程。
    rb::SetStopEvent(g_stopEvent);     // 让监控线程能随服务一起退出
    // 注入告警回调：引擎只管"判定 + 回滚"，展示（写扫描结果 + 弹窗）由服务层负责
    //
    // ---- 三层处置模型的上报端（详见 rollback.h 的说明）----
    //  高风险：引擎**已经**自动终止进程 + 自动回滚（不等用户确认 —— 勒索爆发时
    //          每等一秒就多一批文件被加密）。这里只把结果写进扫描结果并弹窗
    //          **告知**，同时标记"本次处置可撤销"——判定可能误伤（备份软件批量
    //          操作等），必须留反悔通道。
    //  可疑：引擎未动手，弹窗询问用户是否处理（前端走 rollbackdo 命令）。
    rb::SetDetectionCallback([](const rb::DetectionInfo& info) {
        bool highRisk = (info.risk == rb::Risk::High);
        bool didRollback = (info.restored > 0);   // 覆盖写是否真的发生过
        std::string detail;
        if (highRisk && info.autoHandled) {
            detail = info.trigger + "。已自动终止并回滚恢复 " +
                     std::to_string(info.restored) + " 个文件";
            if (info.unrecoverable)
                detail += "，另有 " + std::to_string(info.unrecoverable) +
                          " 个文件因无可用快照未能恢复";
            detail += "。";
            if (info.undoable)
                detail += "若判断有误，可在右下角通知卡点「撤销我的处理」还原。";
        } else {
            detail = info.trigger + "。已拦截该操作，等待你确认是否还原文件。";
        }
        if (!info.processPath.empty())
            detail += "肇事进程：" + info.processPath + "（PID " + std::to_string(info.pid) + "）";
        {
            std::lock_guard<std::mutex> lk(g_resultMutex);
            std::string sev = info.unrecoverable ? "中" : "高";
            bool dup = false;
            for (const auto& f : g_result.findings)
                if (f.category == "勒索回滚") { dup = true; break; }
            if (!dup)
                g_result.findings.push_back({ "勒索回滚", sev,
                                              highRisk ? "勒索行为已拦截并回滚" : "检测到疑似勒索操作",
                                              detail, info.processPath, info.processPath, 90 });
            // 无论是否已有一条，都置为异常状态 —— 勒索是**进行中的破坏**，
            // 不像普通可疑项可以留在"预警"档观察。
            g_result.status = "infected";
            if (g_result.score < 200) g_result.score = 200;
            g_result.timestamp = NowStr();
        }
        LogDbg("[rollback] 告警已上报: " + detail);
        // 弹窗参数：
        //   risk=high + 真的覆盖写过 → 带上撤销凭据，弹窗会渲染「撤销我的处理」按钮
        //   risk=high + 未覆盖写   → 无须撤销，只告知
        //   risk=suspect            → 弹窗询问用户是否处理
        //   rolling 标志：回滚动作会**写回**大批文件，扩展端在窗口期内看到的状态是
        //   "正在恢复中"；这里传出窗口剩余毫秒，让卡片上的说明与实际进度对得上，
        //   而不是弹窗刚出来就宣称"已恢复正常"（那是撤回报文与磁盘状态不一致的旧 bug）。
        {
            std::string riskStr = highRisk ? "high" : "suspect";
            std::string undo = (info.undoable && didRollback) ? info.undoToken : std::string();
            NotifyAnomaly("infected", 200, riskStr, undo, didRollback);
        }
    });
    rb::Start();

    // GPU 加速开关若已打开（注册表 gpu_scan=1），启动后自动把「特征地图」载入显存，
    // 与「打开开关即加载」保持一致（加载进度可经管道命令 gpuprog 查询）。
    if (compute::IsGpuEnabled()) compute::LoadMapAsync();

    WaitForSingleObject(g_stopEvent, INFINITE);
    if (guard.joinable()) guard.join();
    if (pipe.joinable()) pipe.join();
    if (wmi.joinable()) wmi.join();
    if (regrun.joinable()) regrun.join();
    if (landed.joinable()) landed.join();

    // 服务停止：先停回滚引擎（保留已建立的快照，供下次启动继续使用），
    // 再释放显存中的地图与全部 GPU 资源
    rb::Stop();
    compute::UnloadMap();

    g_svcStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_svcHandle, &g_svcStatus);
}

void RunService() {
    // 进程级单实例：防止服务被重复拉起（重复实例会争抢命名管道）
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"Global\\SilverFoxGuardService");
    if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return;   // 已有实例在后台运行，直接退出
    }
    SERVICE_TABLE_ENTRYW table[] = {
        { (LPWSTR)SVC_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcherW(table);
    if (hMutex) CloseHandle(hMutex);
}

// ---------------------------------------------------------------------------
//  守护循环（后台定期扫描）
//
//  ⚠️ 2026-09-18 架构修正（用户实测「每 3 分钟全盘扫描 + 弹窗」的真因）
//
//  旧实现：启动自检跑一次【快扫 + 全盘扫】，然后每 180 秒又跑一次【全盘扫】。
//  全盘扫一轮要遍历 10000+ 文件（含 GPU 深度内容扫描 200000 候选预算），单轮
//  实测 40~90 秒 —— 也就是说**一半以上的时间都在扫盘**，用户观感就是"它一直在扫"。
//
//  更糟的是：全盘扫恰好是 GPU 崩溃的触发点（nvwgf2umx.dll 0xC0000005）。崩了
//  → SCM 按 sc failure 策略 60 秒后重启 → 启动自检又立刻跑一遍快扫+全盘扫
//  → 又崩。用户看到的就是"每 3 分钟扫描一次 + 弹窗"，实际是崩溃重启循环。
//
//  新架构：**分层调度**——重活（全盘扫）降到 6 小时一次并与启动错开，轻活
//  （快扫：只看系统目录与可疑落点）保持 3 分钟一次。这样实时性不丢，CPU/IO
//  占用下降两个数量级，也把 GPU 崩溃的暴露面从"每 3 分钟一次"降到"每 6 小时一次"。
// ---------------------------------------------------------------------------
// 快扫间隔：只扫常规落点 + 已知样本父目录，秒级完成（实时性靠它）
static const DWORD QUICK_SCAN_INTERVAL_MS = 180000;      // 3 分钟
// 全盘精扫间隔：遍历全盘可写目录，分钟级（完整性靠它）
static const DWORD FULL_SCAN_INTERVAL_MS  = 6 * 3600 * 1000;   // 6 小时
// 启动后延迟多久才做首轮全盘精扫：避开开机高峰，也让快扫先出结果
static const DWORD FULL_SCAN_STARTUP_DELAY_MS = 120000;  // 2 分钟

// 状态切换去重：仅当本次状态与上次通知状态不同才弹通知，避免每轮扫描刷屏。
// 首启若为 normal 不弹；之后任何切换（含由异常恢复正常）都弹一次。
//
// ⚠️ 双重去抖（2026-09-18 加固，用户实测「每 3 分钟弹一次」）：
//   ① 状态基线：g_lastToastStatus 跨轮次记忆，同状态不重复弹。
//   ② 升级即时 / 降级滞回：normal→warning/infected 立即弹（风险要马上告知）；
//      warning↔normal 这类「降级」必须连续 DEGRADE_CONFIRM 轮保持才认账并弹，
//      避免单个间歇性发现项（如短暂的高熵临时文件）让状态来回抖动、每轮都弹窗。
//
// ⚠️ 基线持久化（2026-09-18 新增，架构级修复）
//
// 旧实现把基线放在【进程内静态变量】里，服务一重启就清空 → 重启后第一轮扫描
// 必然被当成"新变化"而弹窗。这本身不算错（首启 normal 会跳过），但只要有任何
// 残留发现项（如桌面自建工具被标旁证），每次重启都会弹一次 —— 用户观感就是
// "它老是弹窗"。而服务重启是**常态**：SCM 故障恢复、安装更新、手动重启、
// 崩溃拉起都会触发。所以基线必须落盘。
//
// 落盘文件：<ProgramData>\SilverFoxGuard\toast_state.txt，单行纯文本存上一个
// 已通知过的状态。写入用原子替换（先写 .tmp 再 MoveFileEx）避免半截文件。
static std::string g_lastToastStatus;
static std::string g_pendingStatus;      // 待确认的降级目标状态（连续命中才认账）
static int         g_pendingCount = 0;
static const int   DEGRADE_CONFIRM = 2;  // 降级需连续保持的轮数

static std::wstring ToastStatePathW() {
    wchar_t p[MAX_PATH] = { 0 };
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\toast_state.txt";
}

static void SaveToastBaseline(const std::string& status) {
    std::wstring path = ToastStatePathW();
    std::wstring tmp  = path + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD wn = 0;
    WriteFile(h, status.data(), (DWORD)status.size(), &wn, nullptr);
    CloseHandle(h);
    // 原子替换：避免读到写了一半的文件
    MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING);
}

static std::string LoadToastBaseline() {
    std::string s;
    HANDLE h = CreateFileW(ToastStatePathW().c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return s;   // 首次运行：无基线
    char buf[64] = { 0 };
    DWORD got = 0;
    if (ReadFile(h, buf, sizeof(buf) - 1, &got, nullptr) && got > 0) s.assign(buf, got);
    CloseHandle(h);
    // 清掉可能的空白/换行
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
    return s;
}

// 上一轮扫描的**时间戳**（用于判断"距离上次扫描过了多久"，决定重启后该不该补扫）。
// 存在同一文件里更省事，但为保持格式简单，单独记一个文件。
static std::wstring LastScanPathW() {
    wchar_t p[MAX_PATH] = { 0 };
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\last_scan.txt";
}
static void SaveLastScanTime() {
    auto now = std::chrono::system_clock::now();
    long long sec = (long long)std::chrono::system_clock::to_time_t(now);
    std::string s = std::to_string(sec);
    std::wstring tmp = LastScanPathW() + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD wn = 0;
    WriteFile(h, s.data(), (DWORD)s.size(), &wn, nullptr);
    CloseHandle(h);
    MoveFileExW(tmp.c_str(), LastScanPathW().c_str(), MOVEFILE_REPLACE_EXISTING);
}
static long long LoadLastScanTime() {
    HANDLE h = CreateFileW(LastScanPathW().c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    char buf[32] = { 0 };
    DWORD got = 0;
    long long v = 0;
    if (ReadFile(h, buf, sizeof(buf) - 1, &got, nullptr) && got > 0) v = _atoi64(buf);
    CloseHandle(h);
    return v;
}

// 是否为「降级」迁移（风险等级下降：infected→warning→normal）
static int RiskRank(const std::string& s) {
    if (s == "infected") return 2;
    if (s == "warning")  return 1;
    return 0;   // normal / 空
}

static void CheckAndNotify() {
    std::lock_guard<std::mutex> lk(g_resultMutex);
    if (g_result.status == g_lastToastStatus) {
        g_pendingStatus.clear();
        g_pendingCount = 0;
        LogDbg("[check] skip: status unchanged (" + g_result.status + ")");
        return;
    }
    // 复读卡防护（2026-09-19）：回滚引擎判定时**已经直弹过卡**（SetDetectionCallback
    // 里的 NotifyAnomaly），它写进 g_result 的 infected 状态若再被周期体检发现，
    // 就会对同一事件弹第二张「环境异常」卡。检测到当前异常来自引擎写入的
    // 「勒索回滚」发现项时，这里只同步基线、不再弹窗。
    bool fromLiveEngine = false;
    for (const auto& f : g_result.findings)
        if (f.category == "勒索回滚") { fromLiveEngine = true; break; }
    if (fromLiveEngine && g_result.status != "normal") {
        g_lastToastStatus = g_result.status;
        SaveToastBaseline(g_lastToastStatus);
        LogDbg("[check] skip: 异常状态来自回滚引擎实时处置（已弹过卡），仅同步基线");
        return;
    }
    const std::string prev = g_lastToastStatus;
    const bool isDowngrade = !prev.empty() &&
                             RiskRank(g_result.status) < RiskRank(prev);
    if (isDowngrade) {
        // 降级滞回：连续 DEGRADE_CONFIRM 轮看到同一目标状态才认账，
        // 期间只要回升（或又变了）就重置计数，不弹窗。
        if (g_pendingStatus == g_result.status) {
            ++g_pendingCount;
        } else {
            g_pendingStatus = g_result.status;
            g_pendingCount  = 1;
        }
        if (g_pendingCount < DEGRADE_CONFIRM) {
            LogDbg("[check] hold: downgrade pending " + prev + " -> " + g_result.status +
                   " (" + std::to_string(g_pendingCount) + "/" + std::to_string(DEGRADE_CONFIRM) + ")");
            return;
        }
    }
    g_pendingStatus.clear();
    g_pendingCount = 0;
    g_lastToastStatus = g_result.status;
    SaveToastBaseline(g_lastToastStatus);   // 落盘：服务重启后基线不丢
    if (prev.empty() && g_result.status == "normal") {
        LogDbg("[check] skip: first-run normal");
        return;   // 首启即正常：不打扰
    }
    LogDbg("[check] trigger toast: status=" + g_result.status + " score=" + std::to_string(g_result.score));
    sf::NotifyAnomaly(g_result.status, g_result.score);
}

// 只同步「上次已通知状态」而不弹窗。用于清除成功后立刻重扫的场景：
// 清理结果由发起方（弹窗卡片 / 扩展面板）自行呈现，不该再额外弹一次「环境已恢复正常」；
// 但若不同步基线，下一轮定时扫描又会把这次变化判成新变化而弹窗。
static void SyncLastToastStatus() {
    std::lock_guard<std::mutex> lk(g_resultMutex);
    g_lastToastStatus = g_result.status;
    SaveToastBaseline(g_lastToastStatus);
    LogDbg("[check] sync baseline: " + g_result.status);
}

// 清除报告 → JSON 片段（不含外层大括号，供并入扫描结果帧）
static std::string BuildCleanJson(const CleanReport& rep) {
    std::string s = "\"clean\":{";
    s += "\"requested\":" + std::to_string(rep.requested) + ",";
    s += "\"deleted\":"   + std::to_string(rep.deleted)   + ",";
    s += "\"deferred\":"  + std::to_string(rep.deferred)  + ",";
    s += "\"failed\":"    + std::to_string(rep.failed)    + ",";
    s += "\"skipped\":"   + std::to_string(rep.skipped)   + ",";
    s += "\"killed\":"    + std::to_string(rep.killed)    + ",";
    s += "\"extraDlls\":" + std::to_string(rep.extraDlls) + ",";
    s += "\"killedNames\":[";
    for (size_t i = 0; i < rep.killedNames.size(); ++i) {
        if (i) s += ",";
        s += JsonString(rep.killedNames[i]);
    }
    s += "],\"items\":[";
    for (size_t i = 0; i < rep.items.size(); ++i) {
        if (i) s += ",";
        s += "{\"path\":"   + JsonString(rep.items[i].path)   + ",";
        s += "\"action\":"  + JsonString(rep.items[i].action) + ",";
        s += "\"reason\":"  + JsonString(rep.items[i].reason) + "}";
    }
    s += "]}";
    return s;
}

// P3 主动防御：WMI 实时进程创建监听。银狐落地「发现即处置」——
// 用 __InstanceCreationEvent 订阅 Win32_Process 创建事件，对新进程走**双路判定**：
//   ① 文件启发式 QuickProbeExecutable(path)      —— 抓「随机名落地 / 可疑路径 / PE 异常」
//   ② 行为判定   sf::JudgeProcess(MakeEntityOfPid) —— 抓「命令行 / 父子链 / 白利用 / 注入」
// 任一命中即写 g_result.findings（扩展面板实时可见，无需等下一轮定时扫描）。
//
// ⚠️ 2026-09-19 增强（原实现只做 ①，检测面过窄）：
//   旧版仅取 ExecutablePath 调 QuickProbeExecutable，实测 `[real-time]` 命中 **0 次** ——
//   因为银狐的投递链特征是「正常名宿主进程 + 恶意命令行」（如
//   `mshta.exe javascript:...` / `rundll32.exe javascript:...` / `regsvr32.exe /s /u /i:http://...`），
//   或「Office/WPS 拉起 powershell」这类父子链异常 —— **ExecutablePath 永远是白文件**，
//   只看路径必然全漏。现补齐 CommandLine + ParentProcessId + 父子链三路输入。
class WmiSink : public IWbemObjectSink {
    LONG m_ref = 1;
public:
    ULONG STDMETHODCALLTYPE AddRef() override { return (ULONG)InterlockedIncrement(&m_ref); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return (ULONG)r;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) { *ppv = this; AddRef(); return S_OK; }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Indicate(LONG lObjCount, IWbemClassObject** apObjArray) override {
        for (LONG i = 0; i < lObjCount; ++i) {
            VARIANT vt; VariantInit(&vt);
            if (FAILED(apObjArray[i]->Get(L"TargetInstance", 0, &vt, 0, 0)) || vt.vt != VT_UNKNOWN) { VariantClear(&vt); continue; }
            IWbemClassObject* ti = nullptr;
            if (SUCCEEDED(vt.punkVal->QueryInterface(IID_IWbemClassObject, (void**)&ti)) && ti) {
                // ---- 取 ExecutablePath / ProcessId ----
                std::string p;
                unsigned long pid = 0;
                VARIANT ep; VariantInit(&ep);
                if (SUCCEEDED(ti->Get(L"ExecutablePath", 0, &ep, 0, 0)) && ep.vt == VT_BSTR && ep.bstrVal && ep.bstrVal[0]) {
                    int n = WideCharToMultiByte(CP_UTF8, 0, ep.bstrVal, -1, nullptr, 0, nullptr, nullptr);
                    if (n > 1) { p.resize(n - 1); WideCharToMultiByte(CP_UTF8, 0, ep.bstrVal, -1, &p[0], n, nullptr, nullptr); }
                }
                VariantClear(&ep);
                VARIANT vpid; VariantInit(&vpid);
                if (SUCCEEDED(ti->Get(L"ProcessId", 0, &vpid, 0, 0)) && vpid.vt == VT_I4) pid = (unsigned long)vpid.lVal;
                VariantClear(&vpid);

                if (!p.empty()) {
                    // ---- 判定结果汇总 ----
                    int  lv     = 0;      // 0=正常 1=可疑 2=高危
                    std::string sev, title, detail;
                    std::string tag;
                    // ★ 是否"硬规则命中"（behavior.cpp 的 v.hard）。
                    // 只有硬规则命中才允许直接终止进程 —— 见下方终止段落的说明。
                    bool hardHit = false;

                    // ① 文件启发式（随机名落地 / 可疑路径 / PE 形态）
                    int fileLv = QuickProbeExecutable(p);
                    if (fileLv > 0) {
                        lv    = fileLv;
                        sev   = (fileLv >= 2) ? "高" : "中";
                        title = (fileLv >= 2) ? "实时发现随机名落地文件" : "实时发现疑似随机名落地文件（旁证）";
                        detail = "进程 " + p + " 正在启动，命中随机名落地启发式" +
                                 (fileLv >= 2 ? "（PE 形态异常/盘根）" : "（PE 正常）") + "，疑似银狐载荷被拉起。";
                        tag = "heuristic";
                    }

                    // ② 行为判定（命令行 / 父子链 / 白利用）—— 仅当 ① 未定档时补充，
                    //    或 ① 只判「中危」而行为判定给出「高危」时升级。
                    try {
                        sf::ProcEntity ent = sf::MakeEntityOfPid(pid);
                        if (ent.imagePath.empty()) ent.imagePath = p;
                        sf::ProcVerdict v = sf::JudgeProcess(ent);
                        if (v.level > lv) {
                            lv     = v.level;
                            sev    = (v.level >= 2) ? "高" : "中";
                            title  = (v.level >= 2) ? "实时拦截可疑进程行为" : "实时发现可疑进程行为（旁证）";
                            detail = std::string("进程 ") + (ent.imagePath.empty() ? p : ent.imagePath) +
                                     " 命中行为判定：\n" + v.reason +
                                     (ent.parentImagePath.empty() ? "" : ("\n父进程：" + ent.parentImagePath));
                            tag = v.tag;
                        }
                        hardHit = v.hard;   // 硬规则命中标记（独立于是否升级了 lv）
                    } catch (...) { /* 行为判定异常不影响文件启发式结论 */ }

                    if (lv > 0) {
                        // 5 秒去抖：同一路径只报一次
                        static std::mutex m; static std::unordered_map<std::string, std::chrono::steady_clock::time_point> seen;
                        auto now = std::chrono::steady_clock::now();
                        bool skip = false;
                        { std::lock_guard<std::mutex> lk(m);
                          auto it = seen.find(p);
                          if (it != seen.end() && now - it->second < std::chrono::seconds(5)) skip = true;
                          else { seen[p] = now; if (seen.size() > 4096) seen.clear(); } }
                        if (!skip) {
                            // ---- ★ 分级终止（2026-09-19 新增，修复"拦截太软"）----
                            //
                            // 【为什么现在才加】旧实现命中 lv>=2 只写 findings + 弹窗，
                            // **一行终止都没有** —— 银狐载荷该跑还是在跑。对比同一个程序里
                            // 勒索引擎的动作（rollback.cpp 的 RollbackVictims 里有
                            // TerminateSuspect），会发现两套标准。这就是"看到了但没拦住"。
                            //
                            // 【为什么必须分级】文件启发式（随机名 / 盘根 / PE 形态）的
                            // 误报率天然高于行为硬规则 —— 绿软、自解压包、游戏补丁都可能命中。
                            // 若一律终止，误报的代价就变成"杀掉用户的正常程序"，
                            // 比"只记录不动作"更糟。
                            //
                            // ---- ★ 全量自动拦截（2026-09-19 第二轮，银泊指示"像正经杀软"）----
                            //
                            // 【第一轮的分级策略已被否决】原设计：仅 hard==true（确定性硬规则）
                            // 才终止，纯评分到档只弹窗 —— 因为怕文件启发式误报。银泊明确指示：
                            // 正经杀软就是"有风险活动一律自动处理，再问用户要不要撤销"。
                            // 误伤的兜底从"不杀"改成"杀了可撤销/可重开"。
                            //
                            // 现策略：lv>=2（高危）一律 TerminateProcess；lv==1（旁证）仍只记录。
                            // 进程终止本身无法"撤销"（进程不能复活），但该进程的文件改写
                            // 由回滚引擎兜底（可撤销），自启动项/落地文件/MBR 各有专属撤销。
                            bool terminated = false;
                            // ★ 信誉门 v2（2026-09-19）：知名厂商签名/可信路径的进程，
                            //   「评分型高危」不终止、不拉 infected、不弹高危卡（findings 仍记录）
                            //   —— wallpaper64.exe 误杀事故的根治。
                            //   但**硬规则行为压过信誉**：vssadmin delete shadows 这类确定性
                            //   恶意行为，即使借微软签名的 cmd.exe/powershell.exe 跑也照样拦
                            //   —— 否则真银狐借系统工具作案会被信誉门整个放行（测试盲点）。
                            const bool reputable = (lv >= 2 && pid > 0) ? sf::ProcReputable(p) : false;
                            const bool reputableBlock = reputable && !hardHit;
                            if (lv >= 2 && pid > 0 && !reputableBlock) {
                                HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
                                if (hp) {
                                    terminated = (TerminateProcess(hp, 1) != FALSE);
                                    CloseHandle(hp);
                                }
                                if (terminated) {
                                    LogDbg("[real-time] 已自动终止高危进程 pid=" + std::to_string(pid) +
                                           " " + p + "（tag=" + tag + "）");
                                    detail += "\n已自动终止该进程（正经杀软模式：先处置，误伤可另寻撤销）。";
                                } else {
                                    LogDbg("[real-time] 终止进程失败 pid=" + std::to_string(pid) +
                                           " " + p + "（权限不足或进程已退出）");
                                    detail += "\n尝试自动终止该进程失败（权限不足或进程已退出）。";
                                }
                            } else if (reputableBlock) {
                                LogDbg("[real-time] 高危行为命中但进程签名可信 → 信誉门拦截，跳过终止: " + p +
                                       "（tag=" + tag + "）");
                                detail += "\n进程有可信厂商签名，已跳过终止（仅记录行为）。";
                            }
                            {
                                std::lock_guard<std::mutex> lk(g_resultMutex);
                                // 已在 findings 里（如刚被全盘扫到）则不重复入列
                                bool dup = false;
                                for (const auto& f : g_result.findings) if (f.path == p) { dup = true; break; }
                                if (!dup) g_result.findings.push_back({"实时防护", sev, title, detail,
                                                                       sf::BaseName(p), p});
                                // 信誉门：可信进程不拉 infected（GUI 不显示"已感染"）
                                if (lv >= 2 && !reputableBlock) { g_result.status = "infected"; g_result.score = 200; }
                                g_result.timestamp = NowStr();
                            }
                            LogDbg("[real-time] " + sev + " [" + tag + "] " + p +
                                   (terminated ? " [已终止]" : ""));
                            if (lv >= 2 && !reputableBlock) {
                                // MBR 归因登记 + 弹卡归因数据：可疑活动窗口期内的
                                // MBR 变更要能追到这个进程头上（bootguard 10 分钟窗）
                                boot::NoteSuspicion(pid, p);
                                SetLastAlertInfo("可疑行为已自动拦截",
                                                 "「" + sf::BaseName(p) + "」命中行为规则（" + tag +
                                                 "），已自动终止该进程。",
                                                 sf::BaseName(p));
                                sf::NotifyAnomaly("infected", 200, "proc");
                            }
                        }
                    }
                }
                ti->Release();
            }
            VariantClear(&vt);
        }
        return WBEM_S_NO_ERROR;
    }
    HRESULT STDMETHODCALLTYPE SetStatus(LONG, HRESULT, BSTR, IWbemClassObject*) override { return WBEM_S_NO_ERROR; }
};

// ---------------------------------------------------------------------------
//  落地前置捕获消费线程（2026-09-19 新增）
// ---------------------------------------------------------------------------
//  为什么需要：银狐链条是「下载 → 落盘 → 自启」。回滚引擎（rollback.cpp）
//  已经把"落盘那一刻"的初筛结果放进队列（见 ProbeLandedFile），
//  但那是**纯文件视角**（路径 + 文件名 + 文件头），不知道是谁写入的。
//  本线程负责把它接到**进程视角**：对刚落地的高危文件，
//  用 QuickProbeExecutable + JudgeProcess 做一次完整判定，
//  命中就写 findings + 弹窗（并可终止 —— 见 WmiSink 的分级终止）。
//
//  为什么要独立线程而不是塞进 GuardThread：GuardThread 是秒级的轻量巡检，
//  本线程是 5 秒级轮询队列，生命周期与扫描无关，混在一起会让调度更难懂。
static void LandedAlertWatch() {
    LogDbg("[landed] 落地捕获消费线程已启动");
    while (!g_stop.load()) {
        if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;

        std::string json = rb::TakeLandedAlertsJson();   // 取走即清空
        // 极简解析：逐条抠出 path / reason（不引第三方 JSON 库，与项目一贯做法一致）
        size_t pos = 0;
        int handled = 0;
        while (handled < 16) {                            // 单轮上限，避免突发事件刷屏
            size_t p1 = json.find("\"path\":\"", pos);
            if (p1 == std::string::npos) break;
            p1 += 8;
            size_t p2 = json.find('"', p1);
            if (p2 == std::string::npos) break;
            std::string path = json.substr(p1, p2 - p1);
            pos = p2 + 1;
            if (path.empty()) continue;

            // 完整判定（复用与前台扫描完全相同的判定核心，避免规则两套）
            int lv = QuickProbeExecutable(path);
            std::string detail;
            std::string quarantineId;   // 非空 = 已自动隔离（撤销 token 的后 8 位）
            if (lv >= 1) {
                detail = "文件在落地高发区被创建时即被捕获，命中初始筛查。";
                if (lv >= 2) {
                    // 正经杀软模式（银泊 09-19）：高危落地载荷自动隔离，可撤销移回原位
                    quarantineId = QuarantineLanded(path);
                    boot::NoteSuspicion(0, path);   // MBR 归因登记
                    detail += quarantineId.empty()
                        ? "\n自动隔离失败（文件被占用或权限不足），请手动处理。"
                        : "\n已自动隔离该文件（先处置，误判可点「撤销」移回）。";
                }
            } else {
                continue;   // 初筛过了但完整判定不认账 → 不报（宁可漏报不误报）
            }

            {
                std::lock_guard<std::mutex> lk(g_resultMutex);
                bool dup = false;
                for (const auto& f : g_result.findings) if (f.path == path) { dup = true; break; }
                if (!dup)
                    g_result.findings.push_back({ "落地捕获", lv >= 2 ? "高" : "中",
                                                  lv >= 2 ? "落地即捕获可疑载荷" : "落地即发现可疑文件（旁证）",
                                                  detail + "\n" + path,
                                                  sf::BaseName(path), path });
                if (lv >= 2) { g_result.status = "infected"; if (g_result.score < 200) g_result.score = 200; }
                g_result.timestamp = NowStr();
            }
            LogDbg("[landed] 落地捕获命中（" + std::to_string(lv) + "级）: " + path +
                   (quarantineId.empty() ? "" : " [已隔离]"));
            if (lv >= 2) {
                if (!quarantineId.empty()) {
                    SetLastAlertInfo("落地载荷已自动隔离",
                                     "「" + sf::BaseName(path) + "」在落地高发区被创建且形态可疑，已自动隔离。",
                                     sf::BaseName(path));
                    sf::NotifyAnomaly("infected", 200, "landed", "30" + quarantineId, true);
                } else {
                    sf::NotifyAnomaly("infected", 200);   // 隔离失败 → 普通告警卡（清除威胁）
                }
            }
            handled++;
        }
    }
    LogDbg("[landed] 落地捕获消费线程已退出");
}

// WMI 订阅线程：异步回调（ExecNotificationQueryAsync），每 60 秒重建订阅以防断线；
// g_stop 置位时退出。
static void WmiProcessWatch() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return;
    IWbemLocator* loc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&loc))) { CoUninitialize(); return; }
    IWbemServices* svc = nullptr;
    BSTR ns = SysAllocString(L"root\\cimv2");
    HRESULT ch = loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
    SysFreeString(ns);
    if (FAILED(ch) || !svc) { loc->Release(); CoUninitialize(); return; }
    // 进程级 RPC 安全设置（可与本地服务通信）
    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    while (!g_stop.load()) {
        WmiSink* sink = new WmiSink();
        BSTR wql = SysAllocString(L"SELECT * FROM __InstanceCreationEvent WITHIN 3 WHERE TargetInstance ISA 'Win32_Process'");
        BSTR path = SysAllocString(L"root\\cimv2");
        if (SUCCEEDED(svc->ExecNotificationQueryAsync(path, wql, WBEM_FLAG_SEND_STATUS, nullptr, sink))) {
            // 订阅成功：等 60 秒或服务停止，然后取消并重建
            WaitForSingleObject(g_stopEvent, 60000);
            svc->CancelAsyncCall(sink);
        }
        SysFreeString(path);
        SysFreeString(wql);
        sink->Release();   // 服务端已持引用；释放本地引用（Cancel 后 sink 自我回收）
        if (g_stop.load()) break;
        Sleep(3000);       // 重建间隔，避免 WMI 风暴
    }
    svc->Release(); loc->Release(); CoUninitialize();
}

// ---------------------------------------------------------------------------
//  注册表自启动项实时监控（第二个实时防护事件源）
// ---------------------------------------------------------------------------
//  为什么需要：WMI 进程创建监听只能看见「已经跑起来的进程」，而银狐的持久化
//  是在**写入自启动项**那一刻完成的 —— 此时进程可能早已退出，下次开机才复活。
//  实测（2026-09-19 日志）`[real-time]` 命中 0 次，正是只有单一事件源的后果。
//
//  覆盖范围（银狐最常用的持久化点）：
//    HKLM\...\Run / RunOnce / RunServices / RunServicesOnce / Policies\Explorer\Run
//    HKCU\...\Run / RunOnce / Policies\Explorer\Run
//    HKU\<SID>\...\Run（服务在 Session 0，HKCU 是 SYSTEM 的 hive，必须显式枚举用户 SID）
//
//  实现：**轮询快照比对**（每 5 秒读一次全部值的「名称→命令行」映射）而不是
//  RegNotifyChangeKeyValue —— 后者只能告警「有变化」、拿不到具体是哪个值变了，
//  还得重新枚举一遍才知道，实际开销反而更高；而这些键的值总数通常 < 100，
//  一次全量枚举在微秒级，5 秒轮询 CPU 占用可忽略。
//
//  判定：新增值交给 sf::JudgeCommandLine()（复用与前台扫描/注册表扫描完全相同的
//  行为判定核心，避免规则两套），命中即写 findings + 弹窗。
// ---------------------------------------------------------------------------
static void RegRunWatch() {
    // 目标键（相对根键的路径）
    static const char* kKeys[] = {
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    };
    const size_t kKeysN = sizeof(kKeys) / sizeof(kKeys[0]);

    // 枚举一个键下的全部「值名 → 值内容」
    auto enumKey = [](HKEY root, const std::string& sub,
                      std::map<std::string, std::string>* out) {
        HKEY hk;
        if (RegOpenKeyExA(root, sub.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
        DWORD nVal = 0, nMax = 0;
        if (RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &nVal, &nMax, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::vector<char> name(nMax + 2), data(8192);
            for (DWORD i = 0; i < nVal; ++i) {
                DWORD ns = (DWORD)name.size(), ds = (DWORD)data.size(), type = 0;
                if (RegEnumValueA(hk, i, name.data(), &ns, nullptr, &type,
                                  (LPBYTE)data.data(), &ds) != ERROR_SUCCESS) continue;
                if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
                std::string v(data.data(), ds ? ds - 1 : 0);   // 去掉结尾 NUL
                (*out)[std::string(name.data(), ns)] = v;
            }
        }
        RegCloseKey(hk);
    };

    // 收集全部受监控键（含 HKU\<SID>）
    // ⚠️ 必须显式捕获 [&]：lambda 内要用到 kKeys / kKeysN / enumKey，裸 [] 会报 C3493。
    auto collect = [&]() {
        std::map<std::string, std::string> all;   // "hive|path|valuename" -> 命令行
        for (size_t i = 0; i < kKeysN; ++i) {
            std::map<std::string, std::string> m;
            enumKey(HKEY_LOCAL_MACHINE, kKeys[i], &m);
            for (auto& kv : m) all["HKLM|" + std::string(kKeys[i]) + "|" + kv.first] = kv.second;
            m.clear();
            enumKey(HKEY_CURRENT_USER, kKeys[i], &m);
            for (auto& kv : m) all["HKCU|" + std::string(kKeys[i]) + "|" + kv.first] = kv.second;
        }
        // HKU\<SID>：服务在 Session 0，HKCU 是 SYSTEM hive，用户级自启必须显式枚举
        HKEY hkUsers;
        if (RegOpenKeyExA(HKEY_USERS, nullptr, 0, KEY_READ, &hkUsers) == ERROR_SUCCESS) {
            DWORD nSub = 0;
            RegQueryInfoKeyA(hkUsers, nullptr, nullptr, nullptr, &nSub, nullptr, nullptr,
                             nullptr, nullptr, nullptr, nullptr, nullptr);
            std::vector<char> nm(256);
            for (DWORD i = 0; i < nSub; ++i) {
                DWORD ns = (DWORD)nm.size();
                if (RegEnumKeyA(hkUsers, i, nm.data(), ns) != ERROR_SUCCESS) continue;
                std::string sid(nm.data());
                if (sid.find("S-1-5-21-") == std::string::npos) continue;   // 只看用户 SID
                for (size_t k = 0; k < kKeysN; ++k) {
                    std::map<std::string, std::string> m;
                    enumKey(HKEY_USERS, sid + "\\" + kKeys[k], &m);
                    for (auto& kv : m) all["HKU|" + sid + "\\" + kKeys[k] + "|" + kv.first] = kv.second;
                }
            }
            RegCloseKey(hkUsers);
        }
        return all;
    };

    // 首轮：建立基线，**不报警**（否则每次服务启动都会把全部既有自启动项报一遍）
    std::map<std::string, std::string> base = collect();
    LogDbg("[real-time] 注册表自启动基线已建立，共 " + std::to_string(base.size()) + " 项");

    while (!g_stop.load()) {
        if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;
        std::map<std::string, std::string> cur = collect();
        for (const auto& kv : cur) {
            if (base.count(kv.first)) continue;   // 已有项 → 不是新增
            // ---- 新增自启动项：交给行为判定核心 ----
            const std::string& cmdline = kv.second;
            if (cmdline.empty()) continue;
            // 自排除：我方程序自身写入的项不报
            if (ci_contains(to_lower(cmdline), "silverfox")) continue;
            sf::ProcVerdict v;
            std::string imagePath;
            // 从命令行里抠出可执行路径（首个引号块或首个空格前的 token）
            if (!cmdline.empty() && cmdline[0] == '"') {
                size_t e = cmdline.find('"', 1);
                if (e != std::string::npos) imagePath = cmdline.substr(1, e - 1);
            }
            if (imagePath.empty()) {
                size_t sp = cmdline.find(' ');
                imagePath = (sp == std::string::npos) ? cmdline : cmdline.substr(0, sp);
            }
            try { v = sf::JudgeCommandLine(cmdline, imagePath); } catch (...) { continue; }
            if (v.level <= 0) continue;
            std::string sev = (v.level >= 2) ? "高" : "中";
            std::string removedId;   // 非空 = 已自动移除该启动项（撤销 token 后 8 位）
            if (v.level >= 2) {
                // 正经杀软模式（银泊 09-19）：可疑自启动项自动移除，原值在案可撤销写回
                removedId = RemoveAutorunValue(kv.first);
                boot::NoteSuspicion(0, imagePath);   // MBR 归因登记
            }
            {
                std::lock_guard<std::mutex> lk(g_resultMutex);
                bool dup = false;
                for (const auto& f : g_result.findings) if (f.path == cmdline) { dup = true; break; }
                if (!dup) g_result.findings.push_back({"自启动", sev,
                    (v.level >= 2) ? "实时拦截可疑自启动项" : "实时发现新增自启动项（旁证）",
                    "注册表位置：" + kv.first + "\n命令行：" + cmdline + "\n判定依据：" + v.reason +
                    (removedId.empty() ? "" : "\n已自动移除该启动项（误判可点「撤销」写回）。"),
                    "", imagePath});
                if (v.level >= 2) { g_result.status = "infected"; g_result.score = 200; }
                g_result.timestamp = NowStr();
            }
            LogDbg("[real-time] " + sev + " [regrun] " + kv.first + " => " + cmdline +
                   (removedId.empty() ? "" : " [已移除]"));
            if (v.level >= 2) {
                if (!removedId.empty()) {
                    SetLastAlertInfo("可疑自启动项已自动拦截",
                                     "「" + (imagePath.empty() ? cmdline : sf::BaseName(imagePath)) +
                                     "」试图通过注册表自启动建立持久化，已自动移除该启动项。",
                                     imagePath.empty() ? "" : sf::BaseName(imagePath));
                    sf::NotifyAnomaly("infected", 200, "regrun", "20" + removedId, true);
                } else {
                    sf::NotifyAnomaly("infected", 200);   // 移除失败 → 普通告警卡
                }
            }
        }
        base.swap(cur);   // 更新基线（含被删除项，避免删后重建反复报）
    }
}

void GuardThread() {
    // ---- 恢复跨进程基线 ----
    // 关键：把上次进程记下的「已通知状态」读回来，避免服务重启后第一轮扫描
    // 把同一个状态又当成新变化弹一次窗（旧架构没做这件事，是"老是弹窗"的元凶之一）。
    {
        std::lock_guard<std::mutex> lk(g_resultMutex);
        g_lastToastStatus = LoadToastBaseline();
        if (!g_lastToastStatus.empty())
            LogDbg("[check] 恢复已通知基线: " + g_lastToastStatus);
    }

    // ---- 启动自检 ----
    // 只跑【秒级轻量巡检】：进程 + 注入 + 注册表 + 服务 + 计划任务，纯内存/注册表读取，
    // 立即出初步结果并通知，用户开机后几秒内即可在扩展看到检测状态。
    // 全盘精扫**不在这里跑**——它要 40~90 秒，且是 GPU 崩溃的触发点；放在启动路径上
    // 会让"服务启动"与"重扫描"强耦合，一旦崩就进入重启循环。
    // ⚠️ 2026-09-19：此处原为 RunQuickScan()（含磁盘遍历），改为 RunGuardTick()（零遍历）。
    RunGuardTick();
    CheckAndNotify();
    // 哈希基线只在安装时（DoInstall）写入一次，此处不重复写，
    // 避免被篡改的二进制在启动时自我重新基线化、绕过完整性校验。

    // ---- 分层调度 ----
    // 两个独立计时器：快扫高频（实时性）、全盘扫低频（完整性）。
    // 用 WaitForSingleObject 的毫秒超时做粗粒度调度，单轮扫描耗时不影响相位
    // （扫描结束时重置对应计时器，不做"补跑"，避免多轮积压）。
    const ULONGLONG startedAt = GetTickCount64();
    ULONGLONG lastQuick = startedAt;
    ULONGLONG lastFull  = startedAt;
    bool firstFullDone  = false;

    // 距上次全盘扫描已过多久？若已超过一个完整周期，说明本进程"欠"了一轮全盘扫
    // （服务停过、崩溃过、或机器关机），此时**不等**启动延迟，尽快补上。
    {
        long long last = LoadLastScanTime();
        if (last > 0) {
            auto nowT = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            long long elapsed = (long long)nowT - last;
            if (elapsed * 1000LL >= (long long)FULL_SCAN_INTERVAL_MS) {
                // 让 lastFull 往前推到"已经超期"，从而在首次循环立刻触发全盘扫
                ULONGLONG overdue = (ULONGLONG)(elapsed * 1000LL);
                lastFull = startedAt - (overdue > startedAt ? startedAt : overdue);
                LogDbg("[sched] 距上次全盘扫描 " + std::to_string(elapsed / 3600) +
                       " 小时（已超期），启动后立即补扫");
            }
        }
    }

    while (!g_stop.load()) {
        // 100ms 粒度的轻量等待，便于及时响应停止事件
        if (WaitForSingleObject(g_stopEvent, 100) != WAIT_TIMEOUT) break;
        const ULONGLONG now = GetTickCount64();

        // ---- 全盘精扫（低频；首轮延后到 FULL_SCAN_STARTUP_DELAY_MS）----
        const ULONGLONG fullDue = firstFullDone ? FULL_SCAN_INTERVAL_MS
                                                : FULL_SCAN_STARTUP_DELAY_MS;
        if (now - lastFull >= fullDue) {
            firstFullDone = true;
            lastFull = now;
            RunFullScan();
            CheckAndNotify();
            SaveLastScanTime();
            lastQuick = GetTickCount64();   // 全盘扫已覆盖快扫范围，重置快扫相位
            continue;
        }

        // ---- 轻量巡检（高频，零磁盘遍历）----
        // 2026-09-19 重构：原为 RunQuickScan()，它内部会调 ScanFiles 递归
        // Desktop/Downloads/Temp（预算最多 6 万文件）→ 每 3 分钟一轮缩水全盘，
        // 实测 fullscan 间隔退化为 4~6 分钟（上轮没跑完相位已到期）。
        // 改 RunGuardTick()：只读进程/注册表/服务/计划任务，秒级、CPU 与磁盘近零占用。
        if (now - lastQuick >= QUICK_SCAN_INTERVAL_MS) {
            lastQuick = now;
            RunGuardTick();
            CheckAndNotify();
            BootScanTick();   // MBR 兜底校验：监视线程意外退出时仍 ≤3 分钟必有人盯引导扇区
        }
    }
}

// ---------------------------------------------------------------------------
//  命名管道服务（与 NM 宿主通信，无 TCP 端口，银狐无法劫持）
//  支持：① 单连接多帧（宿主长连接，避免每次轮询都重连 → 不再反复拉起新程序）
//        ② 多客户端并发（nMaxInstances>1，避免 ERROR_PIPE_BUSY 导致扩展侧掉线）
// ---------------------------------------------------------------------------
void PipeServerThread() {
    SECURITY_ATTRIBUTES sa{ sizeof(sa) };
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFW;;;WD)", SDDL_REVISION_1, &sa.lpSecurityDescriptor, nullptr)) {
        return;
    }
    const int MAX_INSTANCES = 8;
    while (!g_stop.load()) {
        HANDLE h = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, MAX_INSTANCES, 8192, 8192, 0, &sa);
        if (h == INVALID_HANDLE_VALUE) { Sleep(500); continue; }
        OVERLAPPED ov{}; ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        ResetEvent(ov.hEvent);
        BOOL ok = ConnectNamedPipe(h, &ov);
        DWORD err = GetLastError();
        if (!ok && err == ERROR_IO_PENDING) {
            HANDLE ws[2] = { ov.hEvent, g_stopEvent };
            // ★ 2026-09-19 修复持续 err=233：等待超时（1s）时客户端可能恰在此刻连上
            //   （事件已触发但等待刚超时返回 WAIT_TIMEOUT），旧代码直接 CloseHandle 把
            //   带着连接的实例扔掉 → 客户端 WriteFile/ReadFile 立刻 233（管道关闭）。
            //   正解：超时后先 GetOverlappedResult(FALSE) 探测，已连接则照常派发。
            DWORD r = WaitForMultipleObjects(2, ws, FALSE, 1000);
            if (r == WAIT_OBJECT_0 + 1 || g_stop.load()) { CloseHandle(h); CloseHandle(ov.hEvent); break; }
            if (r != WAIT_OBJECT_0) {
                DWORD trp = 0;
                if (!GetOverlappedResult(h, &ov, &trp, FALSE)) {
                    CloseHandle(h); CloseHandle(ov.hEvent); continue;   // 真没人连，重开实例
                }
                // 已连接（探测成功）→ 落到下面派发线程
            } else {
                DWORD tr = 0; GetOverlappedResult(h, &ov, &tr, TRUE);
            }
        } else if (!(ok || err == ERROR_PIPE_CONNECTED)) {
            CloseHandle(h); CloseHandle(ov.hEvent); continue;
        }
        CloseHandle(ov.hEvent);
        // 每连接交给独立工作线程：在同一个长连接上循环处理多帧（status/rescan），
        // 主循环立刻回到 accept，从而支持并发与持久连接。
        std::thread([h]() {
            while (!g_stop.load()) {
                std::string req;
                if (!ReadFramed(h, req)) break;            // 客户端断开 → 退出本线程
                std::string cmd = JsonGetString(req, "cmd");
                if (cmd == "probe") {
                    // 右键自定义查杀：单文件启发式判定（服务以 SYSTEM 执行，可读受保护文件）
                    std::string p = JsonGetString(req, "path");
                    if (p.empty()) { WriteFramed(h, "{\"cmd\":\"probe\",\"ok\":false,\"msg\":\"no path\"}"); continue; }
                    std::string verdict;
                    try { verdict = ScanTargetFile(p); }
                    catch (...) {
                        verdict = "{\"level\":0,\"score\":0,\"type\":\"ERR\",\"title\":\"查杀过程异常\",\"hits\":[]}";
                    }
                    // 平铺字段到顶层 + 原样抠出 hits 数组（极简 JSON 解析器取不了嵌套引号中的值）
                    {
                        std::string flat = "{\"cmd\":\"probe\",\"ok\":true,\"path\":" + JsonString(p);
                        flat += ",\"level\":" + std::to_string(JsonGetInt(verdict, "level"));
                        flat += ",\"score\":" + std::to_string(JsonGetInt(verdict, "score"));
                        flat += ",\"type\":\"" + JsonEscape(JsonGetString(verdict, "type")) + "\"";
                        flat += ",\"title\":\"" + JsonEscape(JsonGetString(verdict, "title")) + "\"";
                        size_t hb = verdict.find("\"hits\":[");
                        if (hb != std::string::npos) {
                            size_t ob = hb + 7; int depth = 0; size_t i = ob;
                            for (; i < verdict.size(); ++i) {
                                if (verdict[i] == '{' || verdict[i] == '[') ++depth;
                                else if (verdict[i] == '}' || verdict[i] == ']') { --depth; if (depth == 0) { ++i; break; } }
                            }
                            flat += ",\"hits\":" + verdict.substr(ob, i - ob);
                        } else flat += ",\"hits\":[]";
                        flat += "}";
                        WriteFramed(h, flat);
                    }
                    continue;
                }
                if (cmd == "probeclean") {
                    std::string p = JsonGetString(req, "path");
                    if (p.empty()) { WriteFramed(h, "{\"cmd\":\"probeclean\",\"ok\":false,\"msg\":\"no path\"}"); continue; }
                    CleanReport cr = CleanFiles({ p });
                    WriteFramed(h, "{\"cmd\":\"probeclean\",\"ok\":true,\"path\":" + JsonString(p) + ",\"clean\":" + BuildCleanJson(cr) + "}");
                    continue;
                }
                if (cmd == "gpuget") {
                    WriteFramed(h, std::string("{\"cmd\":\"gpuget\",\"gpu\":") + (compute::IsGpuEnabled() ? "1" : "0") + "}");
                    continue;
                }
                if (cmd == "gpu") {
                    int on = JsonGetInt(req, "on");
                    compute::SetGpuEnabled(on == 1);
                    if (on == 1) {
                        // 开启：后台探测 GPU 性能并构建「特征地图」载入显存（进度经 gpuprog 查询）
                        compute::LoadMapAsync();
                    } else {
                        // 关闭：立即释放显存中的地图与全部 GPU 资源（不残留一点显存占用）
                        compute::UnloadMap();
                    }
                    WriteFramed(h, std::string("{\"cmd\":\"gpu\",\"ok\":true,\"gpu\":") + (compute::IsGpuEnabled() ? "1" : "0") + "}");
                    continue;
                }
                if (cmd == "gpuprog") {
                    // 地图加载进度（扩展端进度条轮询用）：阶段文案 + 百分比 + 地图规模 + 档位
                    // tripped=true 表示本进程内 GPU 已熔断（驱动崩溃后自保停用），
                    // 扩展端据此把开关置灰并提示"本机显卡驱动不稳定，已自动改用 CPU 扫描"。
                    auto mi = compute::GetMapInfo();
                    std::string s = "{\"cmd\":\"gpuprog\",\"loading\":" + std::string(mi.loading ? "true" : "false")
                                  + ",\"loaded\":" + std::string(mi.loaded ? "true" : "false")
                                  + ",\"pct\":" + std::to_string(mi.pct)
                                  + ",\"stage\":" + JsonString(mi.stage)
                                  + ",\"error\":" + JsonString(mi.error)
                                  + ",\"patterns\":" + std::to_string(mi.patterns)
                                  + ",\"states\":" + std::to_string(mi.states)
                                  + ",\"bytes\":" + std::to_string((unsigned long long)mi.bytes)
                                  + ",\"tier\":" + std::to_string(mi.tier)
                                  + ",\"integrated\":" + std::string(mi.integrated ? "true" : "false")
                                  + ",\"e2e\":" + std::to_string(mi.e2eMBs)
                                  + ",\"cpu\":" + std::to_string(mi.cpuMBs)
                                  + ",\"ratio\":" + std::to_string(mi.ratioPct)
                                  + ",\"tripped\":" + std::string(compute::GpuTripped() ? "true" : "false")
                                  + ",\"gpu\":" + JsonString(mi.gpu) + "}";
                    WriteFramed(h, s);
                    continue;
                }

                std::string extra;                         // 附加字段（清除报告）
                if (cmd == "rollbackstatus") {
                    // 勒索回滚引擎运行态：快照数量/占用/累计回滚次数/最近触发原因。
                    // 扩展设置页用它在「勒索防护」卡片里展示真实数字（不吹牛、不隐藏）。
                    WriteFramed(h, "{\"cmd\":\"rollbackstatus\",\"ok\":true,\"data\":" + rb::StatusJson() + "}");
                    continue;
                }
                if (cmd == "rollbacklist") {
                    // 当前受保护（已持有快照）的文件清单，供 UI 展示"哪些文件有后悔药"
                    WriteFramed(h, "{\"cmd\":\"rollbacklist\",\"ok\":true,\"data\":" + rb::ListSnapshotsJson() + "}");
                    continue;
                }
                if (cmd == "rollbackdo") {
                    // 用户主动发起的回滚：把全部持有快照的文件恢复到快照状态。
                    // 这是一把双刃剑（会把用户正常保存的改动也退回去），
                    // 故扩展端必须二次确认后才允许调用。
                    std::string why = JsonGetString(req, "reason");
                    std::string rep = rb::ManualRollback(why);
                    WriteFramed(h, "{\"cmd\":\"rollbackdo\",\"ok\":true,\"report\":" + rep + "}");
                    continue;
                }
                if (cmd == "rollbackclean") {
                    rb::ClearCache();
                    WriteFramed(h, "{\"cmd\":\"rollbackclean\",\"ok\":true}");
                    continue;
                }
                // ---- 密钥截获（2026-09-19 新增）----
                // 用户/维护者可查看已捕获的疑似勒索密钥，并导出内容做解密或取证。
                if (cmd == "keylist") {
                    WriteFramed(h, "{\"cmd\":\"keylist\",\"ok\":true,\"data\":" + rb::ListCapturedKeysJson() + "}");
                    continue;
                }
                if (cmd == "keyread") {
                    // index 缺省为 0（最近捕获的那份往往就是当前攻击用的密钥）
                    int idx = JsonGetInt(req, "index");
                    if (idx < 0) idx = 0;
                    WriteFramed(h, "{\"cmd\":\"keyread\",\"ok\":true,\"data\":" +
                                   rb::ReadCapturedKeyHex((size_t)idx) + "}");
                    continue;
                }
                if (cmd == "keyclear") {
                    rb::ClearCapturedKeys();
                    WriteFramed(h, "{\"cmd\":\"keyclear\",\"ok\":true}");
                    continue;
                }
                // ---- 落地前置捕获（2026-09-19 新增）----
                // 取走当前待处理的落地初筛命中（取走即清空，避免反复上报）。
                if (cmd == "landlist") {
                    WriteFramed(h, "{\"cmd\":\"landlist\",\"ok\":true,\"data\":" + rb::TakeLandedAlertsJson() + "}");
                    continue;
                }
                // ---- MBR 引导扇区防护（2026-09-19 新增）----
                // 状态查询：弹窗卡的「某某程序」归因回填 + GUI 引导防护面板共用。
                if (cmd == "bootstatus") {
                    WriteFramed(h, "{\"cmd\":\"bootstatus\",\"ok\":true,\"data\":" + boot::StatusJson() + "}");
                    continue;
                }
                // 弹窗卡归因回填：最近一次自动拦截事件的标题/详情/进程名（正经杀软文案）
                if (cmd == "lastalert") {
                    WriteFramed(h, "{\"cmd\":\"lastalert\",\"ok\":true,\"data\":" + LastAlertJson() + "}");
                    continue;
                }
                // 被动告警卡「恢复引导」：基线写回扇区 0
                if (cmd == "bootrestore") {
                    bool ok = boot::Restore();
                    if (ok) { std::lock_guard<std::mutex> lk(g_bootAlertMtx); g_bootActive = false; }
                    WriteFramed(h, std::string("{\"cmd\":\"bootrestore\",\"ok\":true,\"report\":{\"ok\":") +
                                (ok ? "true" : "false") + ",\"restored\":0,\"failed\":0,\"reason\":\"" +
                                (ok ? "引导记录已从基线恢复，磁盘引导代码已还原。"
                                    : "恢复失败：写入扇区 0 被拒（可能有磁盘工具占用）。") + "\"}}");
                    continue;
                }
                // 被动告警卡「信任此变更」：当前 MBR 重立为基线（磁盘工具合法改引导）
                if (cmd == "bootaccept") {
                    bool ok = boot::Accept();
                    if (ok) { std::lock_guard<std::mutex> lk(g_bootAlertMtx); g_bootActive = false; }
                    WriteFramed(h, std::string("{\"cmd\":\"bootaccept\",\"ok\":true,\"report\":{\"ok\":") +
                                (ok ? "true" : "false") + ",\"restored\":0,\"failed\":0,\"reason\":\"" +
                                (ok ? "已信任当前引导记录并重立基线。"
                                    : "重立基线失败：读盘或写入 ProgramData 被拒。") + "\"}}");
                    continue;
                }
                // 撤销最近一次自动回滚（"反向回滚"）：把文件还原回"回滚前"的版本。
                // 高风险自动处置后，用户在弹窗里点「撤销我的处理」时走这条命令。
                if (cmd == "rollbackundo") {
                    std::string tok = JsonGetString(req, "token");
                    // 统一撤销入口（银泊 09-19 正经杀软模式）：按 token 前缀分发 ——
                    // 10=引导扇区（bootguard）/ 20=自启动项 / 30=落地隔离 / 其余=勒索回滚
                    std::string rep = UniversalUndo(tok);
                    WriteFramed(h, "{\"cmd\":\"rollbackundo\",\"ok\":true,\"report\":" + rep + "}");
                    continue;
                }
                if (cmd == "history") {
                    // 清除历史：独立轻量响应（不触发扫描），供扩展端「清除记录」卡片
                    WriteFramed(h, BuildHistoryJson());
                    continue;
                } else if (cmd == "rescan") {
                    // 仅 rescan 触发全量扫描；扫描中收到的重复 rescan 直接走通用回包（返回缓存），
                    // 不排队重扫——否则连点 N 次就串行跑 N 轮全盘、N 个弹窗。
                    if (!g_rescanBusy.exchange(true)) {
                        RunFullScan();
                        g_rescanBusy = false;
                        CheckAndNotify();
                    }
                } else if (cmd == "clean_adv") {
                    // 「高级清除」：普通清除（cmd=clean）仍失败的目标清单在此清理。
                    // 遏制（按基名杀全部实例+子进程树）+ 硬删（清属性/解ACL/POSIX删除/重启登记）。
                    std::vector<std::string> adv;
                    {
                        std::lock_guard<std::mutex> lk(g_failedMtx);
                        adv = g_failedTargets;
                    }
                    CleanReport ar = AdvancedCleanFiles(adv);
                    LogDbg("[clean_adv] requested=" + std::to_string(ar.requested) +
                           " deleted=" + std::to_string(ar.deleted) +
                           " deferred=" + std::to_string(ar.deferred) +
                           " failed=" + std::to_string(ar.failed) +
                           " killed=" + std::to_string(ar.killed));
                    g_failedTargets.clear();
                    // 先回包（含高级清除报告）再复查：全盘复查要几十秒，若放在回包前，
                    // 弹窗进度条到 100% 后还要干等复查完成才显示结果。
                    std::string resp;
                    {
                        std::lock_guard<std::mutex> lk(g_resultMutex);
                        resp = BuildResultJson(g_result);
                    }
                    if (!resp.empty() && resp.back() == '}') {
                        resp.pop_back();
                        resp += "," + BuildCleanJson(ar);
                        resp += "}";
                    }
                    WriteFramed(h, resp);
                    AppendCleanHistory("advanced", ar);   // 落历史（回包后写，不阻塞响应）
                    RunFullScan(); SyncLastToastStatus();   // 高级清除后刷新状态（不阻塞回包）
                    continue;
                } else if (cmd == "clean") {
                    // 「一键清除」：清除预扫不重做全盘——直接盯住【上一轮全盘扫描已发现的可疑样本
                    // 所在目录】做定点扫描（RunQuickScan 内部实现：快照 g_result 中样本的父目录，
                    // 只扫这些目录 + 常规落点）。既与展示同源（深层文件夹样本也清得到），又秒级完成。
                    RunQuickScan();
                    std::vector<std::string> targets = CollectCleanTargets();
                    CleanReport cr = CleanFiles(targets);
                    // 记录「未清除干净」的路径清单：failed（当场失败）与 deferred（登记重启删除）都收——
                    // deferred 文件同样有复活/ACL 自保，若留给重启删除可能把样本带到下次开机；
                    // 高级删除（clean_adv）对它们一并夺权+硬删+连坐，当场根除。
                    {
                        std::lock_guard<std::mutex> lk(g_failedMtx);
                        g_failedTargets.clear();
                        for (const auto& it : cr.items)
                            if (it.action == "failed" || it.action == "deferred")
                                g_failedTargets.push_back(it.path);
                    }
                    LogDbg("[clean] requested=" + std::to_string(cr.requested) +
                           " deleted=" + std::to_string(cr.deleted) +
                           " deferred=" + std::to_string(cr.deferred) +
                           " failed=" + std::to_string(cr.failed) +
                           " extraDlls=" + std::to_string(cr.extraDlls) +
                           " killed=" + std::to_string(cr.killed));
                    // 先用「当前结果 + 清除报告」立即回包。全量重扫要 ~20 秒，若放在回包之前，
                    // 调用方（弹窗进度卡片 / 扩展面板）会在进度条走满后干等 20 秒才看到结果。
                    std::string resp;
                    {
                        std::lock_guard<std::mutex> lk(g_resultMutex);
                        resp = BuildResultJson(g_result);
                    }
                    if (!resp.empty() && resp.back() == '}') {
                        resp.pop_back();
                        resp += "," + BuildCleanJson(cr);
                        resp += "}";
                    }
                    WriteFramed(h, resp);
                    AppendCleanHistory("normal", cr);   // 落历史（回包后写，不阻塞响应）
                    // 回包之后再重扫刷新状态；同步通知基线，避免下一轮扫描把「异常→正常」当成新变化又弹一次
                    RunFullScan();
                    SyncLastToastStatus();
                    continue;   // 响应已写出，跳过通用回包流程
                }
                std::string resp;
                {
                    std::lock_guard<std::mutex> lk(g_resultMutex);
                    resp = BuildResultJson(g_result);      // status 直接返回缓存结果（瞬时）
                }
                // 把清除报告并入同一帧响应（status/score 仍在顶层，兼容既有解析）
                if (!extra.empty() && !resp.empty() && resp.back() == '}') {
                    resp.pop_back(); resp += extra; resp += "}";
                }
                if (!WriteFramed(h, resp)) break;
            }
            DisconnectNamedPipe(h);
            CloseHandle(h);
        }).detach();
    }
    if (sa.lpSecurityDescriptor) LocalFree(sa.lpSecurityDescriptor);
}

// ---------------------------------------------------------------------------
//  服务安装
// ---------------------------------------------------------------------------
// 窄串→宽串（按系统 ANSI 代码页，匹配 GetModuleFileNameA 的返回）。
// 用于以 Unicode（CreateServiceW）注册服务，避免中文显示名 / 中文安装路径在服务管理器里乱码。
static std::wstring AToW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// 清除历史版本的遗留服务。SilverFoxEnvScan 更名为 SilverFoxGuard 后，
// 若旧服务未卸载，新旧两个服务会【同时开机自启】→ 各自跑一份「快速扫 + 每 3 分钟全盘扫」，
// 用户感知就是「每 3 分钟扫一次全盘并弹窗」（2026-09-18 用户实测踩坑）。
// 这里在注册新服务前无条件终结并删除全部历史服务名，保证系统内只有一个扫描引擎。
static void RemoveLegacyServices() {
    static const wchar_t* kLegacy[] = { L"SilverFoxEnvScanSvc" };
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;
    for (const wchar_t* name : kLegacy) {
        SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if (!svc) continue;   // 不存在：正常情况
        // ① 优雅停止
        SERVICE_STATUS ss{};
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 20 && ss.dwCurrentState != SERVICE_STOPPED; ++i) {
            Sleep(300);
            if (!QueryServiceStatus(svc, &ss)) break;
        }
        // ② 停止超时（服务卡在命名管道阻塞）→ 按 PID 强杀，否则 SCM 不置为 STOPPED，DeleteService 会静默失败
        if (ss.dwCurrentState != SERVICE_STOPPED) {
            SERVICE_STATUS_PROCESS ssp{};
            DWORD cb = 0;
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                     (LPBYTE)&ssp, sizeof(ssp), &cb) && ssp.dwProcessId) {
                HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, ssp.dwProcessId);
                if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
            }
            for (int i = 0; i < 10; ++i) {
                Sleep(300);
                if (!QueryServiceStatus(svc, &ss) || ss.dwCurrentState == SERVICE_STOPPED) break;
            }
        }
        // ③ 删除服务项（失败也无妨：SCM 下次启动会因 ImagePath 缺失而失败，至少不再扫描）
        BOOL del = DeleteService(svc);
        CloseServiceHandle(svc);
        LogDbg(std::string("[install] 清理历史服务 ") +
               std::string(name, name + wcslen(name)) + (del ? " 成功" : " 失败（可能已在删除标记）"));
    }
    CloseServiceHandle(scm);
}

bool SvcInstall() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;
    // 先摘除历史服务（SilverFoxEnvScanSvc），避免新旧服务并存导致的「双份全盘扫描 + 重复弹窗」
    RemoveLegacyServices();
    std::string exe = GetExePath();
    std::wstring exeW = AToW(exe);
    std::wstring binW = L"\"" + exeW + L"\" --run-service";
    SC_HANDLE svc = CreateServiceW(scm, L"SilverFoxGuardSvc", L"银狐主防服务",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        binW.c_str(), NULL, NULL, NULL, L"LocalSystem", NULL);
    bool ok = !!svc;
    if (svc) { CloseServiceHandle(svc); svc = NULL; }
    else {
        // 服务已存在：必须把 ImagePath 更新成本次安装所在路径，
        // 否则服务仍从旧文件夹启动（用户装到别的文件夹就会触发"路径被写死"错觉）。
        svc = OpenServiceW(scm, L"SilverFoxGuardSvc", SERVICE_CHANGE_CONFIG);
        if (svc) {
            ok = ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                      binW.c_str(), NULL, NULL, NULL, L"LocalSystem", NULL, NULL) != 0;
            CloseServiceHandle(svc); svc = NULL;
        }
    }
    CloseServiceHandle(scm);
    return ok;
}

bool SvcUninstall() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceA(scm, "SilverFoxGuardSvc",
                                 SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (svc) {
        SERVICE_STATUS ss{};
        // ① 优先优雅停止
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 20 && ss.dwCurrentState != SERVICE_STOPPED; ++i) {
            Sleep(500); QueryServiceStatus(svc, &ss);
        }
        // ② 优雅停止超时（服务卡在命名管道 Accept/Connect 阻塞等死锁场景）：强制结束进程
        if (ss.dwCurrentState != SERVICE_STOPPED) {
            SERVICE_STATUS_PROCESS ssp{};
            DWORD cb = 0;
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                    (LPBYTE)&ssp, sizeof(ssp), &cb) && ssp.dwProcessId) {
                HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, ssp.dwProcessId);
                if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
            }
            for (int i = 0; i < 10; ++i) {
                Sleep(300); QueryServiceStatus(svc, &ss);
                if (ss.dwCurrentState == SERVICE_STOPPED) break;
            }
        }
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return true;
}

bool IsServiceRunning() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceA(scm, "SilverFoxGuardSvc", SERVICE_QUERY_STATUS);
    bool running = false;
    if (svc) {
        SERVICE_STATUS ss{};
        if (QueryServiceStatus(svc, &ss))
            running = (ss.dwCurrentState == SERVICE_RUNNING ||
                       ss.dwCurrentState == SERVICE_START_PENDING ||
                       ss.dwCurrentState == SERVICE_CONTINUE_PENDING);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return running;
}

// ---------------------------------------------------------------------------
//  安装器 / 卸载器
// ---------------------------------------------------------------------------
bool DoInstall(const std::string& extIdChrome, const std::string& extIdEdge) {
    std::string svcExe = GetExePath();
    std::string dir = DirName(svcExe);
    // 单程序：服务本体同时作为 Native Messaging 宿主被浏览器拉起
    std::string hostExe = svcExe;

    // 【升级修复】旧服务若正在运行，必须先停止并删除、再重建。原因：ChangeServiceConfig 虽能更新
    // ImagePath，但运行中的服务进程仍执行旧 EXE 的代码（内存映像不会因文件替换而更新）；而紧随其后的
    // StartService 对「已在运行」的服务只会返回 ERROR_SERVICE_ALREADY_RUNNING。结果是
    // 「覆盖安装了新 EXE，服务却仍按旧逻辑跑」——表现为新修复的检测规则不生效。
    SvcUninstall();
    for (int i = 0; i < 30; ++i) {   // 等 SCM 真正移除服务，避免 CreateService 撞上 marked-for-delete
        SC_HANDLE m = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!m) break;
        SC_HANDLE s = OpenServiceA(m, "SilverFoxGuardSvc", SERVICE_QUERY_STATUS);
        if (!s) { CloseServiceHandle(m); break; }
        CloseServiceHandle(s); CloseServiceHandle(m);
        Sleep(400);
    }

    std::string manifestPath;
    if (!WriteNmManifest(hostExe, extIdChrome, extIdEdge, manifestPath)) {
        printf("[错误] 写入 Native Messaging 清单失败。\n"); return false;
    }
    printf("[信息] 清单已写入：%s\n", manifestPath.c_str());

    SaveExtIds(extIdChrome, extIdEdge);   // 记录扩展 ID，供双击重装复用

    if (!RegisterNmHost(manifestPath, extIdChrome, extIdEdge))
        printf("[警告] 注册 Native Messaging 失败（需管理员权限）。\n");

    if (!SvcInstall()) { printf("[错误] 安装服务失败（需管理员权限）。\n"); return false; }
    printf("[信息] Windows 服务 SilverFoxGuardSvc 已安装（自动启动 / SYSTEM）。\n");

    // 立即启动
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE s = OpenServiceA(scm, "SilverFoxGuardSvc", SERVICE_START);
        if (s) { StartServiceA(s, 0, NULL); CloseServiceHandle(s); }
        CloseServiceHandle(scm);
    }
    printf("[完成] 银狐主防已安装并启动。扩展内「主防」将显示盾牌状态。\n");
    return true;
}

bool DoUninstall() {
    SvcUninstall();
    UnregisterNmHost();
    RegDeleteKeyExA(HKEY_LOCAL_MACHINE, CFG_ROOT, KEY_WOW64_64KEY, 0);
    printf("[信息] 已卸载服务、注销原生消息宿主、清除配置。\n");
    return true;
}

// ---------------------------------------------------------------------------
//  调试：前台运行
// ---------------------------------------------------------------------------
static void PrintResult() {
    std::lock_guard<std::mutex> lk(g_resultMutex);
    printf("[%s] status=%s score=%d findings=%zu\n",
        g_result.timestamp.c_str(), g_result.status.c_str(), g_result.score,
        g_result.findings.size());
    for (auto& f : g_result.findings)
        printf("   - [%s/%s] %s | %s | ioc=%s\n", f.category.c_str(), f.severity.c_str(),
               f.title.c_str(), f.detail.c_str(), f.ioc.c_str());
}
void RunConsole() {
    setvbuf(stdout, nullptr, _IONBF, 0);   // 管道下也实时输出，避免被 timeout 杀掉前丢缓冲
    printf("[银狐主防] 前台调试模式（Ctrl+C 退出）\n");
    g_stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    RunFullScan();
    PrintResult();
    while (!g_stop.load()) {
        DWORD r = WaitForSingleObject(g_stopEvent, 15000);
        if (g_stop.load()) break;
        if (r == WAIT_TIMEOUT) { RunFullScan(); PrintResult(); }
    }
}

}  // namespace sf
