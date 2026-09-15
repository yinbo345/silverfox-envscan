// service.cpp — 银狐环境检测服务：SCM 控制 / 守护循环 / 命名管道 / 自保 / 安装
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <sddl.h>
#include <shlobj.h>
#include <thread>
#include <atomic>
#include <mutex>
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
#include "service.h"

#pragma comment(lib, "advapi32.lib")

namespace sf {

SERVICE_STATUS        g_svcStatus{};
SERVICE_STATUS_HANDLE g_svcHandle = NULL;
HANDLE                g_stopEvent = NULL;
std::atomic<bool>     g_stop{false};

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
        dir = std::wstring(p) + L"\\SilverFoxEnvScan";
    else dir = L"C:\\ProgramData\\SilverFoxEnvScan";
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

    std::thread guard(GuardThread);
    std::thread pipe(PipeServerThread);
    WaitForSingleObject(g_stopEvent, INFINITE);
    if (guard.joinable()) guard.join();
    if (pipe.joinable()) pipe.join();

    g_svcStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_svcHandle, &g_svcStatus);
}

void RunService() {
    // 进程级单实例：防止服务被重复拉起（重复实例会争抢命名管道）
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"Global\\SilverFoxEnvScanService");
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
//  守护循环（后台定期扫描；间隔见 SCAN_INTERVAL_MS）
// ---------------------------------------------------------------------------
// 后台扫描间隔（毫秒）。过短会持续占用 CPU；3 分钟一扫在实时性与开销间取得平衡。
static const DWORD SCAN_INTERVAL_MS = 180000;   // 3 分钟

// 状态切换去重：仅当本次状态与上次通知状态不同才弹通知，避免每轮扫描刷屏。
// 首启若为 normal 不弹；之后任何切换（含由异常恢复正常）都弹一次。
static std::string g_lastToastStatus;
static void CheckAndNotify() {
    std::lock_guard<std::mutex> lk(g_resultMutex);
    if (g_result.status == g_lastToastStatus) {
        LogDbg("[check] skip: status unchanged (" + g_result.status + ")");
        return;
    }
    std::string prev = g_lastToastStatus;
    g_lastToastStatus = g_result.status;
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

void GuardThread() {
    // 启动自检：先跑【秒级快速预扫】立即出初步结果并通知（用户开机后几秒内即可在
    // 扩展看到检测状态），再后台全盘精扫补全细节——避免"服务在跑却像没自动扫描"。
    RunQuickScan();
    CheckAndNotify();
    RunFullScan();
    CheckAndNotify();
    int tick = 0;
    while (!g_stop.load()) {
        DWORD r = WaitForSingleObject(g_stopEvent, SCAN_INTERVAL_MS);
        if (g_stop.load()) break;
        if (r == WAIT_TIMEOUT) {
            RunFullScan();
            CheckAndNotify();
            ++tick;
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
            DWORD r = WaitForMultipleObjects(2, ws, FALSE, 1000);
            if (r == WAIT_OBJECT_0 + 1 || g_stop.load()) { CloseHandle(h); CloseHandle(ov.hEvent); break; }
            if (r != WAIT_OBJECT_0) { CloseHandle(h); CloseHandle(ov.hEvent); continue; }
            DWORD tr = 0; GetOverlappedResult(h, &ov, &tr, TRUE);
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
                std::string extra;                         // 附加字段（清除报告）
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
//  服务安装 / 自保重建
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

bool SvcInstall() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;
    std::string exe = GetExePath();
    std::wstring exeW = AToW(exe);
    std::wstring binW = L"\"" + exeW + L"\" --run-service";
    SC_HANDLE svc = CreateServiceW(scm, L"SilverFoxEnvScanSvc", L"银狐环境检测服务",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        binW.c_str(), NULL, NULL, NULL, L"LocalSystem", NULL);
    bool ok = !!svc;
    if (svc) { CloseServiceHandle(svc); svc = NULL; }
    else {
        // 服务已存在：必须把 ImagePath 更新成本次安装所在路径。
        // 否则服务仍从旧文件夹启动，与 DoInstall 写入的哈希基线对不上 → 自身完整性校验永久误报
        // （用户装到别的文件夹就会触发）。这也是“路径被写死”错觉的根因。
        svc = OpenServiceW(scm, L"SilverFoxEnvScanSvc", SERVICE_CHANGE_CONFIG);
        if (svc) {
            ok = ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                      binW.c_str(), NULL, NULL, NULL, L"LocalSystem", NULL, NULL) != 0;
            CloseServiceHandle(svc); svc = NULL;
        }
    }
    if (ok) {
        // 失败自动重启（自保：被杀后 SCM 拉起）
        svc = OpenServiceA(scm, "SilverFoxEnvScanSvc", SERVICE_ALL_ACCESS);
        if (svc) {
            SC_ACTION actions[3];
            for (auto& a : actions) { a.Delay = 60000; a.Type = SC_ACTION_RESTART; }
            SERVICE_FAILURE_ACTIONS fa{};
            fa.cActions = 3; fa.lpsaActions = actions; fa.dwResetPeriod = 86400;
            ChangeServiceConfig2A(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
            CloseServiceHandle(svc);
        }
    }
    CloseServiceHandle(scm);
    return ok;
}

bool SvcUninstall() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceA(scm, "SilverFoxEnvScanSvc",
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
    SC_HANDLE svc = OpenServiceA(scm, "SilverFoxEnvScanSvc", SERVICE_QUERY_STATUS);
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
        SC_HANDLE s = OpenServiceA(m, "SilverFoxEnvScanSvc", SERVICE_QUERY_STATUS);
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
    printf("[信息] Windows 服务 SilverFoxEnvScanSvc 已安装（自动启动 / SYSTEM / 失败自启）。\n");

    // 立即启动
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE s = OpenServiceA(scm, "SilverFoxEnvScanSvc", SERVICE_START);
        if (s) { StartServiceA(s, 0, NULL); CloseServiceHandle(s); }
        CloseServiceHandle(scm);
    }
    printf("[完成] 银狐环境检测已安装并启动。扩展内「环境检测」将显示盾牌状态。\n");
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
    printf("[%s] status=%s score=%d selfCheck=%d findings=%zu\n",
        g_result.timestamp.c_str(), g_result.status.c_str(), g_result.score,
        (int)g_result.selfCheck, g_result.findings.size());
    for (auto& f : g_result.findings)
        printf("   - [%s/%s] %s | %s | ioc=%s\n", f.category.c_str(), f.severity.c_str(),
               f.title.c_str(), f.detail.c_str(), f.ioc.c_str());
}
void RunConsole() {
    setvbuf(stdout, nullptr, _IONBF, 0);   // 管道下也实时输出，避免被 timeout 杀掉前丢缓冲
    printf("[银狐环境检测] 前台调试模式（Ctrl+C 退出）\n");
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
