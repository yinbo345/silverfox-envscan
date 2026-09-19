// main.cpp — 银狐主防服务主入口（模式分发）
// 本程序无托盘、无独立页面、无本地端口；常驻为 Windows 服务，结果只在扩展内查看。
// P6 起：主界面（--gui / 双击）为独立 WebView2 窗口 + 系统托盘，数据经命名管道直连服务。
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>   // IsUserAnAdmin

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>

#include "common.h"
#include "service.h"
#include "gui.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef IDI_SHIELD
#define IDI_SHIELD 101
#endif

static bool HasArg(int argc, char** argv, const char* name) {
    std::string t = std::string("--") + name;
    for (int i = 1; i < argc; ++i) if (t == argv[i]) return true;
    return false;
}
static std::string GetArg(int argc, char** argv, const char* name) {
    std::string n = std::string("--") + name + "=";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind(n, 0) == 0) {
            std::string v = a.substr(n.size());
            // 去掉外壳可能带入的引号（如安装包 --ext-id="xxx"）
            if (!v.empty() && v.front() == '"' && v.back() == '"') v = v.substr(1, v.size() - 2);
            return v;
        }
    }
    return "";
}

// 用我们的品牌盾牌图标弹窗（替代系统默认图标）
static void ShowShieldMsg(const wchar_t* text) {
    HICON hIcon = (HICON)LoadImageW(GetModuleHandle(NULL),
                                    (LPCWSTR)MAKEINTRESOURCEW(IDI_SHIELD),
                                    IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED);
    MSGBOXPARAMSW mbp = { sizeof(mbp) };
    mbp.hwndOwner   = NULL;
    mbp.hInstance   = GetModuleHandle(NULL);
    mbp.lpszText    = text;
    mbp.lpszCaption = L"银狐主防";
    mbp.dwStyle     = MB_OK | MB_USERICON;
    mbp.lpszIcon    = (LPCWSTR)hIcon;
    MessageBoxIndirectW(&mbp);
}

static void GuiNotify(bool ok, const wchar_t* msg) {
    if (GetConsoleWindow() != NULL) return;   // 命令行下不打扰，交给 printf
    ShowShieldMsg(msg);
}

// ASCII 字符串 → wstring（status/score 均为 ASCII 范围，逐字节映射即可）
static std::wstring A2W(const std::string& s) {
    std::wstring w; w.resize(s.size());
    for (size_t i = 0; i < s.size(); ++i) w[i] = (wchar_t)(unsigned char)s[i];
    return w;
}

// ANSI(GBK) → wstring：命令行中文参数按系统 ANSI 代码页传入，逐字节映射会变乱码
static std::wstring AnsiToW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// ---- 预热结果文件（与 toast.cpp 的 PrewarmResultPathW 保持一致）----
static std::wstring PrewarmResultPathW() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p) == S_OK)
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\prewarm_result.txt";
}
static void WritePrewarmResult(const std::string& status, int score) {
    std::wstring path = PrewarmResultPathW();
    DeleteFileW(path.c_str());
    std::string data = "status=" + status + " score=" + std::to_string(score);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                           nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, data.c_str(), (DWORD)data.size(), &w, nullptr);
    CloseHandle(h);
}
static bool PrewarmResultExists() {
    return GetFileAttributesW(PrewarmResultPathW().c_str()) != INVALID_FILE_ATTRIBUTES;
}

// 弹窗去重（落盘版）：浏览器扩展每次轮询都会拉起【新宿主进程】，进程内 static 去重
// 会被重置 → status 非 normal 时每 30 秒弹一次（用户反馈的 bug）。改为写盘记录
// 「已通知状态 + 时间戳」：同状态在 TTL 内不重复弹，状态变化立即弹，TTL 后允许复弹。
// 路径：C:\ProgramData\SilverFoxGuard\toast_dedup.txt，内容 "status|unix秒"
static std::wstring ToastDedupPathW() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p) == S_OK)
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\toast_dedup.txt";
}
// 返回 true=应弹窗（未在 TTL 内通知过相同状态）；false=去重跳过
static bool ShouldToast(const std::string& status, const int ttlSec) {
    std::wstring path = ToastDedupPathW();
    // 读旧记录
    std::string prev;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[128] = {0}; DWORD n = 0;
        ReadFile(h, buf, sizeof(buf) - 1, &n, nullptr);
        CloseHandle(h);
        if (n) prev.assign(buf, n);
    }
    long long now = (long long)time(nullptr);
    std::string cur = status + "|" + std::to_string(now);
    // 解析旧状态与时间
    if (!prev.empty()) {
        size_t bar = prev.find('|');
        if (bar != std::string::npos) {
            std::string pSt = prev.substr(0, bar);
            long long pT  = atoll(prev.c_str() + bar + 1);
            if (pSt == status && (now - pT) < ttlSec) return false;   // 同状态且未过 TTL
        }
    }
    // 写新记录
    h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0; WriteFile(h, cur.c_str(), (DWORD)cur.size(), &w, nullptr);
        CloseHandle(h);
    }
    return true;
}

// 单程序兼任 Native Messaging 宿主：被浏览器拉起时 stdin 是管道。
// 与服务的命名管道保持【单一长连接】，所有 status/rescan 帧复用同一连接，
// 不再每次轮询都重连（避免反复拉起新宿主进程 / 扩展侧掉线）。
static void RunNmHost() {
    HANDLE inh  = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE outh = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetFileType(inh) != FILE_TYPE_PIPE) return;

    HANDLE pipe = INVALID_HANDLE_VALUE;
    auto connectPipe = [&]() -> bool {
        for (int i = 0; i < 25; ++i) {
            pipe = CreateFileW(sf::PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (pipe != INVALID_HANDLE_VALUE) return true;
            Sleep(300);
        }
        return false;
    };

    while (true) {
        if (pipe == INVALID_HANDLE_VALUE) {
            if (!connectPipe()) {
                // 服务还没起来：告知扩展离线，稍后自动重试（保持进程存活，待服务就绪即复用）
                sf::WriteFramed(outh, "{\"type\":\"service_unavailable\"}");
                Sleep(2000);
                continue;
            }
        }
        std::string req;
        if (!sf::ReadFramed(inh, req)) break;   // 浏览器关闭端口 → 退出
        std::string type = sf::JsonGetString(req, "type");
        // clean 也复用同一条命名管道：扩展面板里的「一键清除」由服务以最高权限执行（无需 UAC）
        std::string cmd, extra;
        if (type == "rescan") cmd = "rescan";
        else if (type == "clean") cmd = "clean";
        else if (type == "history") cmd = "history";
        else if (type == "gpuget") cmd = "gpuget";
        else if (type == "gpuprog") cmd = "gpuprog";   // 地图加载进度（扩展端进度条轮询）
        else if (type == "gpu") { cmd = "gpu"; extra = ",\"on\":" + std::to_string(sf::JsonGetInt(req, "on")); }
        // 勒索回滚（对齐卡巴 System Watcher）：状态查询 / 快照清单 / 手动回滚 / 清空缓存
        else if (type == "rollbackstatus") cmd = "rollbackstatus";
        else if (type == "rollbacklist")   cmd = "rollbacklist";
        else if (type == "rollbackdo") {
            cmd = "rollbackdo";
            extra = ",\"reason\":\"" + sf::JsonEscape(sf::JsonGetString(req, "reason")) + "\"";
        }
        else if (type == "rollbackclean")  cmd = "rollbackclean";
        else if (type == "rollbackundo") {
            cmd = "rollbackundo";
            extra = ",\"token\":\"" + sf::JsonEscape(sf::JsonGetString(req, "token")) + "\"";
        }
        else cmd = "status";

        // 预热：rescan 会触发全量扫描（约 20 秒），期间提前预热 WebView2，扫描出异常即可立即显示，
        // 省去扫描完成后弹窗的冷启动 5~8 秒。
        if (cmd == "rescan") {
            wchar_t exepath[MAX_PATH];
            GetModuleFileNameW(nullptr, exepath, MAX_PATH);
            std::wstring precmd = std::wstring(L"\"") + exepath + L"\" --scanprogress";
            STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
            if (CreateProcessW(nullptr, (LPWSTR)precmd.c_str(), nullptr, nullptr, FALSE,
                               0, nullptr, nullptr, &si, &pi)) {
                if (pi.hThread) CloseHandle(pi.hThread);
                if (pi.hProcess) CloseHandle(pi.hProcess);
            }
        }

        if (!sf::WriteFramed(pipe, "{\"cmd\":\"" + cmd + "\"" + extra + "}")) {
            CloseHandle(pipe); pipe = INVALID_HANDLE_VALUE;   // 连接断了，下一轮重连
            continue;
        }
        std::string resp;
        if (!sf::ReadFramed(pipe, resp)) {
            CloseHandle(pipe); pipe = INVALID_HANDLE_VALUE;
            continue;
        }
        sf::WriteFramed(outh, resp);

        // —— 弹窗触发 ——
        // NM 宿主由浏览器拉起，运行在【用户桌面会话】，这里拉起的 --toast 100% 可见有声（Session 0
        // 服务跨会话弹窗在 VM/RDP 下不可见）。rescan 场景优先由预热进程显示（读结果文件）；
        // 预热进程消费结果（删文件）则不再重复拉起，未消费（预热失败）才回退正常 --toast。
        static std::string s_lastNmToast;
        std::string st = sf::JsonGetString(resp, "status");
        int sc = sf::JsonGetInt(resp, "score");   // 必须用 JsonGetInt：JSON 里 score 是裸数字，JsonGetString 取不到
        if (cmd == "rescan") {
            WritePrewarmResult(st, sc);
            bool consumed = false;
            for (int i = 0; i < 15 && PrewarmResultExists(); ++i) Sleep(200);   // 最多等 3 秒
            consumed = !PrewarmResultExists();
            if (consumed) {
                s_lastNmToast = st;   // 预热进程已消费（异常显示 / 正常退出），更新去重，避免后续 status 重复弹
                continue;
            }
        }
        if (!st.empty() && st != "normal" && st != s_lastNmToast && ShouldToast(st, 900)) {
            s_lastNmToast = st;
            wchar_t exepath[MAX_PATH];
            GetModuleFileNameW(nullptr, exepath, MAX_PATH);
            std::wstring tcmd = std::wstring(L"\"") + exepath + L"\" --toast --status=" + A2W(st)
                             + L" --score=" + std::to_wstring(sc);
            STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
            // bInheritHandles=FALSE：避免子进程继承本宿主的 stdin 管道而被误判为 NM 宿主模式
            if (CreateProcessW(nullptr, (LPWSTR)tcmd.c_str(), nullptr, nullptr, FALSE,
                              0, nullptr, nullptr, &si, &pi)) {
                if (pi.hThread) CloseHandle(pi.hThread);
                if (pi.hProcess) CloseHandle(pi.hProcess);
            }
        }
    }
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
}

// GUI 子系统（/SUBSYSTEM:WINDOWS）下进程默认没有控制台，--console 调试模式需手动挂载：
// 优先附着父进程控制台（从 cmd 运行时可见），失败则新建一个。同时把 std 流重定向到控制台，
// 否则 printf 无处可去（GUI 进程的 stdout 默认不连任何设备）。
static void EnsureConsoleForDebug() {
    // 已被重定向到文件/管道（如脚本里 \`> out.txt\`）时直接沿用，绝不能 AllocConsole：
    DWORD t = GetFileType(GetStdHandle(STD_OUTPUT_HANDLE));
    if (t == FILE_TYPE_DISK || t == FILE_TYPE_PIPE) return;
    if (!AttachConsole(ATTACH_PARENT_PROCESS) && !AllocConsole()) return;
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONIN$", "r", stdin);
}

// P3 主动防御：进程加固（所有入口最先执行）。
// 本程序是安全软件自身，禁止动态代码生成/修改 → 注入的 shellcode 无法在本进程内执行
// （防 AtomBombing / ATL thunk / 各类 WriteProcessMemory+远程线程 的注入落地）。
// 纯 C++/MT 单文件，无 JIT，无影响。
static void HardenSelf() {
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dcp{};
    dcp.ProhibitDynamicCode = 1;
    SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dcp, sizeof(dcp));
}

int main(int argc, char** argv) {
    // WebView2 宿主模式（--gui / --toast / --prewarm）不启用「禁止动态代码」策略：
    // Chromium browser 进程需动态分配可执行内存，被 ProcessDynamicCodePolicy 禁止后
    // 渲染进程初始化失败 → 页面白屏、NavigationCompleted 永不触发（P3 加固曾致 GUI/弹窗
    // 双双白屏，本修复按模式豁免 WebView2 宿主，其余入口仍加固）。
    const bool wv2Host = HasArg(argc, argv, "gui") || HasArg(argc, argv, "toast") || HasArg(argc, argv, "prewarm");
    if (!wv2Host) HardenSelf();
    // 浏览器通过 Native Messaging 拉起本程序时，stdin 是匿名管道
    HANDLE inh = GetStdHandle(STD_INPUT_HANDLE);
    if (GetFileType(inh) == FILE_TYPE_PIPE) {
        RunNmHost();
        return 0;
    }

    if (HasArg(argc, argv, "install") || HasArg(argc, argv, "uninstall")) {
        if (!IsUserAnAdmin())
            fprintf(stderr, "[银狐主防] 提示：安装 / 卸载需以管理员身份运行。\n");
    }

    if (HasArg(argc, argv, "run-service")) { sf::RunService(); return 0; }

    if (HasArg(argc, argv, "install")) {
        std::string c = GetArg(argc, argv, "ext-id");
        std::string e = GetArg(argc, argv, "edge-ext-id");
        bool silent = HasArg(argc, argv, "silent");
        bool ok = sf::DoInstall(c, e);
        printf(ok ? "[银狐主防] 安装完成。\n" : "[银狐主防] 安装失败，请检查权限。\n");
        if (!silent) {
            const wchar_t* okMsg   = L"银狐主防已安装并启动。\n\n可在浏览器扩展「主防」中查看盾牌状态（绿=正常 / 红=感染）。";
            const wchar_t* failMsg = L"银狐主防安装失败。\n\n请右键本程序以管理员身份运行后再试。";
            GuiNotify(ok, ok ? okMsg : failMsg);
        }
        return ok ? 0 : 1;
    }

    if (HasArg(argc, argv, "uninstall")) {
        bool silent = HasArg(argc, argv, "silent");
        sf::DoUninstall();
        printf("[银狐主防] 已卸载。\n");
        if (!silent) GuiNotify(true, L"银狐主防已卸载。\n\n相关 Windows 服务与注册表项已清除。");
        return 0;
    }

    if (HasArg(argc, argv, "toast")) {
        std::string st = GetArg(argc, argv, "status");
        std::string sc = GetArg(argc, argv, "score");
        std::string rk = GetArg(argc, argv, "risk");
        std::string ud = GetArg(argc, argv, "undo");
        std::string rb = GetArg(argc, argv, "rolledback");
        int score = sc.empty() ? 0 : atoi(sc.c_str());
        if (st.empty()) st = "infected";
        return sf::RunToast(st, score, rk, ud, rb == "1");
    }

    if (HasArg(argc, argv, "prewarm")) { return sf::RunPrewarm(); }

    if (HasArg(argc, argv, "scanprogress")) { return sf::RunScanProgress(); }

    // 右键自定义查杀（--probe --file=<path>）：由资源管理器以用户会话拉起本进程，
    // 连服务管道执行单文件启发式判定，拿到结果后渲染右下角 WebView2 卡片（可点「立即清除」）。
    if (HasArg(argc, argv, "probe")) {
        std::wstring wfile;
        int wargc = 0;
        LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
        if (wargv) {
            for (int i = 0; i < wargc; ++i) {
                std::wstring a = wargv[i];
                if (a.rfind(L"--file=", 0) == 0) { wfile = a.substr(7); break; }
            }
            LocalFree(wargv);
        }
        if (wfile.empty()) { ShowShieldMsg(L"银狐主防：未提供待查杀文件路径。"); return 1; }
        return sf::RunProbeToast(wfile);
    }


    if (HasArg(argc, argv, "notice")) {
        std::string t = GetArg(argc, argv, "notice");
        if (t.empty()) t = "银狐主防：任务已就绪。";
        ShowShieldMsg(AnsiToW(t).c_str());
        return 0;
    }

    if (HasArg(argc, argv, "console")) { EnsureConsoleForDebug(); sf::RunConsole(); return 0; }

    // ---- 主界面 ----
    // ★ 2026-09-19 主界面已迁 Electron（gui\SilverFoxGUI.exe，由安装包附带）：
    //   双击主程序 / 开始菜单快捷方式打开的都是 Electron 窗口；
    //   WebView2 版（--gui）仅留作开发兜底（Electron 包缺失时自动退回）。
    if (HasArg(argc, argv, "gui")) return sf::RunGui();

    // 无参数：用户双击 → 优先拉起 Electron 主界面（同目录 gui\SilverFoxGUI.exe）。
    //   服务后台常驻，Electron 界面经命名管道实时拉取；服务未运行时界面显示离线状态。
    {
        wchar_t exePath[MAX_PATH] = L"", dir[MAX_PATH] = L"", guiExe[MAX_PATH] = L"";
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        wchar_t* cut = wcsrchr(exePath, L'\\');
        if (cut) {
            *cut = L'\0';
            lstrcpynW(dir, exePath, MAX_PATH);
            wsprintfW(guiExe, L"%s\\gui\\SilverFoxGUI.exe", dir);
            *cut = L'\\';
        }
        if (guiExe[0] && GetFileAttributesW(guiExe) != INVALID_FILE_ATTRIBUTES) {
            STARTUPINFOW si{}; si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};
            if (CreateProcessW(guiExe, nullptr, nullptr, nullptr, FALSE, 0,
                               nullptr, dir, &si, &pi)) {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return 0;
            }
        }
    }
    // 退回：Electron 包缺失（如绿色免安装场景）→ 打开内置 WebView2 版主界面。
    return sf::RunGui();
}
