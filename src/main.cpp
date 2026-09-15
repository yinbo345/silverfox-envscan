// main.cpp — 银狐环境检测服务主入口（模式分发）
// 本程序无托盘、无独立页面、无本地端口；常驻为 Windows 服务，结果只在扩展内查看。
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>   // IsUserAnAdmin

#include <cstdio>
#include <string>

#include "common.h"
#include "service.h"

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
    mbp.lpszCaption = L"银狐环境检测";
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
        dir = std::wstring(p) + L"\\SilverFoxEnvScan";
    else dir = L"C:\\ProgramData\\SilverFoxEnvScan";
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
                // 服务没在运行：告知扩展离线，稍后自动重试（保持进程存活，待服务就绪即复用）。
                // 服务启动交给安装器 / SCM（失败自启策略），此处不做自愈重建。
                sf::WriteFramed(outh, "{\"type\":\"service_unavailable\"}");
                Sleep(2000);
                continue;
            }
        }
        std::string req;
        if (!sf::ReadFramed(inh, req)) break;   // 浏览器关闭端口 → 退出
        std::string type = sf::JsonGetString(req, "type");
        // clean 也复用同一条命名管道：扩展面板里的「一键清除」由服务以最高权限执行（无需 UAC）
        std::string cmd = (type == "rescan") ? "rescan"
                        : (type == "clean")  ? "clean"
                        : (type == "history") ? "history"
                        : "status";

        // 预热：rescan 会触发全量扫描（约 20 秒），期间提前预热 WebView2，扫描出异常即可立即显示，
        // 省去扫描完成后弹窗的冷启动 5~8 秒。
        if (cmd == "rescan") {
            wchar_t exepath[MAX_PATH];
            GetModuleFileNameW(nullptr, exepath, MAX_PATH);
            std::wstring precmd = std::wstring(L"\"") + exepath + L"\" --prewarm";
            STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
            if (CreateProcessW(nullptr, (LPWSTR)precmd.c_str(), nullptr, nullptr, FALSE,
                               0, nullptr, nullptr, &si, &pi)) {
                if (pi.hThread) CloseHandle(pi.hThread);
                if (pi.hProcess) CloseHandle(pi.hProcess);
            }
        }

        if (!sf::WriteFramed(pipe, "{\"cmd\":\"" + cmd + "\"}")) {
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
        if (!st.empty() && st != "normal" && st != s_lastNmToast) {
            s_lastNmToast = st;
            wchar_t exepath[MAX_PATH];
            GetModuleFileNameW(nullptr, exepath, MAX_PATH);
            std::wstring tcmd = std::wstring(L"\"") + exepath + L"\" --toast --status=" + A2W(st)
                             + L" --score=" + std::to_wstring(sc);
            STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
            // bInheritHandles=FALSE：避免子进程继承本宿主的 stdin 管道而被误判为 NM 宿主模式
            // 不传 CREATE_NEW_CONSOLE / DETACHED_PROCESS：toast 子进程会继承本宿主（浏览器拉起）的
            // 不可见控制台，不会弹黑框——与「之前能用的版本」行为一致。
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
    // 已被重定向到文件/管道（如脚本里 `> out.txt`）时直接沿用，绝不能 AllocConsole：
    // GUI 子系统下父进程没有可附着的控制台，AllocConsole 会把输出抢到新弹出的控制台窗口里，
    // 导致重定向文件一片空白（排查构建/扫描问题时曾因此误判为「扫描卡死」）。
    DWORD t = GetFileType(GetStdHandle(STD_OUTPUT_HANDLE));
    if (t == FILE_TYPE_DISK || t == FILE_TYPE_PIPE) return;
    if (!AttachConsole(ATTACH_PARENT_PROCESS) && !AllocConsole()) return;
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONIN$", "r", stdin);
}

int main(int argc, char** argv) {
    // 浏览器通过 Native Messaging 拉起本程序时，stdin 是匿名管道
    HANDLE inh = GetStdHandle(STD_INPUT_HANDLE);
    if (GetFileType(inh) == FILE_TYPE_PIPE) {
        RunNmHost();
        return 0;
    }

    if (HasArg(argc, argv, "install") || HasArg(argc, argv, "uninstall")) {
        if (!IsUserAnAdmin())
            fprintf(stderr, "[银狐环境检测] 提示：安装 / 卸载需以管理员身份运行。\n");
    }

    if (HasArg(argc, argv, "run-service")) { sf::RunService(); return 0; }

    if (HasArg(argc, argv, "install")) {
        std::string c = GetArg(argc, argv, "ext-id");
        std::string e = GetArg(argc, argv, "edge-ext-id");
        bool silent = HasArg(argc, argv, "silent");
        bool ok = sf::DoInstall(c, e);
        printf(ok ? "[银狐环境检测] 安装完成。\n" : "[银狐环境检测] 安装失败，请检查权限。\n");
        if (!silent) {
            const wchar_t* okMsg   = L"银狐环境检测已安装并启动。\n\n可在浏览器扩展「环境检测」中查看盾牌状态（绿=正常 / 红=感染）。";
            const wchar_t* failMsg = L"银狐环境检测安装失败。\n\n请右键本程序以管理员身份运行后再试。";
            GuiNotify(ok, ok ? okMsg : failMsg);
        }
        return ok ? 0 : 1;
    }

    if (HasArg(argc, argv, "uninstall")) {
        bool silent = HasArg(argc, argv, "silent");
        sf::DoUninstall();
        printf("[银狐环境检测] 已卸载。\n");
        if (!silent) GuiNotify(true, L"银狐环境检测已卸载。\n\n相关 Windows 服务与注册表项已清除。");
        return 0;
    }

    if (HasArg(argc, argv, "toast")) {
        std::string st = GetArg(argc, argv, "status");
        std::string sc = GetArg(argc, argv, "score");
        int score = sc.empty() ? 0 : atoi(sc.c_str());
        if (st.empty()) st = "infected";
        return sf::RunToast(st, score);
    }

    if (HasArg(argc, argv, "prewarm")) { return sf::RunPrewarm(); }

    // 通用「原生弹窗通知」：--notice="文本" 用品牌盾牌图标把一段话弹给用户。
    // 用途：宿主界面（如 WorkBuddy）卡死、看不到执行过程时，仍可由本程序的原生弹窗传递状态。
    if (HasArg(argc, argv, "notice")) {
        std::string t = GetArg(argc, argv, "notice");
        if (t.empty()) t = "银狐环境检测：任务已就绪。";
        ShowShieldMsg(AnsiToW(t).c_str());
        return 0;
    }

    if (HasArg(argc, argv, "console")) { EnsureConsoleForDebug(); sf::RunConsole(); return 0; }

    // 无参数：用户双击（Windows 子系统无控制台）。给明确反馈，而不是静默退出。
    if (sf::IsServiceRunning()) {
        ShowShieldMsg(
            L"银狐环境检测已在后台运行（Windows 服务 SilverFoxEnvScanSvc）。\n\n"
            L"无需重复启动，可直接在浏览器扩展「环境检测」中查看盾牌状态（绿=正常 / 红=感染）。");
        return 0;
    }
    // 服务未运行：管理员双击直接执行安装，避免「已管理员却仍提示右键管理员」的死循环
    if (IsUserAnAdmin()) {
        std::string c, e;
        sf::ReadSavedExtIds(c, e);          // 复用安装包之前记录过的扩展 ID
        bool ok = sf::DoInstall(c, e);
        if (ok) {
            std::wstring extra = (c.empty() && e.empty())
                ? L"\n\n未检测到浏览器扩展 ID：扩展可能仍连不上。请用 SilverFoxEnvScan-Setup.exe 安装包重装并填写 Chrome/Edge 扩展 ID，"
                  L"或运行  SilverFoxEnvScanSvc.exe --install --ext-id=你的扩展ID"
                : L"";
            ShowShieldMsg((std::wstring(
                L"银狐环境检测已安装并启动（Windows 服务自动常驻后台）。\n\n"
                L"打开浏览器扩展「环境检测」即可查看盾牌状态（绿=正常 / 红=感染）。") + extra).c_str());
        } else {
            ShowShieldMsg(L"银狐环境检测安装失败。\n\n请使用 SilverFoxEnvScan-Setup.exe 安装包，或以管理员身份运行安装命令。");
        }
        return 0;
    }
    // 非管理员：引导右键管理员运行
    ShowShieldMsg(
        L"银狐环境检测当前未在后台运行。\n\n请右键本程序 →「以管理员身份运行」完成安装，安装后会以 Windows 服务自动常驻后台，结果在浏览器扩展「环境检测」中查看。");
    return 0;
}
