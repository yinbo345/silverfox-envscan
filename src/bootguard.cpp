// ===========================================================================
//  bootguard.cpp — MBR 引导扇区防护实现（见 bootguard.h 的设计说明）
// ---------------------------------------------------------------------------
//  引导代码区分界取 428（0x1AC）而不是教科书式的 446：
//    · 440-443 是磁盘签名、446-509 是分区表、510-511 是 0x55AA —— 都属于
//      "磁盘元数据"，分区工具/DiskGenius 改它们是合法操作；
//    · 真实 bootkit（TDL4/Petya 等）覆盖的都是低偏移引导代码（0x000-0x15x），
//      0-427 已完整覆盖；
//    · 把 428-511 全划给元数据，签名/分区表变化只自动重立基线，不弹窗误报。
// ---------------------------------------------------------------------------
#include <windows.h>
#include <shlobj.h>

#include "bootguard.h"
#include "common.h"
#include "behavior.h"   // ProcReputable：拦截链终止前的进程信誉门

#include <mutex>
#include <vector>
#include <cstdint>

namespace boot {

static const int      kSector      = 512;
static const int      kBootCodeEnd = 428;   // [0,428)=引导代码区  [428,512)=磁盘元数据
static const wchar_t* kDrive       = L"\\\\.\\PhysicalDrive0";

// ---- 状态 ----
static std::mutex      g_mtx;
static unsigned char   g_baseline[kSector] = {0};
static bool            g_haveBaseline = false;
static void*           g_stopEvent = nullptr;
static void (*g_cb)(const BootAlert&) = nullptr;

// 归因环：行为引擎最近标记的可疑进程（10 分钟窗内有效）
struct Suspicion { int pid; std::string path; ULONGLONG at; };
static std::vector<Suspicion> g_suspicions;

// 最近一次自动拦截的上下文（bootstatus JSON 用）
struct LastAlertInfo {
    std::string at, proc, reason;
    int pid = 0;
    bool autoHandled = false, terminated = false, changed = false;
};
static LastAlertInfo g_last;

// ---- 工具 ----
static std::wstring DataRoot() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}
static std::wstring BaselinePath()  { return DataRoot() + L"\\mbr_baseline.bin"; }
static std::wstring QuarantineDir() {
    std::wstring d = DataRoot() + L"\\mbr_quarantine";
    CreateDirectoryW(d.c_str(), nullptr);
    return d;
}
static std::string NowStr() {
    SYSTEMTIME st; GetLocalTime(&st);
    char b[40];
    snprintf(b, sizeof(b), "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}

// 读扇区 0（LocalSystem 无需额外特权；读失败多为主盘无关紧要的探测盘）
static bool ReadMbr(unsigned char buf[kSector]) {
    HANDLE h = CreateFileW(kDrive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER pos; pos.QuadPart = 0;
    BOOL ok = SetFilePointerEx(h, pos, nullptr, FILE_BEGIN);
    DWORD rn = 0;
    if (ok) ok = ReadFile(h, buf, kSector, &rn, nullptr) && rn == kSector;
    CloseHandle(h);
    return ok != FALSE;
}

// 写扇区 0（写前调用方必须已留好隔离/取证副本）
static bool WriteMbr(const unsigned char buf[kSector]) {
    HANDLE h = CreateFileW(kDrive, GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER pos; pos.QuadPart = 0;
    BOOL ok = SetFilePointerEx(h, pos, nullptr, FILE_BEGIN);
    DWORD wn = 0;
    if (ok) ok = WriteFile(h, buf, kSector, &wn, nullptr) && wn == kSector;
    if (ok) FlushFileBuffers(h);
    CloseHandle(h);
    return ok != FALSE;
}

// 把当前扇区内容隔离留存（512B 小文件，供"撤销拦截"写回与取证）
static std::string QuarantineCurrent(const unsigned char cur[kSector]) {
    char id[16];
    snprintf(id, sizeof(id), "%08x", (unsigned)(GetTickCount() & 0xFFFFFFFF));
    std::string sid(id);
    std::wstring p = QuarantineDir() + L"\\mbr_" + std::wstring(sid.begin(), sid.end()) + L".bin";
    HANDLE hf = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return "";
    DWORD wn = 0;
    WriteFile(hf, cur, kSector, &wn, nullptr);
    CloseHandle(hf);
    return id;
}

static bool LoadBaselineFile() {
    HANDLE hf = CreateFileW(BaselinePath().c_str(), GENERIC_READ, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    unsigned char buf[kSector]; DWORD rn = 0;
    BOOL ok = ReadFile(hf, buf, kSector, &rn, nullptr) && rn == kSector;
    CloseHandle(hf);
    if (!ok) return false;
    std::lock_guard<std::mutex> lk(g_mtx);
    memcpy(g_baseline, buf, kSector);
    g_haveBaseline = true;
    return true;
}

static bool SaveBaselineFile(const unsigned char buf[kSector]) {
    HANDLE hf = CreateFileW(BaselinePath().c_str(), GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return false;
    DWORD wn = 0;
    WriteFile(hf, buf, kSector, &wn, nullptr);
    CloseHandle(hf);
    return wn == kSector;
}

// ===========================================================================
//  对外接口
// ===========================================================================
bool Init() {
    unsigned char cur[kSector];
    if (!ReadMbr(cur)) {
        sf::LogDbg("[boot] MBR 基线建立失败：读 PhysicalDrive0 扇区 0 失败（无基线，监视不启动）");
        return false;
    }
    if (LoadBaselineFile()) {
        sf::LogDbg("[boot] MBR 基线已加载（" + sf::Sha256Bytes(g_baseline, kBootCodeEnd).substr(0, 12) + "…）");
        return true;
    }
    // 首次运行：以当前扇区为基线。此刻系统是干净的（木马在我们之前就已存在的
    // bootkit 情形，基线会包含它 —— 这类历史感染交给全盘扫描引擎，不归本模块管）。
    if (!SaveBaselineFile(cur)) {
        sf::LogDbg("[boot] MBR 基线写入失败（ProgramData 不可写？）");
        return false;
    }
    std::lock_guard<std::mutex> lk(g_mtx);
    memcpy(g_baseline, cur, kSector);
    g_haveBaseline = true;
    sf::LogDbg("[boot] MBR 基线已建立（首次运行，sha256 前 12 位 " +
           sf::Sha256Bytes(cur, kBootCodeEnd).substr(0, 12) + "…）");
    return true;
}

void SetStopEvent(void* ev) { g_stopEvent = ev; }

void SetAlertCallback(void (*fn)(const BootAlert&)) { g_cb = fn; }

void NoteSuspicion(int pid, const std::string& path) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_suspicions.push_back({pid, path, GetTickCount64()});
    if (g_suspicions.size() > 8) g_suspicions.erase(g_suspicions.begin());   // 只留最近 8 条
}

CheckResult CheckNow() {
    CheckResult cr;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (!g_haveBaseline) { cr.status = 3; cr.reason = "无基线"; return cr; }
    }
    unsigned char cur[kSector];
    if (!ReadMbr(cur)) { cr.status = 3; cr.reason = "读盘失败"; return cr; }

    bool bootDiff = false, metaDiff = false;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        for (int i = 0; i < kBootCodeEnd; ++i) if (cur[i] != g_baseline[i]) { bootDiff = true; break; }
        for (int i = kBootCodeEnd; i < kSector; ++i) if (cur[i] != g_baseline[i]) { metaDiff = true; break; }
    }
    if (!bootDiff && !metaDiff) { cr.status = 0; return cr; }

    if (!bootDiff && metaDiff) {
        // 仅磁盘元数据变化（分区工具/签名改写）＝ 合法操作：自动重立基线，不弹窗。
        // 引导代码不变的前提下，重立基线不会把 bootkit 洗白。
        SaveBaselineFile(cur);
        std::lock_guard<std::mutex> lk(g_mtx);
        memcpy(g_baseline, cur, kSector);
        sf::LogDbg("[boot] 磁盘元数据（签名/分区表）变化，已自动重立基线");
        cr.status = 2; cr.reason = "磁盘元数据变化，已重立基线";
        return cr;
    }

    // 引导代码区被改 —— 高危
    std::string oldSha = sf::Sha256Bytes(g_baseline, kBootCodeEnd).substr(0, 12);
    std::string newSha = sf::Sha256Bytes(cur, kBootCodeEnd).substr(0, 12);
    cr.status = 1;
    cr.reason = "引导代码区 sha256：" + oldSha + "… → " + newSha + "…";
    sf::LogDbg("[boot] 引导代码区被修改！" + cr.reason);
    return cr;
}

bool Restore() {
    unsigned char base[kSector];
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (!g_haveBaseline) return false;
        memcpy(base, g_baseline, kSector);
    }
    unsigned char before[kSector];
    ReadMbr(before);   // 失败不影响——写回前尽力留取证
    std::string qid = QuarantineCurrent(before);
    if (!WriteMbr(base)) { sf::LogDbg("[boot] 恢复引导失败：写扇区 0 被拒"); return false; }
    unsigned char after[kSector];
    bool verified = ReadMbr(after) && memcmp(after, base, kSector) == 0;
    sf::LogDbg("[boot] 恢复引导记录完成（写回基线，取证副本 " +
           (qid.empty() ? std::string("无") : qid) + "，校验" + (verified ? "通过" : "失败") + "）");
    return true;
}

bool Accept() {
    unsigned char cur[kSector];
    if (!ReadMbr(cur)) return false;
    if (!SaveBaselineFile(cur)) return false;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        memcpy(g_baseline, cur, kSector);
    }
    sf::LogDbg("[boot] 用户信任当前引导记录，已重立基线");
    return true;
}

bool UndoIntercept(const std::string& hexId) {
    // 白名单校验：id 只能是 8 位 hex（文件名拼接边界）
    if (hexId.size() != 8) return false;
    for (char c : hexId)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    std::wstring p = QuarantineDir() + L"\\mbr_" + std::wstring(hexId.begin(), hexId.end()) + L".bin";
    HANDLE hf = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { sf::LogDbg("[boot] 撤销拦截失败：隔离副本不存在"); return false; }
    unsigned char buf[kSector]; DWORD rn = 0;
    BOOL ok = ReadFile(hf, buf, kSector, &rn, nullptr) && rn == kSector;
    CloseHandle(hf);
    if (!ok) return false;
    if (!WriteMbr(buf)) { sf::LogDbg("[boot] 撤销拦截失败：写扇区 0 被拒"); return false; }
    // 写回后以该内容为新基线（用户确认这是合法变更）
    SaveBaselineFile(buf);
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        memcpy(g_baseline, buf, kSector);
    }
    sf::LogDbg("[boot] 用户撤销自动拦截：隔离副本 " + hexId + " 已写回并重立基线");
    return true;
}

std::string StatusJson() {
    unsigned char cur[kSector];
    bool readable = ReadMbr(cur);
    std::string bootSha;
    bool changed = false;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (readable && g_haveBaseline)
            for (int i = 0; i < kBootCodeEnd; ++i) if (cur[i] != g_baseline[i]) { changed = true; break; }
        if (readable) bootSha = sf::Sha256Bytes(cur, kBootCodeEnd).substr(0, 16);
        auto J = [](const std::string& s) { return sf::JsonString(s); };
        std::string js = "{\"baseline\":" + std::string(g_haveBaseline ? "true" : "false");
        js += ",\"changed\":"  + std::string(changed ? "true" : "false");
        js += ",\"bootSha\":"  + J(bootSha);
        js += ",\"lastAlert\":{";
        js += "\"at\":"         + J(g_last.at);
        js += ",\"proc\":"      + J(g_last.proc);
        js += ",\"pid\":"       + std::to_string(g_last.pid);
        js += ",\"autoHandled\":" + std::string(g_last.autoHandled ? "true" : "false");
        js += ",\"terminated\":"  + std::string(g_last.terminated ? "true" : "false");
        js += ",\"changed\":"     + std::string(g_last.changed ? "true" : "false");
        js += ",\"reason\":"      + J(g_last.reason);
        js += "}}";
        return js;
    }
}

// ---------------------------------------------------------------------------
//  监视线程：5 秒一轮；发现"从干净到被改"的边沿时自动拦截/告警。
//  回调在监视线程内执行 —— 服务层的回调实现（写 findings + 弹窗）与
//  rollback 检测回调同模式，已按跨线程调用设计。
// ---------------------------------------------------------------------------
void StartWatch() {
    std::thread([] {
        sf::LogDbg("[boot] MBR 监视线程已启动（5 秒级轮询）");
        int lastStatus = 0;
        while (g_stopEvent == nullptr ||
               WaitForSingleObject((HANDLE)g_stopEvent, 5000) == WAIT_TIMEOUT) {
            CheckResult cr = CheckNow();
            if (cr.status == 1 && lastStatus != 1 && g_cb) {
                BootAlert a;
                a.cr = cr;
                // ---- 归因：10 分钟内的最近一条可疑进程 ----
                {
                    std::lock_guard<std::mutex> lk(g_mtx);
                    ULONGLONG now = GetTickCount64();
                    for (int i = (int)g_suspicions.size() - 1; i >= 0; --i) {
                        if (now - g_suspicions[(size_t)i].at <= 10ull * 60 * 1000) {
                            a.procPath = g_suspicions[(size_t)i].path;
                            a.pid      = g_suspicions[(size_t)i].pid;
                            break;
                        }
                    }
                }
                if (!a.procPath.empty() && sf::ProcReputable(a.procPath)) {
                    // ★ 信誉门：可信厂商签名进程改引导区（GRUB 安装器/磁盘工具
                    //   是合法场景）不自动拦截，清空归因转被动告警——
                    //   弹「恢复引导/信任此变更」卡交用户决定。
                    sf::LogDbg("[boot] 归因进程签名可信 → 信誉门拦截，不自动拦截转被动告警: " + a.procPath);
                    a.procPath.clear();
                    a.pid = 0;
                }
                if (!a.procPath.empty()) {
                    // ---- 自动拦截（正经杀软模式）：终止 → 隔离 → 基线写回 ----
                    a.autoHandled = true;
                    if (a.pid > 0) {
                        HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)a.pid);
                        if (hp) { a.terminated = (TerminateProcess(hp, 1) != FALSE); CloseHandle(hp); }
                    }
                    unsigned char base[kSector], cur[kSector];
                    {
                        std::lock_guard<std::mutex> lk(g_mtx);
                        if (g_haveBaseline) memcpy(base, g_baseline, kSector);
                    }
                    if (ReadMbr(cur)) a.undoToken = QuarantineCurrent(cur);
                    if (WriteMbr(base)) {
                        sf::LogDbg("[boot] 已自动拦截：终止可疑进程" +
                               std::string(a.terminated ? "成功" : "失败(可能已退出)") +
                               "，引导记录已恢复，隔离副本 " +
                               (a.undoToken.empty() ? std::string("无") : a.undoToken));
                    } else {
                        // 写回失败（极罕见）：必须让用户知道 MBR 仍是脏的
                        a.undoToken.clear();
                        a.autoHandled = false;
                        sf::LogDbg("[boot] 自动拦截的写回步骤失败，降级为被动告警（引导区仍是脏的！）");
                    }
                    {
                        std::lock_guard<std::mutex> lk(g_mtx);
                        g_last.at = NowStr(); g_last.proc = a.procPath; g_last.pid = a.pid;
                        g_last.autoHandled = a.autoHandled; g_last.terminated = a.terminated;
                        g_last.changed = true; g_last.reason = cr.reason;
                    }
                    g_cb(a);
                } else {
                    // 无归因：不自动恢复（防误伤磁盘/引导工具），交用户决定
                    {
                        std::lock_guard<std::mutex> lk(g_mtx);
                        g_last.at = NowStr(); g_last.proc = ""; g_last.pid = 0;
                        g_last.autoHandled = false; g_last.terminated = false;
                        g_last.changed = true; g_last.reason = cr.reason;
                    }
                    g_cb(a);
                }
            }
            lastStatus = cr.status;
        }
        sf::LogDbg("[boot] MBR 监视线程已退出");
    }).detach();
}

}  // namespace boot
