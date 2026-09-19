// rollback.cpp — 勒索回滚引擎实现（纯用户态）
//
// 设计依据与工程约束的完整说明见 rollback.h 头部注释。此处只记录**实现层面**
// 的关键决策与踩坑，供后续维护者对照。
//
// ---------------------------------------------------------------------------
//  实现结构
// ---------------------------------------------------------------------------
//   [监控线程] ReadDirectoryChangesW（异步 + IOCP 事件）
//        │  收到 FILE_ACTION_ADDED / MODIFIED / RENAMED_OLD_NAME / RENAMED_NEW_NAME
//        ▼
//   [抢拍快照] TrySnapshotBeforeWrite()
//        │  · 只对"未受信任进程"触及的文件抢拍（可信进程不拍，避免全盘复制）
//        │  · 内容寻址：快照文件名 = <sha256(路径+时间)>.snap，元数据另存 .meta
//        ▼
//   [信号统计] 滑动窗口计数：批量改写 / 高熵扩展名重命名 / 勒索说明文件
//        │
//        ▼
//   [勒索判定] 需要同时满足「批量改写」+（「高熵改名」或「勒索说明」）
//        │      —— 单信号不作为定性依据（压缩/备份软件会制造大批量改写）
//        ▼
//   [处置] 终止进程（可配）→ RollbackVictims() 从快照恢复 → 落报告 + 通知
//
// ---------------------------------------------------------------------------
//  关键踩坑记录
// ---------------------------------------------------------------------------
//  1. ReadDirectoryChangesW 的缓冲区必须**按下一个 FILE_NOTIFY_INFORMATION 的
//     4 字节对齐**推进（NextEntryOffset 的单位是字节，最后一项为 0 表示结束）。
//     直接按 sizeof() 加会踩到未对齐地址 → 偶发崩溃。
//  2. FILE_NOTIFY_INFORMATION.FileName 是**不带结尾 \0** 的变长数组，
//     长度由 FileNameLength 给出（字节数），必须手动按 UTF-16 长度构造 wstring。
//  3. 目录句柄要用 FILE_FLAG_BACKUP_SEMANTICS 才能打开目录本身。
//  4. 排除规则必须包含**本程序自己的快照缓存目录**——否则快照写入自身会触发
//     新事件 → 无限递归快照（第一次实现时踩到，CPU 直接跑满）。
// ===========================================================================
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>

#include <string>
#include <vector>
#include <deque>
#include <map>
#include <set>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdint>

#include "rollback.h"
#include "common.h"
#include "behavior.h"   // FileIsSigned：信誉门读取进程 Authenticode 签名者（带缓存）
#include <tlhelp32.h>

#pragma comment(lib, "bcrypt.lib")

namespace sf {
namespace rb {

// 服务方的停止事件（service.cpp 注入）。未注入时为 nullptr，
// 监控线程退化为 1 秒超时轮询（不影响正确性，只是退出稍慢）。
static HANDLE g_stopEvent = nullptr;
void SetStopEvent(void* hEvent) { g_stopEvent = (HANDLE)hEvent; }

// 告警回调（由服务方注入；未注入时只落日志，不影响引擎本身工作）
static DetectionCallback g_detCb = nullptr;
void SetDetectionCallback(DetectionCallback cb) { g_detCb = cb; }

// ===========================================================================
//  内部工具
// ===========================================================================
static const size_t kMaxListedPaths = 200;   // 报告里最多列出多少条路径

static std::string Lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}
static bool EndsWithCI(const std::string& s, const char* suf) {
    size_t n = strlen(suf);
    if (s.size() < n) return false;
    return Lower(s.substr(s.size() - n)) == Lower(std::string(suf));
}
static bool ContainsCI(const std::string& s, const char* sub) {
    return Lower(s).find(Lower(std::string(sub))) != std::string::npos;
}
static std::string NowStr() {
    SYSTEMTIME st; GetLocalTime(&st);
    char b[48];
    sprintf_s(b, "%04d-%02d-%02d %02d:%02d:%02d",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}
static uint64_t NowMs() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// UTF-16 → UTF-8（宽路径转窄路径，全程序统一用窄串传路径）
static std::string W2A(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return "";
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
static std::wstring A2W(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// 元数据文件内容：path / sha / size / time
struct Meta {
    std::string path;
    std::string sha;
    uint64_t    size = 0;
    uint64_t    time = 0;          // 快照建立时刻（steady ms）
    std::string reason;
};

// 快照目录
static std::string g_cacheDir;

static std::string CacheDirImpl() {
    if (!g_cacheDir.empty()) return g_cacheDir;
    wchar_t p[MAX_PATH] = { 0 };
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard\\rollback_cache";
    else
        dir = L"C:\\ProgramData\\SilverFoxGuard\\rollback_cache";
    // 逐级创建
    std::wstring prog = dir.substr(0, dir.find_last_of(L'\\'));
    CreateDirectoryW(prog.c_str(), nullptr);
    CreateDirectoryW(dir.c_str(), nullptr);
    g_cacheDir = W2A(dir);
    return g_cacheDir;
}

// 简单的文件名哈希：用于生成快照文件名（避免路径里的非法字符）
static std::string HashNameOf(const std::string& path) {
    std::string h = Sha256Bytes(path.data(), path.size());
    if (h.size() >= 32) return h.substr(0, 32);
    return h;
}

static std::string SnapPathOf(const std::string& path) {
    return CacheDirImpl() + "\\" + HashNameOf(path) + ".snap";
}
static std::string MetaPathOf(const std::string& path) {
    return CacheDirImpl() + "\\" + HashNameOf(path) + ".meta";
}

// 元数据读写（key=value 行式，路径可能含 = 故只按**第一个** = 切分）
static bool WriteMeta(const std::string& metaPath, const Meta& m) {
    std::ofstream f(metaPath, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << "path=" << m.path << "\n"
      << "sha=" << m.sha << "\n"
      << "size=" << m.size << "\n"
      << "time=" << m.time << "\n"
      << "reason=" << m.reason << "\n";
    return true;
}
static bool ReadMeta(const std::string& metaPath, Meta& m) {
    std::ifstream f(metaPath, std::ios::binary);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        if (k == "path")        m.path = v;
        else if (k == "sha")    m.sha = v;
        else if (k == "size")   m.size = _strtoui64(v.c_str(), nullptr, 10);
        else if (k == "time")   m.time = _strtoui64(v.c_str(), nullptr, 10);
        else if (k == "reason") m.reason = v;
    }
    return !m.path.empty();
}

// ===========================================================================
//  熵值（Shannon，bit/byte）
//
//  为什么用熵值：文件被加密后字节分布趋于均匀 → 熵值从典型的 3~6 跃升到
//  7.9 以上。这是业界公认的勒索检测信号之一（配合"批量 + 改名"使用）。
//  但**它不充分**：已压缩格式（zip/7z/jpg/mp4）本身就接近 8.0，所以
//  判定时绝不能只看熵值，必须结合下面的批量/改名/勒索说明等旁证。
// ===========================================================================
double EntropyOfBuffer(const std::string& data) {
    if (data.empty()) return 0.0;
    uint64_t freq[256] = { 0 };
    for (unsigned char c : data) freq[c]++;
    double n = (double)data.size(), e = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / n;
        e -= p * (std::log(p) / std::log(2.0));
    }
    return e;
}

double EntropyOfFile(const std::string& path) {
    // 熵值采样：只读前 256KB（加密后的文件熵在全文件上均匀，
    // 头部采样已足够判别；读全文件在大文件上会拖慢监控线程）。
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0.0;
    const DWORD kSample = 256 * 1024;
    std::string buf; buf.resize(kSample);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, &buf[0], kSample, &rd, nullptr);
    CloseHandle(h);
    if (!ok || rd == 0) return 0.0;
    buf.resize(rd);
    return EntropyOfBuffer(buf);
}

// ===========================================================================
//  快照缓存（容量受限 + LRU 淘汰）
// ===========================================================================
struct SnapEntry {
    std::string path;
    std::string sha;
    std::string snapPath;
    std::string metaPath;
    uint64_t    size = 0;
    uint64_t    atime = 0;   // 最近访问（用于 LRU）
};

static std::mutex                        g_cacheMtx;
static std::map<std::string, SnapEntry>  g_cache;      // key = 规范化小写路径
static std::deque<std::string>           g_lru;        // 队首最旧
static Config                            g_cfg;
static std::atomic<bool>                 g_running{ false };
static Stats                             g_stats;
static std::mutex                        g_statsMtx;

// ===========================================================================
//  撤销记录（"反向回滚"）
//
//  为什么需要：高风险判定成立时引擎会**自动**回滚，用户来不及干预。但判定
//  可能误伤（例如备份软件批量操作被误判成勒索），此时用户需要拿回被自动回滚
//  覆盖掉的那一份内容。
//
//  做法：回滚**之前**先把每个受害文件当前的内容（即被改写成密文的版本，也就
//       是用户"刚做出来"的内容）另存到 undo 目录，记录清单；用户点"撤销"时
//       再把这些内容写回原路径。
//
//  生命周期：只保留**最近一次**回滚的撤销记录。原因：
//   ① 撤销是"反悔上一次"的语义，堆叠多份会让用户分不清撤销到哪一步；
//   ② 每份撤销记录占用与快照同级，长期保留会双倍占盘。
//   新的回滚发生时，旧的撤销记录直接删除（此时它已失去意义——用户已经
//   接受了上一次处置，或已过了反悔窗口）。
// ===========================================================================
struct UndoEntry {
    std::string path;       // 原文件路径
    std::string undoPath;   // 回滚前内容的备份路径
    uint64_t    size = 0;
};
static std::mutex              g_undoMtx;
static std::vector<UndoEntry>  g_undoList;
static std::string             g_undoToken;
static std::string             g_undoTrigger;
static uint64_t                g_undoAtMs = 0;

// 撤销记录的保留时限：超过此时限自动作废（默认 10 分钟）。
// 理由：用户的反悔窗口是"刚看到弹窗那会儿"，拖到第二天再点撤销，
//       文件早被别的程序改过，强行写回反而破坏数据。
static const uint64_t kUndoWindowMs = 10 * 60 * 1000;

// 清空撤销记录（调用方须持 g_undoMtx）。删除磁盘上的备份文件。
static void ClearUndoLocked() {
    for (const auto& u : g_undoList) DeleteFileA(u.undoPath.c_str());
    g_undoList.clear();
    g_undoToken.clear();
    g_undoTrigger.clear();
    g_undoAtMs = 0;
}

static void StatAdd(int field, uint64_t v) {
    std::lock_guard<std::mutex> lk(g_statsMtx);
    switch (field) {
        case 0: g_stats.snapshots      += v; break;
        case 1: g_stats.snapBytes      += v; break;
        case 2: g_stats.eventsSeen     += v; break;
        case 3: g_stats.snapshotTaken  += v; break;
        case 4: g_stats.snapshotSkipped+= v; break;
        case 5: g_stats.rollbacks      += v; break;
        case 6: g_stats.restored       += v; break;
        case 7: g_stats.unrecoverable  += v; break;
        case 8: g_stats.detected       += v; break;
        case 9: g_stats.watcherErrors  += v; break;
        case 10: g_stats.keysCaptured  += v; break;   // 密钥候选留存
        case 11: g_stats.keyHits       += v; break;   // 密钥关联提前定性
        case 12: g_stats.landedSuspect += v; break;   // 落地初筛命中
    }
}

// 快照占用的**唯一真相来源**：直接对 g_cache 求和。
// 为什么不用 g_stats.snapBytes 做增量累加：增量记账在本模块里有三处会改动
// （新增 / LRU 淘汰 / 恢复后释放），任何一处漏减都会让占用数永久漂移——
// 而容量淘汰判定直接依赖这个数，漂移会导致"缓存早已超限却不再淘汰"。
// 改为每次求和：g_cache 上限很小（最多几千条），求和开销可忽略，换来的是
// 永远不会算错的占用值。调用方须持 g_cacheMtx。
static uint64_t CacheBytesLocked() {
    uint64_t n = 0;
    for (const auto& kv : g_cache) n += kv.second.size;
    return n;
}

// 把从 g_cache 现算出来的真实值同步回 g_stats（供 UI 展示）。
// 调用方须持 g_cacheMtx。
static void SyncCacheStatsLocked() {
    uint64_t bytes = CacheBytesLocked();
    uint64_t count = (uint64_t)g_cache.size();
    std::lock_guard<std::mutex> lk(g_statsMtx);
    g_stats.snapBytes = bytes;
    g_stats.snapshots = count;
}

static std::string NormKey(const std::string& p) {
    std::string s = Lower(p);
    // 去掉 \\?\ 前缀（长路径形式）以统一 key
    if (s.rfind("\\\\?\\", 0) == 0) s = s.substr(4);
    while (!s.empty() && (s.back() == '\\' || s.back() == '/')) s.pop_back();
    return s;
}

// 淘汰：从最旧开始删，直到占用回到上限内。
// 注意：占用值从 g_cache 现算，不依赖 g_stats 的增量记账（见 CacheBytesLocked 说明）。
static void EvictLocked() {          // 调用方须持 g_cacheMtx
    while (CacheBytesLocked() > g_cfg.maxCacheBytes && !g_lru.empty()) {
        std::string k = g_lru.front(); g_lru.pop_front();
        auto it = g_cache.find(k);
        if (it == g_cache.end()) continue;
        DeleteFileA(it->second.snapPath.c_str());
        DeleteFileA(it->second.metaPath.c_str());
        g_cache.erase(it);
    }
}

// LRU 触碰：把 key 移到队尾
static void TouchLocked(const std::string& k) {   // 调用方须持 g_cacheMtx
    for (auto it = g_lru.begin(); it != g_lru.end(); ++it)
        if (*it == k) { g_lru.erase(it); break; }
    g_lru.push_back(k);
}

// ===========================================================================
//  排除规则
//
//  必须排除的目录（否则会把自己/系统搅乱）：
//    · 本程序自己的快照缓存目录 —— 不排除会无限递归快照（踩过）
//    · 系统卷信息 / 页面文件 / 注册表配置单元
//    · 程序自身的安装目录（自保文件不应被回滚）
// ===========================================================================
static bool IsExcluded(const std::string& pathLower) {
    static const char* kEx[] = {
        "\\rollback_cache\\",           // 自身缓存（防递归）
        "\\system volume information",
        "\\$recycle.bin",
        "\\windows\\winsxs\\",          // 组件存储：改动量大且不应回滚
        "\\windows\\assembly\\",
        "\\.git\\",
        "\\node_modules\\",
        "\\programdata\\silverfoxguard\\",   // 自身数据目录
        "\\appdata\\local\\temp\\sg_",       // 自身临时文件前缀
    };
    for (const char* e : kEx) if (pathLower.find(e) != std::string::npos) return true;
    if (pathLower.find("\\pagefile.sys") != std::string::npos) return true;
    if (pathLower.find("\\hiberfil.sys") != std::string::npos) return true;
    if (pathLower.find("\\swapfile.sys") != std::string::npos) return true;
    // 临时文件不拍（用户本来就要删）
    if (EndsWithCI(pathLower, ".tmp") || EndsWithCI(pathLower, ".temp") ||
        EndsWithCI(pathLower, ".~tmp") || EndsWithCI(pathLower, ".crdownload") ||
        EndsWithCI(pathLower, ".part") || EndsWithCI(pathLower, ".partial")) return true;
    return false;
}

// 受保护扩展名：只对这些文件建立快照（避免把整个磁盘镜像进缓存）
// 依据：卡巴官方列举的"系统重要文件"里明确包含文档（.doc 等）与可执行文件。
static const char* kProtectedExt[] = {
    // ---- 文档 ----
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf",
    ".odt", ".ods", ".odp", ".csv", ".md", ".wps", ".et", ".dps", ".pages",
    // ---- 图片 / 设计 ----
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".psd", ".ai",
    ".svg", ".webp", ".raw", ".cr2", ".nef",
    // ---- 音视频 ----
    ".mp3", ".wav", ".flac", ".aac", ".m4a", ".mp4", ".avi", ".mkv", ".mov", ".wmv",
    // ---- 代码 / 工程 ----
    ".c", ".cpp", ".h", ".hpp", ".cs", ".java", ".py", ".js", ".ts", ".go", ".rs",
    ".html", ".css", ".json", ".xml", ".yml", ".yaml", ".sql", ".sh", ".bat", ".ps1",
    ".sln", ".vcxproj", ".csproj", ".gradle", ".lua", ".gd", ".tscn", ".unity",
    // ---- 压缩 / 数据库 / 虚拟盘 ----
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bak", ".db", ".sqlite", ".mdf", ".accdb",
    ".vhd", ".vhdx", ".vmdk",
    // ---- 可执行（卡巴明确列入"系统重要文件"）----
    ".exe", ".dll", ".sys", ".msi", ".scr", ".com", ".ocx", ".cpl",
};
static bool IsProtectedExt(const std::string& pathLower) {
    // 取最后一个点
    size_t dot = pathLower.find_last_of('.');
    if (dot == std::string::npos) return false;
    std::string ext = pathLower.substr(dot);
    if (ext.size() > 12) return false;              // 超长"扩展名"多半是勒索附加后缀，非受保护类型
    for (const char* e : kProtectedExt) if (ext == e) return true;
    return false;
}

// 压缩/归档后缀（2026-09-19 密钥误报根治）：
//  压缩产物熵天然 ≥7.5（压缩=消除冗余），与"随机密钥"在熵维度完全不可区分——
//  但它是最常见的正常文件形态（下载包/插件市场解压/MC 日志轮转 .log.gz）。
//  密钥截获与勒索改名判定都必须先排除这一大类，否则正常软件刷满候选表。
static bool LooksLikeCompressedExt(const std::string& ext) {
    static const char* kComp[] = {
        ".gz", ".zip", ".7z", ".rar", ".tar", ".bz2", ".xz", ".zst", ".zstd",
        ".tgz", ".tbz", ".txz", ".lz4", ".br", ".jar", ".war", ".pak", ".cab",
        ".iso", ".img", ".apk", ".ipa", ".asar", ".whl", ".nupkg", ".vsix",
        ".crx", ".xpi", ".dmg", ".pkg", ".rpm", ".deb", ".appx", ".msix", ".bundle",
    };
    for (const char* e : kComp) if (ext == e) return true;
    return false;
}

// 内容魔数兜底：改了后缀的压缩包同样熵虚高，按文件头识别。
// （方向不可伪造——真随机密钥不会恰好长着标准压缩头。）
static bool HasArchiveMagic(const std::string& data) {
    static const struct { const char* magic; size_t len; } kMagics[] = {
        { "\x1F\x8B", 2 },                 // gzip
        { "PK\x03\x04", 4 },               // zip
        { "PK\x05\x06", 4 },               // zip 空包
        { "PK\x07\x08", 4 },               // zip spanned
        { "\x37\x7A\xBC\xAF\x27\x1C", 6 }, // 7z
        { "Rar!\x1A\x07", 7 },             // rar
        { "BZh", 3 },                      // bzip2
        { "\xFD" "7zXZ\x00", 6 },          // xz（注意 \xFD 后不能直接跟十六进制字符）
        { "\x28\xB5\x2F\xFD", 4 },         // zstd
        { "MSCF", 4 },                     // cab
        { "\x04\x22\x4D\x18", 4 },         // lz4
    };
    for (const auto& m : kMagics)
        if (data.size() >= m.len && memcmp(data.data(), m.magic, m.len) == 0) return true;
    return false;
}

// 勒索常见的附加后缀（判断"原文件被改成陌生后缀"）
static bool LooksLikeRansomExt(const std::string& ext) {
    if (ext.size() < 4 || ext.size() > 12) return false;   // 短后缀（.txt）不算
    // 合法软件高频改名后缀优先豁免（2026-09-19 PCL2 误报）：日志轮转（.log.gz）、
    // 下载落盘（.download/.crdownload/.partial）、备份轮转（.bak/.old）与勒索改名
    // 在"改后缀"表象上相同，必须先排除再谈勒索特征。
    if (LooksLikeCompressedExt(ext)) return false;
    static const char* kBenign[] = {
        ".download", ".crdownload", ".partial", ".part", ".bak", ".old", ".new",
        ".orig", ".backup", ".sav", ".temp", ".tmp", ".swp", ".dmp", ".cache",
        ".stamp", ".log1",
    };
    for (const char* b : kBenign) if (ext == b) return false;
    // 纯字母/数字混合且长度 >=5 的陌生后缀，多半是勒索家族标记
    // （如 .locked / .encrypted / .WNCRY / .dxxd）
    static const char* kKnown[] = {
        ".locked", ".encrypted", ".enc", ".crypt", ".crypto", ".locky", ".zepto",
        ".wncry", ".wcry", ".wncrypt", ".cerber", ".dharma", ".phobos", ".stop",
        ".djvu", ".conti", ".lockbit", ".revil", ".sodinokibi", ".maze", ".ryuk",
        ".gandcrab", ".teslacrypt", ".petya", ".notpetya", ".badrabbit", ".avos",
        ".dxxd", ".arrow", ".bip", ".blm", ".zeppelin", ".makop", ".nobes",
    };
    for (const char* k : kKnown) if (ext == k) return true;
    // 通用：形如 .xxxxxx 的 6 字符随机串
    if (ext.size() >= 6) {
        bool alphaNum = true;
        for (size_t i = 1; i < ext.size(); ++i)
            if (!isalnum((unsigned char)ext[i])) { alphaNum = false; break; }
        if (alphaNum) return true;   // 保守：仅在配合"批量"信号时才会被采用（见判定逻辑）
    }
    return false;
}

// 勒索说明文件名（README / 解密说明 / HOW TO DECRYPT）
static bool LooksLikeRansomNote(const std::string& baseLower) {
    static const char* kNotes[] = {
        "readme", "how_to_decrypt", "how-to-decrypt", "decrypt", "解密", "恢复文件",
        "restore_files", "recover_files", "help_decrypt", "unlock", "#readme#",
        "!!!readme!!!", "readme.txt", "restore-my-files", "_readme_",
    };
    for (const char* n : kNotes) if (baseLower.find(n) != std::string::npos) return true;
    return false;
}

// ===========================================================================
//  风险分层建快照（2026-09-18，快照瘦身的核心）
//
//  为什么需要：旧策略是"任何改写都建快照"，导致普通软件每次保存文档都存一份
//  （Word 自动保存、IDE 频繁落盘、浏览器缓存写入……），占用迅速堆积，把更早
//  的、真正有价值的快照挤掉。维护者实测反馈"快照占内存太大"即此因。
//
//  判据设计依据：
//    · 勒索的**不可伪装特征**是"把文件改成陌生后缀"（加密后必然改名），
//      正常软件保存时扩展名不变 —— 这是最可靠的单一判据；
//    · 正常软件也可能短时间写大量文件（编译器、解压），但它不会改扩展名。
//      所以"同目录短时间大量改写"单独不足以建快照，需配合其它信号；
//    · 高价值文档（论文/表格/图片/代码）是用户最在意的东西，值得多留一份。
// ===========================================================================

// 高价值文档类型：用户创作内容，误删/被加密的代价最高。
// 与 kProtectedExt 的区别：kProtectedExt 是"值得保护的"（含 exe/dll/系统文件），
// 这里是"用户自己写出来的"（不含可执行体、不含压缩包）。
static bool IsHighValueDoc(const std::string& pathLower) {
    static const char* kDocs[] = {
        // 文档
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf",
        ".odt", ".ods", ".odp", ".md", ".wps", ".et", ".dps", ".csv",
        // 图片（创作素材）
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".psd", ".ai", ".svg",
        ".raw", ".cr2", ".nef", ".arw", ".tif", ".tiff",
        // 音视频（创作成品）
        ".mp3", ".wav", ".flac", ".m4a", ".mp4", ".mov", ".avi", ".mkv", ".flv",
        // 代码（开发者的心血）
        ".c", ".cpp", ".h", ".hpp", ".cs", ".java", ".py", ".js", ".ts", ".go",
        ".rs", ".php", ".rb", ".lua", ".gd", ".sh", ".ps1", ".html", ".css",
        ".json", ".xml", ".yml", ".yaml", ".sln", ".vcxproj", ".csproj", ".unity",
    };
    size_t dot = pathLower.find_last_of('.');
    if (dot == std::string::npos) return false;
    std::string ext = pathLower.substr(dot);
    if (ext.size() > 12) return false;
    for (const char* e : kDocs) if (ext == e) return true;
    return false;
}

// 目录热度表：记录"某目录最近一次批量改写的时间与该窗口内的改写次数"。
// 用于判据②。容量有上限，避免长时间运行后无界增长。
struct DirHeat { uint64_t windowStart = 0; uint32_t count = 0; };
static std::mutex                      g_heatMtx;
static std::map<std::string, DirHeat>  g_heat;

// 落地初筛命中队列（供 service 层拉取，做进程关联与弹窗）。
// 有界队列：只留最近 256 条，避免长时间运行后无界增长。
struct LandAlert {
    std::string path;
    std::string reason;
    uint64_t    at = 0;
};
struct LandQueue {
    std::deque<LandAlert> alerts;
};
static std::mutex  g_landMtx;
static LandQueue   g_landed;

// 前置声明：DirOfPath 定义在下方（目录热度一节），但密钥时序关联也要用。
static std::string DirOfPath(const std::string& lowerPath);

// 自身安装目录（小写，用于排除自身活动）。
// 定义提前到此处：密钥截获 / 落地捕获都要用它做自排除，而它们在文件前半部分。
static std::string g_exeDirLower;

// ===========================================================================
//  勒索密钥截获（2026-09-19 新增）
//
//  ---------------------------------------------------------------------------
//  【为什么这条路比快照回滚更强】
//  ---------------------------------------------------------------------------
//  维护者指出的现代勒索流程：
//      ① 生成本地密钥 → ② 密钥落盘 → ③ 用密钥加密全部文件 → ④ 删密钥 → ⑤ 要赎金
//  第 ④ 步是攻击者的自保：密钥一删，抓到人也解不开。**第 ② 步是唯一窗口**。
//
//  快照回滚 vs 密钥截获：
//    · 快照：需要逐文件备份，受 maxFileBytes/maxCacheBytes 约束，
//      且**只能救"改动前存在过"的文件**；文件被加密后原文件被删/改名就救不回。
//    · 密钥：只需一份小文件（典型 < 8KB），不受快照容量约束；
//      拿到密钥后**任何被加密的文件都可解回明文**，哪怕原文件已被删。
//  两者不是替代关系，而是互补 —— 快照救"来不及截获的"，密钥救"截获到的"。
//
//  ---------------------------------------------------------------------------
//  【判定必须用多信号，不能只看熵】
//  ---------------------------------------------------------------------------
//  高熵小文件在正常系统里很常见：浏览器缓存、编译产物、压缩包分片、日志压缩块……
//  单纯"高熵 + 小体积"会大量误报。所以采用**三条件联合 + 时序验证**：
//    条件1（静态）：体积 16B~64KB 且 熵 >= 7.5 —— 密钥的形态特征；
//    条件2（静态）：扩展名陌生或无扩展名（.key/.pem/.dat/.bin/.enc/.bin 之外多为随机）
//                   —— 正常程序很少把小体积随机数据写成无扩展名文件；
//    条件3（动态）：**落盘后 keyWindowSec 秒内出现同目录批量改写**
//                   —— 这是最强判据：证明"这个文件刚写完就被用来加密东西"。
//
//  条件 1+2 命中时先**留存候选副本**（成本极低，一份几 KB），
//  等条件 3 成立时再正式认定为"勒索密钥"并**提前定性**（不必等 25 个文件的阈值）。
//  这样既不会因为看不到未来而漏掉，也不会因为单看熵值而误报。
// ===========================================================================
struct CapturedKey {
    std::string path;        // 原始落盘路径（用户可查看，但可能已被勒索者删除）
    std::string storePath;   // 我们留存的副本路径（勒索者删不掉）
    std::string sha;
    uint64_t    size    = 0;
    double      entropy = 0.0;
    uint64_t    at      = 0;   // 捕获时刻（steady ms）
    bool        confirmed = false;  // 是否已被时序关联确认为勒索密钥
    size_t      linkedVictims = 0;  // 关联到的受害文件数（确认时填）
};
static std::mutex                  g_keyMtx;
static std::vector<CapturedKey>    g_keys;
static uint64_t                    g_keySeq = 0;   // 副本文件名序号

// 密钥副本目录：<cache>\keys（与快照同级的独立子树）
static std::string KeyDirImpl() {
    std::string d = CacheDirImpl() + "\\keys";
    CreateDirectoryA(d.c_str(), nullptr);
    return d;
}

// 该扩展名是否"像密钥文件"。
// 依据：正常软件的小体积随机数据文件几乎总带已知扩展名（.bin/.dat/.db/.pak…），
// 而勒索密钥常见三类：① 无扩展名 ② .key/.pem/.dat 等密钥专用 ③ 纯随机扩展名。
static bool LooksLikeKeyExt(const std::string& pathLower) {
    size_t slash = pathLower.find_last_of("\\/");
    std::string base = (slash == std::string::npos) ? pathLower : pathLower.substr(slash + 1);
    size_t dot = base.find_last_of('.');
    if (dot == std::string::npos || dot == 0) return true;   // 无扩展名 → 像密钥
    std::string ext = base.substr(dot);
    // 明确"不是密钥"的常见类型（正常程序的小文件）
    static const char* kNotKey[] = {
        ".tmp", ".temp", ".log", ".ini", ".cfg", ".conf", ".json", ".xml", ".txt",
        ".md", ".html", ".css", ".js", ".lock", ".pid", ".cache", ".idx", ".db",
        ".sqlite", ".lnk", ".url", ".crdownload", ".part", ".partial", ".ico", ".png",
        ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".otf",
    };
    for (const char* e : kNotKey) if (ext == e) return false;
    // 压缩/归档后缀（2026-09-19 密钥误报根治）：压缩产物熵天然 ≥7.5，
    // 与随机密钥在熵维度不可区分，必须先于"短扩展名视为可能"整类排除。
    // 否则下载包/插件解压/日志轮转（.log.gz）会持续刷满密钥候选表，
    // 进而被"时序关联"错误定性成勒索密钥（PCL2 误报根因）。
    if (LooksLikeCompressedExt(ext)) return false;
    // 密钥专用扩展名
    static const char* kKeyExt[] = {
        ".key", ".pem", ".der", ".p12", ".pfx", ".keystore", ".jks",
        ".enc", ".encrypted", ".crypt", ".locked", ".aes", ".rsa", ".dat", ".bin",
    };
    for (const char* e : kKeyExt) if (ext == e) return true;
    // 其它：短扩展名（<=6 字符）视为可能 —— 但要靠时序关联确认
    if (ext.size() <= 7) return true;
    return false;
}

// 尝试把一个小体积高熵文件登记为"密钥候选"。
// 返回 true 表示已登记（或已存在）。**此函数会做磁盘 IO（读文件算熵 + 复制副本），
// 但调用点已在监控线程里且只对小文件触发，开销可忽略。**
static bool TryCaptureKey(const std::string& full, const std::string& fullLower) {
    if (!g_cfg.keyHuntEnabled) return false;
    if (fullLower.empty()) return false;
    if (IsExcluded(fullLower)) return false;
    // 自身副本目录不捕获（防递归）
    if (fullLower.find("\\rollback_cache\\") != std::string::npos) return false;

    if (!LooksLikeKeyExt(fullLower)) return false;

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExA(full.c_str(), GetFileExInfoStandard, &fad)) return false;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return false;
    uint64_t sz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (sz < g_cfg.keyMinBytes || sz > g_cfg.keyMaxBytes) return false;

    // 已捕获过同路径 → 跳过（同一文件反复写入不重复登记）
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        for (const auto& k : g_keys) if (k.path == full) return true;
        if (g_keys.size() >= g_cfg.keyMaxKept) return false;   // 已满，不再收
    }

    double ent = EntropyOfFile(full);
    if (ent < g_cfg.keyEntropyMin) return false;   // 熵不够 → 不像随机密钥

    // 读入内存（小文件，一次性读完）并写副本
    HANDLE hs = CreateFileA(full.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hs == INVALID_HANDLE_VALUE) return false;
    std::string data; data.resize((size_t)sz);
    DWORD rd = 0;
    BOOL okRead = ReadFile(hs, &data[0], (DWORD)sz, &rd, nullptr);
    CloseHandle(hs);
    if (!okRead || rd == 0) return false;
    data.resize(rd);

    // 魔数兜底：改了后缀的压缩包（xx.dat.gz、无后缀 zip）同样熵虚高，按文件头识别。
    if (HasArchiveMagic(data)) return false;

    uint64_t seq = (uint64_t)InterlockedIncrement64((volatile LONG64*)&g_keySeq);
    char nm[96];
    sprintf_s(nm, "\\key_%04llu.bin", (unsigned long long)seq);
    std::string store = KeyDirImpl() + nm;

    HANDLE hd = CreateFileA(store.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hd == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    BOOL okWrite = WriteFile(hd, data.data(), (DWORD)data.size(), &wr, nullptr);
    FlushFileBuffers(hd);
    CloseHandle(hd);
    if (!okWrite || wr != data.size()) { DeleteFileA(store.c_str()); return false; }

    CapturedKey k;
    k.path     = full;
    k.storePath= store;
    k.sha      = Sha256Bytes(data.data(), data.size());
    k.size     = data.size();
    k.entropy  = ent;
    k.at       = NowMs();

    size_t kept = 0;
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        // 并发插入检查（两次通知可能同时到）
        for (const auto& e : g_keys) if (e.path == full) { DeleteFileA(store.c_str()); return true; }
        if (g_keys.size() >= g_cfg.keyMaxKept) { DeleteFileA(store.c_str()); return false; }
        g_keys.push_back(k);
        kept = g_keys.size();
    }
    StatAdd(10, 1);
    {
        std::lock_guard<std::mutex> lk(g_statsMtx);
        g_stats.keysKept = kept;
    }
    LogDbg("[rollback] 密钥候选已留存: " + full +
           "（" + std::to_string(k.size) + "B, 熵=" + std::to_string(k.entropy) +
           "）→ " + store);
    return true;
}

// 时序关联：某目录刚出现过密钥候选，随后该目录内出现批量改写
// → 把候选**正式确认**为勒索密钥，并返回 true（调用方据此提前定性，不等阈值）。
static bool ConfirmKeyByBurst(const std::string& dirLower, size_t* outKeyIdx = nullptr) {
    if (!g_cfg.keyHuntEnabled) return false;
    uint64_t now = NowMs();
    uint64_t win = (uint64_t)g_cfg.keyWindowSec * 1000;
    size_t idx = (size_t)-1;
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        // 找最近落盘、尚未确认、且与该目录相关的候选。
        // "相关" = 候选文件本身就在该目录，或候选落在 Temp/盘根这类"任意目录"。
        for (size_t i = g_keys.size(); i-- > 0; ) {
            CapturedKey& k = g_keys[i];
            if (k.confirmed) continue;
            if (now - k.at > win) continue;      // 超出关联窗口，不再认
            std::string kd = DirOfPath(Lower(k.path));
            bool sameDir = (kd == dirLower);
            bool anywhere = (kd.find("\\temp") != std::string::npos) ||
                            (kd.size() <= 3);    // 盘根如 "d:"
            if (sameDir || anywhere) { idx = i; break; }
        }
        if (idx != (size_t)-1) {
            g_keys[idx].confirmed = true;
            g_keys[idx].linkedVictims = 0;
        }
    }
    if (idx == (size_t)-1) return false;
    if (outKeyIdx) *outKeyIdx = idx;
    StatAdd(11, 1);
    LogDbg("[rollback] 密钥时序关联成立：目录 " + dirLower +
           " 在密钥落盘 " + std::to_string((now - g_keys[idx].at) / 1000) +
           " 秒后出现批量改写 → 认定为勒索密钥");
    return true;
}

// ===========================================================================
//  文件落地前置捕获（2026-09-19 新增）
//
//  【为什么需要】
//  银狐的攻击链条是「诱导下载 → 载荷落盘 → 自启执行」。
//  现有事件源（WMI 进程创建 + 注册表 Run）都发生在**第三步之后** ——
//  载荷已经在跑了。把判定点前移到「落盘那一刻」，
//  可以在攻击者还没执行时就已经定性。
//
//  【判据】（多信号联合，不单看一条）
//    ① 落地位置：Temp / 下载 / 盘根 / AppData —— 用户正常程序极少往这些地方放 exe；
//    ② 文件形态：PE 头（MZ）或脚本头（powershell/cmd/ActiveX 特征字符串）；
//    ③ 命名特征：随机名（纯 hex、或数字+字母高混杂）。
//  ① 与（② 或 ③）同时成立才记入候选。
//
//  【为什么不做重判定】
//  本模块（rollback.cpp）的职责是**回滚引擎**，不做完整的行为判定
//  （那在 behavior.cpp / JudgeProcess）。这里只做"低成本初筛"：
//  读文件头 512 字节 + 看路径与文件名，不调 WinVerifyTrust、不做全文件熵扫描 ——
//  避免在监控线程里引入重 IO（这正是本项目"持锁做 I/O"教训的对偶面）。
//  初筛命中的结果交给上层判定层，让专业的判定函数去下结论。
// ===========================================================================
static bool LooksLikeRandomName(const std::string& baseLower) {
    size_t dot = baseLower.find_last_of('.');
    std::string stem = (dot == std::string::npos) ? baseLower : baseLower.substr(0, dot);
    if (stem.size() < 8) return false;

    // 纯 hex 命名（16 位以上）——恶意载荷最常见的形态
    bool allHex = true;
    for (char c : stem)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { allHex = false; break; }
    if (allHex && stem.size() >= 16) return true;

    // 数字与字母高混杂（正常程序名极少如此）
    int digits = 0, upper = 0, lower = 0;
    for (char c : stem) {
        if (c >= '0' && c <= '9') digits++;
        else if (c >= 'A' && c <= 'Z') upper++;
        else if (c >= 'a' && c <= 'z') lower++;
    }
    int n = (int)stem.size();
    if (digits * 3 >= n && (upper + lower) * 2 >= n) return true;
    return false;
}

// 落地高发区判定（入参须为小写路径）
static bool IsLandingHotspot(const std::string& pathLower) {
    if (pathLower.find("\\temp\\") != std::string::npos) return true;
    if (pathLower.find("\\downloads\\") != std::string::npos) return true;
    if (pathLower.find("\\download\\") != std::string::npos) return true;
    if (pathLower.find("\\appdata\\local\\") != std::string::npos) return true;
    if (pathLower.find("\\appdata\\roaming\\") != std::string::npos) return true;
    if (pathLower.find("\\desktop\\") != std::string::npos) return true;
    // 盘根（形如 "d:\xxx.exe"：第 3 字符是反斜杠且后面再无反斜杠）
    if (pathLower.size() > 4 && pathLower[1] == ':' && pathLower[2] == '\\' &&
        pathLower.find('\\', 3) == std::string::npos) return true;
    return false;
}

static bool ReadHeadBytes(const std::string& path, char* out, DWORD want, DWORD* got) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    BOOL ok = ReadFile(h, out, want, got, nullptr);
    CloseHandle(h);
    return ok != FALSE;
}

// 落地初筛。返回 true 表示"值得让上层判定层关注"。
static bool ProbeLandedFile(const std::string& full, const std::string& fullLower,
                            int* outLevel, std::string* outReason) {
    if (!g_cfg.landHuntEnabled) return false;
    if (!IsLandingHotspot(fullLower)) return false;
    if (IsExcluded(fullLower)) return false;
    if (!g_exeDirLower.empty() && fullLower.find(g_exeDirLower) != std::string::npos) return false;

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExA(full.c_str(), GetFileExInfoStandard, &fad)) return false;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return false;
    uint64_t sz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (sz == 0 || sz > g_cfg.landMaxBytes) return false;

    size_t slash = fullLower.find_last_of("\\/");
    std::string base = (slash == std::string::npos) ? fullLower : fullLower.substr(slash + 1);

    // 只关心可执行/脚本类落地（文档/图片落地是正常行为）
    bool exeLike = false;
    static const char* kExeExt[] = { ".exe", ".scr", ".com", ".pif",
                                     ".bat", ".cmd", ".ps1", ".vbs", ".js" };
    for (const char* e : kExeExt) {
        size_t n = strlen(e);
        if (base.size() > n && base.compare(base.size() - n, n, e) == 0) { exeLike = true; break; }
    }
    bool rndName = LooksLikeRandomName(base);
    if (!exeLike && !rndName) return false;

    char head[512] = { 0 };
    DWORD got = 0;
    if (!ReadHeadBytes(full, head, sizeof(head) - 1, &got) || got < 2) return false;
    head[got] = 0;

    bool isPE = ((unsigned char)head[0] == 'M' && (unsigned char)head[1] == 'Z');
    bool isScript = (strstr(head, "powershell") != nullptr ||
                     strstr(head, "cmd.exe") != nullptr ||
                     strstr(head, "WScript") != nullptr ||
                     strstr(head, "ActiveXObject") != nullptr);

    if (isPE && rndName) {
        if (outLevel) *outLevel = 2;
        if (outReason) *outReason = "随机命名的可执行文件落在落地高发区（疑似银狐载荷）";
        return true;
    }
    if (isScript) {
        if (outLevel) *outLevel = 2;
        if (outReason) *outReason = "脚本载荷落在落地高发区（内含 powershell/cmd 执行特征）";
        return true;
    }
    if (isPE) {
        if (outLevel) *outLevel = 1;
        if (outReason) *outReason = "可执行文件落在落地高发区（旁证，命名正常）";
        return true;
    }
    return false;
}

static std::string DirOfPath(const std::string& lowerPath) {
    size_t p = lowerPath.find_last_of("\\/");
    return (p == std::string::npos) ? std::string() : lowerPath.substr(0, p);
}

// 记录一次改写并返回该目录在当前窗口内的累计改写次数
static uint32_t BumpDirHeat(const std::string& dirLower) {
    if (dirLower.empty()) return 0;
    uint64_t now = NowMs();
    uint64_t win = (uint64_t)g_cfg.burstWindowSec * 1000;
    std::lock_guard<std::mutex> lk(g_heatMtx);
    // 表满时清掉过期的，仍满则整体清空（宁可丢失热度，不可无界增长）
    if (g_heat.size() > 4096) {
        for (auto it = g_heat.begin(); it != g_heat.end();) {
            if (now - it->second.windowStart > win) it = g_heat.erase(it);
            else ++it;
        }
        if (g_heat.size() > 4096) g_heat.clear();
    }
    DirHeat& h = g_heat[dirLower];
    if (now - h.windowStart > win) { h.windowStart = now; h.count = 0; }
    return ++h.count;
}

// 决定是否为此文件建立快照。返回 true 表示应该建。
// ext 为文件的扩展名（小写含点），isRename 表示本次通知是否为改名。
static bool ShouldSnapshotThis(const std::string& fullLower, const std::string& ext,
                               bool isRename, uint32_t* outHeat = nullptr) {
    if (!g_cfg.riskTieredSnapshot) return true;   // 分层关闭 → 退回旧行为

    // 判据①：改成陌生后缀 —— 勒索的强特征，无条件建快照
    if (isRename && LooksLikeRansomExt(ext)) return true;

    // 判据②：该目录短时间内已被频繁改写（这片区域"正在被批量动"）
    uint32_t heat = BumpDirHeat(DirOfPath(fullLower));
    if (outHeat) *outHeat = heat;
    if (heat >= g_cfg.burstFileTrigger) return true;

    // 判据③：高价值文档的首次改写（首次改写前那一版最值得留）
    if (g_cfg.highValueOnly && IsHighValueDoc(fullLower)) {
        // "首次改写"由 SnapshotFile 内部的"已持有则跳过"保证：
        // 这里直接返回 true，若已有快照则 SnapshotFile 会立即返回而不重复写盘。
        return true;
    }

    // 其余情况（普通文件偶发写入，如同目录第 1~4 次改写且非高价值类型）不建快照。
    // 注意：判据②说明该目录热度会累积，一旦超过 burstFileTrigger，
    //       后续同目录的改写都会建快照 —— 所以并不存在"完全无保护"的目录。
    return false;
}

// ===========================================================================
//  快照建立
// ===========================================================================
bool SnapshotFile(const std::string& path, const std::string& reason) {
    if (!g_cfg.enabled) return false;
    std::string key = NormKey(path);
    if (key.empty()) return false;
    if (IsExcluded(key)) return false;
    if (!IsProtectedExt(key)) { StatAdd(4, 1); return false; }

    // 已持有快照 → 不重复拍（**关键**：只保留"最初的那一份"，
    // 即文件被改动之前的状态。若反复覆盖快照，勒索进程多轮加密后
    // 快照里存的就成了上一轮的密文，回滚等于没回滚。）
    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        auto it = g_cache.find(key);
        if (it != g_cache.end()) { TouchLocked(key); return true; }
    }

    // 取文件大小
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fad)) return false;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return false;
    uint64_t sz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (sz == 0) return false;                              // 空文件没有回滚价值
    if (sz > g_cfg.maxFileBytes) { StatAdd(4, 1); return false; }

    // 容量预检：即使拍下来也放不下就不拍（避免先写后淘汰的无效 IO）
    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        if (CacheBytesLocked() + sz > g_cfg.maxCacheBytes && sz > g_cfg.maxCacheBytes / 8)
            { StatAdd(4, 1); return false; }
    }

    std::string snap = SnapPathOf(path);
    std::string meta = MetaPathOf(path);

    // 复制原文（带共享读，避免与正在写入的进程互斥而拿不到）
    HANDLE hs = CreateFileA(path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hs == INVALID_HANDLE_VALUE) { StatAdd(4, 1); return false; }
    HANDLE hd = CreateFileA(snap.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hd == INVALID_HANDLE_VALUE) { CloseHandle(hs); StatAdd(4, 1); return false; }

    std::vector<char> buf(1 << 16);
    uint64_t copied = 0;
    std::string sha;
    {
        BCRYPT_ALG_HANDLE ha = nullptr;
        BCRYPT_HASH_HANDLE hh = nullptr;
        bool hasHash = (BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) &&
                       (BCryptCreateHash(ha, &hh, nullptr, 0, nullptr, 0, 0) == 0);
        for (;;) {
            DWORD rd = 0;
            if (!ReadFile(hs, buf.data(), (DWORD)buf.size(), &rd, nullptr) || rd == 0) break;
            DWORD wr = 0;
            if (!WriteFile(hd, buf.data(), rd, &wr, nullptr) || wr != rd) break;
            if (hasHash) BCryptHashData(hh, (PUCHAR)buf.data(), rd, 0);
            copied += rd;
        }
        if (hasHash) {
            BYTE d[32]; ULONG cb = 32;
            if (BCryptFinishHash(hh, d, cb, 0) == 0) {
                static const char* hx = "0123456789abcdef";
                for (int i = 0; i < 32; ++i) { sha += hx[d[i] >> 4]; sha += hx[d[i] & 0xf]; }
            }
            BCryptDestroyHash(hh);
        }
        if (ha) BCryptCloseAlgorithmProvider(ha, 0);
    }
    CloseHandle(hs);
    CloseHandle(hd);
    if (copied == 0) { DeleteFileA(snap.c_str()); StatAdd(4, 1); return false; }

    Meta m;
    m.path = path; m.sha = sha; m.size = copied; m.time = NowMs(); m.reason = reason;
    WriteMeta(meta, m);

    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        SnapEntry e;
        e.path = path; e.sha = sha; e.snapPath = snap; e.metaPath = meta;
        e.size = copied; e.atime = m.time;
        // 若并发插入已存在（两个线程同时抢拍同一文件），保留先到的，
        // 并把刚写的这组文件删掉（否则会留下永远无人引用的孤儿快照 + 泄漏磁盘）
        auto it = g_cache.find(key);
        if (it != g_cache.end()) {
            DeleteFileA(snap.c_str());
            DeleteFileA(meta.c_str());
            TouchLocked(key);
        } else {
            g_cache[key] = e;
            g_lru.push_back(key);
            StatAdd(3, 1);              // snapshotTaken++
            EvictLocked();              // 先淘汰（此时 g_cache 已含新条目）
            SyncCacheStatsLocked();     // 再把真实占用同步给统计
        }
    }
    return true;
}

bool HasSnapshot(const std::string& path) {
    std::lock_guard<std::mutex> lk(g_cacheMtx);
    return g_cache.count(NormKey(path)) > 0;
}

bool RestoreFile(const std::string& path) {
    std::string key = NormKey(path);
    SnapEntry e;
    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        auto it = g_cache.find(key);
        if (it == g_cache.end()) return false;
        e = it->second;
        TouchLocked(key);
    }
    // 清只读属性（勒索常把原文件设为只读防恢复）
    DWORD attr = GetFileAttributesA(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY))
        SetFileAttributesA(path.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);

    HANDLE hs = CreateFileA(e.snapPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hs == INVALID_HANDLE_VALUE) return false;
    HANDLE hd = CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hd == INVALID_HANDLE_VALUE) { CloseHandle(hs); return false; }

    std::vector<char> buf(1 << 16);
    bool ok = true;
    uint64_t wrote = 0;
    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(hs, buf.data(), (DWORD)buf.size(), &rd, nullptr) || rd == 0) break;
        DWORD wr = 0;
        if (!WriteFile(hd, buf.data(), rd, &wr, nullptr) || wr != rd) { ok = false; break; }
        wrote += rd;
    }
    CloseHandle(hs);
    CloseHandle(hd);
    if (!ok) return false;

    // 恢复成功后**删除该快照**：卡巴的回滚是一次性补救动作，不是持续状态。
    // 保留会占满缓存，且若用户之后再改这个文件，旧快照已无意义（文件已是新内容）。
    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        auto it = g_cache.find(key);
        if (it != g_cache.end()) {
            DeleteFileA(it->second.snapPath.c_str());
            DeleteFileA(it->second.metaPath.c_str());
            g_cache.erase(it);
            for (auto i2 = g_lru.begin(); i2 != g_lru.end(); ++i2)
                if (*i2 == key) { g_lru.erase(i2); break; }
            SyncCacheStatsLocked();
        }
    }
    StatAdd(6, 1);
    (void)wrote;
    return true;
}

// ===========================================================================
//  滑动窗口信号统计
//
//  为什么用窗口而不是累计计数：勒索的特征是**爆发式**改文件（秒级几十上百个），
//  而正常软件（编译、批量重命名、解压）虽然也会改很多文件，但通常分布在更长时间里，
//  且不会伴随"高熵随机后缀改名"与"写勒索说明"。窗口 + 多信号联合是关键。
// ===========================================================================
struct Ev {
    std::string path;
    std::string ext;       // 变更后的扩展名（小写）
    bool        isRename = false;
    bool        ransomRename = false;  // 改成了勒索特征后缀（LooksLikeRansomExt 命中）
    bool        isNote   = false;
    double      entropy  = 0.0;
    uint64_t    t        = 0;
};

static std::mutex       g_evMtx;
static std::deque<Ev>   g_ev;
static std::atomic<bool> g_ransomActive{ false };
static std::string      g_lastTrigger;
static std::mutex       g_triggerMtx;

static void TrimWindowLocked() {          // 调用方须持 g_evMtx
    uint64_t cutoff = NowMs() - (uint64_t)g_cfg.windowSeconds * 1000ull;
    while (!g_ev.empty() && g_ev.front().t < cutoff) g_ev.pop_front();
}

// ---------------------------------------------------------------------------
//  临时目录判定（2026-09-19 16:41 codebuddy 插件解压误报风暴后新增）
//  事故：插件市场安装解压 2000+ 文件到 Temp\codebuddy-marketplace-install-*，
//        包内文档命中「解密说明」关键词 → 「勒索说明伴随批量改动」反复成立
//        → 连续弹卡 + 回滚把解压文件覆盖成快照版本（破坏安装）。
//  结论：Temp 永远繁忙（解压/编译/浏览器缓存），**永不参与信号统计**。
//        Temp 事件只保留密钥截获与落地初筛（这两项是有意针对 Temp 设计）。
// ---------------------------------------------------------------------------
static bool IsTempPath(const std::string& p) {
    std::string l = Lower(p);
    return l.find("\\appdata\\local\\temp\\") != std::string::npos ||
           l.find("\\appdata\\roaming\\temp\\") != std::string::npos ||
           l.find("\\windows\\temp\\") != std::string::npos ||
           l.find("\\temp\\") == 0;   // 盘根 Temp 目录（注意：注释行尾勿以反斜杠结尾，C4010 行继续符会吞掉下一行）
}

// 判定当前窗口是否构成勒索事件
static bool EvaluateLocked(uint32_t* outModified, uint32_t* outRenamed,
                           uint32_t* outNotes, std::string* outTrigger,
                           Risk* outRisk = nullptr) {
    TrimWindowLocked();
    uint32_t mod = 0, ren = 0, note = 0;
    for (const auto& e : g_ev) {
        if (e.isNote) note++;
        else if (e.isRename) {
            if (e.ransomRename) ren++;
            else mod++;   // 正常改名（日志轮转/下载落盘）：计入改动量，不作勒索旁证
        }
        else mod++;
    }
    if (outModified) *outModified = mod;
    if (outRenamed)  *outRenamed  = ren;
    if (outNotes)    *outNotes    = note;

    // ---- 判定规则（对齐业界"多信号联合"共识，单信号不定性）----
    //  硬条件：窗口内批量改写数量达标
    bool burst = (mod + ren) >= g_cfg.filesThreshold;
    //  旁证：高熵随机后缀改名 / 勒索说明文件
    bool renameSignal = ren >= g_cfg.renameThreshold;
    bool noteSignal   = note >= g_cfg.noteThreshold;

    //  两条联合判据都按**强证据**处理（高风险）：
    //   · 勒索说明文件出现 = 正常软件绝不写 "HOW TO DECRYPT"；
    //   · 批量改写 + 高熵随机后缀改名 = 加密 + 改名的完整勒索形态。
    //  这两条都要求"至少两个独立信号同时成立"，单独一个都不定性，
    //  所以命中即可直接自动处置。
    if (noteSignal && (mod + ren) >= 3) {
        if (outTrigger) *outTrigger = "检测到勒索说明文件（HOW TO DECRYPT / 解密说明）伴随批量文件改动";
        if (outRisk) *outRisk = Risk::High;
        return true;
    }
    if (burst && renameSignal) {
        if (outTrigger) *outTrigger = "短时间内大量文件被改写并改成高熵随机后缀";
        if (outRisk) *outRisk = Risk::High;
        return true;
    }
    // 说明：本引擎目前**不产出 Risk::Suspect 判定** —— 宁可漏报可疑、不可误伤正常
    // （回滚是覆盖写，误伤代价高于漏报）。Suspect 档位留给上层其他事件源
    // （文件落地 / 计划任务 / 注册表启动项）复用，那些场景不涉及覆盖写，
    // 适合"先弹窗问用户再动手"。
    return false;
}

// ===========================================================================
//  进程归属：找出"谁在改这个文件"
//
//  用户态拿不到内核的 IRP 发起者信息，故用**启发式归属**：
//  在事件发生时枚举进程，优先取"命令行/路径指向该文件所在目录"的进程。
//  取不到时退回 0（报告里如实标注"未能定位肇事进程"）。
// ===========================================================================
struct ProcInfo {
    uint32_t pid = 0;
    std::string path;
};

static bool IsSystemNoiseProc(const std::string& pathLower) {
    static const char* kNoise[] = {
        "\\system32\\svchost.exe", "\\system32\\searchindexer.exe",
        "\\system32\\dllhost.exe", "\\system32\\msmpeng.exe",
        "\\system32\\searchprotocolhost.exe", "\\system32\\searchfilterhost.exe",
        "\\system32\\trustedinstaller.exe", "\\system32\\tiworker.exe",
        "\\system32\\compattelrunner.exe", "\\system32\\backgroundtaskhost.exe",
        "\\system32\\runtimebroker.exe", "\\system32\\smartscreen.exe",
        "\\system32\\conhost.exe", "\\system32\\wmiprvse.exe",
        "\\system32\\taskhostw.exe", "\\system32\\sihost.exe",
        "\\system32\\explorer.exe", "\\system32\\csrss.exe", "\\system32\\winlogon.exe",
        "\\system32\\services.exe", "\\system32\\lsass.exe", "\\system32\\wininit.exe",
        "\\system32\\spoolsv.exe", "\\system32\\registry", "\\system32\\msiexec.exe",
        "silverfoxguardsvc.exe", "\\system32\\dwm.exe",
        "\\system32\\fontdrvhost.exe", "\\system32\\ctfmon.exe",
        "\\system32\\securityhealthservice.exe", "\\system32\\smartscreen.exe",
    };
    for (const char* n : kNoise) if (pathLower.find(n) != std::string::npos) return true;
    return false;
}

// 取进程映像**全路径**（PROCESSENTRY32 只给基名，无法用于目录归属判断）
static std::string FullPathOfPid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "";
    char buf[MAX_PATH * 4] = { 0 };
    DWORD n = (DWORD)sizeof(buf);
    std::string out;
    if (QueryFullProcessImageNameA(h, 0, buf, &n) && n) out.assign(buf, n);
    CloseHandle(h);
    return out;
}

// 枚举进程，挑出最可能的肇事者。
//
// 归属策略（按可信度递减）：
//   ① 映像路径落在**受害者所在目录**内 —— 最可信（勒索常把自己复制到目标目录）
//   ② 映像路径落在**受害者目录的祖先目录**内 —— 次可信（从盘根遍历加密）
//   ③ 映像路径不在系统目录、且不是已知噪声进程 —— 弱候选，仅在①②都无命中时采用
// 若三等都不满足，返回空（报告里如实写"未能定位"），**不硬凑一个**——
// 把无辜进程标成勒索凶手会引发用户恐慌与误杀，比说"没查到"更糟。
static ProcInfo FindSuspectProcess(const std::vector<std::string>& victims) {
    ProcInfo best;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return best;

    // 受害者目录集合（全小写）
    std::set<std::string> dirs;
    for (const auto& v : victims) {
        size_t p = v.find_last_of("\\/");
        if (p != std::string::npos) dirs.insert(Lower(v.substr(0, p)));
    }

    int  bestRank = 99;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            if (pe.th32ProcessID == GetCurrentProcessId()) continue;

            std::string exe = W2A(pe.szExeFile);
            std::string le  = Lower(exe);
            if (IsSystemNoiseProc("\\" + le)) continue;
            if (le.find("silverfoxguard") != std::string::npos) continue;
            // Defender / 第三方杀软排除（全盘扫描会大量读写文件）
            if (le.find("huorong") != std::string::npos || le.find("hrsword") != std::string::npos ||
                le.find("usysdiag") != std::string::npos || le.find("360") != std::string::npos ||
                le.find("qqpctray") != std::string::npos || le.find("kxescore") != std::string::npos ||
                le.find("avp.exe") != std::string::npos || le.find("kavfs") != std::string::npos ||
                le.find("msmpeng") != std::string::npos) continue;
            // Windows Update / 系统维护类后台进程：它们会成批改文件，但**不是**勒索。
            // 实测（2026-09-18）它们会被误判为凶手（MoUsoCoreWorker.exe），
            // 因为原实现"取最后一个候选"且不看路径是否落在受害者目录内。
            if (le.find("mousocoreworker") != std::string::npos ||
                le.find("usoclient") != std::string::npos ||
                le.find("tiworker") != std::string::npos ||
                le.find("trustedinstaller") != std::string::npos ||
                le.find("wuauclt") != std::string::npos ||
                le.find("compattelrunner") != std::string::npos ||
                le.find("defrag") != std::string::npos) continue;

            std::string full = Lower(FullPathOfPid(pe.th32ProcessID));
            if (full.empty()) continue;

            int rank = 3;   // 默认弱候选
            for (const auto& d : dirs) {
                if (d.empty()) continue;
                // ① 映像就在受害者目录内
                size_t dp = full.find_last_of("\\/");
                if (dp != std::string::npos && full.substr(0, dp) == d) { rank = 1; break; }
                // ② 映像落在受害者目录的祖先路径上
                if (d.size() > full.size() && d.compare(0, full.size(), full) == 0) { rank = 2; break; }
                if (full.size() > d.size() && full.compare(0, d.size(), d) == 0 && rank > 2) { rank = 2; }
            }

            if (rank < bestRank) {
                bestRank = rank;
                best.pid = pe.th32ProcessID;
                best.path = full;
                if (rank == 1) break;      // 最高可信度，无需再看
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    // 弱候选（rank 3）可信度太低，宁可报告"未定位"也不冤枉无关进程。
    if (bestRank >= 3) { ProcInfo none; return none; }
    return best;
}

static bool TerminateSuspect(uint32_t pid) {
    if (!pid) return false;
    HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    return ok != FALSE;
}

// ===========================================================================
//  信誉门（2026-09-19 新增：wallpaper64.exe 误杀事故的根治）
//  事故：Wallpaper Engine（Steam 正版、Valve 签名）批量写 Temp 缓存，
//        「高熵随机后缀」判据把 .tmp.js 双扩展当勒索改名 → 归因环拉到
//        wallpaper64.exe → 全量终止。根因不是"归因错了"，而是**终止决策
//        没有信誉层**——正规杀软在终止前都查进程信誉。
//  实现：sf::ProcReputable（behavior.cpp 共享版，签名厂商名单/可信路径）；
//        此处补一个回滚特有的判据：受害文件全部在临时目录 → 不构成勒索
//        目标（Temp 一次性文件），也不终止。
// ===========================================================================
static bool AllVictimsInTemp(const std::vector<std::string>& victims) {
    if (victims.empty()) return false;
    size_t hit = 0;
    for (const auto& v : victims) {
        std::string l = Lower(v);
        if (l.find("\\appdata\\local\\temp\\") != std::string::npos ||
            l.find("\\appdata\\roaming\\temp\\") != std::string::npos ||
            l.find("\\windows\\temp\\") != std::string::npos ||
            l.find("\\temp\\") == 0) hit++;
    }
    return hit == victims.size();
}

// ===========================================================================
//  回滚执行
// ===========================================================================
// 把文件当前内容备份到 undo 目录（回滚前的"用户版本"）。
// 返回备份路径，失败返回空串（失败不阻断回滚——回滚比撤销重要）。
static std::string SaveUndoCopy(const std::string& srcPath, const std::string& token) {
    std::string ud = CacheDirImpl() + "\\undo";
    CreateDirectoryA(ud.c_str(), nullptr);
    // 文件名：token + 序号 + 原文件名的哈希（原文件名可能含非法字符/过长）
    static std::atomic<uint32_t> seq{ 0 };
    char nm[160];
    sprintf_s(nm, "\\%s_%08X_%06u.bak", token.substr(0, 8).c_str(),
              (unsigned)std::hash<std::string>{}(Lower(srcPath)), (unsigned)(seq.fetch_add(1) % 1000000));
    std::string dst = ud + nm;

    HANDLE hs = CreateFileA(srcPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hs == INVALID_HANDLE_VALUE) return {};
    HANDLE hd = CreateFileA(dst.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hd == INVALID_HANDLE_VALUE) { CloseHandle(hs); return {}; }

    std::vector<char> buf(256 * 1024);
    std::string err;
    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(hs, buf.data(), (DWORD)buf.size(), &rd, nullptr)) { err = "read"; break; }
        if (!rd) break;
        DWORD wr = 0;
        if (!WriteFile(hd, buf.data(), rd, &wr, nullptr) || wr != rd) { err = "write"; break; }
    }
    CloseHandle(hs);
    FlushFileBuffers(hd);
    CloseHandle(hd);
    if (!err.empty()) { DeleteFileA(dst.c_str()); return {}; }
    return dst;
}

static RollbackReport RollbackVictims(const std::vector<std::string>& victims, const std::string& trigger,
                                      bool makeUndo = true) {
    RollbackReport rep;
    rep.trigger = trigger;
    rep.victims = victims.size();

    // ---- 撤销凭据：每次回滚生成一个，供后续 UndoLastRollback 校验 ----
    std::string token;
    if (makeUndo) {
        static std::atomic<uint32_t> tokSeq{ 0 };
        char tb[64];
        sprintf_s(tb, "%llx%08x", (unsigned long long)GetTickCount64(), (unsigned)(tokSeq.fetch_add(1)));
        token = tb;
        // 新的回滚发生 → 旧撤销记录作废（见 g_undoList 上方的说明）
        ClearUndoLocked();
    }

    ProcInfo sus = FindSuspectProcess(victims);
    rep.pid = sus.pid;
    rep.processPath = sus.path;

    if (g_cfg.terminateOnDetect && sus.pid) {
        // ★ 信誉门：可信厂商签名进程 / 受害文件全在临时目录 → 跳过终止。
        //   告警照发（用户仍有知情权），但不杀进程（见上方信誉门注释）。
        if (sf::ProcReputable(sus.path) || AllVictimsInTemp(victims)) {
            LogDbg("[rollback] 终止决策被信誉门拦截（签名可信厂商/受害者全在临时目录）→ 跳过终止: " + sus.path);
        } else if (TerminateSuspect(sus.pid)) {
            LogDbg("[rollback] 已终止肇事进程 pid=" + std::to_string(sus.pid) + " " + sus.path);
        } else {
            LogDbg("[rollback] 终止进程失败 pid=" + std::to_string(sus.pid));
        }
    }
    if (!sus.pid)
        LogDbg("[rollback] 未能定位肇事进程（不冤枉无关进程，报告如实标注）");

    for (const auto& v : victims) {
        // 先校验快照是否仍然"对得上"：若快照时间晚于文件当前修改时间，
        // 说明快照拍的就是已被破坏的内容 → 不能用来恢复（诚实标注为不可恢复）。
        bool ok = false;
        {
            std::lock_guard<std::mutex> lk(g_cacheMtx);
            auto it = g_cache.find(NormKey(v));
            if (it != g_cache.end()) ok = true;
        }
        if (!ok) {
            rep.unrecover++;
            if (rep.lostPaths.size() < kMaxListedPaths) rep.lostPaths.push_back(v);
            continue;
        }
        // ★ 覆盖写之前先留一份"用户版本"，供事后撤销（只在能恢复时才留——
        //   恢复不了的文件本来就没被改动，不需要撤销）。
        std::string undoCopy;
        if (makeUndo) undoCopy = SaveUndoCopy(v, token);

        if (RestoreFile(v)) {
            rep.restored++;
            if (rep.restoredPaths.size() < kMaxListedPaths) rep.restoredPaths.push_back(v);
            if (!undoCopy.empty()) {
                std::lock_guard<std::mutex> lk(g_undoMtx);
                UndoEntry ue;
                ue.path = v;
                ue.undoPath = undoCopy;
                // 取备份文件的实际大小（SaveUndoCopy 已写入）
                WIN32_FILE_ATTRIBUTE_DATA fad{};
                if (GetFileAttributesExA(undoCopy.c_str(), GetFileExInfoStandard, &fad))
                    ue.size = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
                g_undoList.push_back(ue);
            }
        } else {
            // 恢复失败 → 那份备份没有意义，删掉（避免留垃圾）
            if (!undoCopy.empty()) DeleteFileA(undoCopy.c_str());
            rep.unrecover++;
            if (rep.lostPaths.size() < kMaxListedPaths) rep.lostPaths.push_back(v);
        }
    }
    StatAdd(5, 1);
    StatAdd(7, rep.unrecover);

    if (makeUndo) {
        std::lock_guard<std::mutex> lk(g_undoMtx);
        g_undoToken   = token;
        g_undoTrigger = trigger;
        g_undoAtMs    = NowMs();
        LogDbg("[rollback] 已留存撤销副本 " + std::to_string(g_undoList.size()) +
               " 份（token=" + token + "，10 分钟内可在弹窗中点「撤销」）");
    }
    return rep;
}

std::string RollbackReport::ToJson() const {
    std::ostringstream os;
    os << "{\"victims\":" << victims
       << ",\"restored\":" << restored
       << ",\"unrecoverable\":" << unrecover
       << ",\"bytesSaved\":" << bytesSaved
       << ",\"pid\":" << pid
       << ",\"process\":" << JsonString(processPath)
       << ",\"trigger\":" << JsonString(trigger)
       << ",\"restoredPaths\":[";
    for (size_t i = 0; i < restoredPaths.size(); ++i) {
        if (i) os << ",";
        os << JsonString(restoredPaths[i]);
    }
    os << "],\"lostPaths\":[";
    for (size_t i = 0; i < lostPaths.size(); ++i) {
        if (i) os << ",";
        os << JsonString(lostPaths[i]);
    }
    os << "]}";
    return os.str();
}

// ===========================================================================
//  勒索处置入口：由监控线程在判定成立时调用
//
//  ⚠️ 冷却期（cooldown）是必需的，不是优化：
//  回滚动作本身要**写回**几十上百个文件，这些写入同样会产生文件变更通知
//  → 又被喂进滑动窗口 → 再次满足触发条件 → 再次回滚……形成正反馈。
//  实测（2026-09-18 端到端模拟）：不加冷却会连续触发 5 次，
//  恢复数从 30 递减到 23（重复回滚同一批文件，且每次都在消耗 CPU/IO）。
//  故处置完成后进入冷却期，期间**只统计不判定**。
// ===========================================================================
static std::atomic<uint64_t> g_cooldownUntilMs{ 0 };
static const uint64_t kCooldownMs = 20000;   // 20 秒：足够把所有回滚写入消化掉

static void HandleRansomDetection() {
    // 冷却期内不判定（回滚自身产生的写入不应再次触发）
    if (NowMs() < g_cooldownUntilMs.load()) return;

    std::vector<std::string> victims;
    std::string trigger;
    Risk risk = Risk::High;
    {
        std::lock_guard<std::mutex> lk(g_evMtx);
        uint32_t mod = 0, ren = 0, note = 0;
        if (!EvaluateLocked(&mod, &ren, &note, &trigger, &risk)) return;
        // 收集窗口内所有**最近被改动**的文件作为受害者
        std::set<std::string> uniq;
        for (auto it = g_ev.rbegin(); it != g_ev.rend(); ++it) {
            if (!it->path.empty()) uniq.insert(it->path);
            if (uniq.size() >= 2000) break;
        }
        victims.assign(uniq.begin(), uniq.end());
        g_ev.clear();     // 清空窗口，避免处理完立即再次触发
    }
    if (victims.empty()) return;

    // 先进入冷却期，再开始回滚 —— 顺序很重要：
    // 若先回滚后设冷却，回滚期间的写入通知会趁冷却尚未生效时挤进窗口。
    g_cooldownUntilMs.store(NowMs() + kCooldownMs);

    StatAdd(8, 1);
    g_ransomActive.store(true);

    LogDbg("[rollback] ==== 勒索行为判定成立 ==== 触发原因: " + trigger +
           "，涉及文件 " + std::to_string(victims.size()) + " 个");
    RollbackReport rep = RollbackVictims(victims, trigger);
    LogDbg("[rollback] 回滚完成: 恢复 " + std::to_string(rep.restored) +
           " / 共计 " + std::to_string(rep.victims) +
           "，不可恢复 " + std::to_string(rep.unrecover) +
           "，肇事进程 pid=" + std::to_string(rep.pid) + " " + rep.processPath);
    LogDbg("[rollback] 进入 " + std::to_string(kCooldownMs / 1000) +
           " 秒冷却期（避免回滚写入触发二次判定）");

    { std::lock_guard<std::mutex> lk(g_triggerMtx); g_lastTrigger = trigger; }

    // 把结果交给上层展示（服务方注入的回调负责写扫描结果 + 弹窗通知）。
    // 本模块不直接引用 g_result / NotifyAnomaly —— 那样会让本模块无法独立测试。
    if (g_detCb) {
        DetectionInfo info;
        info.trigger       = trigger;
        info.processPath   = rep.processPath;
        info.pid           = rep.pid;
        info.victims       = rep.victims;
        info.restored      = rep.restored;
        info.unrecoverable = rep.unrecover;
        info.risk          = risk;
        info.autoHandled   = (rep.restored > 0);   // 已自动终止 + 回滚
        // 撤销凭据：只在"确实覆盖过内容"时提供（没回滚成功就没有可撤销的东西）
        {
            std::lock_guard<std::mutex> lk(g_undoMtx);
            info.undoable = !g_undoList.empty() && (rep.restored > 0);
            if (info.undoable) info.undoToken = g_undoToken;
        }
        g_detCb(info);
    }
}

// ===========================================================================
//  目录监控（ReadDirectoryChangesW）
// ===========================================================================
struct WatchTarget {
    std::string     dir;      // 窄路径（展示用）
    std::wstring    dirW;     // 宽路径（API 用）
    HANDLE          h = INVALID_HANDLE_VALUE;
    OVERLAPPED      ov{};
    HANDLE          ev = nullptr;
    std::vector<char> buf;
    bool            recursive = true;
};

// 枚举本机所有**真实用户**的 profile 目录。
//
// 【为什么必须这样做】
// 服务跑在 LocalSystem / Session 0。此时 SHGetFolderPathW(nullptr, CSIDL_*) 的
// "当前用户"是 **SYSTEM**，返回的是 C:\Windows\system32\config\systemprofile\Desktop
// —— **用户自己的桌面根本不在监控范围内**。
// 实测证据（2026-09-19 日志）：09-18 监控 7 个目录 → 09-19 服务重启后降为 2 个，
// 少的正是桌面/文档/下载，用户桌面上的勒索测试文件因此完全没被监控到。
//
// 做法：枚举 HKU\<SID> 下所有 S-1-5-21-* 的真实用户 SID（与 service.cpp 里
// RegRunWatch 的 HKU 枚举模式一致），对每个 SID 拼出已知文件夹路径。
// 用 %USERPROFILE% 的注册表值（ProfileImagePath）拿用户根目录，再拼子目录 ——
// 比调 SHGetFolderPathW 可靠，因为后者只认"当前进程用户"。
static void CollectUserProfiles(std::vector<std::string>& out) {
    HKEY hkUsers = nullptr;
    if (RegOpenKeyExA(HKEY_USERS, nullptr, 0, KEY_READ, &hkUsers) != ERROR_SUCCESS) return;

    DWORD nSub = 0;
    RegQueryInfoKeyA(hkUsers, nullptr, nullptr, nullptr, &nSub, nullptr, nullptr,
                     nullptr, nullptr, nullptr, nullptr, nullptr);

    std::vector<char> nm(512);
    for (DWORD i = 0; i < nSub; ++i) {
        DWORD ns = (DWORD)nm.size();
        if (RegEnumKeyA(hkUsers, i, nm.data(), ns) != ERROR_SUCCESS) continue;
        std::string sid(nm.data());
        // 只看真实用户 SID（排除 .DEFAULT / S-1-5-18 等系统 SID）；
        // 同时排除 *_Classes（它是 SID 的附属 hive，不是独立用户）
        if (sid.find("S-1-5-21-") == std::string::npos) continue;
        if (sid.size() > 8 && sid.compare(sid.size() - 8, 8, "_Classes") == 0) continue;

        // 取该用户的 ProfileImagePath（即 C:\Users\<name>）
        char prof[MAX_PATH * 2] = { 0 };
        DWORD cb = sizeof(prof), type = 0;
        std::string vkey = sid + "\\Volatile Environment";
        if (RegGetValueA(hkUsers, vkey.c_str(), "USERPROFILE", RRF_RT_REG_SZ,
                         &type, prof, &cb) != ERROR_SUCCESS || !prof[0]) {
            // Volatile Environment 未加载（用户未登录）时兜底走 HKLM 的 ProfileList
            cb = sizeof(prof);
            std::string pkey = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + sid;
            if (RegGetValueA(HKEY_LOCAL_MACHINE, pkey.c_str(), "ProfileImagePath",
                             RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_SZ,
                             &type, prof, &cb) != ERROR_SUCCESS || !prof[0])
                continue;
            // 展开环境变量（ProfileImagePath 常含 %SystemDrive%）
            char exp[MAX_PATH * 2] = { 0 };
            if (ExpandEnvironmentStringsA(prof, exp, sizeof(exp)))
                strncpy_s(prof, exp, _TRUNCATE);
        }
        std::string root(prof);
        if (root.empty()) continue;
        DWORD a = GetFileAttributesA(root.c_str());
        if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY)) continue;
        out.push_back(root);
    }
    RegCloseKey(hkUsers);
}

static std::vector<std::string> DefaultWatchDirs() {
    std::vector<std::string> v;
    wchar_t p[MAX_PATH] = { 0 };

    // ---- ① 所有真实用户的已知文件夹（核心修复）----
    // 服务在 Session 0，必须显式枚举用户 SID，否则取到的是 SYSTEM 的 profile。
    std::vector<std::string> profiles;
    CollectUserProfiles(profiles);
    static const char* kUserSub[] = {
        "\\Desktop", "\\Documents", "\\Downloads", "\\Pictures", "\\Videos", "\\Music",
    };
    for (const auto& root : profiles) {
        for (const char* sub : kUserSub) {
            std::string full = root + sub;
            DWORD a = GetFileAttributesA(full.c_str());
            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) v.push_back(full);
        }
    }
    // 若一个用户 profile 都没枚举到（极端情况），退回旧行为，至少不是空的
    if (profiles.empty()) {
        struct { int csidl; const char* name; } kUser[] = {
            { CSIDL_DESKTOPDIRECTORY, "桌面" }, { CSIDL_PERSONAL, "文档" },
            { CSIDL_MYVIDEO, "视频" }, { CSIDL_MYPICTURES, "图片" },
        };
        for (auto& k : kUser) {
            if (SUCCEEDED(SHGetFolderPathW(nullptr, k.csidl, nullptr, 0, p)) && p[0]) {
                std::string s = W2A(p);
                if (!s.empty()) v.push_back(s);
            }
        }
        PWSTR pw = nullptr;
        static const GUID kDownloads =
            { 0x374DE290, 0x123F, 0x4565, { 0x91, 0x64, 0x39, 0xC4, 0x92, 0x5B, 0x5E, 0xE5 } };
        if (SUCCEEDED(SHGetKnownFolderPath(kDownloads, 0, nullptr, &pw)) && pw) {
            std::string s = W2A(pw);
            if (!s.empty()) v.push_back(s);
            CoTaskMemFree(pw);
        }
    }

    // ---- ② 落地高发区（前置捕获的覆盖范围，2026-09-19 新增）----
    // 银狐载荷落盘的典型位置：用户 Temp、系统 Temp、盘根。
    // 这些目录不建快照（内容多为临时物），但**纳入监控**以便"落盘即判"。
    for (const auto& root : profiles) {
        std::string t = root + "\\AppData\\Local\\Temp";
        DWORD a = GetFileAttributesA(t.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) v.push_back(t);
    }
    {
        char win[MAX_PATH] = { 0 };
        if (GetWindowsDirectoryA(win, MAX_PATH)) {
            std::string t = std::string(win) + "\\Temp";
            DWORD a = GetFileAttributesA(t.c_str());
            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) v.push_back(t);
        }
    }
    // 公共文档
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_DOCUMENTS, nullptr, 0, p)) && p[0]) {
        std::string s = W2A(p);
        if (!s.empty()) v.push_back(s);
    }
    // 数据盘常见文档根（存在才加）——勒索最爱扫驱动器根
    static const char* kRoots[] = { "D:\\", "E:\\", "F:\\" };
    for (const char* r : kRoots) {
        DWORD a = GetFileAttributesA(r);
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) v.push_back(r);
    }
    // 测试钩子：环境变量 SFG_RB_TEST_WATCH 指向的目录也纳入监控。
    // 为什么保留这个钩子：勒索判定是本模块最核心也最危险的逻辑（判错会回滚用户
    // 正常文件），必须能用**真实文件操作**端到端验证，而不是只测内部函数。
    // 生产环境不会设置该变量，故无安全影响。
    {
        char env[MAX_PATH * 4] = { 0 };
        DWORD n = GetEnvironmentVariableA("SFG_RB_TEST_WATCH", env, sizeof(env));
        if (n > 0 && n < sizeof(env)) {
            // 支持用 ; 分隔多个目录
            std::string all(env, n);
            size_t start = 0;
            while (start <= all.size()) {
                size_t sep = all.find(';', start);
                std::string one = all.substr(start, (sep == std::string::npos) ? std::string::npos : sep - start);
                if (!one.empty()) {
                    DWORD a = GetFileAttributesA(one.c_str());
                    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY))
                        v.push_back(one);
                }
                if (sep == std::string::npos) break;
                start = sep + 1;
            }
        }
    }
    // 去重
    std::set<std::string> seen;
    std::vector<std::string> out;
    for (auto& s : v) {
        std::string k = NormKey(s);
        if (k.empty() || seen.count(k)) continue;
        seen.insert(k);
        out.push_back(s);
    }
    return out;
}

static bool OpenWatchTarget(WatchTarget& wt) {
    wt.dirW = A2W(wt.dir);
    wt.h = CreateFileW(wt.dirW.c_str(),
                       FILE_LIST_DIRECTORY,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr, OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                       nullptr);
    if (wt.h == INVALID_HANDLE_VALUE) return false;
    wt.ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    wt.ov.hEvent = wt.ev;
    wt.buf.assign(64 * 1024, 0);
    return true;
}

static void CloseWatchTarget(WatchTarget& wt) {
    if (wt.h != INVALID_HANDLE_VALUE) { CancelIoEx(wt.h, &wt.ov); CloseHandle(wt.h); wt.h = INVALID_HANDLE_VALUE; }
    if (wt.ev) { CloseHandle(wt.ev); wt.ev = nullptr; }
}

// 处理一批变更通知
static void ProcessNotifications(WatchTarget& wt, DWORD bytes) {
    size_t off = 0;
    while (off < bytes) {
        auto* fni = (FILE_NOTIFY_INFORMATION*)(wt.buf.data() + off);
        if (fni->FileNameLength == 0) { if (!fni->NextEntryOffset) break; off += fni->NextEntryOffset; continue; }

        // FileName 是不带结尾 \0 的变长数组（踩坑点）
        std::wstring nameW(fni->FileName, fni->FileNameLength / sizeof(WCHAR));
        std::string  name = W2A(nameW);
        std::string  full = wt.dir;
        if (!full.empty() && full.back() != '\\') full += "\\";
        full += name;
        std::string  fl = Lower(full);

        StatAdd(2, 1);

        bool isRename = (fni->Action == FILE_ACTION_RENAMED_NEW_NAME);
        bool isModify = (fni->Action == FILE_ACTION_MODIFIED ||
                         fni->Action == FILE_ACTION_ADDED ||
                         fni->Action == FILE_ACTION_RENAMED_NEW_NAME);
        bool isDelete = (fni->Action == FILE_ACTION_REMOVED);

        if (isModify || isRename) {
            // ---- 排除自身与系统噪声 ----
            if (IsExcluded(fl)) goto next;
            if (!g_exeDirLower.empty() && fl.find(g_exeDirLower) != std::string::npos) goto next;
            // ---- 临时目录：只保留密钥截获 + 落地初筛，不快照、不进信号统计 ----
            if (IsTempPath(fl)) {
                TryCaptureKey(full, fl);
                if (fni->Action == FILE_ACTION_ADDED || isRename) {
                    int lv = 0; std::string why;
                    if (ProbeLandedFile(full, fl, &lv, &why) && lv >= 2) {
                        std::lock_guard<std::mutex> lk(g_landMtx);
                        g_landed.alerts.push_back({ full, why, NowMs() });
                        if (g_landed.alerts.size() > 256) g_landed.alerts.pop_front();
                    }
                }
                StatAdd(4, 1);   // 记入"跳过"统计
                goto next;
            }

            size_t dotPos = fl.find_last_of('.');
            std::string extOfFile = (dotPos == std::string::npos) ? "" : fl.substr(dotPos);

            // ---- 密钥截获（2026-09-19 新增）----
            // 必须**抢在快照逻辑之前**：密钥文件所在目录（Temp/盘根）通常不在
            // 受保护扩展名里，走不到后面的 SnapshotFile；而且密钥本身也不是
            // "需要快照保护的用户文件"——它的价值在于**内容留存**。
            TryCaptureKey(full, fl);

            // ---- 文件落地前置捕获（2026-09-19 新增）----
            // 只对"新增"动作做（MODIFIED 可能是反复写入，会重复判定）。
            // 判定很轻：路径 + 文件名 + 512 字节文件头，不涉及重 IO。
            if (fni->Action == FILE_ACTION_ADDED || isRename) {
                int lv = 0; std::string why;
                if (ProbeLandedFile(full, fl, &lv, &why)) {
                    StatAdd(12, 1);
                    LogDbg("[rollback] 落地初筛命中（" + std::to_string(lv) + "级）: " +
                           full + " —— " + why);
                    // 高危落地：交给上层判定层（service 的 WmiSink 会读到这个标记）。
                    // 本模块不直接弹窗/终止进程 —— 那是 service 层的职责，
                    // 保持本模块可独立测试（见 rollback.h 的注入回调说明）。
                    if (lv >= 2) {
                        std::lock_guard<std::mutex> lk(g_landMtx);
                        g_landed.alerts.push_back({ full, why, NowMs() });
                        if (g_landed.alerts.size() > 256) g_landed.alerts.pop_front();
                    }
                }
            }

            // ---- 建立写前快照（风险分层：只对"有可疑迹象"的文件建）----
            // 注意：FILE_ACTION_MODIFIED 在文件**第一次写入后**就触发，
            // 所以这次快照可能已经是部分加密后的内容。这就是 header 里说的
            // "竞态窗口"——用下面的基线巡逻做二次保险。
            {
                uint32_t heat = 0;
                bool want = ShouldSnapshotThis(fl, extOfFile, isRename, &heat);
                // 目录热度达到"批量改写"阈值时，说明这片区域正在被大面积动，
                // 即便本次文件本身不满足条件，也建一份（此时风险已显著升高）。
                bool hotDir = (heat >= g_cfg.filesThreshold);
                if (want || hotDir) {
                    LARGE_INTEGER sz{}; HANDLE hq = CreateFileA(full.c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (hq != INVALID_HANDLE_VALUE) {
                        GetFileSizeEx(hq, &sz); CloseHandle(hq);
                        if (sz.QuadPart > 0 && (uint64_t)sz.QuadPart <= g_cfg.maxFileBytes)
                            SnapshotFile(full, isRename ? "rename" : "modify");
                    }
                } else {
                    StatAdd(4, 1);   // 记入"跳过"统计，让 UI 能看到分层生效
                }

                // ---- 密钥时序关联（2026-09-19 新增）----
                // 判据：某目录刚出现过"体积小 + 高熵 + 陌生扩展名"的候选密钥文件，
                // 紧接着这片区域开始被批量改写 —— 这几乎只有一种解释：
                // **攻击者刚生成密钥、紧接着开始用它加密**。
                //
                // 一旦成立，**不必等 filesThreshold（默认 25）个文件被加密**就能定性，
                // 把拦截点从"第 25 个文件"提前到"第一个爆发批次"。
                // 触发条件取 burstFileTrigger（默认 5）—— 比 filesThreshold 更早。
                if (g_cfg.keyHuntEnabled && heat >= g_cfg.burstFileTrigger) {
                    size_t keyIdx = 0;
                    if (ConfirmKeyByBurst(DirOfPath(fl), &keyIdx)) {
                        std::string kpath;
                        { std::lock_guard<std::mutex> lk(g_keyMtx);
                          if (keyIdx < g_keys.size()) kpath = g_keys[keyIdx].path; }
                        LogDbg("[rollback] ==== 密钥关联提前定性 ==== 密钥来源: " + kpath +
                               "，目录热度 " + std::to_string(heat) +
                               "（阈值 " + std::to_string(g_cfg.filesThreshold) + "）");
                        // 立即进入处置（不等常规 8 事件节拍，也不等阈值）
                        HandleRansomDetection();
                        goto next;   // 本事件已并入本次判定，不再重复计入窗口
                    }
                }
            }

            // ---- 信号采集 ----
            Ev e;
            e.path = full;
            e.isRename = isRename;
            // 改名分级（2026-09-19 PCL2 误报根治）：只有改成勒索特征后缀的改名
            // 才算"高熵随机后缀"旁证；日志轮转（.log→.log.gz）、下载落盘、
            // 备份轮转等正常改名仍计入改动量（mod），但不再供勒索判定使用。
            e.ransomRename = isRename && LooksLikeRansomExt(extOfFile);
            e.t = NowMs();
            e.ext = extOfFile;
            if (e.ransomRename) e.entropy = EntropyOfFile(full);
            std::string base = fl.substr(fl.find_last_of("\\/") + 1);
            if (LooksLikeRansomNote(base)) e.isNote = true;

            {
                std::lock_guard<std::mutex> lk(g_evMtx);
                g_ev.push_back(e);
                if (g_ev.size() > 20000) g_ev.pop_front();
            }
            // 判定（每 8 个事件评估一次，避免每条通知都跑一遍 O(n) 统计）
            static std::atomic<int> tick{ 0 };
            if ((++tick % 8) == 0) HandleRansomDetection();
        } else if (isDelete) {
            // 原文件被删除 —— 勒索的重要旁证（业界共识：加密后删除原文件）。
            // 这里不建快照（文件已没了），只是记录下来供判定使用。
            // Temp 的删除不算旁证（解压/清理常态删除海量临时文件）。
            if (IsTempPath(fl)) goto next;
            std::lock_guard<std::mutex> lk(g_evMtx);
            Ev e; e.path = full; e.t = NowMs();
            g_ev.push_back(e);
            if (g_ev.size() > 20000) g_ev.pop_front();
        }
    next:
        if (!fni->NextEntryOffset) break;
        off += fni->NextEntryOffset;   // 按字节推进（踩坑点：不能用 sizeof）
    }
}

// ---- 基线巡逻：对高危目录里的文档做周期性哈希抽样比对 ----
// 这是"抢拍迟了"的二次保险：即使某次快照来晚了，也能从更早的基线快照恢复。
// 为控制开销，每轮只抽样 N 个文件，且只对**尚无快照**的受保护类型文件建立基线。
static void BaselinePatrol(const std::vector<std::string>& dirs) {
    const int kMaxPerRound = 300;
    int done = 0;
    for (const auto& d : dirs) {
        if (done >= kMaxPerRound) break;
        std::string pattern = d;
        if (!pattern.empty() && pattern.back() != '\\') pattern += "\\";
        pattern += "*";
        WIN32_FIND_DATAA fd{};
        HANDLE hf = FindFirstFileA(pattern.c_str(), &fd);
        if (hf == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::string full = d;
            if (!full.empty() && full.back() != '\\') full += "\\";
            full += fd.cFileName;
            std::string fl = Lower(full);
            if (IsExcluded(fl)) continue;
            if (!IsProtectedExt(fl)) continue;
            uint64_t sz = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (sz == 0 || sz > g_cfg.maxFileBytes) continue;
            if (HasSnapshot(full)) continue;
            SnapshotFile(full, "baseline");
            if (++done >= kMaxPerRound) break;
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    }
    if (done) LogDbg("[rollback] 基线巡逻：本轮为 " + std::to_string(done) + " 个文件建立基线快照");
}

// ===========================================================================
//  监控线程
// ===========================================================================
static void WatchThread() {
    SetThreadDescription(GetCurrentThread(), L"SFG-RollbackWatch");

    std::vector<std::string> dirs = DefaultWatchDirs();
    std::vector<WatchTarget> targets;
    for (const auto& d : dirs) {
        WatchTarget wt;
        wt.dir = d;
        if (OpenWatchTarget(wt)) targets.push_back(std::move(wt));
        else LogDbg("[rollback] 无法监控目录（跳过）: " + d);
    }
    {
        std::lock_guard<std::mutex> lk(g_statsMtx);
        g_stats.watching = !targets.empty();
    }
    LogDbg("[rollback] 监控启动，共 " + std::to_string(targets.size()) + " 个目录");

    if (targets.empty()) return;

    // 为每个目录挂初次异步读
    for (auto& t : targets) {
        ResetEvent(t.ev);
        ReadDirectoryChangesW(t.h, t.buf.data(), (DWORD)t.buf.size(), t.recursive,
                              FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                              FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                              FILE_NOTIFY_CHANGE_SECURITY,
                              nullptr, &t.ov, nullptr);
    }

    uint64_t lastPatrol = NowMs();
    while (g_running.load()) {
        // 收集所有事件句柄 + 停止事件，一次性等待
        std::vector<HANDLE> hs;
        hs.reserve(targets.size() + 1);
        for (auto& t : targets) hs.push_back(t.ev);
        hs.push_back(g_stopEvent ? g_stopEvent : nullptr);

        DWORD n = (DWORD)hs.size();
        std::vector<HANDLE> wait = hs;
        if (!wait.back()) { wait.pop_back(); n--; }
        DWORD r = WaitForMultipleObjects(n, wait.data(), FALSE, 1000);

        if (r == WAIT_TIMEOUT) {
            // 超时：做基线巡逻 + 顺便检查是否需要重新挂读
            if (NowMs() - lastPatrol > 30000) {       // 每 30 秒巡逻一轮
                lastPatrol = NowMs();
                BaselinePatrol(dirs);
            }
            continue;
        }
        if (r == WAIT_OBJECT_0 + targets.size()) break;   // 停止事件
        if (r < WAIT_OBJECT_0 || r >= WAIT_OBJECT_0 + targets.size()) {
            StatAdd(9, 1);
            Sleep(50);
            continue;
        }

        size_t idx = r - WAIT_OBJECT_0;
        WatchTarget& t = targets[idx];
        DWORD bytes = 0;
        if (GetOverlappedResult(t.h, &t.ov, &bytes, FALSE) && bytes > 0) {
            try { ProcessNotifications(t, bytes); }
            catch (...) { StatAdd(9, 1); }
        }
        // 重新挂读（必须每次重新投递，ReadDirectoryChangesW 是一次性的）
        ResetEvent(t.ev);
        if (!ReadDirectoryChangesW(t.h, t.buf.data(), (DWORD)t.buf.size(), t.recursive,
                                   FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                   FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                                   FILE_NOTIFY_CHANGE_SECURITY,
                                   nullptr, &t.ov, nullptr)) {
            StatAdd(9, 1);
        }
    }

    for (auto& t : targets) CloseWatchTarget(t);
    LogDbg("[rollback] 监控线程退出");
}

static std::thread g_watchThread;

// ===========================================================================
//  配置加载
// ===========================================================================
std::string DefaultConfigPath() {
    char exe[MAX_PATH]; GetModuleFileNameA(nullptr, exe, MAX_PATH);
    std::string d = exe; size_t q = d.find_last_of('\\');
    std::string base = (q != std::string::npos) ? d.substr(0, q + 1) : "";
    const std::string cands[] = {
        base + "data\\rollback_rules.txt",
        base + "rollback_rules.txt",
        "C:\\ProgramData\\SilverFoxGuard\\rollback_rules.txt"
    };
    for (const auto& c : cands) if (FileExists(c)) return c;
    return "";
}

bool LoadConfigFromFile(const std::string& path, Config& out) {
    if (path.empty()) return false;
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        // 允许行尾注释
        size_t hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        auto trim = [](std::string s) {
            size_t a = s.find_first_not_of(" \t");
            size_t b = s.find_last_not_of(" \t");
            return (a == std::string::npos) ? std::string() : s.substr(a, b - a + 1);
        };
        k = trim(k); v = trim(v);
        if (k.empty() || v.empty()) continue;
        try {
            if (k == "enabled")              out.enabled = (v == "1" || Lower(v) == "true" || v == "on");
            else if (k == "max_cache_mb")    out.maxCacheBytes = (uint64_t)std::stoull(v) * 1024 * 1024;
            else if (k == "max_file_mb")     out.maxFileBytes = (uint64_t)std::stoull(v) * 1024 * 1024;
            else if (k == "window_seconds")  out.windowSeconds = (uint32_t)std::stoul(v);
            else if (k == "files_threshold") out.filesThreshold = (uint32_t)std::stoul(v);
            else if (k == "rename_threshold")out.renameThreshold = (uint32_t)std::stoul(v);
            else if (k == "note_threshold")  out.noteThreshold = (uint32_t)std::stoul(v);
            else if (k == "entropy_threshold") out.entropyThreshold = std::stod(v);
            else if (k == "terminate_on_detect") out.terminateOnDetect = (v == "1" || Lower(v) == "true" || v == "on");
            // ---- 风险分层建快照（2026-09-18 新增，快照瘦身）----
            else if (k == "risk_tiered_snapshot") out.riskTieredSnapshot = (v == "1" || Lower(v) == "true" || v == "on");
            else if (k == "burst_window_sec")     out.burstWindowSec = (uint32_t)std::stoul(v);
            else if (k == "burst_file_trigger")   out.burstFileTrigger = (uint32_t)std::stoul(v);
            else if (k == "high_value_only")      out.highValueOnly = (v == "1" || Lower(v) == "true" || v == "on");
            // ---- 密钥截获 + 落地捕获（2026-09-19 新增）----
            else if (k == "key_hunt_enabled")     out.keyHuntEnabled = (v == "1" || Lower(v) == "true" || v == "on");
            else if (k == "key_max_kb")           out.keyMaxBytes = (uint64_t)std::stoull(v) * 1024;
            else if (k == "key_min_bytes")        out.keyMinBytes = (uint64_t)std::stoull(v);
            else if (k == "key_entropy_min")      out.keyEntropyMin = std::stod(v);
            else if (k == "key_window_sec")       out.keyWindowSec = (uint32_t)std::stoul(v);
            else if (k == "key_max_kept")         out.keyMaxKept = (uint32_t)std::stoul(v);
            else if (k == "land_hunt_enabled")    out.landHuntEnabled = (v == "1" || Lower(v) == "true" || v == "on");
            else if (k == "land_max_mb")          out.landMaxBytes = (uint64_t)std::stoull(v) * 1024 * 1024;
        } catch (...) { /* 单条配置非法不影响其它 */ }
    }
    return true;
}

// ===========================================================================
//  生命周期
// ===========================================================================
static std::once_flag g_startOnce;
static std::atomic<bool> g_startedOnce{ false };

bool Start(const Config& cfg) {
    bool expected = false;
    if (!g_startedOnce.compare_exchange_strong(expected, true)) return true;   // 幂等
    g_cfg = cfg;
    CacheDirImpl();

    // 从外置配置覆盖（对齐卡巴/360 的"配置与规则可热更"做法）
    std::string cp = DefaultConfigPath();
    if (!cp.empty()) {
        Config c2 = g_cfg;
        if (LoadConfigFromFile(cp, c2)) {
            g_cfg = c2;
            LogDbg("[rollback] 已加载配置: " + cp);
        }
    }
    if (!g_cfg.enabled) { LogDbg("[rollback] 配置为禁用，不启动监控"); return true; }

    // 记录自身安装目录（用于排除自身活动）
    g_exeDirLower = Lower(DirName(GetExePath()));

    g_running.store(true);
    g_watchThread = std::thread(WatchThread);
    LogDbg("[rollback] 引擎已启动，快照缓存上限 " + std::to_string(g_cfg.maxCacheBytes / 1024 / 1024) + " MB");
    return true;
}

void Stop() {
    if (!g_running.exchange(false)) return;
    if (g_stopEvent) SetEvent(g_stopEvent);
    if (g_watchThread.joinable()) g_watchThread.join();
    std::lock_guard<std::mutex> lk(g_statsMtx);
    g_stats.watching = false;
}

bool IsRunning() { return g_running.load(); }

Stats GetStats() {
    std::lock_guard<std::mutex> lk(g_statsMtx);
    return g_stats;
}

std::string CacheDir() { return CacheDirImpl(); }

void ClearCache() {
    std::lock_guard<std::mutex> lk(g_cacheMtx);
    for (auto& kv : g_cache) {
        DeleteFileA(kv.second.snapPath.c_str());
        DeleteFileA(kv.second.metaPath.c_str());
    }
    g_cache.clear();
    g_lru.clear();
    SyncCacheStatsLocked();
    LogDbg("[rollback] 快照缓存已清空");
}

// ---------------------------------------------------------------------------
//  手工回滚入口（供扩展面板「我要回滚」/ 测试使用）
// ---------------------------------------------------------------------------
std::string ManualRollback(const std::string& reason);

// ---------------------------------------------------------------------------
//  撤销最近一次自动回滚（"反向回滚"）
//
//  把最近一次自动回滚覆盖掉的内容还原回去 —— 即让文件回到"回滚前"的版本。
//  这不是"取消回滚"，而是"反向回滚"：用户拿回自己被覆盖的那一份。
// ---------------------------------------------------------------------------
bool HasUndoableRollback() {
    std::lock_guard<std::mutex> lk(g_undoMtx);
    if (g_undoList.empty() || g_undoToken.empty()) return false;
    return (NowMs() - g_undoAtMs) <= kUndoWindowMs;
}

std::string UndoLastRollback(const std::string& token) {
    std::vector<UndoEntry> list;
    std::string trig, tok;
    uint64_t age = 0;
    {
        std::lock_guard<std::mutex> lk(g_undoMtx);
        if (g_undoList.empty() || g_undoToken.empty()) {
            return "{\"ok\":false,\"reason\":\"没有可撤销的回滚记录\"}";
        }
        uint64_t now = NowMs();
        if (now - g_undoAtMs > kUndoWindowMs) {
            ClearUndoLocked();
            return "{\"ok\":false,\"reason\":\"撤销时限已过（超过 10 分钟），为避免破坏数据已作废\"}";
        }
        if (!token.empty() && token != g_undoToken) {
            return "{\"ok\":false,\"reason\":\"撤销凭据不匹配（可能已发生新的回滚）\"}";
        }
        list = g_undoList;      // 拷贝一份，避免持锁做磁盘 IO
        trig = g_undoTrigger;
        tok  = g_undoToken;
        age  = now - g_undoAtMs;
    }

    uint64_t restored = 0, failed = 0;
    std::vector<std::string> okPaths, badPaths;
    for (const auto& u : list) {
        HANDLE hs = CreateFileA(u.undoPath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hs == INVALID_HANDLE_VALUE) {
            failed++; if (badPaths.size() < kMaxListedPaths) badPaths.push_back(u.path);
            continue;
        }
        HANDLE hd = CreateFileA(u.path.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hd == INVALID_HANDLE_VALUE) {
            CloseHandle(hs);
            failed++; if (badPaths.size() < kMaxListedPaths) badPaths.push_back(u.path);
            continue;
        }
        std::vector<char> buf(256 * 1024);
        bool okAll = true;
        for (;;) {
            DWORD rd = 0;
            if (!ReadFile(hs, buf.data(), (DWORD)buf.size(), &rd, nullptr)) { okAll = false; break; }
            if (!rd) break;
            DWORD wr = 0;
            if (!WriteFile(hd, buf.data(), rd, &wr, nullptr) || wr != rd) { okAll = false; break; }
        }
        CloseHandle(hs);
        CloseHandle(hd);
        if (okAll) { restored++; if (okPaths.size() < kMaxListedPaths) okPaths.push_back(u.path); }
        else       { failed++;   if (badPaths.size() < kMaxListedPaths) badPaths.push_back(u.path); }
    }

    LogDbg("[rollback] 撤销完成: 还原 " + std::to_string(restored) +
           "，失败 " + std::to_string(failed) + "（触发原因: " + trig + "）");

    // 撤销成功后清理记录（备份文件已用掉；失败项也一并清理，避免反复重试写坏文件）
    {
        std::lock_guard<std::mutex> lk(g_undoMtx);
        ClearUndoLocked();
    }

    std::ostringstream os;
    os << "{\"ok\":true,\"restored\":" << restored
       << ",\"failed\":" << failed
       << ",\"trigger\":" << JsonString(trig)
       << ",\"token\":" << JsonString(tok)
       << ",\"ageMs\":" << age
       << ",\"restoredPaths\":[";
    for (size_t i = 0; i < okPaths.size(); ++i) { if (i) os << ","; os << JsonString(okPaths[i]); }
    os << "],\"failedPaths\":[";
    for (size_t i = 0; i < badPaths.size(); ++i) { if (i) os << ","; os << JsonString(badPaths[i]); }
    os << "]}";
    return os.str();
}

// 对外一次性拉取统计 + 运行态的 JSON（供管道 rollbackstatus 命令）
std::string StatusJson() {
    Stats s = GetStats();
    std::string trig;
    { std::lock_guard<std::mutex> lk(g_triggerMtx); trig = g_lastTrigger; }
    std::ostringstream os;
    uint64_t now = NowMs(), cd = g_cooldownUntilMs.load();
    os << "{\"running\":" << (s.watching ? "true" : "false")
       << ",\"enabled\":" << (g_cfg.enabled ? "true" : "false")
       << ",\"cooldown\":" << ((cd > now) ? "true" : "false")
       << ",\"cooldownLeftMs\":" << ((cd > now) ? (cd - now) : 0)
       << ",\"snapshots\":" << s.snapshots
       << ",\"snapBytes\":" << s.snapBytes
       << ",\"eventsSeen\":" << s.eventsSeen
       << ",\"snapshotTaken\":" << s.snapshotTaken
       << ",\"snapshotSkipped\":" << s.snapshotSkipped
       << ",\"rollbacks\":" << s.rollbacks
       << ",\"restored\":" << s.restored
       << ",\"unrecoverable\":" << s.unrecoverable
       << ",\"detected\":" << s.detected
       << ",\"watcherErrors\":" << s.watcherErrors
       << ",\"cacheDir\":" << JsonString(CacheDirImpl())
       << ",\"maxCacheMB\":" << (g_cfg.maxCacheBytes / 1024 / 1024)
       << ",\"lastTrigger\":" << JsonString(trig);

    // ---- 密钥截获 + 落地捕获（2026-09-19 新增）----
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        size_t confirmed = 0;
        for (const auto& k : g_keys) if (k.confirmed) confirmed++;
        os << ",\"keyHunt\":" << (g_cfg.keyHuntEnabled ? "true" : "false")
           << ",\"keysCaptured\":" << s.keysCaptured
           << ",\"keysKept\":" << g_keys.size()
           << ",\"keysConfirmed\":" << confirmed
           << ",\"keyHits\":" << s.keyHits;
    }
    {
        std::lock_guard<std::mutex> lk(g_landMtx);
        os << ",\"landHunt\":" << (g_cfg.landHuntEnabled ? "true" : "false")
           << ",\"landedSuspect\":" << s.landedSuspect
           << ",\"landedPending\":" << g_landed.alerts.size();
    }

    // 撤销状态（高风险自动处置后，前端据此显示「撤销我的处理」入口）
    {
        std::lock_guard<std::mutex> lk(g_undoMtx);
        bool undoable = !g_undoList.empty() && !g_undoToken.empty() &&
                        (now - g_undoAtMs) <= kUndoWindowMs;
        uint64_t leftMs = 0;
        if (undoable) leftMs = kUndoWindowMs - (now - g_undoAtMs);
        os << ",\"undoable\":" << (undoable ? "true" : "false")
           << ",\"undoToken\":" << JsonString(undoable ? g_undoToken : std::string())
           << ",\"undoCount\":" << (undoable ? g_undoList.size() : (size_t)0)
           << ",\"undoLeftMs\":" << leftMs
           << ",\"undoTrigger\":" << JsonString(undoable ? g_undoTrigger : std::string());
    }
    os << "}";
    return os.str();
}

// 手动回滚：把所有持有快照的文件恢复到快照状态（用户主动发起的"撤销最近改动"）
//
// 同样留存撤销记录：用户手动回滚也可能点错（比如误以为某批改动是异常的），
// 留一份"回滚前内容"让他能反悔。语义与自动回滚一致。
std::string ManualRollback(const std::string& reason) {
    std::vector<std::string> keys;
    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        for (auto& kv : g_cache) keys.push_back(kv.second.path);
    }
    RollbackReport rep = RollbackVictims(keys, reason.empty() ? "用户手动回滚" : reason);
    LogDbg("[rollback] 手动回滚: 恢复 " + std::to_string(rep.restored) +
           "，不可恢复 " + std::to_string(rep.unrecover));
    return rep.ToJson();
}

// 列出当前持有快照的文件（供 UI 展示"哪些文件被保护着"）
std::string ListSnapshotsJson() {
    std::lock_guard<std::mutex> lk(g_cacheMtx);
    std::ostringstream os;
    os << "{\"count\":" << g_cache.size() << ",\"items\":[";
    size_t i = 0;
    for (auto& kv : g_cache) {
        if (i++) os << ",";
        os << "{\"path\":" << JsonString(kv.second.path)
           << ",\"size\":" << kv.second.size
           << ",\"sha\":" << JsonString(kv.second.sha) << "}";
        if (i >= 500) break;      // 上限，避免响应过大
    }
    os << "]}";
    return os.str();
}

// ===========================================================================
//  密钥截获对外接口（2026-09-19 新增）
// ===========================================================================
std::string ListCapturedKeysJson() {
    std::lock_guard<std::mutex> lk(g_keyMtx);
    std::ostringstream os;
    os << "{\"count\":" << g_keys.size() << ",\"items\":[";
    for (size_t i = 0; i < g_keys.size(); ++i) {
        const auto& k = g_keys[i];
        if (i) os << ",";
        os << "{\"index\":" << i
           << ",\"path\":" << JsonString(k.path)
           << ",\"store\":" << JsonString(k.storePath)
           << ",\"size\":" << k.size
           << ",\"sha\":" << JsonString(k.sha)
           << ",\"entropy\":" << k.entropy
           << ",\"at\":" << k.at
           << ",\"confirmed\":" << (k.confirmed ? "true" : "false") << "}";
    }
    os << "]}";
    return os.str();
}

std::string ReadCapturedKeyHex(size_t keyIndex) {
    std::string store;
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        if (keyIndex >= g_keys.size())
            return "{\"ok\":false,\"reason\":\"密钥下标超出范围\"}";
        store = g_keys[keyIndex].storePath;
    }
    // 读文件在锁外做（本项目铁律：不在持锁时做 I/O）
    HANDLE h = CreateFileA(store.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return "{\"ok\":false,\"reason\":\"密钥副本已不存在（可能已被清理）\"}";
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    // 上限保护：单次最多回传 64KB（正常密钥远小于此）
    uint64_t want = (sz.QuadPart > 0 && sz.QuadPart <= 65536) ? (uint64_t)sz.QuadPart : 65536;
    std::string data; data.resize((size_t)want);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, &data[0], (DWORD)want, &rd, nullptr);
    CloseHandle(h);
    if (!ok) return "{\"ok\":false,\"reason\":\"读取密钥副本失败\"}";
    data.resize(rd);

    static const char* hx = "0123456789abcdef";
    std::string hex; hex.reserve(data.size() * 2);
    for (unsigned char c : data) { hex += hx[c >> 4]; hex += hx[c & 0xf]; }

    std::ostringstream os;
    os << "{\"ok\":true,\"size\":" << data.size()
       << ",\"hex\":" << JsonString(hex) << "}";
    return os.str();
}

void ClearCapturedKeys() {
    std::vector<std::string> toDelete;
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        for (const auto& k : g_keys) toDelete.push_back(k.storePath);
        g_keys.clear();
    }
    for (const auto& p : toDelete) DeleteFileA(p.c_str());
    {
        std::lock_guard<std::mutex> lk(g_statsMtx);
        g_stats.keysKept = 0;
    }
    LogDbg("[rollback] 已清空密钥留存（" + std::to_string(toDelete.size()) + " 份）");
}

// ===========================================================================
//  落地捕获对外接口（2026-09-19 新增）
// ===========================================================================
std::string TakeLandedAlertsJson() {
    std::deque<LandAlert> items;
    {
        std::lock_guard<std::mutex> lk(g_landMtx);
        items.swap(g_landed.alerts);      // 取走即清空（避免反复上报刷屏）
    }
    std::ostringstream os;
    os << "{\"count\":" << items.size() << ",\"items\":[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) os << ",";
        os << "{\"path\":" << JsonString(items[i].path)
           << ",\"reason\":" << JsonString(items[i].reason)
           << ",\"at\":" << items[i].at << "}";
    }
    os << "]}";
    return os.str();
}

}  // namespace rb
}  // namespace sf
