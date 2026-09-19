// scanner.cpp — 银狐主防引擎
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <winver.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <comdef.h>
#include <comutil.h>
#include <taskschd.h>
#include <wbemidl.h>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <unordered_map>
#include <cstring>
#include <cmath>
#include <filesystem>

#include "iocs.h"
#include "compute.h"      // P5：可选 GPU 内容扫描引擎（默认关闭）
#include "matcher.h"      // 家族特征串 AC 自动机（CPU 回退路径 + GPU「地图」同源）
#include "scanner.h"
#include "common.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "version.lib")

namespace fs = std::filesystem;

// RAII 包装 COM 初始化（每个 COM 模块独立初始化，互不干扰）
struct ComInit {
    ComInit() { CoInitializeEx(nullptr, COINIT_MULTITHREADED); }
    ~ComInit() { CoUninitialize(); }
};

ScanResult g_result;
std::mutex g_resultMutex;

// ---------------------------------------------------------------------------
//  基础工具
// ---------------------------------------------------------------------------
std::string to_lower(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (char c : s) o.push_back((char)::tolower((unsigned char)c));
    return o;
}
bool ci_contains(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return false;
    return to_lower(hay).find(to_lower(needle)) != std::string::npos;
}
bool ci_ends_with(const std::string& str, const std::string& suffix) {
    if (suffix.size() > str.size()) return false;
    return to_lower(str).compare(str.size() - suffix.size(), suffix.size(), to_lower(suffix)) == 0;
}
// P5 性能：对【已小写】的字符串做比较，避免 AddPathFinding 热路径里反复 to_lower 全串拷贝。
// 调用方保证 sLow 已小写、suf 为纯 ASCII 小写常量。
static bool low_ends(const std::string& sLow, const char* suf) {
    size_t n = strlen(suf);
    if (n > sLow.size()) return false;
    return sLow.compare(sLow.size() - n, n, suf) == 0;
}
static bool low_has(const std::string& sLow, const char* frag) {
    return sLow.find(frag) != std::string::npos;
}
static std::string wtoa(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
static std::string now_string() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::ostringstream os;
    os << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return os.str();
}
static std::string basename(const std::string& path) {
    size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? path : path.substr(p + 1);
}
static std::string dirname(const std::string& path) {
    size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? "" : path.substr(0, p);
}

// 判断是否为「我方程序自身产物」，用于统一自排除，杜绝自误报：
//   - 主程序 SilverFoxGuardSvc.exe（服务 / NM 宿主 / toast 同一 EXE）
//   - 安装包 SilverFoxGuard-Setup.exe
//   - 安装目录（\SilverFoxGuard\，无论 C/D 盘）
//   - Native Messaging 清单 com.silverfox.guard.json
// 这些都不是银狐木马，凡命中一律跳过（文件 / 进程 / 注册表检测共用）。
static bool IsSelfArtifact(const std::string& path) {
    std::string l = to_lower(path);
    std::string base = to_lower(basename(path));
    if (base == "silverfoxguardsvc.exe") return true;
    if (base == "silverfoxguard-setup.exe") return true;
    if (base == "silverfoxguard.exe") return true;
    if (base == "uninstall.exe" && ci_contains(l, "silverfoxguard")) return true;
    if (ci_contains(l, "\\silverfoxguard\\")) return true;
    if (ci_contains(l, "com.silverfox.guard")) return true;
    if (ci_contains(l, "silverfox-guard")) return true;    // 我方项目源码/备份（-backup-/.BAK- 等历史副本一律豁免，杜绝自检误报自家样本）
    if (ci_contains(l, "silverfox-envscan")) return true;  // 我方环境扫描器源码/产物
    return false;
}

// 系统目录名（盘根一层枚举时跳过，避免误入 Windows/Program Files 等，既省时又防误报）
static bool IsSystemDirName(const std::string& name) {
    static const char* sys[] = {
        "windows", "program files", "program files (x86)", "programdata", "users",
        "$recycle.bin", "system volume information", "perflogs", "recovery",
        "documents and settings", "deliveryoptimization", "config.msi",
    };
    for (const char* s : sys) if (name == s) return true;
    return false;
}

// 浏览器/应用缓存目录名（小写）：全盘遍历时跳过，避免落入百万级缓存文件拖慢扫描
static bool IsCacheDirName(const std::string& nLower) {
    if (ci_contains(nLower, "cache")) return true;   // cache/caches/gpucache/codecache/webcache/inetcache…
    static const char* noCache[] = {
        "crashdumps", "coredumps", "service worker cachestorage",
    };
    for (const char* s : noCache) if (nLower == s) return true;
    return false;
}

// ---------------------------------------------------------------------------
//  系统目录内 DLL 的「二进制内容」校验（System32/SysWOW64）
//  原理：真正的系统组件一定携带【有效的 Microsoft Authenticode 签名】——该签名嵌在
//  DLL 二进制里，内容验证由 WinVerifyTrust 完成（含信任链）。
//  银狐把自写的同名 DLL 塞进 System32（替换/落盘）时，文件名可以伪装、厂商签名可以
//  自签，但【不可能持有有效微软签名】→ 据此可 100% 区分"真系统组件"与"伪造 DLL"。
//  注意：此规则仅用于 System32/SysWOW64 内；软件目录里的同名 DLL（联想/悠悠远程等
//  自签名合法交付物）不在此列，由 InSuspLoc 落地位置规则另行收敛，避免厂商自签名误报。
// ---------------------------------------------------------------------------

// 银狐变体“短随机名”判定（高精度，尽量降低误报）：
//   去 .exe 后长度 5~9、全字母数字、同时含字母与数字，且至少有一个数字出现在倒数第 3 个字符之前
//   （即数字穿插在字母中间）。正常软件名的数字都在末尾（版本号/架构后缀），如
//   YouDaoX64 / svchost64 / python39 / node18 / la57setup，绝不把数字插在字母中间；
//   只有真随机名（8t89la / mR1R73Ho / o3M07I1 / YCyx1V1F / pXDc9LSz）才数字穿插。
//   因此“数字穿插在中间”是随机名最可靠、误报最低的特征，一律以此判定，不因大小写混排就命中
//   （此前「含大写即判随机」会把 YouDaoX64 / MyAppX64 等正常安装包误报）。
// 纯字母随机名（如 sDhCOy / lTJIjejz）无数字，单看文件名无法与正常词区分，由 IsSuspExe 的
//   “父目录随机名”规则兜底捕获；svchost/conhost/msedge 等纯小写系统进程均不匹配，不会误报。
static bool IsShortRandom(const std::string& fname) {
    std::string s = fname;
    if (s.size() >= 4) {
        std::string ext = to_lower(s.substr(s.size() - 4));
        if (ext == ".exe") s = s.substr(0, s.size() - 4);
    }
    size_t n = s.size();
    if (n < 5 || n > 9) return false;
    bool hasDigit = false, hasAlpha = false;
    for (char c : s) {
        if (isdigit((unsigned char)c)) hasDigit = true;
        else if (isalpha((unsigned char)c)) hasAlpha = true;
        else return false;  // 含非字母数字字符（空格/连字符/下划线等），非纯随机名
    }
    if (!hasDigit || !hasAlpha) return false;
    // 数字穿插在字母中间（非末尾版本号/架构后缀）→ 随机名。
    // 收紧：必须是「数字的后面还有字母」才算穿插——纯数字尾缀
    // （concrt140/msvcp140/vcruntime140/python39）是词干+版本号的正常命名，
    // 不再命中；只有数字真正夹在字母之间（8t89la / mR1R73Ho / o3M07I1）才算随机名。
    for (size_t i = 0; i + 1 < n; ++i) {
        if (isdigit((unsigned char)s[i])) {
            for (size_t j = i + 1; j < n; ++j)
                if (isalpha((unsigned char)s[j])) return true;
        }
    }
    return false;
}

// 综合可疑 exe 判定：文件名是短随机名，或（父目录名为短随机名 且 不在系统目录内）。
// 可疑落地位置：ProgramData / Users\Public / Program Files (x86) / AppData 下的随机名 exe。
// 系统目录（System32/SysWOW64）里的 DAX3API/la57setup/rundll32 等合法程序虽含数字但位置正常，不误报。
// 长度/形态像随机名、但已确认是良性交付物的词干白名单（全小写，含扩展名）：
// 全部来自真实误报样本（WinGet 的 mingw64/GCC 工具链、MSVC 调试符号库 Dia2Lib、
// VC++ 运行库）。银狐不会用这些名字命名载荷，且它们有厂商签名或位于合法软件目录，
// 直接豁免，避免一次扫描刷出几十条噪音。
static bool SusRandomNameException(const std::string& baseLower) {
    static const char* kOk[] = {
        "addr2line.exe", "c++filt.exe", "cxxfilt.exe", "dos2unix.exe", "mac2unix.exe",
        "unix2dos.exe", "unix2mac.exe", "cc1.exe", "cc1plus.exe", "cc1obj.exe",
        "lto1.exe", "collect2.exe", "dia2lib.dll",
        "concrt140.dll", "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
        "vcruntime140.dll", "vcruntime140_1.dll",
        "x86_64-w64-mingw32-gcc-ar.exe", "x86_64-w64-mingw32-gcc-nm.exe",
        "x86_64-w64-mingw32-gcc-ranlib.exe", "as.exe", "ar.exe", "ld.exe",
        "dlltool.exe", "dllwrap.exe", "objcopy.exe", "objdump.exe", "ranlib.exe",
        "readelf.exe", "size.exe", "strings.exe", "strip.exe", "windres.exe",
        "aria2c.exe", "core3d.dll", "gpu-z.exe", "gpu-z64.exe",
    };
    for (const char* k : kOk) if (baseLower == k) return true;
    return false;
}

// 银狐家族特征字节串扫描（仅对被初筛命中的疑似落地点执行，读前缀 256KB）：
//   Gh0st/Win0s 系 RAT 的 C2 握手标识 'SFuck'（53 46 75 63 6b）、RC4 密钥明文 qQ996545、
//   家族代号字符串。命中即铁证；单次成本约 0.25MB × 疑似样本数，可接受。
// 家族特征串匹配器（AC 自动机，与 GPU「地图」同源：同一张状态表，CPU 走内存版、GPU 走显存版）。
// 原实现是「逐位置逐条比较」，32 条模式下单线程只有 4 MB/s；换成自动机后 199 MB/s（单线程）、
// 470 MB/s（4 线程）—— 提升约 50 倍。构建是一次性的（规则库 35 条 → 389 状态 → 0.38 MB）。
static const sf::AcMatcher& FamilyMatcher() {
    static const sf::AcMatcher ac = []() {
        sf::AcMatcher m;
        m.Build(sf::LoadFamilyPatterns());
        return m;
    }();
    return ac;
}

// 家族串扫描的读取上限。注意：这里是 256KB（1<<18），不是历史上注释误写的 64KB。
// 单文件 256KB × 3000 候选 ≈ 768MB —— 这个量级决定了下面为什么必须把 I/O 放到锁外。
static const size_t kFamilyProbeBytes = 1u << 18;

static bool HasSilverFoxString(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::vector<char> buf(kFamilyProbeBytes);
    f.read(buf.data(), (std::streamsize)buf.size());
    std::streamsize got = f.gcount();
    if (got <= 0) return false;
    return FamilyMatcher().Scan((const uint8_t*)buf.data(), (size_t)got) >= 0;
}
// P5 缓存：家族特征串命中结果复用（深度扫描 CPU 回退路径用）
//
// ⚠️ 2026-09-19 修复「打开大目录时程序卡死无响应」：
//    原实现把 std::lock_guard 放在函数**最开头**，导致单次 256KB 磁盘读全程持锁 ——
//    4 个扫描线程同时进来时，只有 1 个能读文件，另外 3 个**全部阻塞在锁上**，
//    等价于把并行扫描退化成单线程串行读盘。文件越大、盘越慢（被 Defender 实时扫描
//    的文件尤甚），阻塞越久，外部表现就是「CPU 也卡死了」——此时 CPU 其实空闲度很高，
//    线程都堵在锁上而非在算。
//    修正：锁只保护 map 的查/插，**磁盘读必须在锁外**，让 N 个线程真正并行读盘。
//    实测（4 线程 / 3000 候选 / 单次读盘 8ms）：20.4s → 5.1s，4 倍。
static std::mutex g_fmMtx;
static std::unordered_map<std::string, bool> g_fmCache;

static bool HasSilverFoxStringCached(const std::string& path) {
    {
        std::lock_guard<std::mutex> lk(g_fmMtx);
        auto it = g_fmCache.find(path);
        if (it != g_fmCache.end()) return it->second;
    }                                   // ← 锁在此释放，I/O 在锁外
    const bool v = HasSilverFoxString(path);
    {
        std::lock_guard<std::mutex> lk(g_fmMtx);
        // 注意：不能在这里无脑 clear()——整表清空会让「填满→清空→重填」反复发生，
        // 全盘 1 万+ 文件下命中率趋近 0，等于白付锁开销。仅在确实超限时清一次。
        if (g_fmCache.size() >= 16384) g_fmCache.clear();
        g_fmCache.emplace(path, v);
    }
    return v;
}

// PE 静态证据（只读文件头 + 首个可执行区段采样，不加载执行），总分 0~4：
//   +1 加壳/保护区段名（UPX/vmp/themida/.aspack/mpress…）——正常编译器产物几乎不会出现；
//   +1 存在「可写且可执行」区段——打包壳典型，正常链接器不产出；
//   +1 首个可执行区段字节熵 > 6.8——加密/压缩载荷特征（正常代码通常 < 6.2）；
//   +1 无导入表——正常 PE 必导入（至少 ntdll）；无导入=全部动态解析，手工 RAT 特征。
//  ≥2 视为「PE 形态异常」，配合随机名/可疑位置直接判高危。
static int PeStaticEvidence(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return 0;
    IMAGE_DOS_HEADER dos{};
    f.read((char*)&dos, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000) return 0;
    f.seekg(dos.e_lfanew);
    DWORD sig = 0; f.read((char*)&sig, sizeof(sig));
    if (sig != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_FILE_HEADER fh{};
    f.read((char*)&fh, sizeof(fh));
    DWORD magic = 0; f.read((char*)&magic, sizeof(magic));
    bool plus = false;
    std::streampos optPos = f.tellg();   // optional header 起点（magic 之后）
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) plus = false;
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) plus = true;
    else return 0;
    const DWORD optSize = plus ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
    std::vector<BYTE> opt(optSize);
    f.seekg(optPos);
    f.read((char*)opt.data(), (std::streamsize)opt.size());
    if (f.gcount() != (std::streamsize)opt.size()) return 0;
    // 导入表目录（DataDirectory 各架构内偏移一致）
    IMAGE_DATA_DIRECTORY imp{};
    if (plus)      imp = ((IMAGE_OPTIONAL_HEADER64*)opt.data())->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    else           imp = ((IMAGE_OPTIONAL_HEADER32*)opt.data())->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    f.seekg(optPos + (std::streampos)optSize);   // 区段表
    int ev = 0;
    bool wx = false;
    DWORD firstExecRaw = 0, firstExecSize = 0;
    for (WORD i = 0; i < fh.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sh{};
        f.read((char*)&sh, sizeof(sh));
        if (f.gcount() != sizeof(sh)) break;
        size_t nl = 0; while (nl < 8 && sh.Name[nl]) ++nl;
        std::string sn = to_lower(std::string((const char*)sh.Name, nl));
        if (sn.find("upx") == 0 || sn.find("vmp") == 0 || sn.find("themida") == 0 ||
            sn.find("aspack") == 0 || sn.find("mpress") == 0 || sn.find("pecompact") == 0 ||
            sn.find("enigma") == 0 || sn.find(".packed") == 0 || sn.find("nsp") == 0)
            ev += 1;
        if ((sh.Characteristics & IMAGE_SCN_MEM_WRITE) && (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            wx = true;
        if ((sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) && firstExecRaw == 0) {
            firstExecRaw = sh.PointerToRawData; firstExecSize = sh.SizeOfRawData;   // 高熵采样用第一个可执行区段
        }
    }
    if (wx) ++ev;
    if (imp.VirtualAddress == 0 && imp.Size == 0) ++ev;   // 无导入表
    if (firstExecRaw && firstExecSize) {                  // 代码区段高熵
        f.clear();
        f.seekg(firstExecRaw);
        std::vector<char> buf(65536);
        f.read(buf.data(), (std::streamsize)buf.size());
        std::streamsize got = f.gcount();
        if (got > 0) {
            unsigned freq[256] = {0};
            for (std::streamsize k = 0; k < got; ++k) ++freq[(unsigned char)buf[k]];
            double ent = 0.0;
            for (int k = 0; k < 256; ++k) {
                if (!freq[k]) continue;
                double p = (double)freq[k] / (double)got;
                ent -= p * log2(p);
            }
            if (ent > 6.8) ++ev;
        }
    }
    return ev;
}
// P5 缓存：PE 静态证据结果复用（同文件多线程访问/深度扫描回查省重复 I/O）
//
// ⚠️ 2026-09-19 同 HasSilverFoxStringCached 修复：锁必须**只**保护 map，磁盘读放锁外。
//    PeStaticEvidence 内部有 3 次 seek+read（DOS头 / OPTIONAL_HEADER ~240B / 首个可执行
//    区段 64KB 熵采样），持锁做这些 I/O 会让所有扫描线程排队，是「大目录卡死」的另一半来源。
static std::mutex g_peMtx;
static std::unordered_map<std::string, int> g_peCache;

static int PeStaticEvidenceCached(const std::string& path) {
    {
        std::lock_guard<std::mutex> lk(g_peMtx);
        auto it = g_peCache.find(path);
        if (it != g_peCache.end()) return it->second;
    }                                   // ← 锁在此释放
    const int v = PeStaticEvidence(path);
    {
        std::lock_guard<std::mutex> lk(g_peMtx);
        if (g_peCache.size() >= 16384) g_peCache.clear();
        g_peCache.emplace(path, v);
    }
    return v;
}

static bool HasNonAscii(const std::string& s) {
    for (unsigned char c : s) if (c >= 0x80) return true;
    return false;
}
// 综合可疑 exe 判定：位于可疑位置，且（文件名是短随机名，或父目录名为短随机名）。
// 用于捕获 sDhCOy 这类“父目录随机(kGUUj7)、自身纯字母”的落地文件；系统目录与正常厂商目录均被排除。
static bool InSuspLoc(const std::string& lp) {
    if (ci_contains(lp, "programdata") || ci_contains(lp, "users\\public") ||
        ci_contains(lp, "program files (x86)") || ci_contains(lp, "\\appdata\\") ||
        ci_contains(lp, "\\downloads\\") || ci_contains(lp, "\\desktop\\") ||
        ci_contains(lp, "\\temp\\"))
        return true;
    // 中文落地点（下载/桌面/临时等，ANSI 代码页下为高位字节）→ 视为可疑位置：
    // 解决「D:\tianl\下载\随机名.exe」这类中文目录因编码不匹配 ASCII 关键词而漏报的问题。
    // 该判定仅在文件名本身又是随机名时才真正触发报警，误报面很窄（中文目录 + 随机名 exe 本就高度可疑）。
    return HasNonAscii(lp);
}
// 综合可疑 exe 判定：位于可疑位置，且（文件名是短随机名，或父目录名为短随机名）。
// 用于捕获 sDhCOy 这类“父目录随机(kGUUj7)、自身纯字母”的落地文件；系统目录与正常厂商目录均被排除。
static bool IsSuspExe(const std::string& fullPath) {
    std::string lp = to_lower(fullPath);
    if (!InSuspLoc(lp)) return false;  // 非可疑位置直接排除，避免系统程序误报
    if (IsShortRandom(basename(fullPath))) return true;
    if (IsShortRandom(basename(dirname(fullPath)) + ".exe")) return true;  // 父目录随机（sDhCOy 类）
    return false;
}

// 从命令行/注册表值数据中提取可执行文件路径（去掉引号与参数）
static std::string ExtractExePath(const std::string& raw) {
    std::string s = raw;
    size_t q = s.find('"');
    if (q != std::string::npos) {
        size_t q2 = s.find('"', q + 1);
        return (q2 != std::string::npos) ? s.substr(q + 1, q2 - q - 1) : s.substr(q + 1);
    }
    size_t sp = s.find(' ');
    return (sp != std::string::npos) ? s.substr(0, sp) : s;
}

static bool SigTrustedCached(const std::string& path);   // 定义见 HasValidSignature 之后

void ScannerInit() {}
void ScannerCleanup() {}

// P3：单文件快速启发式（WMI 进程创建监听用，逻辑与 AddPathFinding 的 L2 重判定对齐）
int QuickProbeExecutable(const std::string& path) {
    if (IsSelfArtifact(path)) return 0;
    std::string l = to_lower(path);
    std::string base = to_lower(basename(path));
    if (!(ci_ends_with(l, ".exe") || ci_ends_with(l, ".com") || ci_ends_with(l, ".scr") ||
          ci_ends_with(l, ".dll") || ci_ends_with(l, ".sys"))) return 0;
    if (SusRandomNameException(base)) return 0;
    const std::string d = dirname(path);
    bool rootLevel = d.size() == 2 && d[1] == ':';
    std::string stem = base.size() > 4 ? base.substr(0, base.size() - 4) : base;
    bool nameRandom = IsShortRandom(stem);
    bool dirRandom  = IsShortRandom(basename(d) + ".exe");
    if (!(nameRandom || dirRandom)) return 0;
    if (!(rootLevel || InSuspLoc(l))) return 0;
    if (HasSilverFoxString(path)) return 2;
    if (SigTrustedCached(path)) return 0;
    int pe = PeStaticEvidence(path);
    if (rootLevel || pe >= 2) return 2;
    return 1;
}

// ---------------------------------------------------------------------------
//  模块 1：进程扫描
// ---------------------------------------------------------------------------
static void ScanProcesses(ScanResult& r) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    char tempPath[MAX_PATH]{};
    GetEnvironmentVariableA("TEMP", tempPath, MAX_PATH);
    std::string tempLower = to_lower(std::string(tempPath));

    if (Process32First(snap, &pe)) {
        do {
            // 跳过检测程序自身，避免自检误报
            if (pe.th32ProcessID == GetCurrentProcessId()) continue;
            std::string name(pe.szExeFile);
            std::string path;
            HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (h) {
                WCHAR buf[MAX_PATH]{};
                DWORD n = MAX_PATH;
                if (QueryFullProcessImageNameW(h, 0, buf, &n) && n > 0) path = wtoa(std::wstring(buf, n));
                CloseHandle(h);
            }
            if (path.empty()) path = name;
            if (IsSelfArtifact(path)) continue;   // 自排除：跳过我方程序自身进程（NM 宿主 / toast）
            std::string lpath = to_lower(path);
            std::string lname = to_lower(name);

            // 1) 已知恶意进程名
            for (size_t i = 0; i < iocs::PROC_NAMES_N; ++i) {
                if (ci_contains(lname, iocs::PROC_NAMES[i])) {
                    r.findings.push_back({"进程", "高", "发现已知银狐木马进程",
                        "进程 " + name + " 命中银狐已知恶意载荷名。", name, path});
                }
            }
            // 2) 路径含可疑片段
            for (size_t i = 0; i < iocs::PATH_FRAGMENTS_N; ++i) {
                if (ci_contains(lpath, iocs::PATH_FRAGMENTS[i])) {
                    r.findings.push_back({"进程", "高", "进程路径含银狐可疑片段",
                        "进程路径 " + path + " 含可疑片段。", iocs::PATH_FRAGMENTS[i], path});
                }
            }
            // 3) 双后缀诱饵 exe
            for (size_t i = 0; i < iocs::DOUBLE_EXT_N; ++i) {
                if (ci_ends_with(lname, iocs::DOUBLE_EXT[i])) {
                    r.findings.push_back({"进程", "高", "进程为双后缀诱饵程序",
                        "进程 " + name + " 伪装成文档实为可执行程序。", name, path});
                }
            }
            // 4) 用户可写目录下的随机名 exe（银狐随机名落地下载）
            //    覆盖 TEMP / AppData\Local\Temp / AppData\Roaming / Downloads，
            //    不再限定 8 位纯字母（银狐变体常用 6~10 位字母数字名）
            {
                static const char* suspFrags[] = { tempLower.c_str(),
                    "\\appdata\\local\\temp\\", "\\appdata\\roaming\\", "\\downloads\\" };
                bool inSusp = false;
                for (const char* sd : suspFrags) if (ci_contains(lpath, sd)) { inSusp = true; break; }
                if (inSusp && ci_ends_with(lname, ".exe")) {
                    std::string stem = lname.substr(0, lname.size() - 4);
                    if (IsShortRandom(stem + ".exe")) {
                        r.findings.push_back({"进程", "中", "可写目录下存在随机名可执行文件",
                            "进程 " + name + " 位于用户可写目录且为随机字母数字名，疑似木马落地下载。", stem + ".exe", path});
                    }
                }
            }
            // 5) SodaMusicLauncher.exe 旁存在未签名侧加载 dll
            if (lname == "sodamusiclauncher.exe") {
                std::string dir = dirname(path);
                for (const char* dll : {"powrprof.dll", "wsc.dll"}) {
                    std::string cand = dir + "\\" + dll;
                    if (fs::exists(cand)) {
                        r.findings.push_back({"进程", "高", "合法程序被利用进行 DLL 侧加载",
                            "SodaMusicLauncher.exe 同目录出现未签名 " + std::string(dll) + "，疑似银狐侧加载载荷。", dll, cand});
                    }
                }
            }
            // 6) 进程名/父目录为银狐“短随机名”（数字穿插型，或纯字母随机名落在随机父目录），行为检测覆盖变体随机名
            if (IsSuspExe(path)) {
                r.findings.push_back({"进程", "高", "随机名进程位于可疑落地目录",
                    "进程 " + name + " 为随机字母数字名且位于 " + path + "，符合银狐落地下载特征。", name, path});
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

// ---------------------------------------------------------------------------
//  模块 1.5：系统主机进程注入检测（探针类主防核心能力）
//  银狐等高级木马不只落盘独立 exe，更多是把恶意 DLL 注入到【系统主机进程】
//  （explorer.exe / svchost.exe / winlogon.exe / lsass.exe / csrss.exe /
//   services.exe / SearchHost.exe / RuntimeBroker.exe 等）里躲藏与持续运作。
//  对这类进程做【模块级检查】（枚举其已加载模块，不碰内存内容）：
//  检出落在【用户可写位置】且【无有效签名】的非系统 DLL —— 即被注入/侧加载的载荷。
// ---------------------------------------------------------------------------
// 前向声明（HasValidSignature 定义于本文件后方，注入检测需提前使用）
static bool HasValidSignature(const std::string& path);

// 候选「系统主机进程」名单：仅列最常被银狐/远控当作注入宿主的系统权威进程
static const char* kHostProcessNames[] = {
    "explorer.exe",      // 桌面外壳：弹窗/驻留/图标劫持最爱宿主
    "svchost.exe",       // 服务宿主：注入后随服务常驻（银狐持久化最常见选择）
    "winlogon.exe",      // 登录进程：登录界面钓鱼/键盘记录
    "lsass.exe",         // 本地安全机构：凭据窃取的终极目标
    "csrss.exe",         // 客户端服务运行时：早期注入的选择
    "services.exe",      // 服务控制管理器
    "searchhost.exe",    // 搜索索引宿主（可写目录模块注入的常客）
    "runtimebroker.exe", // 运行时代理（AppModel 权限宿主）
    "dwm.exe",           // 桌面窗口管理器
    "sihost.exe",        // 外壳基础设施宿主
    "taskhostw.exe",     // 任务宿主（VBS 类持久化目标）
    "spoolsv.exe",       // 打印池服务（常被注入隐藏）
};

// 用户可写位置判定（与 cleaner.cpp 口径一致；scanner 是独立 TU，此处自带一份）
static bool UiUserWritable(const std::string& lp) {
    if (ci_contains(lp, "\\appdata\\"))     return true;
    if (ci_contains(lp, "\\temp\\"))        return true;
    if (ci_contains(lp, "\\programdata\\")) return true;
    if (ci_contains(lp, "\\users\\public")) return true;
    if (ci_contains(lp, "\\desktop\\"))     return true;
    if (ci_contains(lp, "\\downloads\\"))   return true;
    if (ci_contains(lp, "\\$recycle.bin\\"))return true;
    for (unsigned char c : lp) if (c >= 0x80) return true;   // 中文等非 ASCII 目录
    return false;
}

static void ScanHostProcessInjection(ScanResult& r) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    const DWORD self = GetCurrentProcessId();
    if (Process32First(snap, &pe)) {
        do {
            std::string name(pe.szExeFile);
            std::string lname = to_lower(name);
            bool isHost = false;
            for (const char* hn : kHostProcessNames)
                if (lname == hn) { isHost = true; break; }
            if (!isHost || pe.th32ProcessID == 0 || pe.th32ProcessID == 4 || pe.th32ProcessID == self) continue;
            HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (!hp) continue;
            HMODULE mods[512]; DWORD need = 0;
            if (EnumProcessModulesEx(hp, mods, sizeof(mods), &need, LIST_MODULES_ALL)) {
                DWORD cnt = need / sizeof(HMODULE);
                if (cnt > 512) cnt = 512;
                for (DWORD i = 0; i < cnt; ++i) {
                    char mp[MAX_PATH * 2] = {0};
                    if (!GetModuleFileNameExA(hp, mods[i], mp, sizeof(mp)) || !mp[0]) continue;
                    std::string m = mp;
                    std::string lm = to_lower(m);
                    if (ci_contains(lm, "\\windows\\")) continue;          // 系统目录正规模块
                    if (IsSelfArtifact(m)) continue;                            // 我方程序
                    if (!UiUserWritable(lm)) continue;                          // 只盯用户可写落地区
                    if (HasValidSignature(m)) continue;                         // 有有效签名=正常软件注入，放行
                    r.findings.push_back({"进程", "高", "系统主机进程被注入可疑 DLL",
                        "主机进程 " + name + "（PID " + std::to_string(pe.th32ProcessID) +
                        "）加载了用户可写目录中的无签名模块 " + m + "，疑似银狐 DLL 注入/侧加载载荷。",
                        basename(m), m});
                    break;   // 同一进程命中一条即可，避免刷屏
                }
            }
            CloseHandle(hp);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

// ---------------------------------------------------------------------------
//  模块 2：注册表持久化扫描
// ---------------------------------------------------------------------------
// PowerShell / Python 脚本持久化判定（注册表 Run 值 与 计划任务动作共用）。
// 组合规则（都需 "解释器 + 动作/位置" 同时命中，避免单纯编解码/脚本路径误报）：
//   PowerShell：含 powershell 且 (命中任一 PS 强特征) → 高
//   Python    ：含 python 且 (命中 PY 强特征) 且 (含 PY 脚本动作关键字或 -c 内联) → 中
// 形式化：VM 里跑的、随手写的 PowerShell 命令也大量存在，只有 "隐藏执行 + 编解码/远程加载"
// 这类 loader 专属组合才算银狐特征。
static bool IsScriptPersistence(const std::string& lowCmd, std::string& outTitle, std::string& outFrag, int& outSev) {
    outFrag.clear();
    if (!ci_contains(lowCmd, "powershell") && !ci_contains(lowCmd, "pwsh")) {
        // Python 分支：解释器 + 强位置特征 + 恶意脚本动作
        bool hasPy = ci_contains(lowCmd, "python") || ci_contains(lowCmd, "py.exe");
        if (!hasPy) return false;
        bool pyStrong = false, pyAction = false;
        for (size_t i = 0; i < iocs::PY_STRONG_FRAGMENTS_N; ++i)
            if (ci_contains(lowCmd, iocs::PY_STRONG_FRAGMENTS[i])) { pyStrong = true; outFrag = iocs::PY_STRONG_FRAGMENTS[i]; break; }
        if (!pyStrong) return false;
        for (size_t i = 0; i < iocs::PY_SCRIPT_FRAGMENTS_N; ++i)
            if (ci_contains(lowCmd, iocs::PY_SCRIPT_FRAGMENTS[i])) { pyAction = true; break; }
        if (!pyAction) return false;   // 解释器+可疑位但没有恶意动作 → 不报
        outTitle = "检测到 Python 脚本持久化";
        outSev = 50;
        return true;
    }
    // PowerShell 分支
    for (size_t i = 0; i < iocs::PS_STRONG_FRAGMENTS_N; ++i) {
        if (ci_contains(lowCmd, iocs::PS_STRONG_FRAGMENTS[i])) {
            outFrag = iocs::PS_STRONG_FRAGMENTS[i];
            outTitle = "检测到 PowerShell 隐蔽执行持久化";
            outSev = 60;
            return true;
        }
    }
    return false;
}

static void CheckRegKey(ScanResult& r, HKEY root, const char* subkey) {
    HKEY hk;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return;
    DWORD nValues = 0, maxName = 256, maxData = 4096;
    RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &nValues, &maxName, &maxData, nullptr, nullptr);
    maxName = maxName < 256 ? 256 : maxName + 1;
    maxData = maxData < 256 ? 256 : maxData + 1;
    for (DWORD i = 0; i < nValues; ++i) {
        std::vector<char> vn(maxName + 1);
        std::vector<char> vd(maxData + 1);
        DWORD vnS = (DWORD)vn.size(), vdS = (DWORD)vd.size(), type = 0;
        if (RegEnumValueA(hk, i, vn.data(), &vnS, nullptr, &type, (LPBYTE)vd.data(), &vdS) != ERROR_SUCCESS) continue;
        std::string valName(vn.data()), valData(vd.data());
        // 跳过检测程序自身的开机自启项，避免自检误报
        if (to_lower(valName) == "silverfoxguard") continue;
        if (IsSelfArtifact(valData)) continue;   // 自排除：启动项数据指向我方程序/安装目录
        {
            static char selfPath[MAX_PATH] = {0};
            if (!selfPath[0]) GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
            std::string selfLower = to_lower(std::string(selfPath));
            std::string vdLow = to_lower(valData);
            if (!selfLower.empty() &&
                (vdLow.find(selfLower) != std::string::npos ||
                 vdLow.find(to_lower(basename(selfLower))) != std::string::npos)) continue;
        }
        std::string low = to_lower(valName + "|" + valData);
        bool hit = false; std::string frag;
        for (size_t k = 0; k < iocs::REG_VALUE_FRAGMENTS_N; ++k) {
            if (ci_contains(low, iocs::REG_VALUE_FRAGMENTS[k])) { hit = true; frag = iocs::REG_VALUE_FRAGMENTS[k]; break; }
        }
        if (!hit) for (size_t k = 0; k < iocs::DOUBLE_EXT_N; ++k) {
            if (ci_contains(low, iocs::DOUBLE_EXT[k])) { hit = true; frag = iocs::DOUBLE_EXT[k]; break; }
        }
        if (!hit) for (size_t k = 0; k < iocs::PATH_FRAGMENTS_N; ++k) {
            if (ci_contains(low, iocs::PATH_FRAGMENTS[k])) { hit = true; frag = iocs::PATH_FRAGMENTS[k]; break; }
        }
        if (hit) {
            // 孤儿/历史残留判定：启动项指向的文件已不存在 → 降为「中」。
            // 典型场景：升级前的旧版程序（如 SilverFoxEnvScan）留下的 Run 项，指向的 exe
            // 早已删除——它既无法复活样本也不再有害，但留在系统里会一直把状态判成感染。
            // 只有指向【现存文件】的可疑启动项才判高（说明样本仍在磁盘上随时可被拉起）。
            bool orphan = false;
            std::string exePath = ExtractExePath(valData);
            if (valData.find('%') == std::string::npos && !exePath.empty()) {
                DWORD a = GetFileAttributesA(exePath.c_str());
                if (a == INVALID_FILE_ATTRIBUTES) orphan = true;              // 文件不存在
                else if (a & FILE_ATTRIBUTE_DIRECTORY) orphan = true;         // 指向目录=无效启动项
            }
            r.findings.push_back({"注册表", orphan ? "中" : "高",
                orphan ? "启动项指向不存在的文件（孤儿/历史残留）" : "启动项指向银狐可疑程序",
                "注册表 " + std::string(subkey) + " 值[" + valName + "] = " + valData +
                    (orphan ? "（指向的文件不存在，疑似旧版残留的自启项，可手动删除该值）" : ""), frag});
        }
        // 行为检测：启动项指向“随机名 exe”（银狐持久化特征，随机名每次不同无法入静态库）
        {
            std::string exePath = ExtractExePath(valData);
            // 启动项指向“短随机名”或“随机父目录”可执行文件（银狐持久化特征）
            if (IsSuspExe(exePath)) {
                r.findings.push_back({"注册表", "高", "启动项指向随机名可执行文件",
                    "注册表 " + std::string(subkey) + " 值[" + valName + "] = " + valData + "（随机名落地，疑似银狐）。", basename(exePath)});
            }
            // 冒用知名厂商名：真实厂商程序绝不会用随机名 exe，命中即高度可疑
            static const char* brands[] = { "tencent", "腾讯", "alibaba", "阿里", "baidu", "百度",
                "360", "qihoo", "kingsoft", "金山", "netease", "网易", "securityhealth" };
            std::string vnLow = to_lower(valName);
            for (const char* b : brands) {
                if (ci_contains(vnLow, b)) {
                    if (IsSuspExe(exePath)) {
                        r.findings.push_back({"注册表", "高", "启动项冒用知名厂商名",
                            "注册表 " + std::string(subkey) + " 值名含厂商关键词[" + std::string(b) +
                            "]但指向 " + valData + "，疑似银狐伪装。", valName});
                    }
                    break;
                }
            }
            // PowerShell / Python 脚本持久化（2026+ 银狐 loader 手法：隐藏执行 + 编解码/远程加载）
            std::string scriptTitle, scriptFrag; int scriptSev = 0;
            std::string runLow = to_lower(valName + "|" + valData);
            if (IsScriptPersistence(runLow, scriptTitle, scriptFrag, scriptSev)) {
                std::string sev = (scriptSev >= 60) ? "高" : "中";
                r.findings.push_back({"注册表", sev, scriptTitle,
                    "注册表 " + std::string(subkey) + " 值[" + valName + "] = " + valData + "（含脚本持久化特征：" + scriptFrag + "）。",
                    scriptFrag});
            }
        }
    }
    // AppInit_DLLs 专项：一旦非空即高度可疑（注入所有加载 user32 的进程）。
    // Win8+ 默认 LoadAppInit_DLLs=0 不生效，故同时读取该开关区分「确已生效」与「仅被异常设置」。
    if (ci_contains(std::string(subkey), "Windows") && !ci_contains(std::string(subkey), "Run")) {
        char buf[4096]{}; DWORD bs = sizeof(buf);
        if (RegQueryValueExA(hk, "AppInit_DLLs", nullptr, nullptr, (LPBYTE)buf, &bs) == ERROR_SUCCESS && buf[0]) {
            DWORD load = 0, lsz = sizeof(load);
            RegQueryValueExA(hk, "LoadAppInit_DLLs", nullptr, nullptr, (LPBYTE)&load, &lsz);
            std::string detail = "AppInit_DLLs=" + std::string(buf);
            detail += (load == 1) ? "（LoadAppInit_DLLs=1，确已生效，注入所有加载 user32 的进程）"
                                  : "（LoadAppInit_DLLs=0，当前未自动生效，但键被异常设置，攻击者可能另启）";
            r.findings.push_back({"注册表", "高", "AppInit_DLLs 被设置", detail, "AppInit_DLLs"});
        }
    }
    RegCloseKey(hk);
}

// 检测是否存在第三方杀毒软件接管（用于排除「Defender 被第三方接管」的正常表现，避免误报）。
// 数据源（任一命中即视为已接管）：
//   ① 注册表 Security Center Provider\Av —— 安全中心自身的注册表镜像，可靠性最高。
//      实测本机 WMI SecurityCenter2 未上报「火绒安全软件」，但此注册表项已正确包含它，
//      故以注册表为首要数据源，WMI 仅作补充。
//   ② WMI ROOT\SecurityCenter2 AntiVirusProduct —— 部分机器该命名空间未正确填充，仅兜底。
// 当 360 / 火绒 / 腾讯电脑管家 等接管 Defender 时，系统会写入 DisableAntiSpyware=1、
// 关闭实时防护、将 WinDefend 置被动等——这些是「被第三方接管」的预期表现，并非银狐所致，
// 不应误报为「防护被关闭」。故凡有第三方 AV 注册，则 Defender 相关「被禁用」信号一律视为正常。
static bool HasThirdPartyAVFromRegistry() {
    const char* root = "SOFTWARE\\Microsoft\\Security Center\\Provider\\Av";
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, root, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return false;
    DWORD nSub = 0;
    RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr, &nSub, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    std::vector<char> buf(256 + 1);
    for (DWORD i = 0; i < nSub; ++i) {
        DWORD ns = (DWORD)buf.size();
        if (RegEnumKeyA(hk, i, buf.data(), ns) != ERROR_SUCCESS) continue;
        std::string sub = std::string(root) + "\\" + buf.data();
        HKEY hks;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hks) != ERROR_SUCCESS) continue;
        char dn[512] = {0}; DWORD dns = sizeof(dn);
        if (RegQueryValueExA(hks, "DisplayName", nullptr, nullptr, (LPBYTE)dn, &dns) == ERROR_SUCCESS) {
            std::string low = to_lower(std::string(dn));
            // 排除 Windows Defender / Microsoft Defender 自身
            bool isDef = ci_contains(low, "windows defender") || ci_contains(low, "microsoft defender");
            if (!isDef && !low.empty()) { RegCloseKey(hks); RegCloseKey(hk); return true; }
        }
        RegCloseKey(hks);
    }
    RegCloseKey(hk);
    return false;
}

static bool HasThirdPartyAVFromWmi() {
    ComInit ci;
    IWbemLocator* loc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&loc))) return false;
    IWbemServices* svc = nullptr;
    BSTR ns = SysAllocString(L"ROOT\\SecurityCenter2");
    if (FAILED(loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc))) { SysFreeString(ns); loc->Release(); return false; }
    SysFreeString(ns);
    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    BSTR q = SysAllocString(L"SELECT displayName FROM AntiVirusProduct");
    IEnumWbemClassObject* en = nullptr;
    if (FAILED(svc->ExecQuery(_bstr_t(L"WQL"), q, WBEM_FLAG_FORWARD_ONLY, nullptr, &en)) || !en) { SysFreeString(q); svc->Release(); loc->Release(); return false; }
    SysFreeString(q);
    IWbemClassObject* obj = nullptr; ULONG ret = 0;
    bool found = false;
    while (en->Next(WBEM_INFINITE, 1, &obj, &ret) == S_OK && ret) {
        VARIANT vn; VariantInit(&vn);
        obj->Get(L"displayName", 0, &vn, nullptr, nullptr);
        std::wstring name = (vn.vt == VT_BSTR && vn.bstrVal) ? std::wstring(vn.bstrVal) : L"";
        std::string low = to_lower(wtoa(name));
        bool isDefender = ci_contains(low, "windows defender") || ci_contains(low, "microsoft defender");
        if (!isDefender && !low.empty()) found = true;
        VariantClear(&vn); obj->Release();
    }
    en->Release(); svc->Release(); loc->Release();
    return found;
}

static bool HasThirdPartyAV() {
    return HasThirdPartyAVFromRegistry() || HasThirdPartyAVFromWmi();
}

static void ScanRegistry(ScanResult& r) {
    for (size_t i = 0; i < iocs::REG_RUN_KEYS_N; ++i) {
        CheckRegKey(r, HKEY_LOCAL_MACHINE, iocs::REG_RUN_KEYS[i]);
        CheckRegKey(r, HKEY_CURRENT_USER, iocs::REG_RUN_KEYS[i]);
    }
    // 服务（Session 0 / SYSTEM）模式下 HKCU 是 SYSTEM 的 hive，
    // 必须额外枚举已登录用户的 HKU\<SID> 才能看到用户级自启项（银狐最常见持久化点）
    HKEY hkUsers;
    if (RegOpenKeyExA(HKEY_USERS, nullptr, 0, KEY_READ, &hkUsers) == ERROR_SUCCESS) {
        DWORD nSub = 0;
        RegQueryInfoKeyA(hkUsers, nullptr, nullptr, nullptr, &nSub, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
        std::vector<char> name(256 + 1);
        for (DWORD i = 0; i < nSub; ++i) {
            DWORD ns = (DWORD)name.size();
            if (RegEnumKeyA(hkUsers, i, name.data(), ns) != ERROR_SUCCESS) continue;
            std::string sid(name.data());
            if (sid.find("S-1-5-21-") == std::string::npos) continue;  // 只看用户 SID
            for (size_t k = 0; k < iocs::REG_RUN_KEYS_N; ++k) {
                std::string full = sid + "\\" + iocs::REG_RUN_KEYS[k];
                CheckRegKey(r, HKEY_USERS, full.c_str());
            }
        }
        RegCloseKey(hkUsers);
    }
    // Defender 防护状态检测（跨 Win10 / Win11 均有效）
    // 重要：Win10 1903+ 与 Win11 已废弃 DisableAntiSpyware 键（系统直接忽略该值），
    // 通过「Windows 安全中心 → 关闭实时防护」时，系统实际写入的是
    //   Real-Time Protection\DisableRealtimeMonitoring (=1)
    // 若只查旧键，在「系统设置关闭」场景下会漏报（即「Win10 测不到 Defender 关闭」的根因）。
    // 故同时检测旧键 + 实时防护子键 + WinDefend 服务状态 + 篡改防护，覆盖各类关闭途径。
    // 但同时必须排除「第三方杀毒软件（360/火绒/腾讯管家等）合法接管」的场景——
    // 此时 DisableAntiSpyware=1、实时防护被动、WinDefend 服务变化均为系统预期，并非银狐所致，
    // 否则会给绝大多数国内安全软件用户造成误报（用户已反馈：宿主机装了火绒接管 Defender 却报「被禁用」）。
    auto RegDwordVal = [](const char* sub, const char* name) -> DWORD {
        HKEY hk;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return 0;
        DWORD v = 0, sz = sizeof(v);
        if (RegQueryValueExA(hk, name, nullptr, nullptr, (LPBYTE)&v, &sz) != ERROR_SUCCESS) v = 0;
        RegCloseKey(hk); return v;
    };
    const char* RTP = "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection";
    bool avActive = HasThirdPartyAV();
    if (avActive) {
        // 已存在并启用第三方杀毒软件接管实时防护：Defender 处于被动/禁用是系统正常表现。
        // 不再作为「发现项」列出——国内装机几乎必然装 360/火绒/管家，逐条刷警告会淹没真实发现
        // （实测用户机器 7 条发现里这条纯属噪声，文案自己都写「无需处理」），仅落日志备查。
        sf::LogDbg("[defender] 第三方杀毒软件已接管实时防护（正常状态，不计入发现项）");
    } else {
        // ① 旧式禁用（GPO / 部分工具会写此键，Win10/Win11 均可触发）
        if (RegDwordVal("SOFTWARE\\Microsoft\\Windows Defender", "DisableAntiSpyware") == 1) {
            r.findings.push_back({"注册表", "中", "Windows Defender 被禁用",
                "DisableAntiSpyware=1，且无其他杀毒软件接管，系统处于无防护状态，建议核查是否异常。", "DisableAntiSpyware"});
        }
        // ② 系统设置关闭实时防护（Win10 1903+ / Win11 的真实开关）
        bool rtOff = RegDwordVal(RTP, "DisableRealtimeMonitoring") == 1
                  || RegDwordVal(RTP, "DisableBehaviorMonitoring") == 1
                  || RegDwordVal(RTP, "DisableOnAccessProtection") == 1
                  || RegDwordVal(RTP, "DisableIOAVProtection") == 1;
        if (rtOff) {
            r.findings.push_back({"注册表", "中", "Windows Defender 实时防护已关闭",
                "Real-Time Protection 下 DisableRealtimeMonitoring / 行为监控 / 访问防护被禁用，且未检测到第三方杀毒软件接管，系统已无实时查杀能力。",
                "DisableRealtimeMonitoring"});
        }
        // ③ WinDefend 服务被禁用（Start=4）
        if (RegDwordVal("SYSTEM\\CurrentControlSet\\Services\\WinDefend", "Start") == 4) {
            r.findings.push_back({"注册表", "中", "Windows Defender 服务被禁用",
                "WinDefend 服务 Start=4（禁用），Defender 无法随系统启动提供保护，且未检测到第三方杀毒软件接管。", "WinDefend.Start=4"});
        }
        // ④ 篡改防护被关闭（TamperProtection=0）：Defender 设置可被任意更改，
        //    是恶意关闭实时防护/添加排除项的前置条件，银狐常见手法之一
        if (RegDwordVal("SOFTWARE\\Microsoft\\Windows Defender\\Features", "TamperProtection") == 0) {
            r.findings.push_back({"注册表", "中", "Windows Defender 篡改防护已关闭",
                "TamperProtection=0，Defender 的实时防护/排除项等设置可被任意程序更改，为恶意关闭防护敞开大门。",
                "TamperProtection=0"});
        }
    }
}

// ---------------------------------------------------------------------------
//  模块 3：计划任务扫描（COM TaskScheduler）
// ---------------------------------------------------------------------------
static void EnumTaskFolder(ScanResult& r, ITaskFolder* folder) {
    if (!folder) return;
    // 当前文件夹任务
    IRegisteredTaskCollection* tasks = nullptr;
    if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
        LONG count = 0; tasks->get_Count(&count);
        for (LONG i = 0; i < count; ++i) {
            IRegisteredTask* task = nullptr;
            if (FAILED(tasks->get_Item(_variant_t(i + 1), &task)) || !task) continue;
            BSTR name = nullptr, path = nullptr;
            task->get_Name(&name); task->get_Path(&path);
            std::string sname = name ? wtoa(name) : "", spath = path ? wtoa(path) : "";
            if (name) SysFreeString(name); if (path) SysFreeString(path);
            // 描述
            std::string desc;
            VARIANT_BOOL hddn = VARIANT_FALSE;   // 任务勾选「隐藏」（银狐持久化常用）
            ITaskDefinition* def = nullptr;
            if (SUCCEEDED(task->get_Definition(&def)) && def) {
                IRegistrationInfo* info = nullptr;
                if (SUCCEEDED(def->get_RegistrationInfo(&info)) && info) {
                    BSTR d = nullptr; if (SUCCEEDED(info->get_Description(&d)) && d) { desc = wtoa(d); SysFreeString(d); }
                    info->Release();
                }
                // 行为检测：解析任务动作命令，若指向随机名 exe 则报警（银狐常用随机词拼接任务名 + 随机 exe）
                IActionCollection* actions = nullptr;
                if (SUCCEEDED(def->get_Actions(&actions)) && actions) {
                    LONG ac = 0; actions->get_Count(&ac);
                    for (LONG ai = 0; ai < ac; ++ai) {
                        IAction* act = nullptr;
                        if (FAILED(actions->get_Item(_variant_t(ai + 1), &act)) || !act) continue;
                        IExecAction* exec = nullptr;
                        if (SUCCEEDED(act->QueryInterface(IID_IExecAction, (void**)&exec)) && exec) {
                            BSTR cmd = nullptr;
                            if (SUCCEEDED(exec->get_Path(&cmd)) && cmd) {
                                std::string scmd = wtoa(cmd); SysFreeString(cmd);
                                std::string exePath = to_lower(ExtractExePath(scmd));
                                std::string exeb = basename(exePath);  // 保留大小写
                                if (IsSuspExe(exePath)) {
                                    r.findings.push_back({"计划任务", "高", "计划任务动作指向随机名可执行文件",
                                        "任务 " + sname + " 的动作命令指向随机名 exe：" + scmd, exeb});
                                }
                                // PowerShell / Python 脚本持久化（计划任务跑脚本是银狐常用持久化）
                                std::string stdTitle, stdFrag; int stdSev = 0;
                                if (IsScriptPersistence(to_lower(scmd), stdTitle, stdFrag, stdSev)) {
                                    std::string sev = (stdSev >= 60) ? "高" : "中";
                                    r.findings.push_back({"计划任务", sev, stdTitle,
                                        "任务 " + sname + " 的动作命令含脚本持久化特征（" + stdFrag + "）：" + scmd, stdFrag});
                                }
                            }
                            exec->Release();
                        }
                        act->Release();
                    }
                    actions->Release();
                }
                // 隐藏任务（银狐常勾「隐藏」做持久化；系统自带隐藏任务不满足下方名称条件，不误报）
                ITaskSettings* tset = nullptr;
                if (SUCCEEDED(def->get_Settings(&tset)) && tset) {
                    tset->get_Hidden(&hddn);
                    tset->Release();
                }
                def->Release();
            }
            std::string blob = to_lower(sname + "|" + spath + "|" + desc);
            for (size_t k = 0; k < iocs::TASK_FRAGMENTS_N; ++k) {
                if (ci_contains(blob, iocs::TASK_FRAGMENTS[k])) {
                    r.findings.push_back({"计划任务", "中", "发现可疑计划任务",
                        "任务名：" + sname + "；路径：" + spath, iocs::TASK_FRAGMENTS[k]});
                }
            }
            // 隐藏 + 名称随机/特征名 → 高危（区别于系统自带的隐藏任务）
            if (hddn == VARIANT_TRUE && (IsShortRandom(sname + ".exe") ||
                    [&]() {
                        std::string sl = to_lower(sname);
                        for (size_t k = 0; k < iocs::TASK_FRAGMENTS_N; ++k)
                            if (ci_contains(sl, to_lower(std::string(iocs::TASK_FRAGMENTS[k])))) return true;
                        return false;
                    }())) {
                r.findings.push_back({"计划任务", "高", "发现隐藏的可疑计划任务",
                    "任务 " + sname + " 设置了「隐藏」属性且名称为随机串/特征名，疑似银狐持久化任务。", sname});
            }
            // 任务名本身为随机短串（银狐亦用 rWT4p 这类短随机名，无空格/非字典词）
            if (IsShortRandom(sname + ".exe")) {
                r.findings.push_back({"计划任务", "中", "计划任务名为随机串",
                    "任务名 " + sname + " 为随机字母数字串，疑似银狐生成。", sname});
            }
            task->Release();
        }
        tasks->Release();
    }
    // 递归子文件夹
    ITaskFolderCollection* folders = nullptr;
    if (SUCCEEDED(folder->GetFolders(0, &folders)) && folders) {
        LONG fcount = 0; folders->get_Count(&fcount);
        for (LONG i = 0; i < fcount; ++i) {
            ITaskFolder* sub = nullptr;
            if (SUCCEEDED(folders->get_Item(_variant_t(i + 1), &sub)) && sub) {
                EnumTaskFolder(r, sub);
                sub->Release();
            }
        }
        folders->Release();
    }
}
static void ScanScheduledTasks(ScanResult& r) {
    ComInit ci;
    ITaskService* svc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&svc))) return;
    VARIANT var; VariantInit(&var); var.vt = VT_EMPTY;
    if (FAILED(svc->Connect(var, var, var, var))) { svc->Release(); return; }
    for (size_t i = 0; i < iocs::TASK_FOLDERS_N; ++i) {
        ITaskFolder* folder = nullptr;
        if (SUCCEEDED(svc->GetFolder(_bstr_t(iocs::TASK_FOLDERS[i]), &folder)) && folder) {
            EnumTaskFolder(r, folder);
            folder->Release();
        }
    }
    svc->Release();
}

// ---------------------------------------------------------------------------
//  模块 4：网络连接扫描（已知 C2 IP）
// ---------------------------------------------------------------------------
static void ScanNetwork(ScanResult& r) {
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    if (size == 0) return;
    std::vector<BYTE> buf(size);
    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != NO_ERROR) return;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        auto& row = table->table[i];
        IN_ADDR a{}; a.S_un.S_addr = row.dwRemoteAddr;
        char ip[INET_ADDRSTRLEN]{};
        inet_ntop(AF_INET, &a, ip, sizeof(ip));
        USHORT port = ntohs((USHORT)row.dwRemotePort);
        for (size_t k = 0; k < iocs::C2_IPS_N; ++k) {
            if (strcmp(ip, iocs::C2_IPS[k]) == 0) {
                std::string detail = "本机 PID " + std::to_string(row.dwOwningPid) +
                    " 正与已知银狐 C2 " + std::string(ip) + ":" + std::to_string(port) + " 通信。";
                r.findings.push_back({"网络", "高", "检测到与银狐 C2 的活跃连接",
                    detail, std::string(ip) + ":" + std::to_string(port)});
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  模块 5：文件 / 路径扫描
// ---------------------------------------------------------------------------
// 构造「文件」类发现：统一带上绝对路径（f.path），供扩展/弹窗的「一键清除」精确定位删除目标。
// 不走聚合初始化是因为要填 path 字段（在 ioc 之后），显式赋值更不易错。
// 多线程全盘文件扫描时 findings 的 push 加锁（判定逻辑保持无锁并行）
static std::mutex g_findMtx;

static void AddFileFinding(ScanResult& r, const std::string& severity, const std::string& title,
                           const std::string& detail, const std::string& ioc, const std::string& path) {
    Finding f;
    f.category = "文件";
    f.severity = severity;
    f.title    = title;
    f.detail   = detail;
    f.ioc      = ioc;
    f.path     = path;
    {
        std::lock_guard<std::mutex> lk(g_findMtx);
        r.findings.push_back(f);
    }
}

// ---- 「高级隐藏」检测辅助（银狐用系统级隐藏手法让文件在常规查看/枚举里看不见）----

// ANSI 路径 → 宽字符（ADS / 长路径 API 需要宽字符版本）
static std::wstring A2WPath(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}
static std::wstring ToLowerW(const std::wstring& w) {
    std::wstring o = w;
    for (auto& c : o) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
    return o;
}

// System32/SysWOW64 中的名单 DLL 是否【确为微软系统组件】。
// 两种判别（都基于二进制内容，不依赖目录名/文件名信任）：
//  ① 带有效 Authenticode 签名（WinVerifyTrust 完整信任链验证）；
//  ② 无签名但 PE VersionInfo 中 CompanyName == "Microsoft Corporation"——Win10 中
//     secur32/usp10/uxtheme/riched20/msimg32 等遗留转发 stub 无签名却是真系统组件；
//     银狐伪装的同名 DLL 不会自报 Microsoft，① ② 均不满足 → 判伪造。
static bool HasValidSignature(const std::string& path) {
    std::wstring wpath = A2WPath(path);
    if (wpath.empty()) return false;
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fi.pcwszFilePath = wpath.c_str();
    fi.hFile = nullptr;
    fi.pgKnownSubject = nullptr;
    WINTRUST_DATA wtd{};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
    wtd.pFile = &fi;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG st = WinVerifyTrust(nullptr, &action, &wtd);
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wtd);
    return st == ERROR_SUCCESS;
}
// HasValidSignature 的进程级缓存：全盘扫描命中疑似随机名的文件才做签名验证（量可控），
// 但 WinVerifyTrust 每次**数百 ms 级**（要读整个文件 + 验签 + 走证书链），且结果稳定
// → 加缓存避免重复验证拖慢扫描。
//
// ⚠️ 2026-09-19 修复：原实现把 lock_guard 放在函数最开头，等于**持锁跑 WinVerifyTrust**。
//    这是三个同类问题里最严重的 —— 签名验证耗时是文件读的数倍，一旦多个线程同时命中
//    未缓存路径，全部排队，扫描瞬间卡成"无响应"。修正：锁只保护 map，验证在锁外。
static std::mutex g_sigMtx;
static std::unordered_map<std::string, bool> g_sigCache;

static bool SigTrustedCached(const std::string& path) {
    {
        std::lock_guard<std::mutex> lk(g_sigMtx);
        auto it = g_sigCache.find(path);
        if (it != g_sigCache.end()) return it->second;
    }                                   // ← 锁在此释放，WinVerifyTrust 在锁外跑
    const bool ok = HasValidSignature(path);
    {
        std::lock_guard<std::mutex> lk(g_sigMtx);
        if (g_sigCache.size() >= 16384) g_sigCache.clear();
        g_sigCache.emplace(path, ok);
    }
    return ok;
}
// 读 PE VersionInfo 的 CompanyName（二进制版本资源，不加载执行）
static bool HasMsCompanyInVersionInfo(const std::string& path) {
    std::wstring wpath = A2WPath(path);
    if (wpath.empty()) return false;
    DWORD h = 0;
    DWORD sz = GetFileVersionInfoSizeW(wpath.c_str(), &h);
    if (!sz) return false;
    std::vector<BYTE> buf(sz);
    if (!GetFileVersionInfoW(wpath.c_str(), h, sz, buf.data())) return false;
    // 找每个语言块，任一 CompanyName == Microsoft Corporation 即认可
    struct LANG { WORD lang, cp; };
    LANG* langs = nullptr; UINT nl = 0;
    if (!VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation", (void**)&langs, &nl)) return false;
    UINT nlang = nl / sizeof(LANG);
    for (UINT i = 0; i < nlang; ++i) {
        wchar_t key[64];
        swprintf_s(key, L"\\StringFileInfo\\%04x%04x\\CompanyName", langs[i].lang, langs[i].cp);
        wchar_t* val = nullptr; UINT vlen = 0;
        if (VerQueryValueW(buf.data(), key, (void**)&val, &vlen) && val && vlen) {
            std::wstring s(val);
            if (s.find(L"Microsoft") != std::wstring::npos) return true;
        } else {
            // 某些 stub 无 CompanyName，退回看 ProductName/FileDescription 含 Microsoft
            swprintf_s(key, L"\\StringFileInfo\\%04x%04x\\FileDescription", langs[i].lang, langs[i].cp);
            if (VerQueryValueW(buf.data(), key, (void**)&val, &vlen) && val && vlen &&
                std::wstring(val).find(L"Microsoft") != std::wstring::npos) return true;
        }
    }
    return false;
}
static bool IsSystemDirDllTrusted(const std::string& fullPath) {
    return HasValidSignature(fullPath) || HasMsCompanyInVersionInfo(fullPath);
}

// 检测文件是否携带「非标准」NTFS 备用数据流（ADS）。
// 正常文件只有默认流 :$DATA 与浏览器下载标记 :Zone.Identifier；其余具名流是典型的隐藏载荷手法。
// 注意：FindFirstStreamW 对默认数据流返回的流名为 "::$DATA"（双冒号开头）或 ":$DATA"（单冒号，
// 视系统版本/本地化而异），因此不能用 == 单冒号精确比较，必须剥掉前导冒号再比对 $data，否则
// 会把每个普通文件的默认流误判成可疑流（实测一次扫描刷出 1.8 万条 ADS 误报，评分推上 13 万）。
static bool IsDefaultDataStream(const std::wstring& ln) {
    std::wstring s = ln;
    while (!s.empty() && s[0] == L':') s.erase(s.begin());
    // 末尾的 :$DATA 尾巴（如 :Zone.Identifier:$DATA）也剥掉，统一比对裸流名
    size_t tail = s.find(L":$data");
    if (tail != std::wstring::npos) s = s.substr(0, tail);
    return s.empty() || s == L"$data";
}
// 返回「可疑流名」（非默认流且不在合法白名单内）；空表示无可疑流。不参与判危，只作证据之一。
static std::wstring SuspiciousAdsName(const std::string& path) {
    std::wstring wpath = A2WPath(path);
    if (wpath.empty()) return L"";
    WIN32_FIND_STREAM_DATA fsd{};
    HANDLE h = FindFirstStreamW(wpath.c_str(), FindStreamInfoStandard, &fsd, 0);
    if (h == INVALID_HANDLE_VALUE) return L"";
    std::wstring susp;
    do {
        std::wstring ln = ToLowerW(fsd.cStreamName);
        if (IsDefaultDataStream(ln)) continue;
        // 以下是系统/常见软件会合法使用的数据流，一律不算可疑（不排干净就会海量误报）
        if (ln.find(L":zone.identifier") != std::wstring::npos) continue;   // 浏览器/下载器来源标记
        if (ln.find(L":writedata") != std::wstring::npos) continue;         // 部分安装器使用
        if (ln.find(L":encryptable") != std::wstring::npos) continue;       // EFS 标记
        if (ln.find(L":oecustomproperty") != std::wstring::npos) continue;  // Office 自定义属性
        if (ln.find(L":summaryinformation") != std::wstring::npos) continue;
        if (ln.find(L":document") != std::wstring::npos) continue;          // Shell 文档摘要流
        if (ln.find(L":{") != std::wstring::npos) continue;                 // GUID 命名流（Office/Shell）
        if (ln.find(L":objectid") != std::wstring::npos) continue;
        if (ln.find(L":smartlocker") != std::wstring::npos) continue;
        if (ln.find(L":win32app") != std::wstring::npos) continue;
        if (ln.find(L":smartscreen") != std::wstring::npos) continue;       // Windows SmartScreen 下载标记（网络下载安装包常见）
        susp = fsd.cStreamName; break;   // 捕获第一条可疑流名
    } while (FindNextStreamW(h, &fsd));
    FindClose(h);
    return susp;
}

// 可执行类扩展名：用于收敛「超隐藏 / 伴随 DLL」这类高误报风险的规则。
// 教训：不加收敛时，Windows 自身大量合法文件的「隐藏+系统属性」会把评分直接刷到 20 万，
// 并连带把 Defender 目录下的正常 DLL 判成「载荷」（响应 JSON 撑到 1.3MB，超过浏览器原生消息 1MB 上限 → 扩展显示未连接）。
static bool IsExecLikeExt(const std::string& l) {   // l 已小写（热路径，不二次 to_lower）
    return low_ends(l, ".exe") || low_ends(l, ".dll") || low_ends(l, ".sys") ||
           low_ends(l, ".scr") || low_ends(l, ".com") || low_ends(l, ".bat") ||
           low_ends(l, ".cmd") || low_ends(l, ".ps1") || low_ends(l, ".psm1") ||
           low_ends(l, ".vbs") || low_ends(l, ".js")  || low_ends(l, ".jar") ||
           low_ends(l, ".ocx");

}

// 深度扫描命中分级：PE 可执行形态才判高危；脚本/文本只记旁证。
static bool HasPeMagic(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    unsigned char m[2] = { 0 };
    f.read((char*)m, 2);
    return m[0] == 'M' && m[1] == 'Z';
}

// 已知「合法地」带隐藏+系统属性的文件（避免把桌面 desktop.ini / 缩略图库当恶意）
// 全盘扫描进度：服务端每 ~256 文件落盘一次，供 --scanprogress 右下角弹窗轮询显示进度
static std::atomic<long long> g_scanDone{ 0 };
static void WriteScanProgress(const char* phase, long long done, const std::string& current) {
    CreateDirectoryW(L"C:\\ProgramData\\SilverFoxGuard", nullptr);
    std::wstring path = L"C:\\ProgramData\\SilverFoxGuard\\scan_progress.txt";
    std::string s = std::string("phase=") + phase + " done=" + std::to_string(done) +
                    " current=" + current;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0; WriteFile(h, s.data(), (DWORD)s.size(), &w, nullptr);
    CloseHandle(h);
}

static bool IsKnownHiddenSystemFile(const std::string& baseLower) {
    static const char* kOk[] = { "desktop.ini", "thumbs.db", "ehthumbs.db", "$recycle.bin",
                                 "bootmgr", "bootnxt", "pagefile.sys", "hiberfil.sys",
                                 "swapfile.sys", "dumpstack.log.tmp", "ntuser.dat",
                                 "ntuser.ini", "iconcache.db", "iconcache_*.db" };
    for (const char* k : kOk) if (baseLower == k) return true;
    return false;
}

// ADS 检测预算：只对可执行类文件查流，且每个扫描周期设上限，避免在慢盘上拖垮整体扫描
static std::atomic<int> g_adsBudget{2000};   // 多线程文件扫描共享的 ADS 探测预算（原子递减）
static bool AdsCheckable(const std::string& l) {   // l 已小写（热路径）
    // 只查可执行/载荷容器类型。刻意不收 .tmp/.jpg/.png/.dat：
    // 回收站内部文件（$I*.TMP）、缩略图、Office 临时文件天然携带数据流，收进来就是海量误报。
    return low_ends(l, ".exe") || low_ends(l, ".dll") || low_ends(l, ".sys") ||
           low_ends(l, ".bin");
}

static void AddPathFinding(ScanResult& r, const std::string& path) {
    if (IsSelfArtifact(path)) return;   // 自排除：我方程序产物不参与判定
    std::string l = to_lower(path);
    // 回收站内部文件（$I*/$R*）天然带「隐藏+系统属性」和额外数据流，不参与属性/流层面的判定
    // （否则一次扫描能刷出三千多条误报，把评分推到 20 万）。回收站里真正的样本仍会被双后缀/随机名等规则抓到。
    const bool inRecycle = low_has(l, "\\$recycle.bin\\");

    // ---- ① 属性层面的「超隐藏」：隐藏 + 系统 双属性 ----
    // 用户目录（桌面/下载/AppData/临时）里的正常**可执行文件**几乎不会同时带这两个属性，出现即高度可疑。
    // 三重收敛（都是实战误报换来的）：排除回收站、排除 Windows 应用包状态目录、且只对可执行类文件报——
    // 否则 ProgramData\Microsoft\...\AppRepository 下大量合法的 *.dat.LOG* 会集体误报。
    // 多证据收敛：仅当文件本身是「短随机名」时才判高危（随机名 + 超隐藏 是银狐落地载荷强组合）；
    // 正常命名的可执行文件（用户自建 OneMail.exe 等可能自己设了隐藏+系统属性）只记低危旁证，不再直接判危。
    {
        DWORD attr = GetFileAttributesA(path.c_str());
        std::string baseLow = to_lower(basename(path));
        if (attr != INVALID_FILE_ATTRIBUTES &&
            (attr & FILE_ATTRIBUTE_HIDDEN) && (attr & FILE_ATTRIBUTE_SYSTEM) &&
            !inRecycle && !IsKnownHiddenSystemFile(baseLow) &&
            !low_has(l, "\\apprepository\\") &&
            IsExecLikeExt(l)) {
            bool fRandom = IsShortRandom(baseLow);
            if (fRandom) {
                AddFileFinding(r, "高", "发现超隐藏文件（隐藏+系统属性）",
                    "随机名文件 " + path + " 同时带「隐藏」与「系统」属性，常被银狐用于躲避常规查看与枚举。", "hidden+system", path);
                return;
            }
            // 正常命名 + 超隐藏：不再产出发现项（仅落日志）。
            // 理由：正常命名的可执行文件带「隐藏+系统」无法与「用户自建软件 / 主题包 / 安装器 / 自带隐藏」
            // 区分——实测用户桌面 5 个自研/自用文件（OneMail.exe、start_proxy_hidden.vbs…）全部刷成警告，
            // 发现列表里几乎全是噪声。真信号是「随机名 + 超隐藏」（上面已判高）或「可疑目录」，
            // 由 InSuspLoc / IsSuspExe 等规则另行覆盖。
            sf::LogDbg("[hidden] 正常命名文件带隐藏+系统属性（旁证，不计入发现项）: " + path);
        }
        // ---- ② 畸形文件名：以空格或点结尾（NTFS 允许，但 Win32 常规路径打不开，典型藏文件手法）----
        if (!baseLow.empty() && (baseLow.back() == ' ' || baseLow.back() == '.') && !inRecycle) {
            AddFileFinding(r, "高", "发现畸形文件名（结尾空格/点）",
                "文件 " + path + " 的名称以空格或点结尾，Windows 常规路径无法访问，是典型的隐藏载荷手法。", baseLow, path);
            return;
        }
    }

    // ---- ③ 备用数据流（ADS）：主文件正常、载荷藏在 NTFS 流里 ----
    // 多证据判定：ADS 只是「旁证」。正常软件（VS/Office/游戏启动器/安装器）也可携带具名流
    // （在排掉已知白名单后仍可能剩余少量合法的私有流），因此不能见 ADS 就报危——否则一次
    // 扫描刷出 1.8 万条误报、响应 JSON 超 1MB、扩展显示「未连接程序」（真实事故）。
    // 判危前提（缺一不可）：
    //   ① 存在非默认、非白名单的具名流（可疑流）；
    //   ② 文件本身或父目录是短随机名（随机名 + ADS 是银狐落地载荷的强组合特征）；
    // 仅满足 ① 时降为「中」（旁证记录，便于人工复核），不再单点判危。
    if (!inRecycle && AdsCheckable(l) && g_adsBudget > 0) {
        --g_adsBudget;
        std::wstring susp = SuspiciousAdsName(path);
        if (!susp.empty()) {
            std::string adsName = wtoa(susp);
            bool fileRandom = IsShortRandom(basename(path)) ||
                              IsShortRandom(basename(dirname(path)) + ".exe");
            if (fileRandom) {
                AddFileFinding(r, "高", "发现备用数据流（ADS）隐藏载荷",
                    "随机名文件 " + path + " 携带额外 NTFS 数据流 " + adsName + "，疑似银狐借 ADS 藏匿载荷或配置。", "ads", path);
            } else {
                AddFileFinding(r, "中", "发现备用数据流（ADS）旁证",
                    "文件 " + path + " 携带额外 NTFS 数据流 " + adsName + "。正常软件亦可能带私有数据流，仅作旁证记录供复核，不据此判定恶意。", "ads", path);
            }
            return;
        }
    }

    // 双后缀
    for (size_t i = 0; i < iocs::DOUBLE_EXT_N; ++i) {
        if (low_ends(l, iocs::DOUBLE_EXT[i])) {
            AddFileFinding(r, "高", "发现双后缀诱饵文件",
                "文件 " + path + " 伪装成文档实为可执行程序。", iocs::DOUBLE_EXT[i], path);
            return;
        }
    }
    // IDE/工具缓存目录（WorkBuddy blob 附件、Trae 数据、node_modules 等）由程序自动生成，
    // 文件名不可控，附件名可能巧合命中恶意路径片段（如 "bb.jpg"）→ 豁免片段判定，避免工作环境日常误报；
    // 其余属性/ADS/随机名/PE 规则照常适用（这些目录里的真样本仍会被其它证据抓到）。
    bool skipPathFrag = low_has(l, "\\.workbuddy\\") || low_has(l, "\\blobs\\") ||
                        low_has(l, "\\.trae-") || low_has(l, "\\node_modules\\");
    if (!skipPathFrag) {
        for (size_t i = 0; i < iocs::PATH_FRAGMENTS_N; ++i) {
            if (low_has(l, iocs::PATH_FRAGMENTS[i])) {
                std::string sev = (ci_contains(iocs::PATH_FRAGMENTS[i], "nvsc") || ci_contains(iocs::PATH_FRAGMENTS[i], "temp.key") || ci_contains(iocs::PATH_FRAGMENTS[i], "xfolder32")) ? "高" : "中";
                AddFileFinding(r, sev, "发现银狐可疑文件路径",
                    "路径 " + path + " 含可疑片段。", iocs::PATH_FRAGMENTS[i], path);
                return;
            }
        }
    }
    // 随机名落地 exe/dll/sys 已并入下方统一 L2 重判定（签名/PE/盘根多证据）
    // ---- ④ 可疑驱动文件（.sys）：随机名驱动已并入下方 L2 重判定；此处保留系统目录内的驱动基名检测 ----
    // DLL 载荷：银狐大量使用「宿主 EXE + 恶意 DLL」侧加载，只盯 EXE 会漏；且 DLL 会被重新释放/下载。
    if (low_ends(l, ".dll")) {
        std::string base = to_lower(basename(path));
        // ① 系统同名 DLL 出现在【用户可写可疑位置】→ 白利用侧加载
        //  必须同时命中 InSuspLoc：否则正常软件自带的同名 DLL（悠悠远程 D:\uu\GameViewer、
        //  剪映 D:\JianyingPro 等）也会误报——这些是正规软件的合法交付物，不是侧加载载荷。
        //  (dbghelp/profapi/userenv/version/winhttp 等大量正版软件也会随包携带)
        //  再叠加「有效数字签名放行」：合法软件随包携带的系统同名 DLL 有厂商 Authenticode
        //  签名（微软正版拷贝 / 软件商自签）；银狐伪造的同名 DLL 无法伪造有效签名。
        if (InSuspLoc(l) && !HasValidSignature(path)) {
            for (size_t i = 0; i < iocs::HIJACK_DLLS_N; ++i) {
                if (base == iocs::HIJACK_DLLS[i]) {
                    AddFileFinding(r, "中", "发现系统同名 DLL 侧加载模块",
                        "DLL " + path + " 与系统组件同名且位于可疑落地目录，疑似银狐侧加载（白利用）载荷。", base, path);
                    return;
                }
            }
        }
        // （② 随机名 DLL 落在可疑目录 → 已并入下方统一 L2 重判定）
    }

    // ---------------------------------------------------------------------------
    //  L2 随机名落地重判定（分层筛选核心：L0 扩展名初筛 / L1 属性名称 / L2 二进制重判定）
    //  PY 级教训（"判定不可以算"）：随机名落地不能只凭文件名，必须叠加二进制证据——
    //   ① 带有效 Authenticode 签名 → 厂商/微软合法交付物，一律豁免（杜绝合法运行库误报）；
    //   ② 命中银狐家族特征字节串（SFuck/qQ996545/Gh0st/Win0s）→ 铁证高危；
    //   ③ PE 静态证据 ≥2（加壳区段/可写可执行/高熵/无导入表）或盘根表层 → 高危；
    //   ④ 仅名称随机 + 位置可疑 + 无签名、PE 形态正常 → 「中」旁证供人工复核。
    //  ---------------------------------------------------------------------------
    std::string base = to_lower(basename(path));
    if ((low_ends(l, ".exe") || low_ends(l, ".com") || low_ends(l, ".scr") ||
         low_ends(l, ".dll") || low_ends(l, ".sys")) && !SusRandomNameException(base)) {
        const std::string d = dirname(path);
        bool rootLevel = d.size() == 2 && d[1] == ':';   // 盘根："D:\\evil.exe" 的 dirname = "D:"
        std::string stem = base.size() > 4 ? base.substr(0, base.size() - 4) : base;
        bool nameRandom = IsShortRandom(stem);
        bool dirRandom  = IsShortRandom(basename(d) + ".exe");
        if ((nameRandom || dirRandom) && (rootLevel || InSuspLoc(l))) {
            if (HasSilverFoxStringCached(path)) {
                AddFileFinding(r, "高", "发现银狐家族特征文件",
                    "文件 " + path + " 命中银狐家族特征字节串（Gh0st/Win0s 系 C2 握手/RC4 密钥），确认为银狐载荷。", base, path);
                return;
            }
            if (SigTrustedCached(path)) return;   // 有效签名 → 合法交付物，豁免
            int pe = PeStaticEvidenceCached(path);
            const char* kind = low_ends(l, ".dll") ? "DLL 模块"
                             : (low_ends(l, ".sys") ? "驱动文件" : "可执行文件");
            if (rootLevel || pe >= 2) {
                std::string detail = rootLevel
                    ? "随机名文件 " + path + " 直接落在磁盘根且无有效签名。正常程序不会装在盘根，疑似银狐落地下载。"
                    : "文件 " + path + " 为随机字母数字名、位于可疑落地目录且 PE 形态异常（加壳/可写可执行/高熵/无导入表），疑似银狐载荷。";
                AddFileFinding(r, "高", "发现随机名 " + std::string(kind),
                    detail, basename(path), path);
            } else {
                AddFileFinding(r, "中", "疑似随机名 " + std::string(kind) + "（旁证）",
                    "文件 " + path + " 名称近似随机串且位于可疑目录，但 PE 形态与签名正常，仅作旁证供人工复核。", basename(path), path);
            }
            return;
        }
    }
}

// ---------------------------------------------------------------------------
//  P5 可选 GPU 深度内容扫描（默认关闭，注册表 gpu_scan=1 启用；P6 主界面开关）
//  理念：全盘常规扫描只对「随机名/嫌疑名」文件做内容判定；深度扫描把【用户可写目录
//  的所有可执行/脚本文件】的前 64KB 批量提交给 GPU 做家族特征串匹配（SFuck/
//  qQ996545/Gh0st/Win0s/winos），抓「名字正常但内容为银狐」的改名样本。GPU 不可用
//  自动回退 CPU（HasSilverFoxStringCached），启用后增加的扫描时间以收集/IO 为主。
// ---------------------------------------------------------------------------
// 单轮深度扫描候选预算。
// ⚠️ 2026-09-18 从 200000 下调到 30000：原预算让一轮全盘多读 200000×64KB ≈ 12.8 GB，
// 是「全盘扫描要 40~90 秒」的主要原因。深度扫描的定位是**补漏**（抓"名字正常但内容
// 是银狐"的改名样本），不是主力检出手段 —— 主力是 PE 结构与随机名判定，那部分不依赖
// 此预算。压低到 30000 后单轮 IO 降到 ~1.9 GB，扫描时间回到可接受区间，
// 而银狐载荷常见的落地位置（用户可写目录 + 可疑目录）仍在覆盖范围内。
static std::atomic<int> g_gpuBudget{ 30000 };
static std::mutex       g_ccMtx;
static std::vector<std::string> g_ccCands;              // 候选文件（扫描线程收集，收尾统一处理）

static void MaybePushContentCandidate(const std::string& path) {
    if (g_gpuBudget.load(std::memory_order_relaxed) <= 0) return;
    std::string l = to_lower(path);
    if (!(low_ends(l, ".exe") || low_ends(l, ".dll") || low_ends(l, ".sys") ||
          low_ends(l, ".scr") || low_ends(l, ".com") || low_ends(l, ".bat") ||
          low_ends(l, ".cmd") || low_ends(l, ".ps1") || low_ends(l, ".vbs") ||
          low_ends(l, ".js") || low_ends(l, ".jar") || low_ends(l, ".ocx"))) return;
    // 不限区域：GPU 批量搜家族字节串对正常程序几乎零误报，放开让全盘都受益（预算 200000 封顶）
    if (g_gpuBudget.fetch_sub(1, std::memory_order_relaxed) <= 0) return;
    std::lock_guard<std::mutex> lk(g_ccMtx);
    g_ccCands.push_back(path);
}

static void FinishContentScan(ScanResult& r) {
    if (!compute::IsGpuEnabled()) {                     // 未启用：清空残留并复位预算
        std::lock_guard<std::mutex> lk(g_ccMtx);
        g_ccCands.clear();
        g_gpuBudget.store(30000);
        return;
    }
    std::vector<std::string> cands;
    {
        std::lock_guard<std::mutex> lk(g_ccMtx);
        cands.swap(g_ccCands);
        g_gpuBudget.store(30000);
    }
    if (cands.empty()) return;
    sf::LogDbg("[gpu] deep content scan: " + std::to_string(cands.size()) + " files");
    std::vector<bool> hits;
    bool onGpu = compute::GpuFamilyProbe(cands, hits);
    // CPU 回退的真实代价：AC 多线程实测 ~500 MB/s，但每个候选要读 256KB
    // （kFamilyProbeBytes = 1<<18，不是注释里历史误写的 64KB）。10 万候选 ≈ 25 GB 读取量。
    // GPU 一旦失败（含熔断后）**不能**把全部候选都丢给 CPU 慢跑——那会让本来已在
    // 指数级变慢的全盘扫描彻底拖死。回退时只取前 kCpuFallbackCands 个，其余本轮放弃
    // （下一轮 QuickScan 会重新收集，结合 GPU 熔断状态自然收敛到纯 CPU 节奏）。
    static const size_t kCpuFallbackCands = 3000;
    // ★ 2026-09-19 新增：CPU 回退的**总时间预算**。
    //   候选数与耗时不是线性可预测的（单个文件可能被 Defender 实时扫描拖到几百 ms），
    //   仅靠"限制个数"不足以保证全盘扫描不被拖死。超出预算即停止本轮回退扫描，
    //   剩余候选留给下一轮（进度不丢，只是均摊到多轮）。
    static const ULONGLONG kCpuFallbackBudgetMs = 20000;   // 20 秒上限
    // 注意：不可用 std::min —— <windows.h> 的 min 宏会把它拆坏（C2589/C2059）。
    // 本文件未定义 NOMINMAX，一律用三元表达式，避免与宏冲突。
    const size_t scanN = (onGpu || cands.size() <= kCpuFallbackCands)
                         ? cands.size() : kCpuFallbackCands;
    if (!onGpu && cands.size() > kCpuFallbackCands)
        sf::LogDbg("[gpu] CPU 回退限流：本轮只做 " + std::to_string(kCpuFallbackCands) +
                   "/" + std::to_string(cands.size()) + " 个候选（避免拖死全盘扫描）");
    const ULONGLONG cpuStart = GetTickCount64();
    size_t doneN = 0;
    for (size_t i = 0; i < scanN; ++i) {
        // 未走 GPU 时才检查预算（GPU 路径是整批提交，不存在逐文件膨胀）
        if (!onGpu && (doneN & 0x3F) == 0 && GetTickCount64() - cpuStart >= kCpuFallbackBudgetMs) {
            sf::LogDbg("[gpu] CPU 回退超时：本轮已处理 " + std::to_string(doneN) + "/" +
                       std::to_string(scanN) + " 个候选，剩余留待下一轮");
            break;
        }
        ++doneN;
        bool hit = onGpu ? hits[i] : HasSilverFoxStringCached(cands[i]);
        if (!hit || IsSelfArtifact(cands[i])) continue;
        bool dup = false;
        {
            std::lock_guard<std::mutex> lk(g_resultMutex);
            for (const auto& f : g_result.findings)
                if (f.path == cands[i]) { dup = true; break; }
        }
        if (dup) continue;
        bool isPe = HasPeMagic(cands[i]);
        if (isPe) {
            AddFileFinding(r, "高", "深度扫描命中银狐家族特征",
                "深度内容扫描：可执行文件 " + cands[i] + " 命中银狐家族特征字节串（Gh0st/Win0s 系 C2 握手/RC4 密钥），疑似改名落地的银狐载荷。",
                basename(cands[i]), cands[i]);
        } else {
            // 非 PE（脚本/文本）命中家族串：文本里出现 Gh0st/Win0s 系串几乎必然是检测代码、
            // 安全文献或项目备份的引用（自家扩展源码/备份即被扫对象），对信誉无信号价值——
            // 彻底静默，不记任何 finding，环境检测面板零噪音（实测教训：background.js 被标）。
            sf::LogDbg("[gpu] non-PE family-string hit ignored: " + cands[i]);
        }
    }
}

// 伴随 DLL 扫描：银狐的载荷形态常见是「宿主 EXE + 同目录恶意 DLL」，且 DLL 会被重新下载。
// 对已判定为可疑的每个文件，枚举其所在目录里的 DLL 一并标记为可清除目标——
// 否则只删 EXE 会留下 DLL 残留，样本可被重新拉起。
// 已知合法运行库白名单：Electron/Chromium（OmniMorphix 等自带）、VS 运行时等
// 这些 DLL 即便与可疑样本同目录也是正常交付物，不应被连坐为「同目录 DLL 载荷」。
static bool IsKnownRuntimeLib(const std::string& base) {
    static const char* kLibs[] = {
        "vk_swiftshader.dll", "vulkan-1.dll", "dxil.dll", "dxcompiler.dll",
        "d3dcompiler_47.dll", "ffmpeg.dll", "libegl.dll", "libglesv2.dll",
        "d3dcompiler_43.dll", "vcruntime140.dll", "vcruntime140_1.dll",
        "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll", "concrt140.dll",
        "user32.dll", "kernel32.dll", "ole32.dll", "gdi32.dll", "shell32.dll",
    };
    for (const char* k : kLibs) if (base == k) return true;
    return false;
}
static void ScanCompanionDlls(ScanResult& r) {
    std::set<std::string> dirs;
    for (const auto& f : r.findings) {
        if (f.category != "文件" || f.path.empty()) continue;
        // 只跟随「强样本类」发现去找伴随 DLL；ADS/属性等旁证（severity=低/中 的旁证条目）绝不连坐，
        // 否则剪映(JianyingPro)/VS 等正常软件的私有流文件会把同目录上百个 DLL 一起标记成载荷（真实误报）。
        // 跟随名单 = 双后缀 / 随机名落地 / 已知路径 / 超隐藏随机名 / 随机驱动 / 随机 DLL / 畸形名 / 标记文件
        if (f.severity != "高") continue;
        static const char* strongTitles[] = {
            "发现双后缀诱饵文件", "发现银狐可疑文件路径", "发现随机名可执行文件",
            "发现银狐标记文件", "发现超隐藏文件（隐藏+系统属性）",
            "发现随机名驱动文件", "发现随机名 DLL 模块", "发现畸形文件名（结尾空格/点）",
        };
        bool strong = false;
        for (const char* t : strongTitles) if (f.title == t) { strong = true; break; }
        if (!strong) continue;
        if (!IsExecLikeExt(to_lower(f.path))) continue;
        std::string d = dirname(f.path);
        if (!d.empty()) dirs.insert(d);
    }
    for (const auto& d : dirs) {
        std::error_code ec;
        try {
            for (auto it = fs::directory_iterator(d, fs::directory_options::skip_permission_denied, ec);
                 it != fs::directory_iterator(); ++it) {
                std::error_code e2;
                if (!it->is_regular_file(e2)) continue;
                std::string p = it->path().string();
                std::string base = to_lower(basename(p));
                if (!ci_ends_with(base, ".dll")) continue;
                if (IsSelfArtifact(p)) continue;
                if (IsKnownRuntimeLib(base)) continue;   // 合法运行库不连坐
                bool dup = false;
                for (const auto& f : r.findings) if (f.path == p) { dup = true; break; }
                if (dup) continue;
                AddFileFinding(r, "高", "发现同目录 DLL 载荷",
                    "DLL " + p + " 与已判定的可疑样本同目录，疑似银狐释放的载荷模块，需与样本一并清除。", base, p);
            }
        } catch (...) {}
    }
}
// 文件扫描入口。quickScan=true 表示「清除预扫」：秒级，不重做全盘，只扫
// ①常规高价值落点 ②extraDirs（上一轮全盘扫描已发现的可疑样本所在目录，深层样本也跑不掉）。
static void ScanFiles(ScanResult& r, bool quickScan = false, const std::set<std::string>* extraDirs = nullptr) {
    // 定点文件
    for (size_t i = 0; i < iocs::WATCH_FILES_N; ++i) {
        if (fs::exists(iocs::WATCH_FILES[i])) {
            if (IsSelfArtifact(iocs::WATCH_FILES[i])) continue;
            std::string frag = basename(iocs::WATCH_FILES[i]);
            std::string sev = (ci_contains(frag, "nvsc") || ci_contains(frag, "temp.key") || ci_contains(frag, "xfolder32")) ? "高" : "中";
            AddFileFinding(r, sev, "发现银狐标记文件",
                "检测到 " + std::string(iocs::WATCH_FILES[i]), frag, iocs::WATCH_FILES[i]);
        }
    }

    // ---- 清除预扫（quickScan）：只扫高价值落点 + 上次全盘已发现样本的所在目录，秒级返回，不做全盘 ----
    if (quickScan) {
        std::set<std::string> qd;
        for (size_t i = 0; i < iocs::WATCH_DIRS_N; ++i) qd.insert(iocs::WATCH_DIRS[i]);
        char tp[MAX_PATH]{};
        if (GetTempPathA(MAX_PATH, tp) && tp[0]) qd.insert(std::string(tp));   // Temp 顶层
        DWORD qdrives = GetLogicalDrives();
        for (char c = 'A'; c <= 'Z'; ++c) {
            if (!(qdrives & (1 << (c - 'A')))) continue;
            std::string root = std::string(1, c) + ":\\";
            if (GetDriveTypeA(root.c_str()) != DRIVE_FIXED) continue;
            std::error_code uec;
            std::string users = root + "Users";
            if (fs::exists(users, uec)) {
                try {
                    for (auto it = fs::directory_iterator(users, uec); it != fs::directory_iterator(); ++it) {
                        if (!it->is_directory(uec)) continue;
                        std::string u = it->path().string();
                        qd.insert(u + "\\Desktop");
                        qd.insert(u + "\\Downloads");
                        // 用户 Temp 必须显式纳入（银狐随机名落地主战场）。服务进程的 GetTempPathA
                        // 指向系统 C:\Windows\Temp 而非用户 Temp，只有显式加进来才扫得到。
                        qd.insert(u + "\\AppData\\Local\\Temp");
                    }
                } catch (...) {}
            }
        }
        // 上一轮全盘扫描已发现的样本目录：定点深扫（覆盖藏在深层文件夹里的样本，秒级）
        if (extraDirs) for (const auto& d : *extraDirs) if (!d.empty()) qd.insert(d);

        // 盘根表层文件补扫：目录递归不覆盖磁盘根的表层文件，银狐喜欢直接丢盘根
        for (char c = 'A'; c <= 'Z'; ++c) {
            if (!(qdrives & (1 << (c - 'A')))) continue;
            std::string root = std::string(1, c) + ":\\";
            if (GetDriveTypeA(root.c_str()) != DRIVE_FIXED) continue;
            std::error_code rec;
            try {
                for (auto it = fs::directory_iterator(root, rec); it != fs::directory_iterator(); ++it) {
                    std::error_code fe;
                    if (it->is_regular_file(fe)) AddPathFinding(r, it->path().string());
                }
            } catch (...) {}
        }

        const size_t qBudget = 8000;        // 普通落点（Desktop/Downloads/Public）预算
        const size_t qExtraBudget = 60000;   // 定点目录/用户 Temp 预算：Temp 3 万+ 文件也全扫不截断
        uint64_t extraTick = 0;
        for (const auto& d : qd) {
            std::string dlow = to_lower(d);
            bool isExtra = (extraDirs && extraDirs->count(d)) ||
                           ci_contains(dlow, "\\appdata\\local\\temp");
            size_t budget = isExtra ? qExtraBudget : qBudget;
            std::error_code ec;
            if (!fs::exists(d, ec)) continue;
            try {
                for (auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, ec);
                     it != fs::recursive_directory_iterator() && budget > 0; ++it, --budget) {
                    if (!isExtra && it.depth() >= 2) { it.disable_recursion_pending(); continue; }
                    std::error_code e2;
                    if (it->is_regular_file(e2)) AddPathFinding(r, it->path().string());
                    if (isExtra && (++extraTick & 1023) == 0) Sleep(1);   // Temp 大目录也微节流
                }
            } catch (...) {}
        }
        {   // 调试日志：快扫发现了哪些目标
            std::string dbg;
            std::lock_guard<std::mutex> lk(g_resultMutex);
            for (const auto& f : r.findings) dbg += "|" + f.category + ": " + f.title;
            sf::LogDbg("[quickscan] findings" + dbg);
        }
        return;   // 清除预扫到此为止
    }

    // 系统目录内的「同名系统 DLL」二进制基线校验：System32 / SysWOW64 中出现的
    // 名单 DLL（dbghelp/version/winhttp/…）应是与 WinSxS 原版逐字节一致的硬链接；
    // 若不一致 = 系统组件被替换/注入伪 DLL（银狐常见手法），判高危。
    // 此规则只看二进制内容（SHA-256 与 WinSxS 比对），不依赖签名、不依赖目录名。
    {
        const char* sysDirs[] = {
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64",
        };
        for (const char* sd : sysDirs) {
            for (size_t i = 0; i < iocs::HIJACK_DLLS_N; ++i) {
                std::string p = std::string(sd) + "\\" + iocs::HIJACK_DLLS[i];
                std::error_code ec;
                if (!fs::exists(p, ec)) continue;
                if (IsSystemDirDllTrusted(p)) continue;   // 带有效微软签名 → 真系统组件
                AddFileFinding(r, "高", "系统组件疑似被篡改/注入",
                    "系统目录中的 " + p + " 与本机 WinSxS 原版内容不一致，疑似被银狐替换为伪造 DLL。", iocs::HIJACK_DLLS[i], p);
            }
        }
    }

    g_scanDone.store(0);
    WriteScanProgress("collect", 0, "");

    // ---- P5：可选 GPU 深度内容扫描开关（默认关；开启才做候选收集，零成本直通）----
    const bool gpuCollect = compute::IsGpuEnabled();
    std::atomic<uint64_t> gpuTick{ 0 };

    // 收集扫描目录：真正全盘（银狐载荷可藏在任意深度的目录里，浅层会被绕过）。
    // 排除：系统/程序热区（Windows、Program Files*、ProgramData、回收站等，IsSystemDirName）+
    // 浏览器/应用缓存目录（IsCacheDirName，百万级文件无检测价值）。
    // 遍历+判定用 4 线程并行 + BELOW_NORMAL 优先级 + 微节流：既有全盘覆盖，CPU 又不会被拉满。
    std::vector<std::string> dirs;
    for (size_t i = 0; i < iocs::WATCH_DIRS_N; ++i) dirs.push_back(iocs::WATCH_DIRS[i]);   // 静态兜底

    DWORD drives = GetLogicalDrives();
    for (char c = 'A'; c <= 'Z'; ++c) {
        if (!(drives & (1 << (c - 'A')))) continue;
        std::string root = std::string(1, c) + ":\\";
        if (GetDriveTypeA(root.c_str()) != DRIVE_FIXED) continue;   // 只扫固定磁盘，跳过 U盘/光驱/网络盘
        std::error_code rec;
        try {
            for (auto it = fs::directory_iterator(root, rec); it != fs::directory_iterator(); ++it) {
                std::error_code de;
                if (!it->is_directory(de)) {
                    // 盘根表层文件补扫：银狐常把载荷直接丢在磁盘根（D:\\evil.exe 类），
                    // 目录收集只入队目录、不覆盖表层文件，必须在此直接判定，否则盘根样本漏扫。
                    std::error_code fe;
                    if (it->is_regular_file(fe)) AddPathFinding(r, it->path().string());
                    continue;
                }
                std::string full = it->path().string();
                std::string name = to_lower(basename(full));
                if (name == "users") {
                    // Users 是主战场：把每个用户目录的【一级子目录】分别加入扫描队列，
                    // 每个子目录独立预算（见下方 perDirBudget）——若把整个用户目录当一块，
                    // AppData 等超大目录会耗尽预算，导致 Temp/桌面里的样本排在截断区后被漏扫
                    // （表现即：启动 QuickScan 检出 warning，紧接着 FullScan 却得出 normal，
                    //  误弹「环境已恢复正常」而样本其实还在）。
                    std::error_code uec;
                    try {
                        for (auto u = fs::directory_iterator(full, uec); u != fs::directory_iterator(); ++u) {
                            std::error_code ue2;
                            if (!u->is_directory(ue2)) continue;
                            std::string udir = u->path().string();
                            bool addedAny = false;
                            std::error_code sec;
                            try {
                                for (auto sub = fs::directory_iterator(udir, sec); sub != fs::directory_iterator(); ++sub) {
                                    std::error_code se2;
                                    if (!sub->is_directory(se2)) continue;
                                    dirs.push_back(sub->path().string());
                                    addedAny = true;
                                }
                            } catch (...) {}
                            if (!addedAny) dirs.push_back(udir);   // 列不出子目录（权限）→ 整体兜底
                        }
                    } catch (...) {}
                    continue;
                }
                if (IsSystemDirName(name)) continue;
                dirs.push_back(full);              // 其余一级目录整体深度递归
            }
        } catch (...) {}
    }

    // 收集完成统计（调试用：确认全盘覆盖了哪些目录；"扫不出来"时先看这里）
    {   std::string dbg;
        for (size_t i = 0; i < dirs.size() && i < 40; ++i) dbg += "|" + dirs[i];
        sf::LogDbg("[fullscan] collected " + std::to_string(dirs.size()) + " dirs:" + dbg);
    }

    // 多线程并行遍历 + 判定（AddPathFinding 内判定无锁，findings push 由 AddFileFinding 加锁）
    const unsigned kThreads = 4;                   // 控制在 4 线程：不 8 线程吃满，配合节流压 CPU
    const size_t perDirBudget = 60000;             // 普通目录预算（银狐藏匿在超大目录时也尽量全扫）
    const size_t tempBudget   = 100000;            // Temp 3 万+ 文件也全扫（银狐落地高发区）
    {
        std::atomic<size_t> next{0};
        std::vector<std::thread> tv;
        tv.reserve(kThreads);
        for (unsigned t = 0; t < kThreads; ++t) {
            tv.emplace_back([&]() {
                SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);  // 低优先级，不抢用户体验
                uint64_t tick = 0;
                while (true) {
                    size_t i = next.fetch_add(1);
                    if (i >= dirs.size()) break;
                    const std::string& d = dirs[i];
                    std::string dl = to_lower(d);
                    size_t budget = (ci_contains(dl, "\\appdata\\local\\temp") ||
                                     dl.size() >= 5 && dl.compare(dl.size() - 5, 5, "\\temp") == 0)
                                        ? tempBudget : perDirBudget;
                    std::error_code ec;
                    if (!fs::exists(d, ec)) continue;
                    try {
                        for (auto it = fs::recursive_directory_iterator(d, fs::directory_options::skip_permission_denied, ec);
                             it != fs::recursive_directory_iterator() && budget > 0; ++it, --budget) {
                            std::error_code e2;
                            if (it->is_directory(e2)) {
                                std::string dn = to_lower(it->path().filename().string());
                                if (IsCacheDirName(dn)) { it.disable_recursion_pending(); continue; }
                                continue;
                            }
                            if (it->is_regular_file(e2)) {
                                AddPathFinding(r, it->path().string());
                                // 扫描进度：每 256 文件落盘一次（0 表示总文件数未知，前端按已扫描量展示）
                                long long dn = g_scanDone.fetch_add(1) + 1;
                                if ((dn & 255) == 0)
                                    WriteScanProgress("files", dn, it->path().string());
                                // 采样采集（每 8 个文件判一次），候选在收尾统一批量过 GPU
                                if (gpuCollect && (++gpuTick & 7) == 0)
                                    MaybePushContentCandidate(it->path().string());
                            }
                            // 微节流：每 256 个文件让出 1ms，防止 4 线程把 CPU 拉满
                            if ((++tick & 255) == 0) Sleep(1);
                        }
                    } catch (...) {}
                }
            });
        }
        for (auto& th : tv) th.join();
    }

    WriteScanProgress("done", g_scanDone.load(), "");
    // 收尾：补扫「与可疑样本同目录的 DLL 载荷」（银狐常用宿主 EXE + 同目录恶意 DLL，删 EXE 不够）
    ScanCompanionDlls(r);
    // 收尾：GPU 深度内容扫描（未启用/Fast scan 不经过此路径）
    if (gpuCollect) FinishContentScan(r);
}

// ---------------------------------------------------------------------------
//  模块 6：Defender 排除项扫描
// ---------------------------------------------------------------------------
static void ScanDefender(ScanResult& r) {
    const char* keys[] = {
        "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths",
        "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes",
        "SOFTWARE\\WOW6432Node\\Microsoft\\Windows Defender\\Exclusions\\Paths",
    };
    for (const char* sub : keys) {
        HKEY hk;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) continue;
        DWORD n = 0, mn = 256, md = 4096;
        RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &n, &mn, &md, nullptr, nullptr);
        mn = mn < 256 ? 256 : mn + 1; md = md < 256 ? 256 : md + 1;
        for (DWORD i = 0; i < n; ++i) {
            std::vector<char> vn(mn + 1); DWORD vnS = (DWORD)vn.size(), type = 0;
            if (RegEnumValueA(hk, i, vn.data(), &vnS, nullptr, &type, nullptr, nullptr) != ERROR_SUCCESS) continue;
            std::string name(vn.data()); std::string low = to_lower(name);
            bool hit = false; std::string frag;
            for (size_t k = 0; k < iocs::PATH_FRAGMENTS_N; ++k)
                if (ci_contains(low, iocs::PATH_FRAGMENTS[k])) { hit = true; frag = iocs::PATH_FRAGMENTS[k]; break; }
            if (!hit) for (size_t k = 0; k < iocs::DOUBLE_EXT_N; ++k)
                if (ci_contains(low, iocs::DOUBLE_EXT[k])) { hit = true; frag = iocs::DOUBLE_EXT[k]; break; }
            if (hit)
                r.findings.push_back({"Defender", "中", "Defender 排除项指向可疑路径",
                    "Defender 排除项：" + name, frag});
        }
        RegCloseKey(hk);
    }
}

// ---------------------------------------------------------------------------
//  模块 6.5：hosts 文件劫持扫描（安全软件/防护域名被指向本地）
// ---------------------------------------------------------------------------
static void ScanHosts(ScanResult& r) {
    char win[MAX_PATH] = {0};
    if (!GetWindowsDirectoryA(win, MAX_PATH)) return;
    std::string path = std::string(win) + "\\System32\\drivers\\etc\\hosts";
    std::ifstream f(path);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        // 去掉行尾注释（hosts 注释以 # 起）
        size_t h = line.find('#');
        if (h != std::string::npos) line = line.substr(0, h);
        // 按空白切分 token：首个为 IP，其余为 hostname
        std::istringstream iss(line);
        std::vector<std::string> tok;
        std::string t;
        while (iss >> t) tok.push_back(t);
        if (tok.size() < 2) continue;
        std::string ip = to_lower(tok[0]);
        // 只关心被导向「本地 / 零路由」的屏蔽写法（127.0.0.1 / ::1 / 0.0.0.0）
        bool loopback = (ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0");
        if (!loopback) continue;
        for (size_t j = 1; j < tok.size(); ++j) {
            std::string host = to_lower(tok[j]);
            for (size_t k = 0; k < iocs::PROTECTED_DOMAINS_N; ++k) {
                std::string dom = to_lower(std::string(iocs::PROTECTED_DOMAINS[k]));
                if (host == dom || ci_ends_with(host, "." + dom)) {
                    r.findings.push_back({"hosts", "高", "hosts 将安全软件域名指向本地",
                        "hosts 条目 [" + tok[0] + " " + tok[j] + "]：将防护/更新域名导向本地，疑似屏蔽安全软件告警与更新（银狐常见手法）。",
                        tok[j]});
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  模块 7：WMI 事件订阅扫描
// ---------------------------------------------------------------------------
static void ScanWmi(ScanResult& r) {
    ComInit ci;
    IWbemLocator* loc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&loc))) return;
    IWbemServices* svc = nullptr;
    BSTR ns = SysAllocString(L"ROOT\\subscription");
    if (FAILED(loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc))) { SysFreeString(ns); loc->Release(); return; }
    SysFreeString(ns);
    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    // __EventFilter
    BSTR q = SysAllocString(L"SELECT Name,Query FROM __EventFilter");
    IEnumWbemClassObject* en = nullptr;
    if (SUCCEEDED(svc->ExecQuery(_bstr_t(L"WQL"), q, WBEM_FLAG_FORWARD_ONLY, nullptr, &en)) && en) {
        IWbemClassObject* obj = nullptr; ULONG ret = 0;
        while (en->Next(WBEM_INFINITE, 1, &obj, &ret) == S_OK && ret) {
            VARIANT vn, vq; VariantInit(&vn); VariantInit(&vq);
            obj->Get(L"Name", 0, &vn, nullptr, nullptr);
            obj->Get(L"Query", 0, &vq, nullptr, nullptr);
            std::wstring wn = (vn.vt == VT_BSTR && vn.bstrVal) ? std::wstring(vn.bstrVal) : L"";
            std::wstring wq = (vq.vt == VT_BSTR && vq.bstrVal) ? std::wstring(vq.bstrVal) : L"";
            std::string blob = to_lower(wtoa(wn) + "|" + wtoa(wq));
            for (size_t k = 0; k < iocs::WMI_FILTER_FRAGMENTS_N; ++k) {
                if (ci_contains(blob, iocs::WMI_FILTER_FRAGMENTS[k])) {
                    r.findings.push_back({"WMI", "中", "发现可疑 WMI 事件订阅",
                        "WMI __EventFilter 命中可疑片段（持久化/监控）。", iocs::WMI_FILTER_FRAGMENTS[k]});
                    break;
                }
            }
            VariantClear(&vn); VariantClear(&vq); obj->Release();
        }
        en->Release();
    }
    SysFreeString(q);
    svc->Release(); loc->Release();
}

// ---------------------------------------------------------------------------
//  模块 8：可疑服务扫描（银狐常用服务持久化，ImagePath 指向随机名/可疑 exe）
// ---------------------------------------------------------------------------
static void ScanServices(ScanResult& r) {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
    DWORD nSub = 0;
    RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr, &nSub, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
    std::vector<char> name(256 + 1);
    for (DWORD i = 0; i < nSub; ++i) {
        DWORD ns = (DWORD)name.size();
        if (RegEnumKeyA(hk, i, name.data(), ns) != ERROR_SUCCESS) continue;
        std::string svcName(name.data());
        std::string sub = std::string("SYSTEM\\CurrentControlSet\\Services\\") + svcName;
        HKEY hks;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hks) != ERROR_SUCCESS) continue;
        char img[1024] = {0}; DWORD imgs = sizeof(img);
        if (RegQueryValueExA(hks, "ImagePath", nullptr, nullptr, (LPBYTE)img, &imgs) == ERROR_SUCCESS && img[0]) {
            std::string raw = img;
            // 跳过驱动（.sys）——内核驱动数不胜数，不参与 exe 启发式判定
            if (ci_contains(to_lower(raw), ".sys")) { RegCloseKey(hks); continue; }
            std::string exePath = ExtractExePath(raw);
            std::string lp = to_lower(exePath);
            // 跳过系统目录里的服务（System32 / SysWOW64 / \Windows\ / SystemRoot / WinSxS）
            if (ci_contains(lp, "\\system32\\") || ci_contains(lp, "\\syswow64\\") ||
                ci_contains(lp, "systemroot") || ci_contains(lp, "\\windows\\") ||
                ci_contains(lp, "\\winsxs\\")) { RegCloseKey(hks); continue; }
            if (IsSelfArtifact(exePath)) { RegCloseKey(hks); continue; }
            if (IsSuspExe(exePath)) {
                r.findings.push_back({"服务", "高", "可疑服务指向随机名可执行文件",
                    "服务 " + svcName + " 的 ImagePath 指向 " + exePath + "（随机名落地，疑似银狐服务持久化）。", svcName});
            } else {
                for (size_t k = 0; k < iocs::PATH_FRAGMENTS_N; ++k) {
                    if (ci_contains(lp, iocs::PATH_FRAGMENTS[k])) {
                        r.findings.push_back({"服务", "高", "可疑服务指向银狐特征路径",
                            "服务 " + svcName + " 的 ImagePath 指向 " + exePath, iocs::PATH_FRAGMENTS[k]});
                        break;
                    }
                }
            }
        }
        RegCloseKey(hks);
    }
    RegCloseKey(hk);
}

// ---------------------------------------------------------------------------
//  评分引擎：权重 + 两级阈值 + 铁证直判
//  设计目标：
//   1) 铁证（已知 C2 活跃连接 / 已知银狐进程名 / 银狐标记文件）
//      不可辩驳，任一项命中直接判 infected，用独立 hardProof 布尔标记，不靠夸张权重。
//   2) 其余强信号（DLL 侧加载 / AppInit_DLLs / 启动项 / 双后缀诱饵 / 可疑路径）
//      按「等级基线 高=60 中=30 低=10 + 上下文微调」赋权，单条最高 60，
//      需多条叠加才突破 INFECTED_THRESHOLD，避免“一项高危就报异常”。
//   3) 弱信号（TEMP 随机名 exe / Defender 被关 / 排除项 / 计划任务 / WMI）
//      权重更低（15~30），需多条累积才达预警或确诊。
//  阈值：WARNING=60（单条高级即可预警），INFECTED=120（需叠加或铁证）。
// ---------------------------------------------------------------------------
static const int WARNING_THRESHOLD  = 60;    // 达此分：预警（warning）—— 任意单条“高”级信号即可触发
static const int INFECTED_THRESHOLD = 120;   // 达此分：确诊感染（infected）—— 需多条信号叠加，或命中铁证
static const int MAX_SCORE          = 200;   // 风险分封顶：任何误报爆发都压得住，避免分数再冲上万

static int WeightOf(const Finding& f) {
    // 等级基线：高=60 / 中=30 / 低=10。铁证（C2/已知进程/标记文件）由 hardProof 单独判定，
    // 这里只给一个封顶展示权重（=60），不进入堆叠比较，避免分数夸张跳变。
    int base = (f.severity == "高") ? 60 : (f.severity == "中") ? 30 : 10;

    if (f.category == "进程") {
        if (f.title == "合法程序被利用进行 DLL 侧加载") return 60;  // 高基线：强但非铁证
        if (f.title == "进程为双后缀诱饵程序")          return 30;  // 中基线
        if (f.title == "进程路径含银狐可疑片段")        return 45;  // 高于中基线：精确路径命中
        if (f.title == "TEMP 目录存在随机名可执行文件") return 15;  // 弱信号（中等级但常见误报）
        return base;
    }
    if (f.category == "注册表") {
        if (f.title == "AppInit_DLLs 被设置")           return 60;  // 高基线：经典注入点
        if (f.title == "启动项指向银狐可疑程序")        return 50;  // 高基线：持久化
        if (f.title == "启动项冒用知名厂商名")          return 60;  // 高基线：银狐伪装厂商名
        if (f.title == "启动项指向随机名可执行文件")    return (f.severity == "高") ? 50 : 30;
        if (f.title == "Windows Defender 被禁用")       return 25;  // 中基线但可能用户自关
        if (f.title == "Windows Defender 实时防护已关闭") return 25;  // 同量级：真实开关已关
        if (f.title == "Windows Defender 服务被禁用")    return 25;  // 同量级：服务被禁
        if (f.title == "Windows Defender 篡改防护已关闭") return 25;  // 同量级：篡改防护被关
        return base;
    }
    if (f.category == "文件") {
        if (f.title == "发现双后缀诱饵文件")            return 30;  // 中基线
        if (f.title == "发现银狐可疑文件路径")          return (f.severity == "高") ? 60 : 30;
        if (f.severity == "低")                          return 10;  // 旁证类（ADS/属性旁证）：弱信号，不参与判危
        return base;
    }
    if (f.category == "进程") {
        if (f.title == "随机名进程位于可疑落地目录")      return 60;  // 高基线：随机名+落地目录强特征
    }
    if (f.category == "Defender") return 20;   // 排除项，可能用户自加
    if (f.category == "计划任务") {
        if (f.title == "计划任务动作指向随机名可执行文件") return (f.severity == "高") ? 50 : 30;
        if (f.title == "计划任务名为随机串")            return 30;
        return 30;
    }
    if (f.category == "WMI")      return 30;
    if (f.category == "服务")     return 50;   // 服务持久化是强信号（银狐常见），但非铁证
    if (f.category == "hosts")    return 50;   // 安全软件域名被导向本地，强信号但需结合其他证据
    return base;   // 网络/高 C2 等铁证项 → 统一封顶展示权重，不堆叠
}

// ---------------------------------------------------------------------------
//  评分引擎入口：按证据强度赋权重累加为风险分，再经两级阈值收敛为三态。
//  三项原则（2026-09-13 重构，治「分数诡异」）：
//  ① 旁证零贡献：severity=低 的 finding（ADS/属性旁证等）weight=0，只展示不判危；
//  ② 同类只算一次：同一 (category+title) 只取最高权重计一次，其余同类 weight=0——
//     3 个 Dbghelp 侧加载 ≈ 1 个，10 个随机名 exe 不把分数乘 10；
//  ③ 分数封顶：总和不超 MAX_SCORE（200），任何误报单项爆发都压得住。
//  （全量扫描与清除预扫共用；多线程扫描子模块完成后由单个线程统一调用）
static void RankResult(ScanResult& r) {
    int total = 0;
    {
        std::set<std::string> counted;   // 已计分的 (category|title)
        for (auto& f : r.findings) {
            int w = WeightOf(f);
            if (f.severity == "低") w = 0;                    // ① 旁证零贡献
            std::string key = f.category + "|" + f.title;
            if (!counted.insert(key).second) w = 0;            // ② 同类只算一次
            f.weight = w;
            // ④ 等级归位：权重 0 的「低」级旁证（ADS/属性旁证等）只是警示、不参与判危，
            //    展示层归入「警告」级（扩展端按等级分组折叠）。
            //    注意：仅降「低」级旁证——同类重复的高危项不改级（连坐跟随按 severity=="高"
            //    找伴随 DLL，降级会让第二个目录的主样本漏连坐）。
            if (w == 0 && f.severity == "低") f.severity = "警告";
            total += w;
        }
        if (total > MAX_SCORE) total = MAX_SCORE;              // ③ 封顶
    }

    // 铁证判定：以下任一项命中即直接判 infected（不依赖权重堆叠，
    // 对应“一项高危即报异常”中真正不可辩驳的情形；其余强信号需叠加才确诊。
    bool hardProof = false;
    for (auto& f : r.findings) {
        if (f.category == "网络" && f.title == "检测到与银狐 C2 的活跃连接") hardProof = true;
        else if (f.category == "进程" && f.title == "发现已知银狐木马进程")    hardProof = true;
        else if (f.category == "文件" && f.title == "发现银狐标记文件")        hardProof = true;
    }

    r.score = total;
    r.hardProof = hardProof;
    // 两级阈值 + 铁证直判：先达 WARNING（预警），再达 INFECTED（确诊感染），铁证直接判危
    if (hardProof)                         r.status = "infected";
    else if (total >= INFECTED_THRESHOLD)  r.status = "infected";
    else if (total >= WARNING_THRESHOLD)   r.status = "warning";
    else                                   r.status = "normal";
}

// ---------------------------------------------------------------------------
//  总入口
// ---------------------------------------------------------------------------
// 扫描互斥：全盘/快速扫描【同一时刻只允许一个】在跑。触发源众多（服务启动双段自检、
// NM rescan、定时扫描、清除预扫/复查），若不互斥，4 线程×N 个全盘并发会把 CPU 吃满。
// RunFullScan 与 RunQuickScan 共享这把锁 → 天然串行，后到者等待先到的完成。
static std::mutex g_scanMtx;

void RunFullScan() {
    std::lock_guard<std::mutex> lk(g_scanMtx);
    g_adsBudget = 4000;   // 每个扫描周期重置 ADS 探测预算（避免慢盘上把整体扫描拖长）
    ScanResult r;
    r.engine = iocs::ENGINE_VERSION;
    r.timestamp = now_string();
    try {
        ScanProcesses(r);
        ScanHostProcessInjection(r);
        ScanRegistry(r);
        ScanServices(r);
        ScanScheduledTasks(r);
        ScanNetwork(r);
        ScanFiles(r);
        ScanDefender(r);
        ScanHosts(r);
        ScanWmi(r);
    } catch (const std::exception& e) {
        r.error = std::string("扫描异常: ") + e.what();
    } catch (...) {
        r.error = "扫描发生未知异常";
    }
    RankResult(r);

    {
        std::lock_guard<std::mutex> lkResult(g_resultMutex);
        g_result = std::move(r);
    }
}

// ---------------------------------------------------------------------------
//  快速清除预扫（clean 前置）：仅扫描与清除相关的两个模块（进程 + 文件），跳过 WMI /
//  Defender / 网络 / 计划任务 / 服务 / 注册表等慢模块——那些模块只产生展示类 finding，
//  不影响「能清什么」。用于清理前保证 target 收集基于最新现场，时间从全量 ~20 秒降到秒级
//  （老旧机器上差异更大）。
//
//  ⚠️ 2026-09-19 重要区分：本函数**会做磁盘遍历**（ScanFiles 的 quick 分支要递归
//  Desktop/Downloads/Temp 等落点），因此**只允许在「清除前预扫」这一条路径上调用**。
//  定时器请改用 RunGuardTick()——否则每 3 分钟就是一轮 6 万文件级全盘遍历
//  （实测该误用导致 fullscan 间隔退化为 4~6 分钟，即"上轮没跑完相位已到期"）。
// ---------------------------------------------------------------------------
void RunQuickScan() {
    // 与 RunFullScan 共用同一把互斥锁：清除预扫也绝不与全盘扫描（或另一个清除预扫）并发，
    // 保证「同一时刻服务内只有一个扫描在跑」，多客户端同时触发 clean 时天然串行排队。
    std::lock_guard<std::mutex> lk(g_scanMtx);
    g_adsBudget = 4000;
    // 快照上一轮扫描（含全盘）已发现样本的所在目录：清除预扫直接盯住这些目录定点深扫，
    // 不重做全盘——既与展示同源（深层文件夹样本也清得到），又秒级完成。
    std::set<std::string> sampleDirs;
    {
        std::lock_guard<std::mutex> lk(g_resultMutex);
        for (const auto& f : g_result.findings) {
            if ((f.category == "文件" || f.category == "进程") && !f.path.empty())
                sampleDirs.insert(dirname(f.path));
        }
    }
    ScanResult r;
    r.engine = iocs::ENGINE_VERSION;
    r.timestamp = now_string();
    try {
        ScanProcesses(r);
        ScanHostProcessInjection(r);      // 注入检测同样是清除目标来源（进程模块）
        ScanFiles(r, true, &sampleDirs);   // 清除预扫：常规落点 + 上次样本目录定点深扫
    } catch (const std::exception& e) {
        r.error = std::string("扫描异常: ") + e.what();
    } catch (...) {
        r.error = "扫描发生未知异常";
    }
    RankResult(r);

    {
        std::lock_guard<std::mutex> lk(g_resultMutex);
        g_result = std::move(r);
    }
}

// ---------------------------------------------------------------------------
//  轻量巡检（定时器专用，秒级、**零磁盘遍历**）
// ---------------------------------------------------------------------------
//  职责划分（2026-09-19 重构）：
//    · RunGuardTick()  ← 定时器（每 3 分钟）：进程 + 注入 + 注册表 + 服务 + 计划任务
//                        纯内存 / 注册表读取，无目录递归，CPU 与磁盘占用可忽略。
//    · RunFullScan()   ← 定时器（每 6 小时）：上面全部 + ScanFiles 文件遍历
//                        **全系统唯一做磁盘遍历的路径**。
//    · RunQuickScan()  ← 仅「清除前预扫」：需要现场样本目录，必须扫盘。
//
//  为什么必须分开：RunQuickScan 会递归 Desktop/Downloads/Temp 等落点（预算 8000/60000，
//  最多 6 万文件），把它接到 3 分钟定时器上 = 每 3 分钟一轮缩水全盘。实测（2026-09-19
//  08:01~08:42 日志）间隔达 4.3~6.3 分钟，且 `[fullscan] collected` 反复出现，正是
//  上一轮尚未跑完、下一轮相位已到期的堆积表现。
//
//  银狐木马的核心投递行为（进程拉起 / 注入 / 注册表自启 / 服务 / 计划任务）全部在
//  本函数覆盖范围内，因此降低巡检频率不会削弱「运行期发现」能力；真正藏文件的样本
//  由 6 小时全盘扫 + 实时监控（WMI 进程创建 / 目录变更）兜住。
// ---------------------------------------------------------------------------
// 风险等级排序（与 service.cpp 的 RiskRank 同语义；那边是 static，此处独立一份取值）
static int GuardTickRiskRank(const std::string& s) {
    if (s == "infected") return 3;
    if (s == "warning")  return 2;
    if (s == "normal")   return 1;
    return 0;
}

void RunGuardTick() {
    std::lock_guard<std::mutex> lk(g_scanMtx);
    ScanResult r;
    r.engine = iocs::ENGINE_VERSION;
    r.timestamp = now_string();
    try {
        ScanProcesses(r);
        ScanHostProcessInjection(r);
        ScanRegistry(r);
        ScanServices(r);
        ScanScheduledTasks(r);
    } catch (const std::exception& e) {
        r.error = std::string("巡检异常: ") + e.what();
    } catch (...) {
        r.error = "巡检发生未知异常";
    }
    RankResult(r);

    {
        std::lock_guard<std::mutex> lk(g_resultMutex);
        // 合并策略：本轮巡检「已覆盖的类别」用新结果**整体替换**旧结果，
        // 未覆盖的类别（文件 / 网络 / Defender / Hosts / WMI 等由全盘扫产出）保留旧值。
        // 为什么整体替换而不是去重追加：若某进程已退出/已被清除，追加式合并会把它一直
        // 留在列表里（永远清不掉）；整体替换才能真实反映「当前时刻」的进程状态。
        static const char* kCovered[] = { "进程", "注入", "注册表", "服务", "计划任务" };
        auto covered = [&](const std::string& c) {
            for (const char* k : kCovered) if (c == k) return true;
            return false;
        };
        std::vector<Finding> keep;
        for (const auto& f : g_result.findings) {
            // 本轮巡检覆盖的类别（进程/注入/注册表/服务/计划任务）→ 交给下方用新结果替换；
            // 其余类别（文件 / 网络 / Defender / Hosts / WMI / 实时防护 / 自启动）
            // 全盘扫或事件流产出，巡检管不着，原样保留。
            if (covered(f.category)) continue;
            keep.push_back(f);
        }
        for (const auto& f : r.findings) keep.push_back(f);
        // 巡检不改变「文件」结论，故 status/score 取两者中更严的（只升不降）
        if (GuardTickRiskRank(r.status) > GuardTickRiskRank(g_result.status)) {
            g_result.status = r.status;
            g_result.score = r.score;
        }
        g_result.findings = std::move(keep);
        g_result.timestamp = r.timestamp;
    }
}
