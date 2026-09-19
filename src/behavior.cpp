// behavior.cpp — 进程行为判定层实现
//
// ===========================================================================
//  设计依据与取舍（详见 docs/behavior-rules-design.md）
// ===========================================================================
//  结构（对齐业界骨架）：
//    ① 归一化层  —— 抗混淆，让字符串拼接/插入符/全角字符等绕过手法失效
//    ② 硬规则层  —— 只放「正常情况几乎不可能出现」的确凿恶意语义，命中即拦
//    ③ 评分层    —— 多信号加权累加，过阈值才判（Bitdefender ATC 式打分制）
//    ④ 信誉层    —— 签名/可信路径**调权重**，而非直接放行（卡巴：可信程序跑
//                    不安全代码也要告警 / 白利用）
//
//  抗绕过设计要点（每一条都对应一个已知的绕过手法）：
//    · 归一化后再匹配            → 破 "From"+"Base64" / -e^nc / 全角 ｉｅｘ
//    · 豁免改为身份校验          → 破 往命令行塞 --parent-window= 洗白
//    · 解释器须与参数同现        → 破 单独出现 "downloadstring" 字符串的误命中
//    · 系统名 + 非系统目录       → 破 伪装 svchost.exe（但仍会被改名绕过，
//                                   故这条只是辅助信号，权重低）
//    · 签名只降权不豁免          → 破 白利用（拿签名的正常程序加载恶意 DLL）
//
//  规则阈值：误报比漏报更致命，阈值偏高，宁可漏。
// ===========================================================================
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>

#include "behavior.h"
#include "common.h"

#include <algorithm>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace sf {

// ---------------------------------------------------------------------------
//  小工具
// ---------------------------------------------------------------------------
static std::string Lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c += 32;
    return s;
}
static bool Has(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}
static bool InList(const std::string& v, const char* const* list, size_t n) {
    for (size_t i = 0; i < n; ++i) if (v == list[i]) return true;
    return false;
}
#define IN_LIST(v, arr) InList((v), (arr), sizeof(arr) / sizeof((arr)[0]))

// 字符串是否"看起来随机"（连续辅音过长 / 大小写数字混杂无意义）
// 注意：这条**不单独驱动判定**（历史教训：随机名单独判档会误伤正常库名，
// 如 libGLESv2.dll / aria2c.exe）。只作评分层的一个小权重旁证。
static bool LooksRandomStem(const std::string& stem) {
    if (stem.size() < 5 || stem.size() > 14) return false;
    int letters = 0, digits = 0, upper = 0, lower = 0, vowels = 0;
    int maxConsRun = 0, curConsRun = 0;
    for (char c : stem) {
        if (c >= 'a' && c <= 'z') {
            ++letters; ++lower;
            if (c=='a'||c=='e'||c=='i'||c=='o'||c=='u') { ++vowels; curConsRun = 0; }
            else { if (++curConsRun > maxConsRun) maxConsRun = curConsRun; }
        } else if (c >= 'A' && c <= 'Z') {
            ++letters; ++upper;
            if (c=='A'||c=='E'||c=='I'||c=='O'||c=='U') { ++vowels; curConsRun = 0; }
            else { if (++curConsRun > maxConsRun) maxConsRun = curConsRun; }
        } else if (c >= '0' && c <= '9') { ++digits; curConsRun = 0; }
        else return false;   // 含其它符号 → 不算随机名（正常名也可能带下划线等）
    }
    if (letters < 4) return false;
    // 元音缺失 或 连续辅音 ≥5 → 典型随机串特征
    if (vowels == 0) return true;
    if (maxConsRun >= 5) return true;
    return false;
}

// ---------------------------------------------------------------------------
//  名单：全部来自「正常情况下的必然语义」，不做经验性猜测
// ---------------------------------------------------------------------------

// 脚本/命令宿主 —— 攻击链的必经环节。
// 注意：**不能放 conhost.exe** —— 它是被 cmd 派生的控制台宿主，放进名单必然误报
//（实测本机 4 个 conhost.exe 全被误判，就是这条错误规则导致的）。
static const char* kHosts[] = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "installutil.exe", "msbuild.exe", "forfiles.exe", "pcalua.exe", "wmic.exe",
    "curl.exe", "msiexec.exe", "runonce.exe", "regasm.exe", "regsvcs.exe"
};

// 「不该派生脚本宿主」的父进程 —— 文档 / 聊天 / 浏览器
// 依据：Defender 官方 Pyordono.A 检测（脚本引擎以可疑参数执行 cmd/powershell）
static const char* kOffice[] = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe",
    "wps.exe", "et.exe", "wpp.exe", "acrobat.exe", "acrord32.exe",
    "foxitreader.exe", "foxitpdfreader.exe", "sumatrapdf.exe"
};
static const char* kIm[] = {
    "wechat.exe", "weixin.exe", "qq.exe", "tim.exe", "dingtalk.exe", "feishu.exe",
    "lark.exe", "telegram.exe", "slack.exe", "discord.exe", "skype.exe", "zoom.exe"
};
static const char* kBrowser[] = {
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "360se.exe", "360chrome.exe", "brave.exe", "opera.exe"
};

// 系统关键进程名 —— 出现在非系统目录即为伪装（低误报、中风险）
static const char* kSystemNames[] = {
    "svchost.exe", "lsass.exe", "services.exe", "winlogon.exe", "csrss.exe",
    "smss.exe", "wininit.exe", "dwm.exe", "spoolsv.exe", "fontdrvhost.exe",
    "taskhostw.exe", "explorer.exe", "lsaiso.exe", "sihost.exe",
    "smartscreen.exe", "securityhealthservice.exe", "msmpeng.exe",
    "nissrv.exe", "sppsvc.exe", "wscsvc.exe"
};

// 可信安装目录 —— 这里的程序默认是正常软件（用于**降权**，不是豁免）
static const char* kTrustedDirs[] = {
    "\\program files\\", "\\program files (x86)\\", "\\windows\\system32\\",
    "\\windows\\syswow64\\", "\\windows\\winsxs\\", "\\windows\\microsoft.net\\",
    "\\programdata\\microsoft\\windows defender\\"
};

// 高风险的落地目录 —— 银狐等木马的传统落脚点
static const char* kSuspDirs[] = {
    "\\appdata\\roaming\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\",
    "\\downloads\\", "\\users\\public\\", "\\programdata\\",
    "\\appdata\\locallow\\", "\\$recycle.bin\\"
};

// ---------------------------------------------------------------------------
//  规则表
// ---------------------------------------------------------------------------
struct CmdRule {
    const char* needle;   // 已小写的匹配串（对归一化后的命令行做匹配）
    int         level;    // 0=仅计分（用 score 字段），1=可疑，2=高危
    int         score;    // 评分层权重
    const char* tag;
    const char* reason;
};

// 硬规则：正常情况几乎不可能出现的组合，命中即拦。
// 依据栏见 docs/behavior-rules-design.md。
static const CmdRule kHardRules[] = {
    // ---- 内存加载 / 编码执行（无文件攻击标配）----
    { "frombase64string",       2, 60, "b64",     "Base64 解码执行（FromBase64String），内存加载器标配" },
    { "invoke-expression",      2, 60, "iex",     "IEX 动态执行字符串代码（下载器/加载器常见）" },
    { "iex(",                   2, 60, "iex",     "IEX 动态执行字符串代码" },
    { "[char[]]",               1, 30, "obfusc",  "字符串转字符数组拼接，常见于脚本混淆" },
    { "-join[char",             1, 30, "obfusc",  "字符数组 Join 还原字符串，常见于脚本混淆" },
    { "[convert]::frombase64",  2, 60, "b64",     "Convert::FromBase64String 解码（.NET 加载器）" },
    { "system.reflection.assembly", 2, 55, "loadasm", "反射加载程序集（.NET 内存加载）" },
    { "virtualalloc",           1, 30, "mem",     "内存分配 API 出现在命令行（注入工具）" },
    { "createthread",           1, 30, "mem",     "创建线程 API 出现在命令行（注入工具）" },

    // ---- 远程下载 ----
    { "downloadstring",         2, 55, "dl",      "脚本远程下载（DownloadString）" },
    { "downloadfile",           2, 55, "dl",      "脚本远程下载（DownloadFile）" },
    { "downloaddata",           2, 55, "dl",      "脚本远程下载（DownloadData）" },
    { "invoke-webrequest",      1, 45, "dl",      "脚本远程下载（Invoke-WebRequest）" },
    { "start-bitstransfer",     2, 55, "dl",      "BITS 后台静默下载" },
    { "-urlcache",              2, 60, "dl",      "certutil -urlcache 下载载荷（经典 LOLBin）" },
    { "certutil -decode",       2, 55, "dl",      "certutil 解码还原载荷" },
    { "/transfer",              2, 55, "dl",      "bitsadmin 静默下载载荷" },
    { "mshta http",             2, 60, "mshta",   "mshta 远程执行 HTA 脚本" },
    { "mshta javascript",       2, 60, "mshta",   "mshta 内联脚本执行" },
    { "mshta vbscript",         2, 60, "mshta",   "mshta 内联脚本执行" },
    { "scrobj.dll",             2, 65, "regsvr32","regsvr32 + scrobj.dll 远程脚本（Squiblydoo）" },
    { "scrobj",                 2, 55, "regsvr32","regsvr32 加载脚本对象（Squiblydoo）" },
    { "javascript:",            1, 35, "script",  "javascript: 协议执行脚本" },
    { "vbscript:",              1, 35, "script",  "vbscript: 协议执行脚本" },

    // ---- 隐藏窗口 / 规避察觉 ----
    { "windowstyle hidden",     2, 50, "hidden",  "以隐藏窗口方式执行命令，规避用户察觉" },
    { "windowstyle 1",          1, 25, "hidden",  "以隐藏窗口方式执行命令" },
    { "w hidden",               2, 50, "hidden",  "以隐藏窗口方式执行命令" },

    // ---- 勒索 / 反取证 ----
    { "vssadmin delete shadows", 2, 80, "ransom", "删除卷影副本（勒索行为，明确恶意）" },
    { "vssadmin resize shadowstorage", 1, 40, "ransom", "调整卷影存储大小（勒索准备）" },
    { "wbadmin delete",         2, 70, "ransom",  "删除备份（勒索行为）" },
    { "delete catalog -quiet",  2, 70, "ransom",  "静默删除备份目录（勒索行为）" },
    { "wevtutil cl",            2, 60, "anti",    "清空事件日志（反取证）" },
    { "cipher /w",              1, 30, "anti",    "擦除磁盘空闲空间（反取证）" },
    { "bcdedit",                1, 35, "boot",    "修改启动配置（可能用于破坏恢复模式）" },

    // ---- 持久化 / 提权 ----
    { "schtasks /create",       1, 35, "persist", "创建计划任务（持久化，需结合来源判断）" },
    { "reg add",                1, 25, "persist", "写注册表（需结合键路径判断）" },
    { "/create /tn",            1, 30, "persist", "创建计划任务" },
    { "sc create",              1, 35, "persist", "创建系统服务（持久化）" },
    { " sc config",             1, 35, "persist", "修改服务配置" },
    { "netsh advfirewall set",  1, 40, "fw",      "修改防火墙配置（关闭防护）" },
    { "net stop",               1, 35, "fw",      "停止系统服务（可能关闭防护）" },
    { "taskkill /f /im",        1, 25, "kill",    "强制结束进程（需结合目标判断）" },

    // ---- 关闭安全软件（火绒披露：银狐会遍历并强杀安全进程）----
    { "360tray",                2, 60, "killsav", "针对 360 安全软件的进程操作（银狐常用手法）" },
    { "huorong",                2, 60, "killsav", "针对火绒安全软件的进程操作（银狐常用手法）" },
    { "defender",               1, 30, "killsav", "针对 Defender 的操作（需结合上下文）" },
    { "securityhealth",         1, 30, "killsav", "针对 Windows 安全中心的操作" },
    { "windefend",              1, 35, "killsav", "针对 Windows Defender 服务的操作" },

    // ---- 凭据窃取 ----
    { "lsass",                  2, 60, "cred",    "针对 lsass 进程的操作（凭据窃取）" },
    { "comsvcs.dll",            2, 60, "cred",    "rundll32 + comsvcs.dll 转储 lsass（凭据窃取）" },
    { "mini dump",              1, 25, "cred",    "进程转储（可能用于凭据窃取）" },
    { "sekurlsa",               2, 65, "cred",    "Mimikatz 模块名（凭据窃取工具）" },
};

// 注意：上面规则表里的 needle 必须能对「归一化后」的命令行命中 ——
// 例如原本带空格的 "netsh advfirewall set" 归一化后仍保留单空格（见 NormalizeCommandLine）。

// ---------------------------------------------------------------------------
//  规则外置化存储（热更新）
// ---------------------------------------------------------------------------
struct ExtRule { std::string needle; int level; int score; std::string tag, reason; };
static std::vector<ExtRule>      g_extRules;
static std::vector<std::string>  g_whiteParents;
static std::mutex                g_ruleMutex;

void ClearExternalRules() {
    std::lock_guard<std::mutex> lk(g_ruleMutex);
    g_extRules.clear();
    g_whiteParents.clear();
}

// 懒加载：首次判定时自动加载一次（避免要求所有调用点都记得初始化）。
static void EnsureRulesLoaded() {
    static std::once_flag once;
    std::call_once(once, [] {
        if (!LoadExternalRules(""))
            LogDbg("[behavior] 未找到 behavior_rules.txt，使用内置规则");
    });
}

bool LoadExternalRules(const std::string& filePath) {
    std::string path = filePath;
    // 空路径 → 按 probe_rules.txt 同样的策略在候选位置找（安装目录 data\ 优先）
    if (path.empty()) {
        char exe[MAX_PATH] = {0};
        GetModuleFileNameA(nullptr, exe, MAX_PATH);
        std::string d = exe;
        size_t q = d.find_last_of('\\');
        std::string base = (q != std::string::npos) ? d.substr(0, q + 1) : "";
        const std::string cands[] = {
            base + "data\\behavior_rules.txt",
            base + "behavior_rules.txt",
            "C:\\ProgramData\\SilverFoxGuard\\behavior_rules.txt"
        };
        for (const auto& c : cands) {
            if (GetFileAttributesA(c.c_str()) != INVALID_FILE_ATTRIBUTES) { path = c; break; }
        }
        if (path.empty()) return false;
    }

    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    std::string content;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) content.append(buf, n);
    fclose(f);

    std::vector<ExtRule>      rules;
    std::vector<std::string>  whites;
    size_t pos = 0;
    while (pos <= content.size()) {
        size_t nl = content.find('\n', pos);
        std::string line = content.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? content.size() + 1 : nl + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        // 拆 | 分隔字段
        std::vector<std::string> f2;
        size_t p2 = 0;
        while (true) {
            size_t bar = line.find('|', p2);
            f2.push_back(line.substr(p2, bar == std::string::npos ? std::string::npos : bar - p2));
            if (bar == std::string::npos) break;
            p2 = bar + 1;
        }
        if (f2.empty()) continue;
        std::string kind = Lower(f2[0]);
        if (kind == "w" && f2.size() >= 2) {
            whites.push_back(Lower(f2[1]));
        } else if (kind == "h" && f2.size() >= 5) {
            // H|level|tag|needle|reason  —— 硬规则，分数由 level 反推
            ExtRule r;
            r.level  = atoi(f2[1].c_str());
            r.tag    = f2[2];
            r.needle = Lower(f2[3]);
            r.reason = f2[4];
            r.score  = (r.level >= 2) ? 60 : 35;
            rules.push_back(r);
        } else if (kind == "s" && f2.size() >= 5) {
            // S|weight|tag|needle|reason —— 评分项，weight 直接作分数
            ExtRule r;
            r.score  = atoi(f2[1].c_str());
            r.tag    = f2[2];
            r.needle = Lower(f2[3]);
            r.reason = f2[4];
            r.level  = 0;
            rules.push_back(r);
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_ruleMutex);
        g_extRules    = std::move(rules);
        g_whiteParents = std::move(whites);
    }
    LogDbg("[behavior] 外置规则已加载: 规则 " + std::to_string(g_extRules.size()) +
           " 条, 白名单父进程 " + std::to_string(g_whiteParents.size()) + " 个");
    return true;
}

// ---------------------------------------------------------------------------
//  归一化层 —— 抗混淆的核心
//
//  处理的手法和对应目的：
//    · 全角字符转半角        → 破 ｉｅｘ 之类全角写法
//    · 去掉单/双引号         → 破 "From"+"Base64String" 这类插引号
//    · 去掉脱字符 ^ 与反引号 ` → 破 cmd 转义 p^o^w^e^r^s^h^e^l^l / PS 反引号
//    · 合并被拆开的拼接      → 破 'a'+'b' 形式的字符串拼接
//    · 连续空白折叠为单空格  → 破 多空格/Tab 干扰
//    · 大小写折叠            → 破 大小写变换
//  注意：不做「删除所有空白」——那会把 "netsh advfirewall set" 变成
//  "netshadvfirewallset"，反而让合理规则匹配不上。只做折叠。
// ---------------------------------------------------------------------------
std::string NormalizeCommandLine(const std::string& raw) {
    std::string s;
    s.reserve(raw.size());

    // ① 全角 → 半角
    //    ⚠️ 这段的字节布局是实测出来的，不要凭记忆改（此前写错两次）：
    //    · 全角 ASCII（U+FF01..U+FF5E）的 UTF-8 编码是 EF BC 81 .. EF BD 9E 的**连续区间**，
    //      而不是简单的两段。即整个 94 个码位铺在 [EF BC 81] .. [EF BD 9E] 上。
    //    · 所以第三字节 b3 的取值范围只有 0x81..0x9E（30 个值），要表示 94 个码位，
    //      必须按**顺序**推：前 30 个码位在 EF BC 区，接着 30 个在 EF BD 区……不够，实际是
    //      用 (b3 - 0x81) 作为下标去查 94 码位的线性表。
    //    最稳的做法：不推导公式，直接构造 94 个码位的字节表并做反查。
    for (size_t i = 0; i < raw.size();) {
        unsigned char c = (unsigned char)raw[i];
        // 全角空格单独处理（不属于 U+FF01..FF5E 区间）
        if (c == 0xE3 && i + 2 < raw.size() &&
            (unsigned char)raw[i+1] == 0x80 && (unsigned char)raw[i+2] == 0x80) {
            s += ' ';
            i += 3;
            continue;
        }
        if (c == 0xEF && i + 2 < raw.size()) {
            unsigned char b2 = (unsigned char)raw[i+1];
            unsigned char b3 = (unsigned char)raw[i+2];
            // U+FF01..U+FF5E 的 UTF-8：EF BC 81..BF (前 63 个) 后 EF BD 80..9E (后 31 个)
            int idx = -1;
            if (b2 == 0xBC && b3 >= 0x81 && b3 <= 0xBF)      idx = b3 - 0x81;          // 0..62
            else if (b2 == 0xBD && b3 >= 0x80 && b3 <= 0x9E) idx = 63 + (b3 - 0x80);   // 63..93
            if (idx >= 0 && idx < 94) {
                s += (char)(0x21 + idx);      // 0x21='!' .. 0x7E='~'
                i += 3;
                continue;
            }
        }
        s += (char)c;
        ++i;
    }

    // ② 去引号 + 去转义符，同时处理字符串拼接
    std::string t;
    t.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '"' || c == '\'') continue;         // 引号本身丢弃
        if (c == '^' || c == '`') continue;          // cmd 脱字符 / PS 反引号 丢弃
        // 拼接合并：前一个非空字符 + '+' 紧跟引号/字符 → 直接连上
        if (c == '+') {
            // 往后看：跳过空白，若下一个字符是引号或字母数字，则视为拼接 → 丢弃 '+'
            size_t j = i + 1;
            while (j < s.size() && (s[j] == ' ' || s[j] == '\t')) ++j;
            if (j < t.size() || j < s.size()) {
                if (j < s.size() && (s[j] == '"' || s[j] == '\'' ||
                                     (s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z') ||
                                     (s[j] >= '0' && s[j] <= '9'))) {
                    continue;   // 丢弃 '+'
                }
            }
        }
        t += c;
    }

    // ③ 空白折叠为单空格 + 大小写折叠
    std::string out;
    out.reserve(t.size());
    bool lastSpace = false;
    for (char c : t) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f') {
            if (!lastSpace && !out.empty()) out += ' ';
            lastSpace = true;
            continue;
        }
        if (c >= 'A' && c <= 'Z') c += 32;
        out += c;
        lastSpace = false;
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    return out;
}

// ---------------------------------------------------------------------------
//  签名校验（带缓存）
//  Bitdefender / 卡巴都用签名做信誉层输入。这里只取「是否已签名 + 签名者名」，
//  不查系统信任链（自签证书也能拿到签名者名），因此对自签软件同样有效。
// ---------------------------------------------------------------------------
struct SignCacheEntry { int state; std::string signer; };
static std::map<std::string, SignCacheEntry> g_signCache;
static std::mutex g_signMutex;

bool FileIsSigned(const std::string& path, std::string* outSignerName) {
    if (path.empty()) return false;
    {
        std::lock_guard<std::mutex> lk(g_signMutex);
        auto it = g_signCache.find(path);
        if (it != g_signCache.end()) {
            if (outSignerName) *outSignerName = it->second.signer;
            return it->second.state == 1;
        }
    }

    bool signedOk = false;
    std::string signer;

    std::wstring wpath;
    {
        int n = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
        if (n > 0) {
            std::wstring w(n, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &w[0], n);
            if (!w.empty() && w.back() == L'\0') w.pop_back();
            wpath = w;
        }
    }
    if (!wpath.empty()) {
        // 用 CryptQueryObject 直接读嵌入的 PKCS7 签名（不查信任链，自签也认）
        HCERTSTORE store = nullptr;
        DWORD enc{}, ct{}, ft{};
        if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath.c_str(),
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                             CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                             &enc, &ct, &ft, &store, nullptr, nullptr)) {
            if (store) {
                PCCERT_CONTEXT ctx = CertEnumCertificatesInStore(store, nullptr);
                if (ctx) {
                    signedOk = true;   // 有嵌入式签名块即算已签名
                    wchar_t name[512] = {0};
                    DWORD n = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 512);
                    if (n > 1) {
                        int need = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
                        if (need > 1) {
                            signer.resize(need - 1);
                            WideCharToMultiByte(CP_UTF8, 0, name, -1, &signer[0], need, nullptr, nullptr);
                        }
                    }
                    CertFreeCertificateContext(ctx);
                }
                CertCloseStore(store, 0);
            }
        }
    }

    {
        std::lock_guard<std::mutex> lk(g_signMutex);
        if (g_signCache.size() > 8192) g_signCache.clear();
        SignCacheEntry e; e.state = signedOk ? 1 : 0; e.signer = signer;
        g_signCache[path] = e;
    }
    if (outSignerName) *outSignerName = signer;
    return signedOk;
}

// ---------------------------------------------------------------------------
//  可信发起者校验 —— 替代旧版「命令行含某字符串即豁免」的危险做法
//
//  旧实现：if (命令行含 "chrome-extension://" || "nativemessaging" || "--parent-window=")
//              return level 0;
//  → 攻击者在自己的命令行尾部加一个 "--parent-window=0" 就整条链洗白。
//
//  新实现要求**两个条件同时成立**：
//    ① 父进程确实是浏览器（名字在 kBrowser 里），且**该浏览器文件带数字签名**
//       —— 攻击者要伪造就得先拿到 Chrome/Edge 的签名，这是做不到的；
//    ② 命令行里出现**真实的命名管道路径**（\\.\pipe\ 开头），而不是随便一个字符串
//       —— 浏览器拉起 Native Messaging 宿主时必须走管道转发，管道名是内核对象，
//          伪造不了（要真建一个同名管道才能通信）。
//  另：如果命令行还带其它高危特征（如 -EncodedCommand），豁免不生效，继续走判定。
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
//  进程信誉门（2026-09-19 新增，wallpaper64.exe 误杀事故的根治）
//  用途：所有「终止进程」决策前的最后守门（回滚终止 / WmiSink 终止 /
//        bootguard 拦截链）。评分体系里的信誉调权（FinalizeScoreLevel）
//        决定"多可疑"，本函数决定"能不能杀"——两件事必须分开。
//  判可信：① 签名者命中知名厂商名单；或 ② 有签名且安装在可信目录。
//  未签名一律不可信（勒索/银狐载荷几乎都不签名）。
//  注意：内部 FileIsSigned 带缓存（同路径只做一次磁盘 IO），且本函数
//        不持任何锁，符合「缓存函数不得持锁做 I/O」铁律。
// ---------------------------------------------------------------------------
bool ProcReputable(const std::string& exePath) {
    if (exePath.empty()) return false;
    std::string signer;
    if (!FileIsSigned(exePath, &signer)) return false;   // 未签名 → 不可信
    static const char* kVendors[] = {
        "valve", "steam", "microsoft", "google", "mozilla", "nvidia",
        "amd", "intel", "apple", "adobe", "tencent", "netease", "bilibili",
        "kingsoft", "qihoo", "huorong", "huawei", "lenovo", "alibaba",
        "baidu", "bytedance", "douyin", "wps", "python software", "github",
        "kaspersky", "eset", "bitdefender", "avast", "avg"
    };
    std::string low = signer;
    for (auto& c : low) c = (char)tolower((unsigned char)c);
    for (const char* v : kVendors)
        if (low.find(v) != std::string::npos) return true;
    // 有签名但厂商不在名单：安装路径可信也算（正常商业软件的正常位置）
    std::string pl = exePath;
    for (auto& c : pl) c = (char)tolower((unsigned char)c);
    if (pl.find("\\program files") != std::string::npos ||
        pl.find("\\steamapps\\") != std::string::npos ||
        pl.find("\\windows\\system32\\") != std::string::npos) return true;
    return false;
}

bool IsTrustedBrowserHost(const std::string& parentImagePath,
                          const std::string& commandLine) {
    // 条件①：父进程是浏览器 + 有签名
    std::string p = Lower(BaseName(parentImagePath));
    if (p.empty() || !IN_LIST(p, kBrowser)) return false;
    if (!FileIsSigned(parentImagePath)) {
        // 父进程名字叫 chrome.exe 但没有签名 → 可能是假冒的浏览器（可疑）
        return false;
    }

    // 条件②：命令行里有真实的命名管道路径
    std::string lc = Lower(commandLine);
    bool pipeOk = Has(lc, "\\\\.\\pipe\\") || Has(lc, "\\\\?\\pipe\\");
    if (!pipeOk) return false;

    // 附加条件③：命令行里不能同时出现明显的高危语义（避免"真浏览器 + 恶意参数"被整体豁免）
    static const char* kDeny[] = {
        "-encodedcommand", "-enc ", "frombase64string", "invoke-expression", "iex(",
        "downloadstring", "downloadfile", "mshta http", "scrobj.dll",
        "vssadmin delete shadows", "wevtutil cl", "windowstyle hidden", "w hidden"
    };
    for (const char* d : kDeny) if (Has(lc, d)) return false;

    return true;
}

// ---------------------------------------------------------------------------
//  Windows 自身的 Native Messaging 管道转发也走 cmd —— 但父进程是浏览器，
//  同样验证父进程签名（浏览器本体）。这是对上面函数的补充：
//  有些浏览器拉起的命令行不带 chrome-extension:// 但管道名是 chrome.nativeMessaging。
// ---------------------------------------------------------------------------
static bool IsNativeMessagingPipe(const std::string& cmdLower) {
    return Has(cmdLower, "chrome.nativemessaging") ||
           Has(cmdLower, "native_messaging") ||
           Has(cmdLower, ".pipe\\chrome") ||
           Has(cmdLower, "firefox")  && Has(cmdLower, "\\\\.\\pipe\\");
}

// ---------------------------------------------------------------------------
//  父进程链判定
//  依据：Defender 官方 Pyordono.A（脚本引擎以可疑参数执行 cmd/powershell）
//        + 卡巴 AEP（可信程序被利用执行可疑代码也要拦）
// ---------------------------------------------------------------------------
ProcVerdict JudgeParentChain(const std::string& parentImagePath,
                             const std::string& childImagePath,
                             const std::string& childCommandLine) {
    ProcVerdict v;
    std::string p = Lower(BaseName(parentImagePath));
    std::string c = Lower(BaseName(childImagePath));
    if (p.empty() || c.empty()) return v;
    if (!IN_LIST(c, kHosts)) return v;          // 子进程不是脚本宿主 → 本条不适用

    // 外置白名单父进程（用户可自定义）
    {
        std::lock_guard<std::mutex> lk(g_ruleMutex);
        for (const auto& w : g_whiteParents) if (w == p) return v;
    }

    // 父进程是浏览器 → 交给可信发起者校验，不在这里粗暴判档
    if (IN_LIST(p, kBrowser)) {
        if (IsTrustedBrowserHost(parentImagePath, childCommandLine)) return v;  // 真宿主 → 放行
        v.level = 1; v.score = 35; v.tag = "browser-spawn-host";
        v.reason = "浏览器 " + p + " 派生了命令/脚本宿主 " + c +
                   "，但未能验证为 Native Messaging 正常调用，可能是漏洞利用或恶意下载后执行";
        return v;
    }
    if (IN_LIST(p, kOffice)) {
        v.level = 2; v.score = 70; v.tag = "office-spawn-host"; v.hard = true;
        v.reason = "文档程序 " + p + " 派生了命令/脚本宿主 " + c +
                   "，这是宏病毒与文档漏洞利用的典型链，正常文档不会这么做";
        return v;
    }
    if (IN_LIST(p, kIm)) {
        v.level = 2; v.score = 70; v.tag = "im-spawn-host"; v.hard = true;
        v.reason = "聊天软件 " + p + " 派生了命令/脚本宿主 " + c +
                   "，常见于「发文件让你执行」类钓鱼";
        return v;
    }
    if (IN_LIST(p, kHosts) && p != c) {
        v.level = 1; v.score = 25; v.tag = "host-chain";
        v.reason = "命令/脚本宿主链式调用（" + p + " → " + c + "），需结合命令行判断";
        return v;
    }
    // 注意：explorer.exe → cmd/powershell 是用户正常开命令行，此处**不报**（控制误报）
    return v;
}

// ---------------------------------------------------------------------------
//  评分层定档：把累计分数映射成风险等级。
//
//  ⚠️ 踩坑（2026-09-18 回归测试暴露）：这段逻辑原先**只写在 JudgeProcessInner 里**，
//     而 JudgeCommandLine 直接 return，导致「单独判定命令行」这条路径上
//     分数累加了却永远不升级 —— 实测 `net user backdoor P@ss /add` 得 45 分、
//     `wevtutil sl Security /e:false` 得 50 分（均远超 level 1 阈值 30），
//     返回的却是 level=0。
//     影响面：所有**以命令行为唯一事件源**的调用点（文件落地 / 计划任务 /
//     注册表启动项）全部漏报。硬规则路径不受影响（硬规则自带 level）。
//     正解：抽成函数，两条路径共用同一个阈值来源。
//
//  阈值依据：对齐 Bitdefender ATC 的「多信号累加 + 阈值」思路，
//            具体数值由本项目回归测试（误报 0% 为目标）反推得出。
// ---------------------------------------------------------------------------
static void FinalizeScoreLevel(ProcVerdict& v) {
    if (v.hard) return;                     // 硬规则自带等级，不参与评分定档
    if (v.score >= 55)      { v.level = 2; }
    else if (v.score >= 30) { v.level = 1; }
    else                    { v.level = 0; if (v.score < 15) v.reason.clear(); }
}

// ---------------------------------------------------------------------------
//  命令行判定（对**归一化后**的文本做匹配）
// ---------------------------------------------------------------------------
ProcVerdict JudgeCommandLine(const std::string& commandLine, const std::string& imagePath) {
    ProcVerdict v;
    if (commandLine.empty()) return v;

    // ★ 关键：先归一化再匹配。这是抗绕过的第一道防线。
    std::string l = NormalizeCommandLine(commandLine);
    if (l.empty()) return v;

    const std::string lbase = Lower(BaseName(imagePath));

    // ---- 解释器识别：与解释器绑定的规则必须先确认解释器在场 ----
    // 为什么要这一步：避免「文档里恰好写了 downloadstring 这个词」之类误命中。
    const bool ps   = Has(l, "powershell") || Has(l, "pwsh") || lbase == "powershell.exe" ||
                      lbase == "pwsh.exe";
    const bool host = ps || Has(l, "mshta") || Has(l, "wscript") || Has(l, "cscript") ||
                      Has(l, "rundll32") || Has(l, "regsvr32") || Has(l, "certutil") ||
                      Has(l, "bitsadmin") || Has(l, "cmd.exe") || Has(l, "cmd /") ||
                      lbase == "cmd.exe" || lbase == "mshta.exe" || lbase == "wscript.exe" ||
                      lbase == "rundll32.exe" || lbase == "regsvr32.exe" ||
                      lbase == "certutil.exe" || lbase == "msbuild.exe" ||
                      lbase == "installutil.exe";
    const bool psOrScript = ps || Has(l, "mshta") || Has(l, "wscript") || Has(l, "cscript") ||
                            lbase == "powershell.exe" || lbase == "mshta.exe" ||
                            lbase == "wscript.exe" || lbase == "cscript.exe";

    // ---- PS 编码命令（-enc / -EncodedCommand）----
    // 归一化去掉了引号与转义符，所以 "-e^n^c" / "-Enc" / '"-e"' 都能命中。
    if (ps) {
        if (Has(l, "-encodedcommand") || Has(l, "-enc ") || Has(l, "-e ") ||
            Has(l, " /enc ") || Has(l, " /encodedcommand")) {
            v.level = 2; v.score = 70; v.hard = true; v.tag = "ps-encoded";
            v.reason = "PowerShell 编码命令（-EncodedCommand），免杀常用手法，正常脚本不会这么写";
            return v;
        }
        // -nop / -w hidden / -ep bypass 三件套组合 = 典型的攻击用法
        int combo = (Has(l, "-nop") || Has(l, "-noprofile") ? 1 : 0)
                  + (Has(l, "-w hidden") || Has(l, "windowstyle hidden") ? 1 : 0)
                  + (Has(l, "-ep bypass") || Has(l, "-executionpolicy bypass") ||
                     Has(l, "bypass") ? 1 : 0);
        if (combo >= 2) {
            v.level = 2; v.score = 60; v.hard = true; v.tag = "ps-bypass";
            v.reason = "PowerShell 以「无配置 + 隐藏窗口 + 绕过执行策略」组合启动，"
                       "这是恶意脚本的标准启动参数，正常管理脚本不会这么嵌套使用";
            return v;
        }
        if (Has(l, "-nop") && Has(l, "-c ")) {
            v.level = 1; v.score = 35; v.tag = "ps-nop";
            v.reason = "PowerShell 以 -NoProfile -Command 执行，常见于自动化脚本，需结合内容判断";
        }
    }

    // ---- 隐藏窗口（通用，不只 PS）----
    if (host && (Has(l, "windowstyle hidden") || Has(l, "w hidden") || Has(l, "-hidden"))) {
        if (v.level < 2) {
            v.level = 2; v.score = 55; v.hard = true; v.tag = "hidden";
            v.reason = "以隐藏窗口方式执行命令，典型规避用户察觉的手法";
        }
        return v;
    }

    // ---- rundll32 加载【系统目录之外】的 DLL ----
    // 依据：Bitdefender 明确把 DLL 侧载列为高危行为；正常 rundll32 调用都在 System32。
    // 注意：这条**不能**因为命令行含 http/路径就无脑命中，必须同时有 .dll, 与
    //       非系统目录引用 —— 否则会误伤 shell32.dll,Control_RunDLL 这类正常调用。
    if (Has(l, "rundll32") || lbase == "rundll32.exe") {
        if (Has(l, ".dll,") || Has(l, ".dll ")) {
            bool inSystem = Has(l, "\\windows\\") || Has(l, "system32") || Has(l, "syswow64");
            if (!inSystem) {
                v.level = 2; v.score = 65; v.hard = true; v.tag = "rundll32";
                if (Has(l, "comsvcs")) {
                    v.reason = "rundll32 调用 comsvcs.dll 转储 lsass，这是凭据窃取的标准手法";
                    v.tag = "cred";
                } else {
                    v.reason = "rundll32 加载了系统目录之外的 DLL，这是白利用（侧加载）的典型形态";
                }
                return v;
            }
        }
        // rundll32 + javascript:/vbscript: 也是白利用
        if (Has(l, "javascript:") || Has(l, "vbscript:")) {
            v.level = 2; v.score = 65; v.hard = true; v.tag = "rundll32";
            v.reason = "rundll32 执行内联脚本，属于白利用（Squiblydoo 变种）";
            return v;
        }
    }

    // ---- 表驱动硬规则 ----
    for (const auto& r : kHardRules) {
        if (Has(l, r.needle)) {
            if (r.level >= 2) {
                v.level = 2; v.score = r.score; v.tag = r.tag; v.reason = r.reason; v.hard = true;
                return v;
            }
            if (r.level == 1 && v.level < 1) {
                v.level = 1; v.score += r.score; v.tag = r.tag; v.reason = r.reason;
            }
        }
    }

    // ---- 外置规则（热更新）----
    {
        std::lock_guard<std::mutex> lk(g_ruleMutex);
        for (const auto& r : g_extRules) {
            if (l.find(r.needle) != std::string::npos) {
                if (r.level >= 2) {
                    v.level = 2; v.score = r.score ? r.score : 60; v.tag = r.tag;
                    v.reason = r.reason; v.hard = true;
                    return v;
                }
                if (r.level >= 1 && v.level < 1) {
                    v.level = 1; v.score += r.score; v.tag = r.tag; v.reason = r.reason;
                } else if (r.level == 0) {
                    v.score += r.score;
                }
            }
        }
    }

    // ---- 脚本宿主 + 远程 URL → 升级（Defender 无文件检测思路）----
    if (psOrScript && (Has(l, "http://") || Has(l, "https://") || Has(l, "ftp://"))) {
        if (v.level < 2) {
            v.level = 2; v.score = 60; v.hard = true; v.tag = "host-url";
            v.reason = "脚本宿主直接执行远程 URL 内容，属于远程载荷执行";
        }
    }

    // ---- 评分项：可疑但不是确凿恶意，累加权重 ----
    // ⚠️ 踩坑（重复计分）：曾同时写 Has(l, "temp\\") 与 Has(l, "\\temp") ——
    //    这俩在子串匹配下是**同一个信号**（`C:\Temp\` 两个都命中），等于路径里
    //    出现一个临时目录就白拿 20 分。实测把 C:\Temp\ 下的正常程序判到 30 分
    //    → 误报。正解：一个语义信号只写一条，并优先用带路径分隔符的形式。
    if (v.level < 2) {
        if (Has(l, "-nop") || Has(l, "noprofile"))  v.score += 10;
        if (Has(l, "encoded"))                      v.score += 10;
        if (Has(l, "hidden"))                       v.score += 15;
        if (Has(l, "bypass"))                       v.score += 15;
        if (Has(l, "\\temp\\") || Has(l, "\\tmp\\")) v.score += 10;  // 从临时目录执行
        if (Has(l, "\\appdata\\"))                  v.score += 10;
        if (Has(l, "\\public\\"))                   v.score += 10;
        if (Has(l, "http://") || Has(l, "https://")) v.score += 10;
        if (Has(l, "base64"))                       v.score += 15;
        if (Has(l, ".txt"))                         v.score += 5;   // 从文本文件读指令
        if (Has(l, "\\programdata\\"))              v.score += 10;
    }

    // ---- 评分层定档（关键：单独判定命令行时也必须定档，否则全体漏报）----
    FinalizeScoreLevel(v);
    return v;
}

// ---------------------------------------------------------------------------
//  映像路径判定
// ---------------------------------------------------------------------------
static ProcVerdict JudgeImagePath(const std::string& imagePath) {
    ProcVerdict v;
    if (imagePath.empty()) return v;
    std::string l = Lower(imagePath);
    std::string base = Lower(BaseName(imagePath));

    // 伪装系统进程：系统名出现在非系统目录
    if (IN_LIST(base, kSystemNames)) {
        bool inSystem = Has(l, "\\windows\\system32\\") || Has(l, "\\windows\\syswow64\\") ||
                        Has(l, "\\windows\\winsxs\\") || Has(l, "\\windows\\");
        if (!inSystem) {
            v.level = 2; v.score = 65; v.hard = true; v.tag = "masquerade";
            v.reason = "进程名为 " + base + " 但不在系统目录（" + imagePath +
                       "），这是伪装系统进程的典型手法";
            return v;
        }
    }
    return v;
}

// ---------------------------------------------------------------------------
//  综合判定
// ---------------------------------------------------------------------------
static ProcVerdict JudgeProcessInner(ProcEntity e) {
    ProcVerdict best;

    EnsureRulesLoaded();   // 首次调用时自动加载外置规则

    if (e.imagePath.empty() && e.commandLine.empty()) return best;

    // ---- 补全签名信息（信誉层输入）----
    std::string signer;
    bool signedFile = false;
    if (e.signState == -1 && !e.imagePath.empty()) {
        signedFile = FileIsSigned(e.imagePath, &signer);
        e.signState = signedFile ? 1 : 0;
        e.signerName = signer;
    } else {
        signedFile = (e.signState == 1);
        signer = e.signerName;
    }

    // ---- 整体豁免：可信浏览器的 Native Messaging 宿主 ----
    // 注意：这里调用的是**身份校验**版（父进程须为已签名浏览器 + 真实管道），
    // 不再看命令行里的可伪造字符串。
    if (!e.parentImagePath.empty() &&
        IsTrustedBrowserHost(e.parentImagePath, e.commandLine)) {
        return best;   // level 0
    }

    auto take = [&best](const ProcVerdict& v) {
        if (v.level > best.level || (v.level == best.level && v.score > best.score)) best = v;
        else if (v.level == best.level && v.score == best.score && best.reason.empty() && !v.reason.empty()) best = v;
    };
    take(JudgeImagePath(e.imagePath));
    take(JudgeCommandLine(e.commandLine, e.imagePath));
    take(JudgeParentChain(e.parentImagePath, e.imagePath, e.commandLine));

    // ---- 信誉层：签名 / 可信目录 → 调权重，而不是直接放行 ----
    // 依据：卡巴官方明确「可信应用执行不安全代码也要拦」（白利用）。
    // 所以签名只在**非硬规则命中**时降权；硬规则（确凿恶意语义）不受签名影响。
    //
    // 唯一的例外：微软系统目录内的已签名程序 + 未被硬规则命中 → 直接放行。
    // 理由：System32 下的签名文件被替换的前提是攻击者已有管理员权限，
    //       此时任何用户态方案都拦不住，放行不影响实际安全边界。
    if (!best.hard && signedFile) {
        std::string l = Lower(e.imagePath);
        bool sysDir = Has(l, "\\windows\\system32\\") || Has(l, "\\windows\\syswow64\\") ||
                      Has(l, "\\windows\\winsxs\\");
        std::string signerL = Lower(signer);
        bool msSigned = Has(signerL, "microsoft");
        if (sysDir && msSigned) {
            ProcVerdict ok;   // 系统签名文件 → 放行
            return ok;
        }
        // 其它签名程序 → 分数降 60%（不是清零）。若降后已低于阈值即放行。
        best.score = best.score * 4 / 10;
        if (best.score < 40 && best.level <= 1) {
            best.level = 0;
        }
        if (best.level == 1 && !best.reason.empty()) {
            best.reason += "（该文件带数字签名，风险等级已下调）";
        }
    }

    // ---- 可信目录 → 小幅降权 ----
    if (!best.hard) {
        std::string l = Lower(e.imagePath);
        for (const char* d : kTrustedDirs) {
            if (Has(l, d)) { best.score = best.score * 7 / 10; break; }
        }
    }

    // ---- 评分层定档：达到阈值才升级（与 JudgeCommandLine 共用同一函数）----
    FinalizeScoreLevel(best);

    // ---- 可疑落地目录加成（银狐传统落脚点）----
    if (best.level >= 1) {
        std::string l = Lower(e.imagePath);
        for (const char* d : kSuspDirs) {
            if (Has(l, d)) { best.reason += "；且文件位于高风险目录"; break; }
        }
    }

    return best;
}

ProcVerdict JudgeProcess(const ProcEntity& e) {
    return JudgeProcessInner(e);
}

ProcVerdict JudgeProcess(const std::string& imagePath,
                         const std::string& commandLine,
                         const std::string& parentImagePath) {
    ProcEntity e;
    e.imagePath = imagePath;
    e.commandLine = commandLine;
    e.parentImagePath = parentImagePath;
    if (parentImagePath.empty()) {
        e.parentPid = 0;
    }
    return JudgeProcessInner(e);
}

// ---------------------------------------------------------------------------
//  PID 辅助
// ---------------------------------------------------------------------------
std::string ImagePathOfPid(unsigned long pid) {
    if (pid == 0) return {};
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return {};
    wchar_t buf[MAX_PATH * 2] = { 0 };
    DWORD n = (DWORD)(sizeof(buf) / sizeof(buf[0]));
    std::string out;
    if (QueryFullProcessImageNameW(h, 0, buf, &n) && n > 0) {
        int need = WideCharToMultiByte(CP_UTF8, 0, buf, (int)n, nullptr, 0, nullptr, nullptr);
        if (need > 0) {
            out.resize(need);
            WideCharToMultiByte(CP_UTF8, 0, buf, (int)n, &out[0], need, nullptr, nullptr);
        }
    }
    CloseHandle(h);
    return out;
}

unsigned long ParentPidOfPid(unsigned long pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 e{};
    e.dwSize = sizeof(e);
    unsigned long ppid = 0;
    if (Process32First(snap, &e)) {
        do {
            if (e.th32ProcessID == (DWORD)pid) { ppid = e.th32ParentProcessID; break; }
        } while (Process32Next(snap, &e));
    }
    CloseHandle(snap);
    return ppid;
}

// 读目标进程命令行（需读 PEB；非本用户进程或权限不足时返回空）
// 用 NtQueryInformationProcess 取 PEB 再 ReadProcessMemory —— 这是用户态唯一可行路径。
typedef LONG (NTAPI *pfnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
struct UNICODE_STR { USHORT Length; USHORT MaximumLength; PWSTR Buffer; };
struct PEB_LDR_DATA_PARTIAL { BYTE Reserved1[16]; PVOID Reserved2[3]; LIST_ENTRY InMemoryOrderModuleList; };
struct RTL_USER_PROCESS_PARAMETERS_PARTIAL {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STR ImagePathName;
    UNICODE_STR CommandLine;
};

static std::string ReadRemoteCommandLine(HANDLE h) {
    static pfnNtQueryInformationProcess pNtQIP = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt) pNtQIP = (pfnNtQueryInformationProcess)GetProcAddress(nt, "NtQueryInformationProcess");
    }
    if (!pNtQIP) return {};

    // ProcessBasicInformation = 0
    struct { PVOID Reserved1; PVOID PebBaseAddress; PVOID Reserved2[2]; ULONG_PTR UniqueProcessId; PVOID Reserved3; } pbi{};
    ULONG retLen = 0;
    if (pNtQIP(h, 0, &pbi, sizeof(pbi), &retLen) != 0 || !pbi.PebBaseAddress) return {};

    // 读 PEB 里的 ProcessParameters 指针（64 位 PEB 偏移 0x20）
    PVOID params = nullptr;
    SIZE_T rd = 0;
    if (!ReadProcessMemory(h, (PBYTE)pbi.PebBaseAddress + 0x20, &params, sizeof(params), &rd) || !params)
        return {};

    RTL_USER_PROCESS_PARAMETERS_PARTIAL upp{};
    if (!ReadProcessMemory(h, params, &upp, sizeof(upp), &rd)) return {};
    if (!upp.CommandLine.Buffer || upp.CommandLine.Length == 0) return {};

    std::wstring wbuf(upp.CommandLine.Length / sizeof(wchar_t), L'\0');
    if (!ReadProcessMemory(h, upp.CommandLine.Buffer, &wbuf[0], upp.CommandLine.Length, &rd))
        return {};
    int need = WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(), (int)wbuf.size(), nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(need, 0);
    WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(), (int)wbuf.size(), &out[0], need, nullptr, nullptr);
    return out;
}

ProcEntity MakeEntityOfPid(unsigned long pid) {
    ProcEntity e;
    e.pid = pid;
    e.imagePath = ImagePathOfPid(pid);
    e.parentPid = ParentPidOfPid(pid);
    if (e.parentPid) e.parentImagePath = ImagePathOfPid(e.parentPid);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (h) {
        e.commandLine = ReadRemoteCommandLine(h);
        CloseHandle(h);
    }
    if (e.commandLine.empty()) e.commandLine = e.imagePath;   // 降级：至少给映像路径
    return e;
}

}  // namespace sf
