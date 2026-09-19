// probe_regress — 单文件查杀引擎回归测试（直接链接 probe.cpp / common.cpp）
// 修正：路径一律用 UTF-8 传入（与产品一致），存在性用宽字符 API 判断（此前 GetFileAttributesA
// 会把 UTF-8 字面量当 GBK，导致中文路径与「下载」目录全部被跳过）。
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include "probe.h"
#include "common.h"

static bool ExistsU8(const std::string& u8) {
    int n = MultiByteToWideChar(CP_UTF8, 0, u8.c_str(), -1, nullptr, 0);
    if (n <= 0) return false;
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, u8.c_str(), -1, &w[0], n);
    return GetFileAttributesW(w.c_str()) != INVALID_FILE_ATTRIBUTES;
}

struct Row { int level, score; std::string type, title; std::string hits; };

static Row RunOne(const std::string& p) {
    Row r{-9, -9, "", "", ""};
    std::string j = sf::ScanTargetFile(p);
    r.level = sf::JsonGetInt(j, "level");
    r.score = sf::JsonGetInt(j, "score");
    r.type  = sf::JsonGetString(j, "type");
    r.title = sf::JsonGetString(j, "title");
    // 抓 hits 里的 name 字段（粗略，仅用于展示）
    size_t pos = 0;
    while ((pos = j.find("\"name\":\"", pos)) != std::string::npos) {
        pos += 8; size_t e = j.find('"', pos);
        if (e == std::string::npos) break;
        if (!r.hits.empty()) r.hits += "；";
        r.hits += j.substr(pos, e - pos);
        pos = e;
    }
    return r;
}

int main(int argc, char** argv) {
    if (argc > 1) {   // 调试模式：打印某文件完整 JSON。注意原生命令行 argv 是 ANSI，需转 UTF-8
        int wac = 0;
        LPWSTR* wav = CommandLineToArgvW(GetCommandLineW(), &wac);
        std::string u8;
        if (wav && wac > 1) {
            int n = WideCharToMultiByte(CP_UTF8, 0, wav[1], -1, nullptr, 0, nullptr, nullptr);
            if (n > 0) { u8.resize(n - 1); WideCharToMultiByte(CP_UTF8, 0, wav[1], -1, &u8[0], n, nullptr, nullptr); }
            LocalFree(wav);
        }
        printf("%s\n", sf::ScanTargetFile(u8).c_str());
        return 0;
    }
    std::vector<std::string> good = {
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\taskmgr.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\calc.exe",
        "C:\\Windows\\System32\\powrprof.dll",
        "C:\\Windows\\System32\\version.dll",
        "C:\\Windows\\System32\\winhttp.dll",
        "C:\\Windows\\System32\\user32.dll",
        "C:\\Windows\\System32\\explorer.exe",
        "C:\\Windows\\System32\\kernel32.dll",
        "C:\\Program Files\\nodejs\\node.exe",
        "C:\\Program Files (x86)\\NSIS\\makensis.exe",
        "D:\\SilverFoxEnvScan\\SilverFoxGuard\\7z.exe",
        "D:\\SilverFoxGuard\\dist\\SilverFoxGuardSvc.exe",
        "D:\\SilverFoxGuard\\dist\\shell\\SilverFoxShell.dll",
        "D:\\SilverFoxGuard\\dist\\update_ver.exe",
        "D:\\SilverFoxEnvScan\\SilverFoxEnvScanSvc.exe",
        "D:\\tianl\\下载\\node-v24.18.0-x64.msi",
        "D:\\tianl\\下载\\Bilidown Setup 1.2.7.exe",
        "D:\\tianl\\下载\\0.3.6_x64-setup.exe",
        "D:\\tianl\\下载\\CozyUI+ v1.10 [26.2].zip",
        "D:\\tianl\\下载\\2026考研资料大全【度和U和迅的19号】(2).zip",
        "D:\\silverfox-guard-dist\\silverfox-guard-v1.6.1.zip",
        "D:\\silverfox-guard\\background.js",
        "D:\\silverfox-guard\\content\\content.js",
        "C:\\temp\\probe_regress\\samples\\normal_app.exe",           // 正常名真 PE（对照）
    };
    std::vector<std::string> expectHit = {
        "C:\\temp\\probe_regress\\samples\\setup.pdf.exe",            // 双后缀真 PE（应 1 级）
        "C:\\temp\\probe_regress\\中文目录\\包.zip",                   // 中文路径 + 包内双后缀（应 1 级）
        "C:\\temp\\probe_regress\\中文目录\\报告.zip",                 // 中文路径 + 包内正常 PE（应 0 级）
    };

    printf("%-5s%-7s%-8s%-7s%s\n", "级别", "分数", "类型", "判定", "文件");
    printf("%s\n", std::string(118, '=').c_str());
    int n = 0, fp = 0;
    for (const auto& p : good) {
        if (!ExistsU8(p)) { printf("%-5s%-7s%-8s%-7s%s  （读不到，跳过）\n", "-","-","-","-", p.c_str()); continue; }
        Row r = RunOne(p);
        ++n;
        bool isFp = r.level >= 1;
        if (isFp) ++fp;
        printf("%-5d%-7d%-8s%-7s%s\n", r.level, r.score, r.type.c_str(), isFp ? "⚠误报" : "正常", p.c_str());
        if (isFp) printf("%28s└ %s | %s\n", "", r.title.c_str(), r.hits.c_str());
    }
    printf("%s\n", std::string(118, '=').c_str());
    printf("正常文件 %d 个，误报 %d 个，误报率 %.0f%%\n\n", n, fp, n ? fp * 100.0 / n : 0.0);

    printf("--- 期望命中 / 对照 ---\n");
    for (const auto& p : expectHit) {
        if (!ExistsU8(p)) { printf("  （读不到）%s\n", p.c_str()); continue; }
        Row r = RunOne(p);
        printf("  level=%d score=%-4d type=%-6s %s\n", r.level, r.score, r.type.c_str(), p.c_str());
        printf("      结论: %s | 证据: %s\n", r.title.c_str(), r.hits.c_str());
    }
    return 0;
}
