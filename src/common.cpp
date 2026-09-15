// common.cpp — 银狐环境检测程序共享基础实现
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <Wtsapi32.h>

#include "common.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace sf {

const wchar_t* SVC_NAME     = L"SilverFoxEnvScanSvc";
const wchar_t* SVC_DISPLAY  = L"银狐环境检测服务";
const wchar_t* PIPE_NAME    = L"\\\\.\\pipe\\SilverFoxEnvScan";
const char*    NM_HOST_NAME = "com.silverfox.envscan";
const char*    CFG_ROOT     = "SOFTWARE\\SilverFoxEnvScan";

// 调试日志：统一写到 C:\ProgramData\SilverFoxEnvScan\envscan.log（VM 可访问）
void LogDbg(const std::string& msg) {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p) == S_OK)
        dir = std::wstring(p) + L"\\SilverFoxEnvScan";
    else dir = L"C:\\ProgramData\\SilverFoxEnvScan";
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring path = dir + L"\\envscan.log";
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    SetFilePointer(hf, 0, nullptr, FILE_END);
    int n = MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), -1, nullptr, 0);
    std::wstring w; w.resize(n); MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    std::wstring line = w + L"\r\n";
    DWORD wn = 0; WriteFile(hf, line.c_str(), (DWORD)(line.size() * sizeof(wchar_t)), &wn, nullptr);
    CloseHandle(hf);
}

// ---------------------------------------------------------------------------
//  路径
// ---------------------------------------------------------------------------
std::string GetExePath() {
    char buf[MAX_PATH]{};
    DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return n ? std::string(buf, n) : std::string();
}
std::string DirName(const std::string& path) {
    size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? "." : path.substr(0, p);
}
std::string BaseName(const std::string& path) {
    size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? path : path.substr(p + 1);
}
bool FileExists(const std::string& path) {
    DWORD a = GetFileAttributesA(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

// ---------------------------------------------------------------------------
//  哈希（BCrypt SHA-256）
// ---------------------------------------------------------------------------
static std::string Sha256Finish(BCRYPT_HASH_HANDLE hh) {
    BYTE buf[32]; ULONG cb = 32;
    if (BCryptFinishHash(hh, buf, cb, 0) != 0) return "";
    static const char* hx = "0123456789abcdef";
    std::string o; o.reserve(64);
    for (int i = 0; i < 32; ++i) { o += hx[buf[i] >> 4]; o += hx[buf[i] & 0xf]; }
    return o;
}
std::string Sha256Bytes(const void* data, size_t len) {
    BCRYPT_ALG_HANDLE h;
    if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return "";
    BCRYPT_HASH_HANDLE hh;
    if (BCryptCreateHash(h, &hh, nullptr, 0, nullptr, 0, 0) != 0) { BCryptCloseAlgorithmProvider(h, 0); return ""; }
    BCryptHashData(hh, (PUCHAR)data, (ULONG)len, 0);
    std::string r = Sha256Finish(hh);
    BCryptDestroyHash(hh); BCryptCloseAlgorithmProvider(h, 0);
    return r;
}
std::string Sha256File(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    BCRYPT_ALG_HANDLE h;
    if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return "";
    BCRYPT_HASH_HANDLE hh;
    if (BCryptCreateHash(h, &hh, nullptr, 0, nullptr, 0, 0) != 0) { BCryptCloseAlgorithmProvider(h, 0); return ""; }
    char buf[1 << 16];
    std::streamsize n;
    while ((n = f.read(buf, sizeof(buf)).gcount()) > 0) BCryptHashData(hh, (PUCHAR)buf, (ULONG)n, 0);
    std::string r = Sha256Finish(hh);
    BCryptDestroyHash(hh); BCryptCloseAlgorithmProvider(h, 0);
    return r;
}

// ---------------------------------------------------------------------------
//  JSON
// ---------------------------------------------------------------------------
std::string JsonEscape(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b"; break;
            case '\f': o += "\\f"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    static const char* hx = "0123456789abcdef";
                    o += "\\u00"; o += hx[(c >> 4) & 0xf]; o += hx[c & 0xf];
                } else o += c;
        }
    }
    return o;
}
std::string JsonString(const std::string& s) { return "\"" + JsonEscape(s) + "\""; }

std::string JsonGetString(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t pos = json.find(pat);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + pat.size());
    if (pos == std::string::npos) return "";
    // 跳过空白
    while (pos + 1 < json.size() && (json[pos + 1] == ' ' || json[pos + 1] == '\t' || json[pos + 1] == '\r' || json[pos + 1] == '\n')) ++pos;
    if (pos + 1 >= json.size() || json[pos + 1] != '"') return "";  // 仅处理字符串值
    size_t start = pos + 2;
    std::string val;
    while (start < json.size()) {
        char c = json[start];
        if (c == '\\' && start + 1 < json.size()) {
            char n = json[start + 1];
            if (n == 'n') val += '\n';
            else if (n == 't') val += '\t';
            else if (n == 'r') val += '\r';
            else if (n == '"') val += '"';
            else if (n == '\\') val += '\\';
            else val += n;
            start += 2; continue;
        }
        if (c == '"') break;
        val += c; ++start;
    }
    return val;
}

// 取 JSON 中的【数字】字段（也兼容被引号包起来的数字串）。
// 必须用本函数而不是 atoi(JsonGetString(...))：BuildResultJson 输出的 score / weight / count 都是
// 裸数字（如 "score":220），而 JsonGetString 只认带引号的字符串值 → 对数字一律返回空串，
// atoi 恒得 0。曾导致「扩展侧主动发起扫描时，通知卡片的风险评分永远是 0」（服务侧直接传结构体不受影响）。
int JsonGetInt(const std::string& json, const std::string& key) {
    std::string s = JsonGetString(json, key);          // 兼容 "score":"220" 这种带引号写法
    if (!s.empty()) return atoi(s.c_str());
    std::string pat = "\"" + key + "\"";
    size_t pos = json.find(pat);
    if (pos == std::string::npos) return 0;
    pos = json.find(':', pos + pat.size());
    if (pos == std::string::npos) return 0;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) ++pos;
    bool neg = false;
    if (pos < json.size() && (json[pos] == '-' || json[pos] == '+')) { neg = (json[pos] == '-'); ++pos; }
    long long n = 0; bool any = false;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') { n = n * 10 + (json[pos] - '0'); ++pos; any = true; }
    if (!any) return 0;
    return (int)(neg ? -n : n);
}

std::string BuildResultJson(const ScanResult& r) {
    std::string s = "{";
    s += "\"type\":\"scan_result\",";
    s += "\"status\":" + JsonString(r.status) + ",";
    s += "\"score\":" + std::to_string(r.score) + ",";
    s += "\"engine\":" + JsonString(r.engine) + ",";
    s += "\"timestamp\":" + JsonString(r.timestamp) + ",";
    s += "\"selfCheck\":" + std::string(r.selfCheck ? "true" : "false") + ",";
    s += "\"hardProof\":" + std::string(r.hardProof ? "true" : "false") + ",";
    s += "\"count\":" + std::to_string(r.findings.size()) + ",";
    s += "\"truncated\":";
    const size_t MAX_FINDINGS_JSON = 400;   // 防响应超 1MB（Chrome 原生消息上限）：超长只发前 N 条
    const size_t outN = (r.findings.size() > MAX_FINDINGS_JSON) ? MAX_FINDINGS_JSON : r.findings.size();
    s += std::string(r.findings.size() > MAX_FINDINGS_JSON ? "true" : "false") + ",";
    s += "\"findings\":[";
    for (size_t i = 0; i < outN; ++i) {
        if (i) s += ",";
        const Finding& f = r.findings[i];
        s += "{";
        s += "\"category\":" + JsonString(f.category) + ",";
        s += "\"severity\":" + JsonString(f.severity) + ",";
        s += "\"title\":" + JsonString(f.title) + ",";
        s += "\"detail\":" + JsonString(f.detail) + ",";
        s += "\"ioc\":" + JsonString(f.ioc) + ",";
        // 关联文件绝对路径（非文件类为空串）：扩展 / 弹窗据此精确清除，不必从 detail 反解
        s += "\"path\":" + JsonString(f.path) + ",";
        s += "\"weight\":" + std::to_string(f.weight);
        s += "}";
    }
    s += "],";
    s += "\"error\":" + JsonString(r.error);
    s += "}";
    return s;
}

// ---------------------------------------------------------------------------
//  命名管道帧 IO
// ---------------------------------------------------------------------------
bool WriteFramed(HANDLE h, const std::string& msg) {
    uint32_t len = (uint32_t)msg.size();
    unsigned char hdr[4] = { (unsigned char)(len & 0xFF), (unsigned char)((len >> 8) & 0xFF),
                             (unsigned char)((len >> 16) & 0xFF), (unsigned char)((len >> 24) & 0xFF) };
    DWORD w = 0;
    if (!WriteFile(h, hdr, 4, &w, nullptr) || w != 4) return false;
    if (len && (!WriteFile(h, msg.data(), len, &w, nullptr) || w != len)) return false;
    return true;
}
bool ReadFramed(HANDLE h, std::string& out) {
    out.clear();
    unsigned char hdr[4] = {0,0,0,0};
    DWORD r = 0;
    // 读取 4 字节长度头（循环确保读满）
    DWORD got = 0;
    while (got < 4) {
        if (!ReadFile(h, hdr + got, 4 - got, &r, nullptr) || r == 0) return false;
        got += r;
    }
    uint32_t len = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) | ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    if (len > 16 * 1024 * 1024) return false;  // 防异常大包
    if (len == 0) { out.clear(); return true; }
    out.resize(len);
    got = 0;
    while (got < len) {
        if (!ReadFile(h, &out[got], len - got, &r, nullptr) || r == 0) return false;
        got += r;
    }
    return true;
}

// ---------------------------------------------------------------------------
//  Native Messaging 宿主注册
// ---------------------------------------------------------------------------
static bool SetRegDefaultSZ(HKEY root, const char* sub, const std::string& data) {
    HKEY hk;
    if (RegCreateKeyExA(root, sub, 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &hk, nullptr) != ERROR_SUCCESS) return false;
    LONG r = RegSetValueExA(hk, nullptr, 0, REG_SZ, (const BYTE*)data.c_str(), (DWORD)data.size() + 1);
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}
static bool DelRegKey(HKEY root, const char* sub) {
    // 递归删除（含子项）
    return RegDeleteTreeA(root, sub) == ERROR_SUCCESS || RegDeleteKeyA(root, sub) == ERROR_SUCCESS;
}

bool WriteNmManifest(const std::string& hostExePath,
                     const std::string& extIdChrome,
                     const std::string& extIdEdge,
                     std::string& outManifestPath) {
    std::string dir = DirName(hostExePath);
    outManifestPath = dir + "\\com.silverfox.envscan.json";
    std::string chrome = extIdChrome.empty() ? extIdEdge : extIdChrome;
    std::string edge   = extIdEdge.empty()   ? extIdChrome : extIdEdge;
    if (chrome.empty()) chrome = "<EXTENSION_ID>";  // 占位（安装时应传入真实 ID）
    std::string json;
    json += "{\n";
    json += "  \"name\": \"" + std::string(NM_HOST_NAME) + "\",\n";
    json += "  \"description\": \"银狐环境检测原生消息宿主\",\n";
    json += "  \"path\": \"" + JsonEscape(hostExePath) + "\",\n";
    json += "  \"type\": \"stdio\",\n";
    json += "  \"allowed_origins\": [\n";
    json += "    \"chrome-extension://" + chrome + "/\"";
    if (!edge.empty() && edge != chrome) json += ",\n    \"chrome-extension://" + edge + "/\"";
    json += "\n  ]\n";
    json += "}\n";
    std::ofstream f(outManifestPath, std::ios::binary);
    if (!f) return false;
    f << json;
    return true;
}

bool RegisterNmHost(const std::string& manifestPath,
                    const std::string& extIdChrome,
                    const std::string& extIdEdge) {
    bool ok = true;
    const char* nm = NM_HOST_NAME;
    // HKLM：系统级安装的 Chrome / Edge
    ok &= SetRegDefaultSZ(HKEY_LOCAL_MACHINE, ("SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    ok &= SetRegDefaultSZ(HKEY_LOCAL_MACHINE, ("SOFTWARE\\WOW6432Node\\Google\\Chrome\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    ok &= SetRegDefaultSZ(HKEY_LOCAL_MACHINE, ("SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    ok &= SetRegDefaultSZ(HKEY_LOCAL_MACHINE, ("SOFTWARE\\WOW6432Node\\Microsoft\\Edge\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    // HKCU：用户级安装的 Chrome / Edge（不写则读不到清单 -> connectNative 失败）
    ok &= SetRegDefaultSZ(HKEY_CURRENT_USER, ("SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    ok &= SetRegDefaultSZ(HKEY_CURRENT_USER, ("SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    (void)extIdChrome; (void)extIdEdge;  // ID 已写入清单，此处仅登记清单路径
    return ok;
}
bool UnregisterNmHost() {
    bool ok = true;
    const char* nm = NM_HOST_NAME;
    ok &= DelRegKey(HKEY_LOCAL_MACHINE, ("SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\" + std::string(nm)).c_str());
    ok &= DelRegKey(HKEY_LOCAL_MACHINE, ("SOFTWARE\\WOW6432Node\\Google\\Chrome\\NativeMessagingHosts\\" + std::string(nm)).c_str());
    ok &= DelRegKey(HKEY_LOCAL_MACHINE, ("SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts\\" + std::string(nm)).c_str());
    ok &= DelRegKey(HKEY_LOCAL_MACHINE, ("SOFTWARE\\WOW6432Node\\Microsoft\\Edge\\NativeMessagingHosts\\" + std::string(nm)).c_str());
    return ok;
}

// 记录已配置的本机扩展 ID（双击重装时复用，避免丢失 allowed_origins 导致扩展连不上）
bool SaveExtIds(const std::string& chrome, const std::string& edge) {
    HKEY hk;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, CFG_ROOT, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hk, NULL) != ERROR_SUCCESS)
        return false;
    if (!chrome.empty())
        RegSetValueExA(hk, "ExtIdChrome", 0, REG_SZ, (const BYTE*)chrome.c_str(), (DWORD)chrome.size() + 1);
    if (!edge.empty())
        RegSetValueExA(hk, "ExtIdEdge", 0, REG_SZ, (const BYTE*)edge.c_str(), (DWORD)edge.size() + 1);
    RegCloseKey(hk);
    return true;
}

bool ReadSavedExtIds(std::string& outChrome, std::string& outEdge) {
    outChrome.clear(); outEdge.clear();
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, CFG_ROOT, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return false;
    auto rd = [&](const char* name, std::string& out) {
        char buf[256] = {0}; DWORD sz = sizeof(buf);
        if (RegQueryValueExA(hk, name, 0, NULL, (LPBYTE)buf, &sz) == ERROR_SUCCESS) out = buf;
    };
    rd("ExtIdChrome", outChrome);
    rd("ExtIdEdge", outEdge);
    RegCloseKey(hk);
    return !outChrome.empty() || !outEdge.empty();
}

}  // namespace sf
