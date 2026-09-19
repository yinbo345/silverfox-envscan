// matcher.cpp — Aho-Corasick 自动机实现（构建 + CPU 扫描 + 规则库加载）
#include "matcher.h"

#include <windows.h>
#include <algorithm>
#include <fstream>
#include <queue>
#include <unordered_set>

namespace sf {

void AcMatcher::Build(const std::vector<std::string>& pats) {
    // 过滤：空串、超长串（模式 255 字节上限，避免畸形规则撑爆状态机），并去重
    std::vector<std::string> uniq;
    {
        std::unordered_set<std::string> seen;
        for (const auto& p : pats) {
            if (p.empty() || p.size() > 255) continue;
            if (seen.insert(p).second) uniq.push_back(p);
        }
    }
    pats_.swap(uniq);

    struct Node { int nx[256]; int fail; int pat; };
    std::vector<Node> ac;
    ac.reserve(1024);
    Node root;
    for (int i = 0; i < 256; ++i) root.nx[i] = -1;
    root.fail = 0; root.pat = -1;
    ac.push_back(root);

    maxLen_ = 0;
    for (size_t pi = 0; pi < pats_.size(); ++pi) {
        const std::string& p = pats_[pi];
        if (p.size() > maxLen_) maxLen_ = p.size();
        int cur = 0;
        for (unsigned char b : p) {
            if (ac[cur].nx[b] == -1) {
                Node nd;
                for (int i = 0; i < 256; ++i) nd.nx[i] = -1;
                nd.fail = 0; nd.pat = -1;
                ac[cur].nx[b] = (int)ac.size();
                ac.push_back(nd);
            }
            cur = ac[cur].nx[b];
        }
        if (ac[cur].pat < 0) ac[cur].pat = (int)pi;   // 同一结点只记首个模式
    }

    // BFS 构建 fail 链，并把 goto 展开成【确定性转移】（这样运行时无需回溯）
    std::queue<int> q;
    for (int b = 0; b < 256; ++b) {
        int c = ac[0].nx[b];
        if (c != -1) { ac[c].fail = 0; q.push(c); }
        else         { ac[0].nx[b] = 0; }             // 根上不存在的转移 → 回到根
    }
    while (!q.empty()) {
        int u = q.front(); q.pop();
        for (int b = 0; b < 256; ++b) {
            int c = ac[u].nx[b];
            if (c != -1) {
                int f = ac[ac[u].fail].nx[b];
                ac[c].fail = f;
                if (ac[c].pat < 0) ac[c].pat = ac[f].pat;   // 继承 fail 链上的命中
                q.push(c);
            } else {
                ac[u].nx[b] = ac[ac[u].fail].nx[b];         // 失配边直接补成确定转移
            }
        }
    }

    states_ = (int)ac.size();
    table_.assign((size_t)states_ * 256, 0);
    term_.assign(states_, 0);
    termPat_.assign(states_, -1);
    for (int s = 0; s < states_; ++s) {
        uint32_t* row = &table_[(size_t)s * 256];
        for (int b = 0; b < 256; ++b) row[b] = (uint32_t)ac[s].nx[b];
        termPat_[s] = ac[s].pat;
        term_[s] = (ac[s].pat >= 0) ? 1u : 0u;
    }
}

int AcMatcher::Scan(const uint8_t* data, size_t len) const {
    if (states_ <= 1 || !data || len == 0) return -1;
    uint32_t st = 0;
    for (size_t i = 0; i < len; ++i) {
        st = table_[(size_t)st * 256 + data[i]];
        if (term_[st]) return (int)termPat_[st];
    }
    return -1;
}

// ---------------------------------------------------------------------------
//  规则库加载（家族特征串 = 地图上的「路标」）
// ---------------------------------------------------------------------------
static std::string ExeDir() {
    char buf[MAX_PATH] = { 0 };
    DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string p(buf, n);
    size_t s = p.find_last_of("\\/");
    return (s == std::string::npos) ? std::string(".") : p.substr(0, s);
}

std::vector<std::string> LoadFamilyPatterns() {
    // 内置核心串：与 scanner.cpp 的 CPU 判定、原 HLSL 硬编码保持一致的家族标识。
    // 大小写变体都放进来（AC 是逐字节比较，大小写敏感）。
    std::vector<std::string> pats = {
        "SFuck", "sfuck", "+sfuck",
        "qQ996545",
        "Win0s", "win0s",
        "Gh0st", "gh0st",
        "winos",
    };

    // 规则库 F 行（规则库是外置的，新增家族串无需重新编译二进制）
    std::string exeDir = ExeDir();
    std::string cands[] = {
        exeDir + "\\data\\probe_rules.txt",
        exeDir + "\\probe_rules.txt",
        "C:\\ProgramData\\SilverFoxGuard\\probe_rules.txt",
    };
    for (const auto& fp : cands) {
        std::ifstream f(fp, std::ios::binary);
        if (!f) continue;
        std::string line;
        while (std::getline(f, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.size() < 3) continue;
            if (line[0] != 'F' || line[1] != '|') continue;      // 只要家族串
            std::string v = line.substr(2);
            if (v.empty() || v.size() > 255) continue;
            pats.push_back(v);
        }
        break;
    }
    return pats;
}

}  // namespace sf
