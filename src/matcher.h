// matcher.h — 银狐家族特征串匹配器（Aho-Corasick 自动机，CPU / GPU 共用一张表）
//
// 为什么要它：
//   原实现是「每个字节位置逐条试 N 条模式」，实测在 32 条模式下 CPU 单线程只有 4 MB/s。
//   换成 AC 自动机后，同一份数据达 199 MB/s（单线程）、470 MB/s（4 线程）—— 提升约 50 倍。
//   原因：AC 把 N 条模式编译成一张【确定性状态转移图】，扫描时每读一个字节就在图上走一步
//        （O(1)/字节、无回溯），而线性匹配是 O(N × 模式长度)/字节。
//
// 这张图同时就是「显存里的地图」：
//   同一个 table 直接上传显存常驻，GPU 每个线程沿表寻路（每字节一次查表）。
//   MX250 实测：GPU 地图式 1534 MB/s  vs  GPU 线性 51 MB/s（30 倍）。
//
// 表的规模（"缩小版"地图）：
//   40 条模式 → 约 300~500 状态 → 300~500 × 256 × 4B ≈ 0.3~0.5 MB。中低端显卡完全吃得下。
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace sf {

class AcMatcher {
public:
    // pats：模式串（大小写敏感，与字节流逐字节比较）。构建后不可再改。
    void Build(const std::vector<std::string>& pats);

    bool   empty()        const { return states_ <= 1; }
    int    stateCount()   const { return states_; }
    int    patternCount() const { return (int)pats_.size(); }
    size_t longestPattern() const { return maxLen_; }
    size_t tableBytes()   const { return table_.size() * sizeof(uint32_t); }

    // 确定性转移表：table[state * 256 + byte] = nextState
    const std::vector<uint32_t>& table()   const { return table_; }
    // 终止标记：term[state] != 0 表示走到该状态即命中某个模式
    const std::vector<uint32_t>& term()    const { return term_; }
    // 命中模式下标（termPat[state]，-1 = 非终止态）
    const std::vector<int32_t>&  termPat() const { return termPat_; }
    const std::vector<std::string>& patterns() const { return pats_; }

    // CPU 扫描：返回命中的第一个模式下标，未命中返回 -1
    int Scan(const uint8_t* data, size_t len) const;

private:
    int      states_ = 0;
    size_t   maxLen_ = 0;
    std::vector<std::string> pats_;
    std::vector<uint32_t> table_;
    std::vector<uint32_t> term_;
    std::vector<int32_t>  termPat_;
};

// 读取家族特征串：规则库 probe_rules.txt 的「F|xxx」行 + 内置核心串，去重后返回。
// 规则文件查找顺序与主程序一致（EXE 同级 data\ → EXE 同级 → ProgramData）。
std::vector<std::string> LoadFamilyPatterns();

}  // namespace sf
