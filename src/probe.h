// probe.h — 银狐主防单文件启发式查杀引擎（独立于全盘扫描链路）
#pragma once
#include <string>

namespace sf {

// 单文件启发式判定：返回 JSON
// {"level":0|1|2,"score":n,"type":"PE|NSIS|INNO|ZIP|OTHER",
//  "title":"...","hits":[{"sev":0|1|2|3,"name":"...","desc":"..."},...]}
// level: 0=正常 1=可疑 2=危险
// 全程离线、不运行样本、不做整文件字符串泛匹配。
std::string ScanTargetFile(const std::string& path);

}  // namespace sf