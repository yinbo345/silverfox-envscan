## 银狐环境检测程序 · Preview

针对「银狐 / 游蛇（Silver Fox / APT-Q-27）」远控木马的 Windows 环境检测与清除工具。
单个 C++ EXE，同时作为 **Windows 常驻服务** 与「银狐防护」浏览器扩展的 **联动宿主**。

### 功能

- **九大维度巡检**：进程 / 注册表 / 服务 / 计划任务 / 网络 / 文件（含 ADS 备用数据流、双后缀、畸形文件名）/ Defender 状态 / Hosts 劫持 / WMI 持久化
- **一键清除**：结束占用进程 → 删除载荷与伴生 DLL → 仍被占用则登记重启删除
- **高级清除**：遏制强杀全部同名实例与子进程树 → 夺权解 ACL → 硬删 → 跨 Temp / Roaming / Downloads / Public / ProgramData 连坐清除随机名衍生物
- **评分模型**：铁证直判 + 旁证零贡献 + 同类只算一次 + 分数封顶
- **检测结果分级**：高危 / 中危 / 低危 / 警告（不计分提示）四级

### 使用

1. 下载下方 `SilverFoxEnvScan-preview-Setup.exe`，以**管理员身份**安装（自动注册 Windows 服务，无窗口、无托盘，可随时在服务管理器卸载）
2. 配合浏览器扩展 [银狐防护 silverfox-guard](https://github.com/yinbo345/silverfox-guard) 使用：扩展内可查看实时环境状态、触发全量扫描、一键清除并查看清除记录

### 说明

- 本版本为 **Preview 预览版**，检测规则与清除策略仍在快速迭代，欢迎反馈
- 源码以 **MIT 协议**开源，**自保模块已移除**（详见仓库 README）
- 系统要求：Windows 10 64 位（21H2+）/ Windows 11；Intel 奔腾 G4560 或同级即可运行
