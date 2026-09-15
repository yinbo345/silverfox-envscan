# SilverFoxEnvScan — 银狐环境检测程序（开源版）

针对「银狐 / 游蛇（Silver Fox / APT-Q-27）」远控木马的 Windows 环境检测与清除工具。单个 C++ EXE，同时作为：

- **Windows 常驻服务**（`SilverFoxEnvScanSvc`）：每 3 分钟巡检本机九大维度
- **浏览器 Native Messaging 宿主**：与「银狐防护」浏览器扩展联动（无 TCP 端口，命名管道通信）

配套浏览器扩展：<https://github.com/yinbo345/silverfox-guard>

## 检测维度（九大模块）

进程 / 注册表 Run 键 / 系统服务 / 计划任务 / 网络连接 / 文件系统（含 ADS 备用数据流、双后缀、畸形文件名）/ Windows Defender 状态 / Hosts 劫持 / WMI 事件订阅（持久化）。

评分模型：铁证直判（C2 活跃连接 / 已知样本进程 / 标记文件）+ 旁证零贡献 + 同类只算一次 + 分数封顶。

## 清除能力

- **普通清除**：结束占用进程 → 删除载荷与伴生 DLL → 失败登记重启删除（`PendingFileRenameOperations`，`\??\` NT 路径）
- **高级清除**：按基名强杀全部同名实例与子进程树（两轮快照防复活）→ 清属性 + 夺权解 DACL → 硬删（POSIX 语义）→ 跨 `Temp` / `Roaming` / `Downloads` / `Public` / `ProgramData` 连坐清除随机名衍生物

## 构建

依赖：

- MSVC BuildTools 2022（MSVC v143，x64）
- Windows SDK 10.0.26100.0
- WebView2 SDK（`nuget install microsoft.web.webview2 -Version 1.0.2651.64`）
- （打包安装包）NSIS 3.x + 7-Zip

```bash
bash build_envscan.sh     # 完整构建：编译 → 注入版本 → （可选签名）→ 安装包
# 或
build.bat                 # 仅编译（旧脚本，产物在 dist\）
```

源码为 UTF-8，`cl` 参数已带 `/utf-8`。未配置代码签名证书时构建脚本会跳过签名并打印警告（功能不受影响）。

## 演示样本

`samples-demo.ps1` 一键释放全套无害对抗样本（`ping.exe` 改名），用于验证检测 / 普通删除 / 高级删除全链路：

```powershell
powershell -ExecutionPolicy Bypass -File samples-demo.ps1
```

包含：已知银狐进程名、双后缀诱饵、深层随机名、复活守护 + ACL 压制、同名多实例、快速轮换 PID、独占锁持有者，以及**跨目录衍生物**（散布 Temp / Roaming / Downloads / Public / ProgramData 五个高发区）。

## 开源版说明

本仓库为**开源版**，与作者自用版本的区别：**自保模块已整体移除**，包括——

- 服务被删除后的自动重建（`EnsureServiceRegistered` / NM 宿主自愈）
- 程序文件 ACL 加固（`HardenFileAcl`）
- 自身完整性哈希基线与签名指纹校验（`VerifySelfIntegrity` / `StoreHash`）

核心检测与清除能力完整保留。

## 协议

[MIT](./LICENSE)
