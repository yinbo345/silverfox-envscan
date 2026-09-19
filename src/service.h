// service.h — 银狐主防服务（守护 / 安装 / 控制台）
#pragma once
#include <windows.h>

namespace sf {

// 服务模式入口：调用 StartServiceCtrlDispatcher，由 SCM 拉起 ServiceMain
void RunService();

// 安装 / 卸载（需管理员 / SYSTEM 权限）
bool SvcInstall();
bool SvcUninstall();

// 查询后台服务是否已在运行（RUNNING / START_PENDING）
bool IsServiceRunning();

// 安装器（--install）：注册 NM 宿主 + 安装服务 + 加固 + 记录哈希 + 启动
bool DoInstall(const std::string& extIdChrome, const std::string& extIdEdge);
bool DoUninstall();

// 调试：前台运行守护循环（不注册服务），每 15s 扫描并打印结果
void RunConsole();

// 守护线程 / 管道服务线程
void GuardThread();
void PipeServerThread();

// 停止信号
void RequestStop();
bool IsStopRequested();

}  // namespace sf
