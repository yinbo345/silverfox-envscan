#!/usr/bin/env bash
# 银狐防护主防程序（SilverFoxGuardSvc）构建脚本（MSVC，静态单文件 /MT）
#
# 依赖：
#   1. MSVC BuildTools 2022（cl.exe）+ Windows SDK 10.0.26100
#   2. WebView2 SDK：nuget 下载 microsoft.web.webview2 1.0.2651.64，
#      解压后把 WV2 指向其目录（需要 build/native/include 与 build/native/x64/WebView2LoaderStatic.lib）
#   3. 在仓库根目录执行：bash build.sh
#
# 产物：dist/SilverFoxGuardSvc.exe（服务 + Native Messaging 宿主 + WebView2 通知 单程序）
set -e

VC="C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207"
SDK="C:/Program Files (x86)/Windows Kits/10"
SDKVER="10.0.26100.0"
WV2="C:/Users/tianl/.nuget/packages/microsoft.web.webview2/1.0.2651.64"

export INCLUDE="$VC/include;$SDK/Include/$SDKVER/ucrt;$SDK/Include/$SDKVER/um;$SDK/Include/$SDKVER/shared;$SDK/Include/$SDKVER/winrt;$WV2/build/native/include"
export LIB="$VC/lib/x64;$SDK/Lib/$SDKVER/ucrt/x64;$SDK/Lib/$SDKVER/um/x64;$WV2/build/native/x64"

CL="$VC/bin/Hostx64/x64/cl.exe"
RC="$SDK/bin/$SDKVER/x64/rc.exe"

ROOT="$(cd "$(dirname "$0")" && pwd -W 2>/dev/null || pwd)"
SRC="$ROOT/src"
DIST="$ROOT/dist"
mkdir -p "$DIST"

echo "==> 编译资源脚本 resource.rc → resource.res"
"$RC" /nologo /fo "$SRC/resource.res" "$SRC/resource.rc"

echo "==> 编译 SilverFoxGuardSvc.exe（服务 + Native Messaging 宿主，WebView2 通知 + 主界面）"
# 子系统必须是 WINDOWS(GUI)：WebView2 宿主，避免子进程冒出控制台黑框
# --console 调试模式由 main.cpp 的 EnsureConsoleForDebug() 手动挂回控制台
"$CL" /nologo /MT /std:c++17 /utf-8 /O2 /EHsc /W3 \
  "$SRC/scanner.cpp" "$SRC/common.cpp" "$SRC/service.cpp" "$SRC/main.cpp" "$SRC/toast.cpp" "$SRC/cleaner.cpp" "$SRC/compute.cpp" "$SRC/matcher.cpp" "$SRC/gui.cpp" "$SRC/probe.cpp" "$SRC/behavior.cpp" "$SRC/rollback.cpp" "$SRC/bootguard.cpp" \
  /Fe:"$DIST/SilverFoxGuardSvc.exe" \
  /link "$SRC/resource.res" /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup /MACHINE:X64 \
  advapi32.lib bcrypt.lib shell32.lib gdi32.lib user32.lib shcore.lib dwmapi.lib \
  ole32.lib oleaut32.lib uuid.lib wbemuuid.lib \
  WebView2LoaderStatic.lib \
  psapi.lib iphlpapi.lib ws2_32.lib taskschd.lib shlwapi.lib comsuppw.lib wtsapi32.lib

# ---- Shell 扩展 DLL（Win11 一级右键菜单，稀疏包 IExplorerCommand）----
echo "==> 编译 SilverFoxShell.dll（Win11 一级右键菜单）"
mkdir -p "$DIST/shell"
"$CL" /nologo /LD /MT /std:c++17 /utf-8 /O2 /EHsc \
  "$SRC/shell/SilverFoxShell.cpp" /Fe:"$DIST/shell/SilverFoxShell.dll" \
  /link advapi32.lib ole32.lib uuid.lib shlwapi.lib shell32.lib

echo "==> 完成"
ls -la "$DIST"
