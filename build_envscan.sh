#!/usr/bin/env bash
# 银狐环境检测程序构建脚本（MSVC，静态单文件 /MT）
set -e

VC="C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207"
SDK="C:/Program Files (x86)/Windows Kits/10"
SDKVER="10.0.26100.0"
# WebView2 SDK（来自 nuget：microsoft.web.webview2 1.0.2651.64）
WV2="C:/Users/tianl/.nuget/packages/microsoft.web.webview2/1.0.2651.64"

export INCLUDE="$VC/include;$SDK/Include/$SDKVER/ucrt;$SDK/Include/$SDKVER/um;$SDK/Include/$SDKVER/shared;$SDK/Include/$SDKVER/winrt;$WV2/build/native/include"
export LIB="$VC/lib/x64;$SDK/Lib/$SDKVER/ucrt/x64;$SDK/Lib/$SDKVER/um/x64;$WV2/build/native/x64"

CL="$VC/bin/Hostx64/x64/cl.exe"
SRC="D:/silverfox-envscan/src"
ROOT="D:/silverfox-envscan"
DIST="$ROOT/dist"
mkdir -p "$DIST"

# 预授权：dist 下的 EXE 一旦被 HardenFileAcl 收过权（SYSTEM/Administrators:F + Everyone:RX），
# 链接器会报 LNK1104「无法打开文件」——注意这不是文件被占用，而是 ACL 拒绝写入。
# 自己对该文件有 WRITE_DAC（所有者隐含权限），先补一条完全控制再编译，避免每次手动 icacls。
icacls.exe 'D:\silverfox-envscan\dist\SilverFoxEnvScanSvc.exe' /grant "$(whoami):F" >/dev/null 2>&1 || true

echo "==> 编译 SilverFoxEnvScanSvc.exe（服务 + Native Messaging 宿主 单程序，WebView2 通知）"
# 子系统必须是 WINDOWS(GUI)：本程序是 WebView2 宿主，而 CONSOLE 子系统下服务（SCM 启动、无控制台）
# 拉起 toast 时系统会给子进程新建/分配控制台，WebView2 在这种「带隐藏控制台」的非常规宿主里会渲染失败
# （实测 [ctrl] hr=0x8000FFFF / 超时 → 退化成兜底 MessageBox），且子进程会冒出控制台黑框。
# GUI 子系统下任何子进程都没有控制台，WebView2 走标准宿主路径，稳定且无黑框；
# --console 调试模式由 main.cpp 的 EnsureConsoleForDebug()（AttachConsole / AllocConsole）手动挂回控制台。
"$CL" /nologo /MT /std:c++17 /utf-8 /O2 /EHsc /W3 \
  "$SRC/scanner.cpp" "$SRC/common.cpp" "$SRC/service.cpp" "$SRC/main.cpp" "$SRC/toast.cpp" "$SRC/cleaner.cpp" \
  /Fe:"$DIST/SilverFoxEnvScanSvc.exe" \
  /link "$SRC/resource.res" /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup /MACHINE:X64 \
  advapi32.lib bcrypt.lib shell32.lib gdi32.lib user32.lib shcore.lib dwmapi.lib \
  ole32.lib oleaut32.lib uuid.lib wbemuuid.lib \
  WebView2LoaderStatic.lib \
  psapi.lib iphlpapi.lib ws2_32.lib taskschd.lib shlwapi.lib comsuppw.lib wtsapi32.lib

# ---- Authenticode 代码签名（自保必需，勿跳过）----
# VerifySelfIntegrity 自检要求 EXE 携带官方签名（内置指纹 82CECE...）；未签名的 EXE 会被
# 判为「自身完整性失败」→ 高危误报。因此每次编译后必须立即签名。
# 证书：silverfox-sign.pfx（私钥，绝不进 git/开源仓库）。
# 密码优先读签名密码文件（signing/.pfx-password），不存在则回退环境变量 SF_SIGN_PWD；
# 两者都没有则跳过签名并打印警告（仅限开发调试，发布前必须签名）。
SIGNTOOL="C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/signtool.exe"
PFX="$ROOT/signing/silverfox-sign.pfx"
PFX_PW_FILE="$ROOT/signing/.pfx-password"

# ---- 注入 VersionInfo 版本资源（须在签名前）----
# 编译器自带 cvtres 对 RT_VERSION 的目录树合并有 bug（资源数据进了 .rsrc 但类型未注册，
# 资源管理器显示版本空白）。改用系统 API BeginUpdateResource/UpdateResource 注入，可靠有效。
UPDVER="$ROOT/dist/update_ver.exe"
if [ -f "$UPDVER" ]; then
  echo "==> 注入 VersionInfo 版本资源（update_ver.exe）"
  "$UPDVER" "$DIST/SilverFoxEnvScanSvc.exe" || echo "!! 版本注入失败（不影响功能，仅详情页空白）"
else
  echo "!! 未找到 $UPDVER，跳过版本注入（详情页版本信息为空）"
fi

echo "==> Authenticode 签名 SilverFoxEnvScanSvc.exe（自保校验必需）"
if [ ! -f "$PFX" ]; then
  echo "!! 未找到签名证书 $PFX，跳过签名——发布版必须签名！"
elif [ -f "$PFX_PW_FILE" ]; then
  "$SIGNTOOL" sign /fd SHA256 /f "$PFX" /p "$(cat "$PFX_PW_FILE")" "$DIST/SilverFoxEnvScanSvc.exe"
elif [ -n "${SF_SIGN_PWD:-}" ]; then
  "$SIGNTOOL" sign /fd SHA256 /f "$PFX" /p "$SF_SIGN_PWD" "$DIST/SilverFoxEnvScanSvc.exe"
else
  echo "!! 未提供签名密码（.pfx-password 或 SF_SIGN_PWD），跳过签名——发布版必须签名！"
fi

# ---- 7-Zip 多线程压缩 WebView2 运行库 ----
# 运行库是已压缩的 PE 文件，NSIS 单线程 LZMA 压它几乎零收益却要 8 分钟；
# 改用 7z 多线程压成 WebView2Runtime.7z（约 178MB），NSIS 以 zlib 原样存包（秒级）。
# 带「运行库比 7z 新则跳过」判断：运行库不变时增量构建只花编译 + 10 秒 NSIS。
RUNTIME7Z="$ROOT/WebView2Runtime.7z"
RUNTIME_DIR="$ROOT/WebView2Runtime"
if [ ! -f "$RUNTIME7Z" ] || [ "$RUNTIME_DIR" -nt "$RUNTIME7Z" ]; then
  echo "==> 7-Zip 多线程压缩 WebView2 运行库（耗时可观；已最新则跳过）"
  "/c/Program Files/7-Zip/7z.exe" a -t7z -mm=lzma2 -mmt=on -mx=7 "$RUNTIME7Z" "$RUNTIME_DIR"
else
  echo "==> 运行库未变动，跳过 7z 压缩"
fi

echo "==> 构建安装包（NSIS，7z 运行库内嵌进安装包，数据整合为单文件分发）"
NSIS="/c/Program Files (x86)/NSIS/makensis.exe"
"$NSIS" "$ROOT/installer.nsi"

echo "==> 完成"
ls -la "$DIST" "$ROOT/SilverFoxEnvScan-Setup.exe"
