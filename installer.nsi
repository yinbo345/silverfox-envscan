Unicode true
; ===========================================================================
;  银狐环境检测 · 安装包 (NSIS)
;  双击即可安装：释放文件 + 注册 Windows 服务 + 注册 Native Messaging 宿主
;  纯静态 /MT 编译，无需 VC 运行库，零第三方依赖。
; ===========================================================================
SetCompressor zlib

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

!define MUI_ICON "D:\silverfox-envscan\shield.ico"
!define MUI_UNICON "D:\silverfox-envscan\shield.ico"

Name "银狐环境检测"
OutFile "D:\silverfox-envscan\SilverFoxEnvScan-preview-Setup.exe"
Icon "D:\silverfox-envscan\shield.ico"
UninstallIcon "D:\silverfox-envscan\shield.ico"
InstallDir "$PROGRAMFILES64\SilverFoxEnvScan"
RequestExecutionLevel admin        ; 写 HKLM + 安装 Windows 服务必须管理员
XPStyle on

VIProductVersion "1.0.0.0"
VIAddVersionKey "ProductName" "银狐环境检测"
VIAddVersionKey "CompanyName" "银狐防护"
VIAddVersionKey "FileDescription" "银狐环境检测安装程序"
VIAddVersionKey "LegalCopyright" "银狐防护"
VIAddVersionKey "FileVersion" "1.0.0.0"

; ---------------- MUI 页面 ----------------
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
Page custom ExtIdPageShow ExtIdPageLeave
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TEXT "安装完成。银狐环境检测已作为 Windows 服务常驻后台，$\n可在浏览器扩展「环境检测」中查看盾牌状态（绿=正常 / 红=感染）。"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "SimpChinese"

; ---------------- 变量 ----------------
Var Dialog
Var ChromeId
Var EdgeId
Var ChromeEdit
Var EdgeEdit

; ---------------- 安装段 ----------------
Section "安装" SEC_INSTALL
  SetOutPath "$INSTDIR"

  ; 先强制停止服务、结束进程（防止旧 EXE 被占用导致无法覆盖）；nsExec 静默执行不弹控制台窗口
  nsExec::Exec '"$SYSDIR\sc.exe" stop SilverFoxEnvScanSvc'
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM SilverFoxEnvScanSvc.exe'

  ; 旧版 ACL 可能锁死文件；直接重命名让路，避免覆盖被锁文件
  IfFileExists "$INSTDIR\SilverFoxEnvScanSvc.exe" 0 +2
    nsExec::Exec 'cmd.exe /c takeown /F "$INSTDIR\SilverFoxEnvScanSvc.exe" >nul 2>&1 & icacls "$INSTDIR\SilverFoxEnvScanSvc.exe" /grant *S-1-1-0:F /T >nul 2>&1 & rename "$INSTDIR\SilverFoxEnvScanSvc.exe" SilverFoxEnvScanSvc.exe.old'

  SetOutPath "$INSTDIR"
  File "D:\silverfox-envscan\dist\SilverFoxEnvScanSvc.exe"

  ; 通知提示音（弹出环境异常提示时播放；缺失不影响通知显示）
  SetOutPath "$INSTDIR\assets"
  File "D:\silverfox-envscan\assets\dragon-studio-new-notification-3-398649.mp3"
  SetOutPath "$INSTDIR"

  ; 自带 WebView2 固定版本运行时（完整未精简，不依赖系统 Edge，卸载 Edge 也不影响）。
  ; 运行库预先用 7-Zip 多线程压成 WebView2Runtime.7z（约 178MB），直接内嵌进安装包数据块，
  ; 安装时由捆绑的 7z.exe 解压（ExecWait 会弹出命令行窗口，便于查看解压进度）。
  ; 大文件用 SetCompress off 原样存储：NSIS 构建秒级，且 WriteUninstaller 用本（CONSOLE 子系统）方案不卡。
  SetCompress off
  File "D:\silverfox-envscan\WebView2Runtime.7z"
  SetCompress auto
  ; 捆绑 7-Zip 提取器（目标机未必装 7-Zip，解压后删除）
  File "C:\Program Files\7-Zip\7z.exe"
  File "C:\Program Files\7-Zip\7z.dll"
  ; 清理旧运行库（避免升级时文件被占用导致解压失败）
  RMDir /r "$INSTDIR\WebView2Runtime"
  ; 用捆绑的 7-Zip 解压运行库（ExecWait 弹命令行窗口，可见解压进度）
  ExecWait '"$INSTDIR\7z.exe" x -y "$INSTDIR\WebView2Runtime.7z" -o"$INSTDIR"'
  ; 解压完成，删除压缩包与提取器
  Delete "$INSTDIR\WebView2Runtime.7z"
  Delete "$INSTDIR\7z.exe"
  Delete "$INSTDIR\7z.dll"

  DetailPrint "正在生成卸载程序..."
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SilverFoxEnvScan" "DisplayName" "银狐环境检测"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SilverFoxEnvScan" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SilverFoxEnvScan" "DisplayIcon" "$\"$INSTDIR\SilverFoxEnvScanSvc.exe$\""
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SilverFoxEnvScan" "Publisher" "银狐防护"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SilverFoxEnvScan" "NoModify" "1"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SilverFoxEnvScan" "NoRepair" "1"

  ; 调用服务 EXE 自注册（--silent：由 NSIS 完成页统一提示，不重复弹窗；EXE 为 CONSOLE 子系统，
  ; ExecWait 会弹出命令行窗口显示注册进度——与之前可用的「有命令行弹出」方案一致）
  ExecWait '"$INSTDIR\SilverFoxEnvScanSvc.exe" --install --silent --ext-id=$ChromeId --edge-ext-id=$EdgeId'
SectionEnd

; ---------------- 卸载段 ----------------
Section "Uninstall"
  ; ① 强制结束所有残留进程：服务常驻且可能卡在命名管道阻塞无法优雅停止，连同 NM 宿主 / toast 一并清理。
  ;    不先杀进程，SCM 不会把服务标记为已停止，后续的 sc delete 会静默失败 → 服务残留（旧版坑）。
  ExecWait '"$SYSDIR\taskkill.exe" /F /IM SilverFoxEnvScanSvc.exe'
  Sleep 1000
  ; ② 进程退出后 SCM 才把服务置为已停止，此时删除服务项才能成功
  nsExec::Exec '"$SYSDIR\sc.exe" delete SilverFoxEnvScanSvc'
  ; ③ 再用程序自身清理注册表 / Native Messaging 项并兜底删除服务（SvcUninstall 已加强制终止兜底）
  ExecWait '"$INSTDIR\SilverFoxEnvScanSvc.exe" --uninstall --silent'
  Delete "$INSTDIR\SilverFoxEnvScanSvc.exe"
  Delete "$INSTDIR\SilverFoxEnvScanSvc.exe.old"
  Delete "$INSTDIR\com.silverfox.envscan.json"
  Delete "$INSTDIR\assets\dragon-studio-new-notification-3-398649.mp3"
  RMDir "$INSTDIR\assets"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\SilverFoxEnvScan"
SectionEnd

; ---------------- 自定义页面：收集扩展 ID ----------------
Function ExtIdPageShow
  !insertmacro MUI_HEADER_TEXT "扩展标识" "填写浏览器扩展 ID 以建立联动"
  nsDialogs::Create 1018
  Pop $Dialog
  ${If} $Dialog == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 36u "银狐环境检测通过 Native Messaging 与浏览器扩展联动。请在扩展管理页（需开启开发者模式）复制银狐防护扩展的 ID 填入下方。"
  Pop $R0
  ${NSD_CreateLabel} 0 48u 100% 12u "Chrome / Edge 扩展 ID（必填）："
  Pop $R0
  ${NSD_CreateText} 0 62u 100% 12u ""
  Pop $ChromeEdit
  ${NSD_CreateLabel} 0 90u 100% 12u "Edge 扩展 ID（可选，仅 Chrome 可留空）："
  Pop $R0
  ${NSD_CreateText} 0 104u 100% 12u ""
  Pop $EdgeEdit

  nsDialogs::Show
FunctionEnd

Function ExtIdPageLeave
  ${NSD_GetText} $ChromeEdit $ChromeId
  ${NSD_GetText} $EdgeEdit $EdgeId
  ${If} $ChromeId == ""
    MessageBox MB_OK|MB_ICONEXCLAMATION "Chrome 扩展 ID 不能为空，否则无法与扩展联动。$\n（浏览器地址栏输入 chrome://extensions 并开启开发者模式即可看到 ID）"
    Abort
  ${EndIf}
FunctionEnd
