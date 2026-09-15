@echo off
setlocal
REM 银狐环境检测程序 编译脚本（MSVC BuildTools 2022，静态链接 /MT 单文件 EXE）
set "VSCMD=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VSCMD%" (
    echo [错误] 找不到 vcvars64.bat，请确认 MSVC BuildTools 2022 已安装。
    goto :fail
)
call "%VSCMD%" >nul 2>&1
if errorlevel 1 (
    echo [错误] vcvars64.bat 初始化失败。
    goto :fail
)

set "SRC=%~dp0src"
set "OUT=%~dp0dist"
if not exist "%OUT%" mkdir "%OUT%"

echo [编译] 正在用 cl.exe 编译（/MT /std:c++17 /utf-8 /O2）...
cl.exe /nologo /MT /std:c++17 /utf-8 /O2 /EHsc /W3 ^
  "%SRC%\scanner.cpp" "%SRC%\httpd.cpp" "%SRC%\main.cpp" ^
  /Fe:"%OUT%\SilverFoxEnvScan.exe" ^
  /link /SUBSYSTEM:WINDOWS /MACHINE:X64

if errorlevel 1 (
    echo [失败] 编译出错。
    goto :fail
)
echo [成功] 产物：%OUT%\SilverFoxEnvScan.exe
goto :end

:fail
echo BUILD FAILED
:end
endlocal
