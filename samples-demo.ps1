# =============================================================
#  SilverFox 环境检测 · 高级演示样本一键部署（难样本 / 带自保能力）
#  用法:  powershell -ExecutionPolicy Bypass -File samples-demo.ps1
#  说明:  自动清理旧样本 → 释放全套对抗性样本 → 打印样本清单
#  样本均为 ping.exe 改名，wan全无害，仅用于演示检测/普通删除/高级删除链路。
#  其中 ACL 压制文件仅保留当前用户权限，服务(LocalSystem) 无权删除 →
#  普通删除必然失败 → 自动升级「高级删除」（夺权+硬删+衍生物连坐）。
# =============================================================
$ErrorActionPreference = 'Continue'
$tmp  = $env:TEMP
$ME   = $env:USERNAME
$PING = 'C:\Windows\System32\ping.exe'

function New-RandName {
    -join ((0..8) | ForEach-Object { 'abcdefghijklmnopqrstuvwxyz0123456789'[(Get-Random -Maximum 36)] })
}
function Start-Demo([string]$file) { Start-Process $file -ArgumentList '-t','127.0.0.1' -WindowStyle Hidden }

# ---------- 1. 清理旧样本 ----------
Write-Host '==> 清理旧样本...' -ForegroundColor Yellow
foreach ($n in @('DesignAccent','k9xR3vq','qzP5xT8','x7wPq2m','z9qKx4v')) {
    Get-Process $n -ErrorAction SilentlyContinue | Stop-Process -Force
}
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -like '*k9xR3vq*' -or $_.CommandLine -like '*x7wPq2m*' -or $_.CommandLine -like '*z9qKx4v*' } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
foreach ($p in @("$tmp\DesignAccent.exe","$tmp\k9xR3vq.exe","$tmp\qzP5xT8.exe","$tmp\multi","$tmp\deepdemo","$tmp\hardcase","$tmp\x7wPq2m.exe","$tmp\z9qKx4v.exe","$tmp\spread")) {
    Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
}
# 跨目录衍生物旧残留（固定 sf_spread 子目录，一处清全清）
foreach ($p in @("$env:TEMP\sf_spread","$env:APPDATA\sf_spread","$env:USERPROFILE\Downloads\sf_spread",'C:\Users\Public\Downloads\sf_spread','C:\ProgramData\sf_spread')) {
    Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
}
Get-ChildItem 'C:\Users\Public\download\*.exe' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

# ---------- 2. 释放样本 ----------
Write-Host '==> 释放对抗性样本...' -ForegroundColor Cyan
$rA = New-RandName; $rB = New-RandName; $rC = New-RandName

# —— 简单陪衬（普通删除段就清得掉）——
Copy-Item $PING "$tmp\DesignAccent.exe" -Force; Start-Demo "$tmp\DesignAccent.exe"   # 已知银狐进程名
New-Item -ItemType Directory -Path 'C:\Users\Public\download' -Force | Out-Null
'x' | Out-File 'C:\Users\Public\download\季度报表.xlsx.exe' -Encoding default -Force
'x' | Out-File 'C:\Users\Public\download\合同.docx.exe' -Encoding default -Force

# —— S1: 随机名进程 + 复活守护 + ACL 压制（运行中，最硬）——
Copy-Item $PING "$tmp\k9xR3vq.exe" -Force; Start-Demo "$tmp\k9xR3vq.exe"
$wg = "while(`$true){if(-not(Get-Process k9xR3vq -ErrorAction SilentlyContinue)){Start-Process '$tmp\k9xR3vq.exe' -ArgumentList '-t','127.0.0.1' -WindowStyle Hidden};Start-Sleep -Milliseconds 400}"
Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-Command', $wg

# —— S2: 深层 ACL 压制静止型 + 伴生衍生物（.dll/.bin 连坐验证）——
New-Item -ItemType Directory -Path "$tmp\hardcase\nested" -Force | Out-Null
Copy-Item $PING "$tmp\hardcase\nested\$rA.exe" -Force
'data' | Out-File "$tmp\hardcase\nested\$rA.dll" -Encoding default -Force   # 同批释放的随机名 DLL(衍生物)
'data' | Out-File "$tmp\hardcase\nested\$rA.bin" -Encoding default -Force   # 随机名配置(衍生物)

# —— S3: 同名多实例（遏制按基名全杀验证）——
Copy-Item $PING "$tmp\qzP5xT8.exe" -Force; Start-Demo "$tmp\qzP5xT8.exe"
New-Item -ItemType Directory -Path "$tmp\multi" -Force | Out-Null
Copy-Item $PING "$tmp\multi\qzP5xT8.exe" -Force; Start-Demo "$tmp\multi\qzP5xT8.exe"

# —— 深层随机名静止文件（全盘/定点扫描验证）——
New-Item -ItemType Directory -Path "$tmp\deepdemo\inner" -Force | Out-Null
Copy-Item $PING "$tmp\deepdemo\inner\$rB.exe" -Force

# —— S4: 快速轮换 PID（进程高频重生，快照杀不完，只能靠删文件断根）——
Copy-Item $PING "$tmp\x7wPq2m.exe" -Force
# watchdog：每 250ms 拉一个短命实例（ping -n 1 约 1 秒退出），PID 持续变化
$rot = "while(`$true){Start-Process '$tmp\x7wPq2m.exe' -ArgumentList '-n','1','127.0.0.1' -WindowStyle Hidden;Start-Sleep -Milliseconds 250}"
Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-Command', $rot

# —— S5: 独占锁持锁者（FileShare.None 独占打开，持锁进程不以样本名运行，杀不到）——
Copy-Item $PING "$tmp\z9qKx4v.exe" -Force; Start-Demo "$tmp\z9qKx4v.exe"
$lock = "$f=[System.IO.File]::Open('$tmp\z9qKx4v.exe','Open','Read','None');while(`$true){Start-Sleep -Milliseconds 800}"
Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-Command', $lock  # 持锁者（命令行含 holdlock 标记用于清理）

# —— S6: 跨目录衍生物（主样本 ACL 压制深层静止；衍生物同批随机名散布 5 个高发区）——
# 主样本在 TEMP\spread\host\（同目录连坐只能扫到这里），衍生物靠「跨目录高发区收集」连坐清除。
$rD = New-RandName
New-Item -ItemType Directory -Path "$tmp\spread\host" -Force | Out-Null
Copy-Item $PING "$tmp\spread\host\$rD.exe" -Force
'data' | Out-File "$tmp\spread\host\$rD.dat" -Encoding default -Force          # 同目录配置(同目录连坐覆盖)
foreach ($d in @("$tmp\sf_spread","$env:APPDATA\sf_spread","$env:USERPROFILE\Downloads\sf_spread",'C:\Users\Public\Downloads\sf_spread','C:\ProgramData\sf_spread')) {
    New-Item -ItemType Directory -Path $d -Force | Out-Null
}
'data' | Out-File "$tmp\sf_spread\$rD.dll" -Encoding default -Force            # TEMP 区衍生物
'data' | Out-File "$env:APPDATA\sf_spread\$rD.dat" -Encoding default -Force    # Roaming 区衍生物
'data' | Out-File "$env:USERPROFILE\Downloads\sf_spread\$rD.bin" -Encoding default -Force   # Downloads 区衍生物
'data' | Out-File "C:\Users\Public\Downloads\sf_spread\$rD.vbs" -Encoding default -Force    # Public\Downloads 脚本衍生物
'data' | Out-File "C:\ProgramData\sf_spread\$rD.tmp" -Encoding default -Force  # ProgramData 区衍生物

# —— 收紧 ACL：仅留当前用户，移除 SYSTEM/管理员（服务无权删 → 逼出高级删除）——
foreach ($f in @("$tmp\k9xR3vq.exe","$tmp\hardcase\nested\$rA.exe","$tmp\hardcase\nested\$rA.dll","$tmp\hardcase\nested\$rA.bin","$tmp\x7wPq2m.exe","$tmp\spread\host\$rD.exe")) {
    icacls $f /inheritance:r /remove:g "NT AUTHORITY\SYSTEM" "BUILTIN\Administrators" /grant:r "$ME`:(F)" | Out-Null
    attrib +h +s +r $f | Out-Null
}

# ---------- 3. 样本清单 ----------
Start-Sleep -Milliseconds 900
Write-Host ''
Write-Host '================ 对抗样本清单 ================' -ForegroundColor Green
Write-Host '--- 普通删除能清 ---' -ForegroundColor White
Write-Host "  [进程] DesignAccent.exe  (已知银狐进程名)" -ForegroundColor Red
Write-Host "  [文件] C:\Users\Public\download\季度报表.xlsx.exe / 合同.docx.exe  (双后缀诱饵)" -ForegroundColor Red
Write-Host "  [文件] $env:TEMP\deepdemo\inner\$rB.exe  (深层文件夹随机名)" -ForegroundColor Red
Write-Host '--- 需升级高级删除(自保对抗) ---' -ForegroundColor DarkRed
Write-Host "  [进程] k9xR3vq.exe  (复活守护+ACL压制+隐藏/系统/只读，运行中)" -ForegroundColor Red
Write-Host "  [文件] $env:TEMP\hardcase\nested\$rA.exe  (深层ACL压制静止型)" -ForegroundColor Red
Write-Host "  [文件] $env:TEMP\hardcase\nested\$rA.dll / $rA.bin  (随机名衍生物，连坐删除)" -ForegroundColor Red
Write-Host "  [进程] qzP5xT8.exe ×2 实例  (同名多实例)" -ForegroundColor Red
Write-Host "  [进程] x7wPq2m.exe  (快速轮换PID：进程每250ms高频重生，需删文件断根)" -ForegroundColor DarkRed
Write-Host "  [文件] $env:TEMP\z9qKx4v.exe  (被FileShare.None独占锁持锁者锁定，高级删除走重启登记兜底)" -ForegroundColor DarkRed
Write-Host '--- 跨目录衍生物(主样本ACL压制,衍生物散布5区,连坐验证) ---' -ForegroundColor Magenta
Write-Host "  [文件] $env:TEMP\spread\host\$rD.exe  (主样本·深层ACL压制)" -ForegroundColor Red
Write-Host "  [衍生物] $env:TEMP\sf_spread\$rD.dll" -ForegroundColor Magenta
Write-Host "  [衍生物] $env:APPDATA\sf_spread\$rD.dat" -ForegroundColor Magenta
Write-Host "  [衍生物] $env:USERPROFILE\Downloads\sf_spread\$rD.bin" -ForegroundColor Magenta
Write-Host "  [衍生物] C:\Users\Public\Downloads\sf_spread\$rD.vbs" -ForegroundColor Magenta
Write-Host "  [衍生物] C:\ProgramData\sf_spread\$rD.tmp" -ForegroundColor Magenta
Write-Host '==============================================' -ForegroundColor Green
Write-Host '下一步：浏览器扩展点「扫描」→ 检出全部；' -ForegroundColor White
Write-Host '点「清除威胁」→ 普通删除清掉简单部分，ACL 压制部分失败 → 自动升级' -ForegroundColor White
Write-Host '「高级删除」→ 遏制+夺权+解ACL+硬删+衍生物连坐，全部清除。' -ForegroundColor White