# startup.ps1 - Windows 开机/手动启动脚本（完全支持中文，无乱码）
# 使用方法：右键 → 用 PowerShell 运行（或设成开机自启）

$ScriptPath = Join-Path $PSScriptRoot "main.py"          # 改成你的主入口文件，例如 proxy.py 或 main.py
$LogPath    = Join-Path $PSScriptRoot "startup_log.log"
$Python     = "python"                                    # 如果有多个 Python，可改成完整路径如 "C:\Python39\python.exe"

# 检查 Python 是否可用
if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    "[ERROR] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Python 未安装或未加入 PATH" | Out-File -FilePath $LogPath -Append -Encoding utf8
    Read-Host "按 Enter 退出"
    exit 1
}

# 检查脚本文件是否存在
if (-not (Test-Path $ScriptPath)) {
    "[ERROR] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 脚本不存在：$ScriptPath" | Out-File -FilePath $LogPath -Append -Encoding utf8
    Read-Host "按 Enter 退出"
    exit 1
}

# 检查是否以管理员权限运行
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    "[INFO] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 正在请求管理员权限..." | Out-File -FilePath $LogPath -Append -Encoding utf8
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

"[INFO] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 开始启动代理程序..." | Out-File -FilePath $LogPath -Append -Encoding utf8

# 以后台方式启动 Python（不阻塞窗口）
Start-Process -NoNewWindow -FilePath $Python -ArgumentList $ScriptPath -RedirectStandardOutput $LogPath -RedirectStandardError $LogPath -Append

"[INFO] $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') 启动命令已执行，程序运行中" | Out-File -FilePath $LogPath -Append -Encoding utf8

# 可选：暂停查看日志（调试时打开）
# Read-Host "按 Enter 退出（程序已在后台运行）"