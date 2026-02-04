#!/bin/bash
# startup.sh - 开机自启脚本
#
# 此脚本检查 Python 环境、脚本存在，并以 root 权限启动代理。
# 记录详细日志到 startup_log.log，支持错误排查。
# 注意：防火墙操作需 root 权限。

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/main.py"  # 入口脚本路径
LOG_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/startup_log.log"  # 日志路径
PYTHON_PATH="python3"  # Python 命令

# 检查 Python 是否安装
if ! command -v $PYTHON_PATH &> /dev/null; then
    echo "[$(date)] ERROR: Python3 未安装" >> "$LOG_PATH"
    exit 1
fi

# 检查脚本是否存在
if [ ! -f "$SCRIPT_PATH" ]; then
    echo "[$(date)] ERROR: 代理脚本不存在：$SCRIPT_PATH" >> "$LOG_PATH"
    exit 1
fi

# 检查 root 权限（防火墙操作需要）
if [ "$(id -u)" -ne 0 ]; then
    echo "[$(date)] INFO: 正在请求 root 权限..." >> "$LOG_PATH"
    sudo "$0" "$@"
    exit $?
fi

# 启动安全代理（后台运行，避免终端阻塞）
echo "[$(date)] INFO: 开始启动安全代理" >> "$LOG_PATH"
nohup $PYTHON_PATH "$SCRIPT_PATH" >> "$LOG_PATH" 2>&1 &

# 检查启动结果
if [ $? -ne 0 ]; then
    echo "[$(date)] ERROR: 安全代理启动失败" >> "$LOG_PATH"
    exit 1
else
    echo "[$(date)] INFO: 安全代理启动成功，PID=$!" >> "$LOG_PATH"
fi