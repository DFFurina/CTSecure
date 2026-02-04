# clean_bans.py - Windows 专用：自动清理过期的防火墙封禁规则
# 使用方法：python clean_bans.py
# 建议：设成 Windows 计划任务，每小时或每天运行一次

import json
import time
import subprocess
import os

BLACKLIST_FILE = "blacklist.json"  # 和主程序同目录

def clean_firewall():
    if not os.path.exists(BLACKLIST_FILE):
        print("黑名单文件不存在，无需清理")
        return

    try:
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
            bans = json.load(f)
    except Exception as e:
        print(f"读取黑名单失败：{e}")
        return

    now = time.time()
    cleaned_count = 0

    for ip, expire_str in list(bans.items()):
        try:
            expire = float(expire_str)
            if now >= expire:
                # 规则名格式和 security.py 保持一致
                rule_name = f"CTSBan_{ip.replace('.', '_').replace(':', '_')}"
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                    capture_output=True, text=True
                )
                if "Ok." in result.stdout or result.returncode == 0:
                    print(f"已删除规则：{rule_name}")
                    cleaned_count += 1
                else:
                    print(f"删除失败 {rule_name}：{result.stderr.strip() or '未知错误'}")
        except:
            continue

    if cleaned_count == 0:
        print("没有过期的封禁规则需要清理")
    else:
        print(f"共清理 {cleaned_count} 条过期防火墙规则")

if __name__ == "__main__":
    clean_firewall()
    input("按 Enter 退出...")