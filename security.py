# security.py
# 安全核心模块 - 负责黑名单、AI异常检测、GeoIP过滤、真实防火墙封禁等功能
# 所有注释均为简体中文，便于理解和维护

import time
import logging
import platform
import subprocess
import json
import os
import threading
from collections import defaultdict, deque
import math
from ipaddress import ip_address, ip_network
import maxminddb  # 需要 pip install maxminddb

from config import CONFIG, WHITELIST

SYSTEM = platform.system().lower()  # 'windows' 或 'linux'

BLACKLIST_FILE = "blacklist.json"
BLACKLIST = {}                  # ip -> 过期时间戳（float）
BLACKLIST_LOCK = threading.Lock()

# 请求上下文：每个IP的最近行为记录，用于AI检测
REQUEST_CONTEXT = defaultdict(lambda: {
    'uas': deque(maxlen=20),          # 最近20个User-Agent
    'paths': deque(maxlen=20),        # 最近20个路径
    'timestamps': deque(maxlen=100),  # 最近100次请求时间戳
    'status_codes': deque(maxlen=50), # 最近50次响应状态码
})
CONTEXT_LOCK = threading.Lock()

# 阈值缓存（支持热加载）
_thresholds = None
_thresholds_lock = threading.Lock()

# GeoIP 数据库读取器
geo_reader = None


def get_thresholds():
    """
    获取当前安全阈值（支持配置文件热更新）
    """
    global _thresholds
    with _thresholds_lock:
        if _thresholds is None:
            sec = CONFIG.get('security', {})
            _thresholds = {
                "request_rate_threshold": sec.get('request_rate_threshold', 30),
                "ua_diversity_threshold": sec.get('ua_diversity_threshold', 8),
                "path_entropy_threshold": sec.get('path_entropy_threshold', 4.0),
                "error_rate_threshold": sec.get('error_rate_threshold', 0.65),
                "ban_duration": sec.get('ban_duration', 3600),
            }
        return _thresholds.copy()


def reload_thresholds():
    """
    强制重新加载阈值（配置修改后调用）
    """
    global _thresholds
    with _thresholds_lock:
        _thresholds = None


def is_whitelisted(ip: str) -> bool:
    """
    判断IP是否在白名单（支持CIDR格式）
    """
    try:
        ip_obj = ip_address(ip)
        for cidr in WHITELIST.get('whitelist_ips', []):
            if ip_obj in ip_network(cidr):
                return True
    except ValueError:
        pass
    return ip in WHITELIST.get('whitelist_ips', [])


def is_ua_whitelisted(ua: str) -> bool:
    """
    判断User-Agent是否在白名单
    """
    if not ua:
        return False
    ua_lower = ua.lower()
    for pattern in WHITELIST.get('whitelist_uas', []):
        if pattern.lower() in ua_lower:
            return True
    return False


def load_blacklist():
    """
    从文件加载黑名单，只保留未过期的记录
    """
    global BLACKLIST
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                now = time.time()
                BLACKLIST = {ip: float(t) for ip, t in data.items() if now < float(t)}
            logging.info(f"[黑名单] 加载完成，有效条目：{len(BLACKLIST)}")
        except Exception as e:
            logging.error(f"[黑名单] 加载失败：{e}")


def save_blacklist():
    """
    保存当前有效黑名单到文件
    """
    try:
        with BLACKLIST_LOCK:
            now = time.time()
            valid_data = {ip: t for ip, t in BLACKLIST.items() if now < t}
            with open(BLACKLIST_FILE, 'w', encoding='utf-8') as f:
                json.dump(valid_data, f)
        logging.debug("[黑名单] 已保存")
    except Exception as e:
        logging.error(f"[黑名单] 保存失败：{e}")


def ban_ip(ip: str, reason: str = ""):
    """
    封禁一个IP：加入黑名单、保存文件、执行防火墙规则
    """
    if is_whitelisted(ip):
        logging.info(f"[封禁跳过] 白名单IP {ip} ({reason})")
        return

    thresholds = get_thresholds()
    duration = thresholds['ban_duration']

    with BLACKLIST_LOCK:
        if ip in BLACKLIST and time.time() < BLACKLIST[ip]:
            return
        expire_time = time.time() + duration
        BLACKLIST[ip] = expire_time
        save_blacklist()

    logging.warning(f"[封禁] {ip} 被封禁 {duration//60} 分钟 - {reason}")

    # 执行真实防火墙封禁
    _apply_firewall_ban(ip, duration)


def _apply_firewall_ban(ip: str, duration: int):
    """
    根据系统执行防火墙封禁
    Linux 优先使用 ipset（需预创建）
    Windows 使用 netsh（无自动到期，靠 auto_clean_bans 清理）
    """
    if SYSTEM == "linux":
        try:
            result = subprocess.run(
                ["ipset", "add", "cts_ban", ip, "timeout", str(duration)],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                logging.info(f"[防火墙] ipset 封禁 {ip} {duration}秒 成功")
                return
        except FileNotFoundError:
            logging.warning("[ipset] 命令不存在，尝试 fallback iptables")

        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        logging.info(f"[防火墙] iptables 封禁 {ip} 成功（无自动解封）")

    elif SYSTEM == "windows":
        rule_name = f"CTSBan_{ip.replace('.', '_').replace(':', '_')}"
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes"
        ], capture_output=True)
        logging.info(f"[防火墙] netsh 封禁 {ip} 成功（自动清理线程将处理过期）")


def calculate_entropy(s: str) -> float:
    """
    计算字符串的信息熵，用于检测随机性高的扫描路径
    """
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


def ai_scan_loop():
    """
    AI异常检测主循环（每4秒检查一次）
    """
    while True:
        try:
            thresholds = get_thresholds()
            now = time.time()

            with CONTEXT_LOCK:
                for ip, ctx in list(REQUEST_CONTEXT.items()):
                    if is_whitelisted(ip):
                        continue

                    timestamps = ctx['timestamps']
                    recent = [t for t in timestamps if now - t < 5]
                    if len(recent) >= thresholds['request_rate_threshold']:
                        ban_ip(ip, f"高频请求：{len(recent)}次/5秒")
                        del REQUEST_CONTEXT[ip]
                        continue

                    ua_set = set(ctx['uas'])
                    if len(ua_set) >= thresholds['ua_diversity_threshold']:
                        ban_ip(ip, f"UA多样性异常：{len(ua_set)}种")
                        del REQUEST_CONTEXT[ip]
                        continue

                    if ctx['paths']:
                        entropies = [calculate_entropy(p) for p in ctx['paths']]
                        avg_entropy = sum(entropies) / len(entropies)
                        if avg_entropy > thresholds['path_entropy_threshold']:
                            ban_ip(ip, f"路径熵异常：{avg_entropy:.2f}")
                            del REQUEST_CONTEXT[ip]
                            continue

                    if len(ctx['status_codes']) >= 10:
                        err_count = sum(1 for code in ctx['status_codes'] if code >= 400)
                        err_rate = err_count / len(ctx['status_codes'])
                        if err_rate >= thresholds['error_rate_threshold']:
                            ban_ip(ip, f"高错误率：{err_rate:.1%}")
                            del REQUEST_CONTEXT[ip]
                            continue

                    if timestamps and now - max(timestamps) > 600:
                        del REQUEST_CONTEXT[ip]

        except Exception as e:
            logging.error(f"[AI检测线程] 异常：{e}", exc_info=True)

        time.sleep(4)


def daily_report():
    """
    每日封禁报告（每24小时输出一次）
    """
    while True:
        time.sleep(86400)
        report_lines = []
        now = time.time()
        with BLACKLIST_LOCK:
            for ip, expire in BLACKLIST.items():
                if now < expire:
                    remain_min = int((expire - now) / 60)
                    report_lines.append(f"{ip}（剩余 {remain_min} 分钟）")

        if report_lines:
            logging.info("[每日报告] 当前封禁IP汇总：")
            for line in report_lines:
                logging.info(f"  - {line}")
        else:
            logging.info("[每日报告] 当前没有封禁中的IP")


def auto_clean_bans():
    """
    自动清理过期黑名单及防火墙规则（每5分钟检查一次）
    """
    while True:
        try:
            now = time.time()
            with BLACKLIST_LOCK:
                to_remove = [ip for ip, expire in BLACKLIST.items() if now >= expire]

                for ip in to_remove:
                    del BLACKLIST[ip]
                    # Windows: 删除防火墙规则
                    if SYSTEM == "windows":
                        rule_name = f"CTSBan_{ip.replace('.', '_').replace(':', '_')}"
                        result = subprocess.run(
                            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                            capture_output=True, text=True
                        )
                        if result.returncode == 0:
                            logging.info(f"[自动清理] 删除过期封禁 {ip} 及防火墙规则")
                        else:
                            logging.warning(f"[自动清理] 删除规则 {rule_name} 失败: {result.stderr.strip()}")
                    # Linux ipset 自带 timeout，无需手动删

                if to_remove:
                    save_blacklist()
                    logging.info(f"[自动清理] 已移除 {len(to_remove)} 条过期封禁")

        except Exception as e:
            logging.error(f"[自动清理线程] 异常: {e}")

        time.sleep(300)  # 每5分钟检查一次


def record_request(ip: str, ua: str, path: str, status_code: int = None):
    """
    记录单次请求的上下文信息，供AI检测使用
    """
    if is_whitelisted(ip) or is_ua_whitelisted(ua):
        return

    with CONTEXT_LOCK:
        ctx = REQUEST_CONTEXT[ip]
        now = time.time()
        ctx['timestamps'].append(now)
        if ua:
            ctx['uas'].append(ua[:120])
        if path:
            ctx['paths'].append(path[:200])
        if status_code is not None:
            ctx['status_codes'].append(status_code)


def init_geoip():
    """
    初始化 GeoIP 数据库（MaxMind GeoLite2 Country）
    """
    global geo_reader
    cfg = CONFIG.get('geoip', {})
    if not cfg.get('enabled', False):
        return

    db_path = cfg.get('db_path')
    if db_path and os.path.isfile(db_path):
        try:
            geo_reader = maxminddb.open_database(db_path)
            logging.info(f"[GeoIP] 数据库加载成功：{db_path}")
        except Exception as e:
            logging.error(f"[GeoIP] 加载失败：{e}")
            geo_reader = None
    else:
        logging.warning("[GeoIP] 数据库文件不存在或路径错误，功能已禁用")


def check_geoip(ip: str) -> bool:
    """
    检查IP所在国家是否允许访问
    返回 True 表示允许，False 表示阻断
    """
    if geo_reader is None:
        return True

    try:
        info = geo_reader.get(ip)
        if not info:
            return True

        country = info.get('country', {}).get('iso_code')
        if not country:
            return True

        block_list = CONFIG['geoip'].get('block_countries', [])
        allow_list = CONFIG['geoip'].get('allow_countries', [])

        if allow_list and country not in allow_list:
            return False
        if block_list and country in block_list:
            return False

        return True
    except Exception:
        return True  # 解析失败默认放行


def start_security():
    """
    启动安全模块（在main.py中调用）
    """
    load_blacklist()
    init_geoip()
    threading.Thread(target=ai_scan_loop, daemon=True, name="AI-Scan").start()
    threading.Thread(target=daily_report, daemon=True, name="Daily-Report").start()
    threading.Thread(target=auto_clean_bans, daemon=True, name="Auto-Clean-Bans").start()
    logging.info("[安全模块] 启动完成（包含AI检测 + GeoIP + 真实防火墙 + 自动清理）")