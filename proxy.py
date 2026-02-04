"""
proxy.py - 最终生产级代理模块
包含：多后端轮询 + 重试、证书热重载、Prometheus 指标、更强蜜罐
"""

import asyncio
import json
import logging
import logging.handlers
import os
import re
import time
import gzip
import base64
import random
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import threading
from asyncio import Semaphore
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import aiohttp
from aiohttp import web, ClientSession, ClientTimeout, TCPConnector
from maxminddb import open_database

# Prometheus
from prometheus_client import Counter, Gauge, Histogram, generate_latest

REQUESTS_TOTAL = Counter('ctsecure_requests_total', '总请求数', ['method', 'status'])
REQUEST_DURATION = Histogram('ctsecure_request_duration_seconds', '请求耗时', ['method'])
ERROR_RATE = Gauge('ctsecure_error_rate', '错误率 (4xx+5xx)')
BANNED_IPS = Gauge('ctsecure_banned_ips', '当前封禁 IP 数')

from config import CONFIG, WHITELIST, load_config
from security import (
    BLACKLIST, BLACKLIST_LOCK,
    record_request, ban_ip, is_whitelisted, is_ua_whitelisted,
    get_thresholds, check_geoip, save_blacklist
)

# 日志配置
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

class JsonFormatter(logging.Formatter):
    def format(self, record):
        data = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
            "file": record.pathname,
            "line": record.lineno,
        }
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        try:
            return json.dumps(data, ensure_ascii=False)
        except:
            data["msg"] = str(record.msg)
            return json.dumps(data, ensure_ascii=False)

access_logger = logging.getLogger("CTSecure.access")
access_logger.setLevel(logging.INFO)
access_handler = logging.handlers.TimedRotatingFileHandler(
    os.path.join(LOG_DIR, "access.log"), when="midnight", backupCount=30, encoding="utf-8"
)
access_handler.setFormatter(JsonFormatter())
access_logger.addHandler(access_handler)

error_logger = logging.getLogger("CTSecure.error")
error_logger.setLevel(logging.WARNING)
error_handler = logging.handlers.TimedRotatingFileHandler(
    os.path.join(LOG_DIR, "error.log"), when="midnight", backupCount=30, encoding="utf-8"
)
error_handler.setFormatter(JsonFormatter())
error_logger.addHandler(error_handler)

console = logging.StreamHandler()
console.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logging.getLogger().addHandler(console)

# 连接池
_session_pool: ClientSession = None
_connector: TCPConnector = None
_pool_lock = threading.Lock()

PER_IP_MAX_CONCURRENT = 5
per_ip_semaphores = defaultdict(lambda: Semaphore(PER_IP_MAX_CONCURRENT))

def get_http_session() -> ClientSession:
    global _session_pool, _connector
    if _session_pool is not None and not _session_pool.closed:
        return _session_pool

    with _pool_lock:
        if _session_pool is not None and not _session_pool.closed:
            return _session_pool

        error_logger.info("正在初始化全局 HTTP 连接池...")
        _connector = TCPConnector(limit=200, limit_per_host=50, force_close=False)
        _session_pool = ClientSession(connector=_connector)
        error_logger.info("全局 HTTP 连接池初始化完成")

    return _session_pool

# Prometheus 路由
async def metrics_handler(request):
    BANNED_IPS.set(len([ip for ip, t in BLACKLIST.items() if time.time() < t]))
    return web.Response(
        body=generate_latest(),
        headers={'Content-Type': 'text/plain; version=0.0.4'}
    )

# 证书热重载
ssl_context = None
cert_files = set()

def init_ssl_context():
    global ssl_context
    ssl_context = None
    for domain_cfg in CONFIG['domains'].values():
        if domain_cfg.get('ssl'):
            cert = domain_cfg['cert']
            key = domain_cfg['key']
            if os.path.exists(cert) and os.path.exists(key):
                try:
                    ssl_context = aiohttp.web.SSLContext()
                    ssl_context.load_cert_chain(cert, key)
                    error_logger.info(f"SSL 上下文加载成功: {cert}")
                    cert_files.add(cert)
                    cert_files.add(key)
                    break
                except Exception as e:
                    error_logger.error(f"SSL 加载失败 {cert}: {e}")

class CertChangeHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path in cert_files:
            error_logger.info(f"证书文件变更: {event.src_path}，热重载...")
            init_ssl_context()

def start_cert_monitor():
    if not cert_files:
        return
    observer = Observer()
    observer.schedule(CertChangeHandler(), path="certs", recursive=False)
    observer.start()
    error_logger.info("证书文件监控已启动（certs 目录）")

# 蜜罐
FAKE_PAGES = [
    "<html><head><title>404 Not Found</title></head><body><h1>404 - 文件不存在</h1><p>您访问的页面不存在或已被移除。</p></body></html>",
    "<html><head><title>500 Internal Server Error</title></head><body><h1>500 - 服务器内部错误</h1><p>服务器遇到问题，请稍后重试。</p></body></html>",
]

async def honeypot_response():
    await asyncio.sleep(random.uniform(2, 8))
    fake_body = random.choice(FAKE_PAGES).encode('utf-8')
    headers = {
        "Server": random.choice(["nginx/1.18.0", "Apache/2.4.41"]),
        "X-Powered-By": random.choice(["PHP/8.1.0", ""]),
        "Content-Type": "text/html; charset=utf-8"
    }
    return web.Response(status=random.choice([404, 500]), body=fake_body, headers=headers)

# WAF 引擎
class WAFEngine:
    def __init__(self):
        self.rules = []
        self.load_rules()

    def load_rules(self):
        rules_file = CONFIG.get("waf", {}).get("rules_file", "waf_rules.yaml")
        if not Path(rules_file).is_file():
            error_logger.warning(f"WAF 规则文件未找到: {rules_file}")
            return

        import yaml
        try:
            with open(rules_file, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                self.rules = sorted(data.get("rules", []), key=lambda x: x.get("priority", 100))
            error_logger.info(f"已加载 {len(self.rules)} 条 WAF 规则")
        except Exception as e:
            error_logger.error(f"WAF 规则加载失败: {e}")

    async def evaluate(self, request: web.Request, body_bytes: bytes) -> tuple[bool, str, int]:
        if not CONFIG.get("waf", {}).get("enabled", False):
            return False, "", 0

        uri = str(request.rel_url)
        query = request.rel_url.query_string
        ua = request.headers.get("User-Agent", "")
        path = request.path
        headers_dict = dict(request.headers)
        args = {**request.query}

        if body_bytes and "application/x-www-form-urlencoded" in request.headers.get("Content-Type", "").lower():
            try:
                text = body_bytes.decode("utf-8", errors="ignore")
                for pair in text.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        args[k] = v
            except:
                pass

        for rule in self.rules:
            pattern = rule.get("match", {}).get("pattern", "")
            if not pattern:
                continue

            hit = False
            fields = rule.get("match", {}).get("fields", [])

            for field in fields:
                if field == "path" and re.search(pattern, path, re.IGNORECASE):
                    hit = True
                elif field == "query_string" and re.search(pattern, query, re.IGNORECASE):
                    hit = True
                elif field == "user_agent" and re.search(pattern, ua, re.IGNORECASE):
                    hit = True
                elif field == "args":
                    for v in args.values():
                        if isinstance(v, str) and re.search(pattern, v, re.IGNORECASE):
                            hit = True
                            break
                elif field == "body" and body_bytes:
                    try:
                        body_text = body_bytes.decode("utf-8", errors="ignore")
                        if re.search(pattern, body_text, re.IGNORECASE):
                            hit = True
                    except:
                        pass
                elif field in headers_dict and re.search(pattern, headers_dict[field], re.IGNORECASE):
                    hit = True

                if hit:
                    break

            if hit:
                action = rule.get("action", "log")
                msg = f"WAF 规则 {rule.get('id','?')} [{rule.get('name','未知')}] 触发 | {uri}"
                if rule.get("log", True):
                    error_logger.warning(msg + f" | ip={get_real_ip(request)}")
                if action == "block":
                    return True, msg, 403
                elif action == "challenge":
                    return True, msg, 403

        return False, "", 0

waf_engine = WAFEngine()

# 辅助函数
def get_real_ip(request: web.Request) -> str:
    cf_enabled = CONFIG.get('cloudflare', {}).get('enabled', False)
    if not cf_enabled:
        return request.remote

    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip.strip()

    xff = request.headers.get('X-Forwarded-For')
    if xff:
        return xff.split(',')[0].strip()

    return request.remote


def is_rate_limited(ip: str, rpm: int) -> bool:
    now = time.time()
    window = 60
    RATE_LIMIT_STORE[ip] = [t for t in RATE_LIMIT_STORE.get(ip, []) if now - t < window]
    if len(RATE_LIMIT_STORE[ip]) >= rpm:
        return True
    RATE_LIMIT_STORE[ip].append(now)
    return False


RATE_LIMIT_STORE = defaultdict(list)


# 主代理函数
async def proxy_handler(request: web.Request):
    start = time.monotonic()
    real_ip = get_real_ip(request)
    ua = request.headers.get("User-Agent", "-")[:120]
    method = request.method
    scheme = request.scheme
    host = request.host
    path_qs = str(request.rel_url)

    log_ctx = {
        "ip": real_ip,
        "method": method,
        "scheme": scheme,
        "host": host,
        "path": path_qs,
        "ua": ua
    }

    REQUESTS_TOTAL.labels(method=method, status=0).inc()

    # 蜜罐
    if any(p in path_qs.lower() for p in ['.env', 'phpinfo', 'admin', 'shell', 'wp-login', '1.php', 'test.php']):
        error_logger.warning(f"蜜罐触发: {real_ip} {path_qs}")
        return await honeypot_response()

    # 黑名单
    with BLACKLIST_LOCK:
        if real_ip in BLACKLIST and time.time() < BLACKLIST[real_ip]:
            log_ctx["action"] = "banned"
            access_logger.info(json.dumps(log_ctx))
            error_logger.warning(json.dumps(log_ctx))
            BANNED_IPS.set(len([ip for ip, t in BLACKLIST.items() if time.time() < t]))
            return web.Response(status=403, text="访问被禁止")

    # GeoIP
    if CONFIG.get("geoip", {}).get("enabled", False):
        if not check_geoip(real_ip):
            log_ctx["action"] = "geo_blocked"
            error_logger.warning(json.dumps(log_ctx))
            return web.Response(status=403, text="地区受限")

    # 读取请求体
    try:
        body_bytes = await request.read()
        max_size = get_thresholds().get("max_body_size", 10*1024*1024)
        if len(body_bytes) > max_size:
            log_ctx["action"] = "payload_too_large"
            error_logger.warning(json.dumps(log_ctx))
            return web.Response(status=413, text="请求体过大")
    except Exception as e:
        body_bytes = b""
        log_ctx["body_read_error"] = str(e)

    # WAF
    blocked, waf_msg, waf_code = await waf_engine.evaluate(request, body_bytes)
    if blocked:
        log_ctx["action"] = "waf_block"
        log_ctx["waf_msg"] = waf_msg
        error_logger.warning(json.dumps(log_ctx))
        return web.Response(status=waf_code, text="WAF 拦截")

    # 白名单豁免
    path_exempt = any(path_qs.startswith(p) for p in WHITELIST.get("path_prefix_exempt", []))
    ua_exempt = any(re.match(r, ua) for r in WHITELIST.get("ua_regex_exempt", []))
    exempt = path_exempt or ua_exempt

    # 速率限制
    rl_cfg = CONFIG.get("rate_limit", {})
    if not exempt and rl_cfg.get("enabled", False):
        rpm = rl_cfg.get("default", {}).get("requests_per_minute", 60)
        if is_rate_limited(real_ip, rpm):
            log_ctx["action"] = "rate_limited"
            error_logger.warning(json.dumps(log_ctx))
            return web.Response(status=429, text="请求过于频繁")

    # AI 记录
    if not exempt:
        record_request(real_ip, ua, path_qs)

    # 域名配置
    domain_cfg = CONFIG["domains"].get(host.split(":")[0])
    if not domain_cfg:
        return web.Response(status=421, text="域名未配置")

    targets = domain_cfg["target"] if isinstance(domain_cfg["target"], list) else [domain_cfg["target"]]
    max_retries = 3

    headers_out = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "transfer-encoding")
    }

    for attempt in range(max_retries):
        target = random.choice(targets)
        target_url = target.rstrip("/") + path_qs

        try:
            sess = get_http_session()
            sem = per_ip_semaphores[real_ip]
            async with sem:
                timeout_val = get_thresholds().get("slow_request_timeout", 30)
                timeout = ClientTimeout(total=timeout_val, connect=5, sock_connect=5, sock_read=timeout_val-5)

                async with sess.request(
                    method, target_url,
                    headers=headers_out,
                    data=body_bytes,
                    allow_redirects=False,
                    timeout=timeout
                ) as resp:

                    body = await resp.read()
                    status = resp.status

                    out_headers = dict(resp.headers)

                    if len(body) > 1400 and "text/" in out_headers.get("Content-Type", ""):
                        body = gzip.compress(body)
                        out_headers["Content-Encoding"] = "gzip"
                        out_headers["Content-Length"] = str(len(body))

                    record_request(real_ip, ua, path_qs, status)

                    duration_ms = round((time.monotonic() - start) * 1000, 1)
                    log_ctx.update({
                        "status": status,
                        "size": len(body),
                        "duration_ms": duration_ms,
                        "action": "proxy_ok",
                        "backend": target,
                        "attempt": attempt + 1
                    })
                    access_logger.info(json.dumps(log_ctx))

                    REQUESTS_TOTAL.labels(method=method, status=status).inc()
                    REQUEST_DURATION.labels(method=method).observe(duration_ms / 1000)
                    ERROR_RATE.set(1 if status >= 400 else 0)

                    return web.Response(status=status, headers=out_headers, body=body)

        except Exception as e:
            log_ctx["attempt"] = attempt + 1
            log_ctx["backend"] = target
            error_logger.warning(f"后端尝试 {attempt+1}/{max_retries} 失败: {target} - {type(e).__name__}: {str(e)}")
            if attempt == max_retries - 1:
                log_ctx["action"] = "backend_error"
                log_ctx["error"] = str(e)
                error_logger.error(json.dumps(log_ctx))
                REQUESTS_TOTAL.labels(method=method, status=502).inc()
                ERROR_RATE.set(1)
                return web.Response(status=502, text="网关错误")

    return web.Response(status=502, text="所有后端不可用")


async def cleanup():
    global _session_pool
    if _session_pool and not _session_pool.closed:
        await _session_pool.close()
        error_logger.info("全局 HTTP 连接池已关闭")