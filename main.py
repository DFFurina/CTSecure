"""
main.py - 项目入口模块
负责启动代理服务器、守护进程、安全模块、优雅关闭等
Windows 兼容版：使用 atexit + KeyboardInterrupt 实现优雅关闭
"""

import asyncio
import ssl
from aiohttp import web
from proxy import proxy_handler, cleanup, metrics_handler  # 导入所需函数
from config import load_config, CONFIG
import sys
import subprocess
import time
import os
import socket
import logging
import threading
import atexit  # Windows 优雅关闭关键

def watchdog():
    """守护进程：每10秒检查代理是否存活，崩溃则自动重启"""
    while True:
        time.sleep(10)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('127.0.0.1', CONFIG.get('listen', {}).get('http_port', 80)))
        except:
            logging.error("[WATCHDOG] 代理崩溃，自动重启...")
            time.sleep(5)  # 延迟5秒，避免端口未释放
            subprocess.Popen([sys.executable] + sys.argv)
            sys.exit(0)

if len(sys.argv) > 1:
    arg = sys.argv[1].lower()
    if arg == "tui":
        from tui import CTSecureTUI
        CTSecureTUI().run()
        sys.exit(0)
    elif arg == "gui":
        from gui import ConfigGUI
        from PyQt6.QtWidgets import QApplication
        app = QApplication(sys.argv)
        window = ConfigGUI()
        window.show()
        sys.exit(app.exec())
    elif arg == "help":
        print("用法: python main.py [tui|gui|help]")
        sys.exit(0)

async def create_app():
    load_config()
    app = web.Application()
    app.router.add_route('*', '/{tail:.*}', proxy_handler)
    app.router.add_get('/metrics', metrics_handler)
    return app

async def run_servers():
    # 启动守护进程
    threading.Thread(target=watchdog, daemon=True).start()

    # 启动安全模块
    import security
    security.start_security()

    app = await create_app()

    runner = web.AppRunner(app)
    await runner.setup()

    http_port = CONFIG.get('listen', {}).get('http_port', 80)
    http_site = web.TCPSite(runner, '0.0.0.0', http_port)
    await http_site.start()
    logging.info(f"HTTP 服务器运行于 http://0.0.0.0:{http_port}")

    has_ssl = any(cfg.get('ssl') for cfg in CONFIG.get('domains', {}).values())
    if has_ssl:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        for cfg in CONFIG['domains'].values():
            if cfg.get('ssl'):
                ssl_context.load_cert_chain(cfg['cert'], cfg['key'])
                break

        https_port = CONFIG.get('listen', {}).get('https_port', 443)
        https_site = web.TCPSite(runner, '0.0.0.0', https_port, ssl_context=ssl_context)
        await https_site.start()
        logging.info(f"HTTPS 服务器运行于 https://0.0.0.0:{https_port}")

    # Windows 优雅关闭：注册 atexit 回调
    def graceful_shutdown():
        logging.info("程序正在关闭，进行优雅清理...")
        # 同步调用 cleanup 的同步部分（如果需要异步，可用 loop.call_soon_threadsafe）
        if hasattr(asyncio, 'get_running_loop'):
            loop = asyncio.get_event_loop()
            loop.run_until_complete(cleanup())
        else:
            # 旧版兼容
            asyncio.run(cleanup())

    atexit.register(graceful_shutdown)

    # 捕获 KeyboardInterrupt (Ctrl+C)
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logging.info("收到 Ctrl+C，启动优雅关闭...")
        await graceful_shutdown()  # 直接 await 清理
        raise

if __name__ == "__main__":
    asyncio.run(run_servers())