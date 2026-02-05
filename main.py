"""
main.py - 项目入口模块
负责启动代理服务器、守护进程、安全模块、优雅关闭等
Windows 兼容版：优化了 Ctrl+C 退出处理
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

# 加强健康检查（异步版）
async def is_healthy(http_port):
    import aiohttp
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f'http://127.0.0.1:{http_port}/metrics', timeout=3) as resp:
                return resp.status == 200
    except Exception:
        return False

def watchdog():
    """守护进程：每10秒检查代理是否健康，异常则尝试重启"""
    while True:
        time.sleep(10)
        # 用健康检查代替简单 connect
        if not asyncio.run(is_healthy(CONFIG.get('listen', {}).get('http_port', 80))):
            logging.error("[WATCHDOG] 健康检查失败，尝试自动重启...")
            time.sleep(45)  # 延长延迟，给旧进程释放 socket 的时间
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

def check_port_available(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(('0.0.0.0', port))
        return True
    except OSError:
        return False
    finally:
        s.close()

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

    if not check_port_available(http_port):
        logging.critical(f"端口 {http_port} 已被占用，无法启动！请检查并释放端口。")
        sys.exit(1)

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
        
        if not check_port_available(https_port):
            logging.critical(f"端口 {https_port} 已被占用，无法启动！请检查并释放端口。")
            sys.exit(1)

        https_site = web.TCPSite(runner, '0.0.0.0', https_port, ssl_context=ssl_context)
        await https_site.start()
        logging.info(f"HTTPS 服务器运行于 https://0.0.0.0:{https_port}")

    # ────────────────────────────────────────────────
    #           新增：启动完成后的明显提示
    # ────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print(" " * 15 + "CTSecure 代理服务器启动成功！")
    print("=" * 60)
    print(f"  HTTP 监听端口 : {http_port}")
    if has_ssl:
        print(f" HTTPS 监听端口 : {https_port}")
    print(f"  当前时间      : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  监听地址      : http://0.0.0.0:{http_port}  (或你的域名)")
    if has_ssl:
        print(f"                : https://0.0.0.0:{https_port}")
    print("-" * 60)
    print("  • 现在可以用浏览器访问 http://127.0.0.1 或域名 测试")
    print("  • 运行 'python main.py tui' 可查看实时监控面板")
    print("  • 按 Ctrl+C 正常退出程序")
    print("=" * 60 + "\n")

    # 无限等待 + 可选心跳（可选启用）
    try:
        while True:
            await asyncio.sleep(3600)  # 每1小时打印一次心跳（可改为60秒或注释掉）
            print(f"[心跳] 服务器仍在运行 | {time.strftime('%Y-%m-%d %H:%M:%S')}")
    except KeyboardInterrupt:
        print("\n" + "-" * 60)
        print("收到 Ctrl+C，正在优雅关闭...")
        try:
            await cleanup()
            await runner.cleanup()
            print("清理完成，程序已正常退出")
        except Exception as e:
            print(f"关闭时发生异常: {e}")
        raise

if __name__ == "__main__":
    try:
        asyncio.run(run_servers())
    except KeyboardInterrupt:
        logging.info("主程序已通过 Ctrl+C 退出")
    except Exception as e:
        logging.error(f"主程序异常退出: {e}", exc_info=True)
        sys.exit(1)