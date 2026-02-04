# tui.py - 只读监控面板（适配 access.log + error.log + 当前封禁数）

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Label, Log, TabbedContent, TabPane
from textual.containers import Vertical
from textual import work
import asyncio
import os
import time
from datetime import datetime
from config import CONFIG, load_config
from security import BLACKLIST, BLACKLIST_LOCK

load_config("config.yaml")

class AccessLog(Log):
    def on_mount(self):
        self.border_title = "实时访问日志 (access.log)"
        self.styles.background = "black"
        self.styles.color = "lime"
        self.last_position = 0

    @work(thread=True, exclusive=True)
    async def tail_log(self):
        log_file = "logs/access.log"
        if not os.path.exists(log_file):
            self.write_line("[bold red]访问日志文件不存在[/bold red]")
            return
        while True:
            await asyncio.sleep(0.8)
            try:
                file_size = os.path.getsize(log_file)
                if file_size < self.last_position:
                    self.last_position = 0
                if file_size > self.last_position:
                    with open(log_file, "r", encoding="utf-8") as f:
                        f.seek(self.last_position)
                        new_content = f.read()
                        if new_content:
                            for line in new_content.splitlines():
                                if line.strip():
                                    self.write_line(line.strip())
                            self.last_position += len(new_content.encode('utf-8'))
            except Exception as e:
                self.write_line(f"[red]读取访问日志错误: {e}[/red]")
                await asyncio.sleep(3)

class ErrorLog(Log):
    def on_mount(self):
        self.border_title = "实时错误日志 (error.log)"
        self.styles.background = "black"
        self.styles.color = "red"
        self.last_position = 0

    @work(thread=True, exclusive=True)
    async def tail_log(self):
        log_file = "logs/error.log"
        if not os.path.exists(log_file):
            self.write_line("[bold red]错误日志文件不存在[/bold red]")
            return
        while True:
            await asyncio.sleep(0.8)
            try:
                file_size = os.path.getsize(log_file)
                if file_size < self.last_position:
                    self.last_position = 0
                if file_size > self.last_position:
                    with open(log_file, "r", encoding="utf-8") as f:
                        f.seek(self.last_position)
                        new_content = f.read()
                        if new_content:
                            for line in new_content.splitlines():
                                if line.strip():
                                    self.write_line(line.strip())
                            self.last_position += len(new_content.encode('utf-8'))
            except Exception as e:
                self.write_line(f"[red]读取错误日志错误: {e}[/red]")
                await asyncio.sleep(3)

class CTSecureTUI(App):
    TITLE = "CTSecure 只读监控面板"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="overview"):
            with TabPane("概览", id="overview"):
                yield Vertical(
                    Label("[bold green]服务器状态：运行中[/bold green]"),
                    Label(id="listen-ports"),
                    Label(id="domain-count"),
                    Label(id="rate-limit-status"),
                    Label(id="cloudflare-status"),
                    Label(id="banned-count")
                )
            with TabPane("访问日志", id="access"):
                yield AccessLog()
            with TabPane("错误/封禁日志", id="error"):
                yield ErrorLog()
        yield Footer()

    def on_mount(self) -> None:
        self.update_overview()
        self.query_one(AccessLog).tail_log()
        self.query_one(ErrorLog).tail_log()
        self.set_interval(10, self.update_banned_count)

    def update_overview(self):
        listen = CONFIG.get('listen', {})
        self.query_one("#listen-ports").update(
            f"监听端口：HTTP {listen.get('http_port', '未知')} | HTTPS {listen.get('https_port', '未知')}"
        )
        self.query_one("#domain-count").update(
            f"域名数量：{len(CONFIG.get('domains', {}))}"
        )
        rl = CONFIG.get('rate_limit', {})
        self.query_one("#rate-limit-status").update(
            f"限流：{'启用' if rl.get('enabled', False) else '未启用'} (默认 {rl.get('default', {}).get('requests_per_minute', '?')} req/min)"
        )
        cf = CONFIG.get('cloudflare', {})
        self.query_one("#cloudflare-status").update(
            f"Cloudflare 适配：{'启用' if cf.get('enabled', False) else '未启用'}"
        )

    def update_banned_count(self):
        with BLACKLIST_LOCK:
            active_bans = sum(1 for expire in BLACKLIST.values() if time.time() < expire)
        self.query_one("#banned-count").update(f"当前封禁 IP 数量：{active_bans}")


if __name__ == "__main__":
    app = CTSecureTUI()
    app.run()