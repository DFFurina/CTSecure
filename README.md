# CTSecure  
轻量级安全反向代理 + 基础 WAF

用 Python + aiohttp 写的一个反向代理，重点放在安全防护上。  
内置 WAF、IP 黑名单、速率限制、异常行为检测（UA 多样性 + 路径熵）、GeoIP 过滤、Cloudflare 支持、Prometheus 监控，还带图形界面和终端面板。

适合放 VPS 上保护个人网站、小型 API、测试环境等。

### 主要功能

- 多域名支持 + HTTPS（证书自动热重载）
- 基础 WAF 规则（防 SQL 注入、XSS、路径穿越、命令注入等）
- 限流 + 异常检测（高频请求、UA 频繁切换、路径混乱等）
- Cloudflare 真实 IP 识别 + 可选只允许 CF 流量
- 黑名单持久化 + Windows 防火墙 / Linux ipset 联动封禁
- Prometheus /metrics 接口
- PyQt6 图形配置界面 + Textual 终端实时监控
- Windows & Linux 开机自启脚本

### 快速上手

1. 安装依赖

```bash
pip install aiohttp pyyaml prometheus_client maxminddb watchdog PyQt6 textual
```

2. 准备证书（如果要用 HTTPS）

把 Let's Encrypt 的 `fullchain.pem` 和 `privkey.pem` 放到 `certs/` 目录下。

3. 编辑 config.yaml（最简单示例）

```yaml
listen:
  http_port: 80
  https_port: 443

domains:
  example.com:
    target: http://127.0.0.1:3000
    ssl: true
    cert: certs/fullchain.pem
    key: certs/privkey.pem
    force_https: true
```

4. 启动方式

```bash
# 普通启动（后台运行建议用 nohup 或 systemd）
python main.py

# 图形界面配置
python main.py gui

# 终端监控面板（实时看日志 + 封禁数）
python main.py tui
```

### 开机自启建议

- **Linux**：把 `startup.sh` 加入 systemd 服务 或 crontab @reboot
- **Windows**：用任务计划程序运行 `startup.ps1`（记得勾选“以最高权限运行”）

### 目录说明（简要）

```
CTSecure/
├── main.py             程序入口
├── proxy.py            代理核心逻辑
├── security.py         WAF / 黑名单 / 异常检测
├── config.py           配置读写
├── gui.py              PyQt6 配置界面
├── tui.py              Textual 监控面板
├── clean_bans.py       Windows 清理过期防火墙规则
├── config.yaml         主配置文件
├── whitelist.json      IP / UA 白名单
├── waf_rules.yaml      WAF 规则文件
├── blacklist.json      自动生成的黑名单（运行时产生）
├── logs/               access.log / error.log
├── startup.sh          Linux 自启脚本
└── startup.ps1         Windows 自启脚本
```

### 常见问题

**端口 80/443 被占用怎么办？**  
改成高位端口测试（比如 8080/8443），或者用管理员权限运行。

**想临时关闭 WAF / 限流？**  
在 config.yaml 里把对应模块的 `enabled: false` 即可。

**如何加新 WAF 规则？**  
直接编辑 `waf_rules.yaml`，格式参考已有规则，priority 越小优先级越高。

有 bug / 想加功能欢迎 issue 或 PR～

GPLv3 License  
2025–2026
Codetea TEAM