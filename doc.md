# CTSecure 项目说明

这是一个用 Python 实现的轻量级安全反向代理，目标是给个人/小型站点提供基本的防护能力。

当前版本特点：
- 异步高性能（基于 aiohttp）
- 安全优先（WAF + 限流 + 行为检测 + 黑名单 + 防火墙联动）
- 配置友好（GUI + YAML）
- 监控友好（Prometheus + 实时日志面板）
- 跨平台（Windows / Linux）

## 核心模块功能一览

- proxy.py      主代理逻辑：域名路由、多后端轮询、重试、gzip 压缩、连接池
- security.py   安全核心：黑名单管理、WAF 匹配、GeoIP 过滤、AI 风格异常检测（熵/UA/速率）、防火墙规则
- config.py     配置加载/保存/校验
- gui.py        PyQt6 图形配置界面（通用设置、域名、Cloudflare）
- tui.py        Textual 终端监控（实时 access/error 日志 + 封禁数）
- main.py       程序入口 + 守护进程 + 优雅关闭
- clean_bans.py Windows 专用：清理过期防火墙规则（建议计划任务）

## 启动流程

1. 读取 config.yaml → 加载 whitelist.json
2. 初始化日志（JSON 格式，access/error 分开，按天轮转）
3. 启动安全模块线程（AI 检测、每日报告、自动清理黑名单）
4. 启动 aiohttp 服务（HTTP + HTTPS 如有证书）
5. 守护线程每 10 秒检查端口存活，崩溃则重启

## 配置热更新说明

- 修改 config.yaml 后，手动调用 `python main.py` 重启生效
- GUI 保存会自动调用 save_config() 并重载，但代理服务本身需重启
- WAF 规则（waf_rules.yaml）修改后也需重启服务

## 安全机制简述

1. 白名单优先（IP / UA / 路径前缀 / 正则 UA）
2. GeoIP 过滤（可选，需下载 GeoLite2-Country.mmdb）
3. WAF 正则匹配（优先级排序）
4. 速率限制（每分钟请求数）
5. 行为异常检测：
   - 短时高频请求
   - UA 变化过于频繁
   - 路径熵过高（扫描特征）
   - 错误率过高
6. 超过阈值 → 加入黑名单 → 防火墙封禁（Windows netsh / Linux ipset）

祝使用愉快～