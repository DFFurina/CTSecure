"""
gui.py - 配置编辑 GUI 模块

使用 PyQt6 构建图形界面，支持通用设置、域名管理、Cloudflare 配置、安全阈值编辑。
提供保存、添加域名、浏览证书等功能，并支持清空黑名单。
"""

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QCheckBox, QFileDialog, QMessageBox,
    QTabWidget, QComboBox, QInputDialog
)
from PyQt6.QtCore import Qt
import sys
import yaml
from config import CONFIG, load_config, save_config
import subprocess

class ConfigGUI(QMainWindow):
    """
    主配置 GUI 窗口类。
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CTSecure 配置编辑器")
        self.setGeometry(100, 100, 800, 600)

        load_config("config.yaml")

        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)

        self.general_tab = QWidget()
        self.domain_tab = QWidget()
        self.cloudflare_tab = QWidget()
        self.security_tab = QWidget()

        self.tab_widget.addTab(self.general_tab, "通用设置")
        self.tab_widget.addTab(self.domain_tab, "域名管理")
        self.tab_widget.addTab(self.cloudflare_tab, "Cloudflare")
        self.tab_widget.addTab(self.security_tab, "安全阈值")

        self.init_general_tab()
        self.init_domain_tab()
        self.init_cloudflare_tab()
        self.init_security_tab()

    def init_general_tab(self):
        """
        初始化通用设置标签页。
        """
        layout = QVBoxLayout()
        h1 = QHBoxLayout()
        h1.addWidget(QLabel("HTTP 端口:"))
        self.http_port = QLineEdit(str(CONFIG.get('listen', {}).get('http_port', 80)))
        h1.addWidget(self.http_port)
        layout.addLayout(h1)

        h2 = QHBoxLayout()
        h2.addWidget(QLabel("HTTPS 端口:"))
        self.https_port = QLineEdit(str(CONFIG.get('listen', {}).get('https_port', 443)))
        h2.addWidget(self.https_port)
        layout.addLayout(h2)

        h3 = QHBoxLayout()
        h3.addWidget(QLabel("限流启用:"))
        self.rl_enabled = QCheckBox()
        self.rl_enabled.setChecked(CONFIG.get('rate_limit', {}).get('enabled', False))
        h3.addWidget(self.rl_enabled)
        layout.addLayout(h3)

        h4 = QHBoxLayout()
        h4.addWidget(QLabel("默认限流阈值 (req/min):"))
        self.rl_rpm = QLineEdit(str(CONFIG.get('rate_limit', {}).get('default', {}).get('requests_per_minute', 100)))
        h4.addWidget(self.rl_rpm)
        layout.addLayout(h4)

        save_btn = QPushButton("保存并应用")
        save_btn.clicked.connect(self.save_general)
        layout.addWidget(save_btn)

        self.general_tab.setLayout(layout)

    def init_domain_tab(self):
        """
        初始化域名管理标签页。
        """
        layout = QVBoxLayout()
        self.domain_list = QComboBox()
        self.domain_list.addItems(CONFIG.get("domains", {}).keys())
        self.domain_list.currentTextChanged.connect(self.load_domain)
        layout.addWidget(self.domain_list)

        self.target_edit = QLineEdit()
        layout.addWidget(QLabel("Target URL:"))
        layout.addWidget(self.target_edit)

        self.ssl_enabled = QCheckBox("启用 SSL")
        layout.addWidget(self.ssl_enabled)

        self.cert_edit = QLineEdit()
        layout.addWidget(QLabel("证书路径:"))
        layout.addWidget(self.cert_edit)
        cert_btn = QPushButton("浏览证书文件")
        cert_btn.clicked.connect(self.browse_cert)
        layout.addWidget(cert_btn)

        self.key_edit = QLineEdit()
        layout.addWidget(QLabel("私钥路径:"))
        layout.addWidget(self.key_edit)
        key_btn = QPushButton("浏览私钥文件")
        key_btn.clicked.connect(self.browse_key)
        layout.addWidget(key_btn)

        self.force_https = QCheckBox("强制 HTTPS")
        layout.addWidget(self.force_https)

        self.auth_edit = QLineEdit()
        layout.addWidget(QLabel("Basic Auth (user:pass, 留空无密码):"))
        layout.addWidget(self.auth_edit)

        save_domain_btn = QPushButton("保存当前域名配置")
        save_domain_btn.clicked.connect(self.save_domain)
        layout.addWidget(save_domain_btn)

        add_domain_btn = QPushButton("添加新域名")
        add_domain_btn.clicked.connect(self.add_domain)
        layout.addWidget(add_domain_btn)

        self.domain_tab.setLayout(layout)

        if self.domain_list.count() > 0:
            self.domain_list.setCurrentIndex(0)
            self.load_domain(self.domain_list.currentText())

    def init_cloudflare_tab(self):
        """
        初始化 Cloudflare 配置标签页。
        """
        layout = QVBoxLayout()

        h1 = QHBoxLayout()
        h1.addWidget(QLabel("启用 Cloudflare 适配:"))
        self.cf_enabled = QCheckBox()
        self.cf_enabled.setChecked(CONFIG.get('cloudflare', {}).get('enabled', True))
        h1.addWidget(self.cf_enabled)
        layout.addLayout(h1)

        h2 = QHBoxLayout()
        h2.addWidget(QLabel("信任 Cloudflare 头:"))
        self.cf_trust = QCheckBox()
        self.cf_trust.setChecked(CONFIG.get('cloudflare', {}).get('trust_headers', True))
        h2.addWidget(self.cf_trust)
        layout.addLayout(h2)

        h3 = QHBoxLayout()
        h3.addWidget(QLabel("仅允许 Cloudflare IP (only_allow_from_cf):"))
        self.cf_only = QCheckBox()
        self.cf_only.setChecked(CONFIG.get('cloudflare', {}).get('only_allow_from_cf', False))
        h3.addWidget(self.cf_only)
        layout.addLayout(h3)

        save_cf_btn = QPushButton("保存 Cloudflare 配置")
        save_cf_btn.clicked.connect(self.save_cloudflare)
        layout.addWidget(save_cf_btn)

        self.cloudflare_tab.setLayout(layout)

    def init_security_tab(self):
        """
        初始化安全阈值标签页，支持编辑阈值和清空黑名单。
        """
        layout = QVBoxLayout()

        h1 = QHBoxLayout()
        h1.addWidget(QLabel("扫描阈值 (scan_threshold):"))
        self.scan_threshold = QLineEdit(str(CONFIG.get('security', {}).get('scan_threshold', 100)))
        h1.addWidget(self.scan_threshold)
        layout.addLayout(h1)

        h2 = QHBoxLayout()
        h2.addWidget(QLabel("登录失败阈值 (login_fail_threshold):"))
        self.login_threshold = QLineEdit(str(CONFIG.get('security', {}).get('login_fail_threshold', 5)))
        h2.addWidget(self.login_threshold)
        layout.addLayout(h2)

        h3 = QHBoxLayout()
        h3.addWidget(QLabel("请求频率阈值 (request_rate_threshold):"))
        self.rate_threshold = QLineEdit(str(CONFIG.get('security', {}).get('request_rate_threshold', 20)))
        h3.addWidget(self.rate_threshold)
        layout.addLayout(h3)

        h4 = QHBoxLayout()
        h4.addWidget(QLabel("UA 多样性阈值 (ua_diversity_threshold):"))
        self.ua_threshold = QLineEdit(str(CONFIG.get('security', {}).get('ua_diversity_threshold', 5)))
        h4.addWidget(self.ua_threshold)
        layout.addLayout(h4)

        h5 = QHBoxLayout()
        h5.addWidget(QLabel("路径熵阈值 (path_entropy_threshold):"))
        self.entropy_threshold = QLineEdit(str(CONFIG.get('security', {}).get('path_entropy_threshold', 3.5)))
        h5.addWidget(self.entropy_threshold)
        layout.addLayout(h5)

        h6 = QHBoxLayout()
        h6.addWidget(QLabel("封禁时长 (ban_duration, 秒):"))
        self.ban_duration = QLineEdit(str(CONFIG.get('security', {}).get('ban_duration', 3600)))
        h6.addWidget(self.ban_duration)
        layout.addLayout(h6)

        save_sec_btn = QPushButton("保存安全阈值")
        save_sec_btn.clicked.connect(self.save_security)
        layout.addWidget(save_sec_btn)

        clear_ban_btn = QPushButton("清空所有封禁")
        clear_ban_btn.clicked.connect(self.clear_bans)
        layout.addWidget(clear_ban_btn)

        self.security_tab.setLayout(layout)

    def save_security(self):
        """
        保存安全阈值到 CONFIG 并持久化到文件。
        """
        if 'security' not in CONFIG:
            CONFIG['security'] = {}
        CONFIG['security']['scan_threshold'] = int(self.scan_threshold.text() or 100)
        CONFIG['security']['login_fail_threshold'] = int(self.login_threshold.text() or 5)
        CONFIG['security']['request_rate_threshold'] = int(self.rate_threshold.text() or 20)
        CONFIG['security']['ua_diversity_threshold'] = int(self.ua_threshold.text() or 5)
        CONFIG['security']['path_entropy_threshold'] = float(self.entropy_threshold.text() or 3.5)
        CONFIG['security']['ban_duration'] = int(self.ban_duration.text() or 3600)
        
        # 持久化到文件
        save_config()
        
        # 通知 security 模块热加载阈值
        from security import reload_thresholds
        reload_thresholds()
        
        QMessageBox.information(self, "保存成功", "安全阈值已更新并持久化！需重启代理生效")

    def clear_bans(self):
        """
        清空所有黑名单 IP，并清理防火墙规则（支持 IPv6）。
        """
        from security import BLACKLIST, BLACKLIST_LOCK, save_blacklist, SYSTEM
        import subprocess
        with BLACKLIST_LOCK:
            BLACKLIST.clear()
            save_blacklist()
        # 清空防火墙规则（简化示例，实际根据 SYSTEM 调整）
        if SYSTEM == "windows":
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=CTSecureBan'], capture_output=True)
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name=CTSecureBanIPv6'], capture_output=True)
        elif SYSTEM == "linux":
            subprocess.run(['iptables', '-F'], capture_output=True)
            subprocess.run(['ip6tables', '-F'], capture_output=True)
        QMessageBox.information(self, "清理完成", "所有封禁 IP 已清除！")

    def load_domain(self, domain):
        """
        加载选定域名的配置到编辑框。

        :param domain: 域名字符串
        """
        if domain in CONFIG.get("domains", {}):
            cfg = CONFIG["domains"][domain]
            self.target_edit.setText(cfg.get("target", ""))
            self.ssl_enabled.setChecked(cfg.get("ssl", False))
            self.cert_edit.setText(cfg.get("cert", ""))
            self.key_edit.setText(cfg.get("key", ""))
            self.force_https.setChecked(cfg.get("force_https", True))
            self.auth_edit.setText(cfg.get("basic_auth", ""))

    def browse_cert(self):
        """
        浏览并选择证书文件。
        """
        file = QFileDialog.getOpenFileName(self, "选择证书文件", "certs", "证书文件 (*.pem *.crt)")[0]
        if file:
            self.cert_edit.setText(file)

    def browse_key(self):
        """
        浏览并选择私钥文件。
        """
        file = QFileDialog.getOpenFileName(self, "选择私钥文件", "certs", "私钥文件 (*.pem *.key)")[0]
        if file:
            self.key_edit.setText(file)

    def save_general(self):
        """
        保存通用配置到 CONFIG 并持久化。
        """
        try:
            if 'listen' not in CONFIG:
                CONFIG['listen'] = {}
            CONFIG['listen']['http_port'] = int(self.http_port.text() or 80)
            CONFIG['listen']['https_port'] = int(self.https_port.text() or 443)

            if 'rate_limit' not in CONFIG:
                CONFIG['rate_limit'] = {'default': {}}
            CONFIG['rate_limit']['enabled'] = self.rl_enabled.isChecked()
            CONFIG['rate_limit']['default']['requests_per_minute'] = int(self.rl_rpm.text() or 100)

            save_config()
            load_config("config.yaml")
            QMessageBox.information(self, "保存成功", "通用配置已更新！")
        except ValueError as e:
            QMessageBox.critical(self, "保存失败", f"值错误: {e}")
        except Exception as e:
            QMessageBox.critical(self, "保存失败", str(e))

    def save_domain(self):
        """
        保存当前域名的配置到 CONFIG 并持久化。
        """
        domain = self.domain_list.currentText()
        if domain in CONFIG["domains"]:
            cfg = CONFIG["domains"][domain]
            cfg["target"] = self.target_edit.text()
            cfg["ssl"] = self.ssl_enabled.isChecked()
            cfg["cert"] = self.cert_edit.text()
            cfg["key"] = self.key_edit.text()
            cfg["force_https"] = self.force_https.isChecked()
            cfg["basic_auth"] = self.auth_edit.text() if self.auth_edit.text() else None

            save_config()
            load_config("config.yaml")
            QMessageBox.information(self, "保存成功", f"{domain} 已更新！")

    def add_domain(self):
        """
        添加新域名到 CONFIG 并更新列表。
        """
        domain, ok = QInputDialog.getText(self, "添加域名", "输入新域名:")
        if ok and domain:
            CONFIG["domains"][domain] = {
                "target": "http://127.0.0.1:8080",
                "ssl": False,
                "cert": "",
                "key": "",
                "force_https": True,
                "basic_auth": None
            }
            save_config()
            load_config("config.yaml")
            self.domain_list.addItem(domain)
            self.domain_list.setCurrentText(domain)
            QMessageBox.information(self, "添加成功", f"域名 {domain} 已添加！")

    def save_cloudflare(self):
        """
        保存 Cloudflare 配置到 CONFIG 并持久化。
        """
        if 'cloudflare' not in CONFIG:
            CONFIG['cloudflare'] = {}
        CONFIG['cloudflare']['enabled'] = self.cf_enabled.isChecked()
        CONFIG['cloudflare']['trust_headers'] = self.cf_trust.isChecked()
        CONFIG['cloudflare']['only_allow_from_cf'] = self.cf_only.isChecked()

        save_config()
        load_config("config.yaml")
        QMessageBox.information(self, "保存成功", "Cloudflare 配置已更新！")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ConfigGUI()
    window.show()
    sys.exit(app.exec())